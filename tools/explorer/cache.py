"""In-memory TTL cache with stale-while-revalidate for the explorer API.

On cache miss: compute synchronously (first request pays the cost).
On cache stale: return stale value immediately, refresh in background.
This means users almost never wait for slow RPC calls after the first load.
"""

import logging
import threading
import time
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class TTLCache:
    def __init__(self, default_ttl: float = 30.0, max_size: int = 2000):
        self._data: dict[str, tuple[float, Any]] = {}  # key -> (expires_at, value)
        self._fns: dict[str, tuple[Callable, float]] = {}  # key -> (compute_fn, ttl)
        self._refreshing: set[str] = set()  # keys currently being refreshed
        self._lock = threading.Lock()
        self._default_ttl = default_ttl
        self._max_size = max_size

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            expires_at, value = entry
            if expires_at > 0 and time.time() > expires_at:
                del self._data[key]
                return None
            return value

    def get_stale(self, key: str) -> Optional[Any]:
        """Return cached value even if expired (for stale-while-revalidate)."""
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            return entry[1]

    def is_expired(self, key: str) -> bool:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return True
            expires_at, _ = entry
            return expires_at > 0 and time.time() > expires_at

    def set(self, key: str, value: Any, ttl: Optional[float] = None):
        t = ttl if ttl is not None else self._default_ttl
        expires_at = time.time() + t if t > 0 else -1  # -1 = permanent
        with self._lock:
            self._data[key] = (expires_at, value)
            if len(self._data) > self._max_size:
                self._evict_expired()

    def get_or_compute(self, key: str, fn: Callable[[], Any], ttl: Optional[float] = None) -> Any:
        # Fast path: fresh cache hit
        cached = self.get(key)
        if cached is not None:
            return cached

        # Stale-while-revalidate: return stale value, refresh in background
        stale = self.get_stale(key)
        if stale is not None:
            self._background_refresh(key, fn, ttl)
            return stale

        # True cache miss (first request): compute synchronously
        # Store the fn for future background refreshes
        t = ttl if ttl is not None else self._default_ttl
        with self._lock:
            self._fns[key] = (fn, t)
        value = fn()
        self.set(key, value, ttl)
        return value

    def _background_refresh(self, key: str, fn: Callable[[], Any], ttl: Optional[float]):
        """Refresh a cache entry in a background thread. Deduplicates concurrent refreshes."""
        with self._lock:
            if key in self._refreshing:
                return  # already refreshing
            self._refreshing.add(key)

        def _do_refresh():
            try:
                value = fn()
                self.set(key, value, ttl)
            except Exception as e:
                logger.debug("Background cache refresh failed for %s: %s", key, e)
            finally:
                with self._lock:
                    self._refreshing.discard(key)

        t = threading.Thread(target=_do_refresh, daemon=True)
        t.start()

    def _evict_expired(self):
        """Remove expired entries. Must be called under lock."""
        now = time.time()
        expired = [k for k, (exp, _) in self._data.items() if exp > 0 and now > exp]
        for k in expired:
            del self._data[k]


# Global cache instance
cache = TTLCache(default_ttl=30.0)
