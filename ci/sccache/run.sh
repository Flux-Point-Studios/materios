#!/bin/sh
# Container entrypoint: an eviction pass every CACHE_PRUNE_SECONDS beside
# nginx in the foreground.
set -eu
store=/var/cache/nginx
mkdir -p "$store/data" "$store/incoming"
(
    while :; do
        /etc/nginx/prune.sh "$store/data" "$CACHE_HIGH_KIB" "$CACHE_LOW_KIB" \
            || echo "prune: pass failed with status $?, retrying" >&2
        sleep "$CACHE_PRUNE_SECONDS"
    done
) &
exec nginx -g 'daemon off;'
