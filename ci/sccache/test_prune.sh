#!/bin/sh
# Eviction tests for prune.sh, run in the cache's own image (busybox).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
fail() { echo "FAIL: $*" >&2; exit 1; }

# A store of five 64 KiB entries, last read in the order e1 (oldest) .. e5.
fresh_store() {
    store=$(mktemp -d)
    mkdir -p "$store/a/b/c"
    i=1
    for name in e1 e2 e3 e4 e5; do
        dd if=/dev/zero of="$store/a/b/c/$name" bs=1024 count=64 2>/dev/null
        touch -a -d "@$((1700000000 + i * 3600))" "$store/a/b/c/$name"
        i=$((i + 1))
    done
    echo "$store"
}
remaining() { (cd "$1/a/b/c" && ls | tr '\n' ' '); }
used_kib() { du -sk "$1" | cut -f1; }

store=$(fresh_store)
"$here/prune.sh" "$store" 1000 900
[ "$(remaining "$store")" = "e1 e2 e3 e4 e5 " ] || fail "under the high mark nothing is evicted: $(remaining "$store")"

store=$(fresh_store)
high=$(( $(used_kib "$store") - 1 ))
low=$(( high - 100 ))
"$here/prune.sh" "$store" "$high" "$low"
[ "$(remaining "$store")" = "e3 e4 e5 " ] || fail "over the high mark the least recently read go first: $(remaining "$store")"
[ "$(used_kib "$store")" -le "$low" ] || fail "eviction stops only at or under the low mark: $(used_kib "$store") > $low"

store=$(fresh_store)
touch -a -d "@1800000000" "$store/a/b/c/e1"
high=$(( $(used_kib "$store") - 1 ))
"$here/prune.sh" "$store" "$high" "$(( high - 100 ))"
[ "$(remaining "$store")" = "e1 e4 e5 " ] || fail "a read entry is kept over older unread ones: $(remaining "$store")"

echo "prune: 3 tests passed"
