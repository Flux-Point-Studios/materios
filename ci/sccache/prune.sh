#!/bin/sh
# One eviction pass: once DATA holds more than HIGH_KIB, delete the entries
# read longest ago until it holds at most LOW_KIB.
# Usage: prune.sh DATA HIGH_KIB LOW_KIB
set -eu
data=$1 high=$2 low=$3
used=$(du -sk "$data" | cut -f1)
[ "$used" -gt "$high" ] || exit 0
evicted=$(find "$data" -type f -exec stat -c '%X %b %B %n' {} + \
    | sort -n \
    | awk -v excess=$((used - low)) '
        freed >= excess { exit }
        { freed += $2 * $3 / 1024; print $4 }' \
    | xargs -r rm -fv -- | wc -l)
echo "prune: evicted $evicted entries, $used KiB -> $(du -sk "$data" | cut -f1) KiB"
