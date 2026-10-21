#!/bin/sh
# The store's nginx configuration, served by the detached "store" step,
# against client.sh in both roles. Credentials come from e2e_fixture.sh.
set -eu
cd "$(dirname "$0")"
fixture=$PWD/.e2e
export SCCACHE_CA_FILE="$fixture/ca.pem" SCCACHE_WEBDAV_ENDPOINT=https://store:3910 \
    SCCACHE_IDLE_TIMEOUT=0 CARGO_INCREMENTAL=0
fail() { echo "FAIL: $*" >&2; exit 1; }

answer() { # USER METHOD PATH [curl options]: the HTTP status
    user=$1 method=$2 path=$3
    shift 3
    password=wrong
    [ ! -f "$fixture/$user.password" ] || password=$(cat "$fixture/$user.password")
    printf 'user = "%s:%s"\n' "$user" "$password" \
        | curl -s -o /dev/null -w '%{http_code}' --cacert "$fixture/ca.pem" -K - -X "$method" "$@" \
            "$SCCACHE_WEBDAV_ENDPOINT$path" || :
}
expect() { # STATUS USER METHOD PATH [curl options]
    want=$1
    shift
    got=$(answer "$@")
    [ "$got" = "$want" ] || fail "$1 $2 $3 answered $got, expected $want"
    echo "ok: $1 $2 $3 -> $got"
}

tries=0
until [ "$(answer sccache-reader GET /absent)" = 404 ]; do
    tries=$((tries + 1))
    [ "$tries" -lt 60 ] || fail "the store never answered"
    sleep 1
done

# Every request is authenticated; only the writer changes anything, and
# nothing deletes or moves.
expect 401 nobody GET /0/0/0/0
expect 401 nobody PUT /0/0/0/0 --data-binary x
expect 404 sccache-reader GET /0/0/0/0
expect 401 sccache-reader PUT /0/0/0/0 --data-binary x
expect 401 sccache-reader MKCOL /0/
expect 401 sccache-reader DELETE /0/0/0/0
expect 201 sccache-writer PUT /0/0/0/0 --data-binary x
expect 200 sccache-reader GET /0/0/0/0
expect 405 sccache-writer DELETE /0/0/0/0
expect 405 sccache-writer MOVE /0/0/0/0 -H "Destination: $SCCACHE_WEBDAV_ENDPOINT/0/0/0/1"
expect 404 sccache-writer PROPFIND /0/
# The store's certificate verifies only through the pinned CA.
if curl -s -o /dev/null "$SCCACHE_WEBDAV_ENDPOINT/"; then
    fail "the store's certificate verified without the pinned CA"
fi
echo "ok: the store's certificate is refused without the pinned CA"

use() { # USER [MODE]: the step environment client.sh reads
    export SCCACHE_WEBDAV_USERNAME=$1 SCCACHE_WEBDAV_PASSWORD="$(cat "$fixture/$1.password")"
    if [ $# -gt 1 ]; then export SCCACHE_WEBDAV_RW_MODE=$2; else unset SCCACHE_WEBDAV_RW_MODE; fi
    unset RUSTC_WRAPPER
}
build() { # EXPECTED "hits misses writes" for one clean build of the crate
    . ./client.sh
    [ "${RUSTC_WRAPPER:-}" = sccache ] || fail "client.sh left the build uncached"
    (cd /tmp/e2e-crate && cargo clean -q && cargo build -q)
    got=$(sccache --show-stats --stats-format json | python3 -c '
import json, sys
s = json.load(sys.stdin)["stats"]
print(sum(s["cache_hits"]["counts"].values()), sum(s["cache_misses"]["counts"].values()), s["cache_writes"])')
    sccache --stop-server >/dev/null
    [ "$got" = "$1" ] || fail "$SCCACHE_WEBDAV_USERNAME build: hits misses writes $got, expected $1"
    echo "ok: $SCCACHE_WEBDAV_USERNAME build: hits misses writes $got"
}

cargo new -q --lib /tmp/e2e-crate
use sccache-reader READ_ONLY
build "0 1 0"
use sccache-writer
build "0 1 1"
use sccache-reader READ_ONLY
build "1 0 0"

# A read-only step whose credential the store lets write fails at once.
use sccache-writer READ_ONLY
if (. ./client.sh); then
    fail "client.sh carried on after the store took a read-only step's write"
fi
echo "ok: a store that takes a read-only step's write fails the step"

# A store that does not answer leaves the build uncached.
use sccache-reader READ_ONLY
export SCCACHE_WEBDAV_ENDPOINT=https://store:3911
. ./client.sh
[ -z "${RUSTC_WRAPPER:-}" ] || fail "client.sh used a store that does not answer"
echo "ok: an unanswering store leaves the build uncached"
echo "e2e: all checks passed"
