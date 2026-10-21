#!/bin/sh
# The store's nginx configuration, served by the detached "store" step,
# against client.sh in both roles. Credentials come from e2e_fixture.sh.
set -eu
cd "$(dirname "$0")"
fixture=$PWD/.e2e
export SCCACHE_CA_FILE="$fixture/ca.pem" SCCACHE_WEBDAV_ENDPOINT=https://store:3910 \
    SCCACHE_IDLE_TIMEOUT=0 CARGO_INCREMENTAL=0 \
    SCCACHE_LOG=sccache::compiler::compiler=debug SCCACHE_ERROR_LOG=/tmp/sccache-e2e.log
fail() { echo "FAIL: $*" >&2; exit 1; }

credentials() { # USER: the curl config line that logs in as USER
    password=wrong
    [ ! -f "$fixture/$1.password" ] || password=$(cat "$fixture/$1.password")
    printf 'user = "%s:%s"\n' "$1" "$password"
}
answer() { # USER METHOD PATH [curl options]: the HTTP status
    user=$1 method=$2 path=$3
    shift 3
    credentials "$user" \
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

use() { # USER [MODE]: a fresh step environment for client.sh
    export SCCACHE_WEBDAV_USERNAME=$1 SCCACHE_WEBDAV_PASSWORD="$(cat "$fixture/$1.password")"
    if [ $# -gt 1 ]; then export SCCACHE_WEBDAV_RW_MODE=$2; else unset SCCACHE_WEBDAV_RW_MODE; fi
    unset RUSTC_WRAPPER SCCACHE_RECACHE
}
build() { # "HITS MISSES WRITES" ANSWER: one clean build of the crate, and what its binary prints
    . ./client.sh
    [ "${RUSTC_WRAPPER:-}" = sccache ] || fail "client.sh left the build uncached"
    (cd /tmp/e2e-crate && cargo clean -q && cargo build -q)
    got="$(sccache --show-stats --stats-format json | python3 -c '
import json, sys
s = json.load(sys.stdin)["stats"]
print(sum(s["cache_hits"]["counts"].values()), sum(s["cache_misses"]["counts"].values()), s["cache_writes"])') $(/tmp/e2e-crate/target/debug/e2e-crate)"
    sccache --stop-server >/dev/null
    [ "$got" = "$1 $2" ] || fail "$SCCACHE_WEBDAV_USERNAME build: hits misses writes answer $got, expected $1 $2"
    echo "ok: $SCCACHE_WEBDAV_USERNAME build: hits misses writes answer $got"
}
answer_is() { printf 'pub fn answer() -> u32 {\n    %s\n}\n' "$1" > /tmp/e2e-crate/src/lib.rs; }
last_entry() { # the store path of the library sccache hashed last
    key=$(grep -o 'Hash key: [0-9a-f]*' "$SCCACHE_ERROR_LOG" | tail -1 | cut -d' ' -f3)
    echo "/$(echo "$key" | cut -c1)/$(echo "$key" | cut -c2)/$(echo "$key" | cut -c3)/$key"
}

# A library, cached, and a binary, never cached, that prints its answer.
cargo new -q --lib /tmp/e2e-crate
printf 'fn main() {\n    println!("{}", e2e_crate::answer());\n}\n' > /tmp/e2e-crate/src/main.rs
answer_is 42
use sccache-reader READ_ONLY
build "0 1 0" 42
use sccache-writer
build "0 1 1" 42
use sccache-reader READ_ONLY
build "1 0 0" 42
honest=$(last_entry)

# Someone holding the writer's credential stores the library that answers 41
# under the key of the one that answers 42.
answer_is 41
use sccache-writer
build "0 1 1" 41
credentials sccache-reader | curl -sSf --cacert "$fixture/ca.pem" -K - -o /tmp/planted \
    "$SCCACHE_WEBDAV_ENDPOINT$(last_entry)"
expect 204 sccache-writer PUT "$honest" --data-binary @/tmp/planted
answer_is 42
# Pull requests build what the store holds, so the plant reaches them...
use sccache-reader READ_ONLY
build "1 0 0" 41
# ...but the writer reads nothing: main compiles the library itself and
# replaces the plant, and pull requests read main's from then on.
use sccache-writer
build "0 1 1" 42
use sccache-reader READ_ONLY
build "1 0 0" 42

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
