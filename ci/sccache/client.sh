# Sourced by a CI build step to put sccache in front of rustc (see README.md).
# The step's environment names the store (SCCACHE_WEBDAV_ENDPOINT) and the
# role: READ_ONLY with the reader's credential on pull requests, the writer's
# on pushes to main. The writer reads nothing: it compiles every crate and
# replaces its entry, so what the store holds never reaches a main build. A
# store that cannot be reached, or that refuses the writer, leaves the build
# uncached; a store that takes a write from a read-only step fails the step.

sccache_release=v0.18.0
sccache_sha256=45f1447fbe231e3037bde351ef70677dd212216c8d62ae7ca409fecc4d6acc89
if ! command -v sccache >/dev/null; then
    curl -fsSL -o /tmp/sccache.tar.gz "https://github.com/mozilla/sccache/releases/download/$sccache_release/sccache-$sccache_release-x86_64-unknown-linux-musl.tar.gz"
    echo "$sccache_sha256  /tmp/sccache.tar.gz" | sha256sum -c -
    tar xzf /tmp/sccache.tar.gz -C /tmp
    install /tmp/sccache-$sccache_release-x86_64-unknown-linux-musl/sccache /usr/local/bin/sccache
fi
install -m 0644 "${SCCACHE_CA_FILE:-$CI_WORKSPACE/ci/sccache/ca.pem}" /usr/local/share/ca-certificates/materios-sccache.crt
update-ca-certificates >/dev/null

# A write probe, with the credential kept off the command line.
sccache_status=$(printf 'user = "%s:%s"\n' "$SCCACHE_WEBDAV_USERNAME" "$SCCACHE_WEBDAV_PASSWORD" \
    | curl -s -o /dev/null -w '%{http_code}' --max-time 10 -K - -X PUT --data-binary probe \
        "$SCCACHE_WEBDAV_ENDPOINT/.write-probe") || :
case "${SCCACHE_WEBDAV_RW_MODE:-READ_WRITE}:$sccache_status" in
    READ_ONLY:401 | READ_ONLY:403)
        echo "sccache: the store refuses this step's writes (HTTP $sccache_status); reading only" ;;
    READ_ONLY:2??)
        echo "sccache: the store accepted a write from a read-only step (HTTP $sccache_status)" >&2
        exit 1 ;;
    READ_WRITE:2??)
        echo "sccache: the store takes this step's writes (HTTP $sccache_status); compiling every crate, reading none"
        export SCCACHE_RECACHE=1 ;;
    *)
        echo "sccache: write probe answered HTTP $sccache_status in ${SCCACHE_WEBDAV_RW_MODE:-READ_WRITE} mode; building uncached" >&2
        sccache_status=unusable ;;
esac
if [ "$sccache_status" != unusable ] && sccache --start-server; then
    export RUSTC_WRAPPER=sccache
else
    echo "sccache: no server; building uncached" >&2
fi
