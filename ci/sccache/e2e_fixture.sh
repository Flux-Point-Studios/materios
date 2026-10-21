#!/bin/sh
# Throwaway TLS and credentials for test_e2e.sh: a CA constrained to the
# detached "store" step's name, its server certificate, and both users.
set -eu
out=$(cd "$(dirname "$0")" && pwd)/.e2e
mkdir -p "$out"
cd "$out"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.pem -days 1 \
    -subj "/CN=e2e sccache store CA" -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" -addext "nameConstraints=critical,permitted;DNS:store" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout server.key -out server.csr \
    -subj "/CN=e2e sccache store" 2>/dev/null
printf 'subjectAltName=DNS:store\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n' > server.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -set_serial 1 -days 1 -extfile server.ext \
    -out server.crt 2>/dev/null
for user in sccache-reader sccache-writer; do
    openssl rand -hex 32 > "$user.password"
    printf '%s:%s\n' "$user" "$(openssl passwd -6 -stdin < "$user.password")" >> htpasswd-read
done
grep '^sccache-writer:' htpasswd-read > htpasswd-write
rm ca.key server.csr server.ext
# The store step runs as nginx's unprivileged user.
chmod 0644 ./*
echo "fixture: $(ls | tr '\n' ' ')"
