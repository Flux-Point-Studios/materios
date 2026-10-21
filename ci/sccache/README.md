# Shared sccache store

`check-test` in `.woodpecker/rust.yaml` compiles through
[sccache](https://github.com/mozilla/sccache) against one store on Node-3,
`https://192.168.0.133:3910`. Pull requests read it; only pushes to main
write it, so no pull request can plant a compiled artifact that a later main
build reuses.

## Write policy

| Pipeline | Step | Credential | Store answer to a write |
|---|---|---|---|
| `pull_request` to main | `check-test` | `sccache-reader` (`sccache_reader_password`, events push and pull_request) | 401 |
| `push` to main | `check-test-main` | `sccache-writer` (`sccache_writer_password`, event push only) | 201/204 |

Two controls hold this, neither of them in the pipeline file a pull request
can edit:

- The store (`nginx.conf`) authenticates every request. GET and HEAD take
  either user; every other method needs the writer (`limit_except`). DELETE,
  COPY and MOVE are enabled for no one, so even the writer only adds and
  replaces entries.
- Woodpecker releases `sccache_writer_password` to push events alone. A
  pull_request pipeline that names it fails to compile ("secret ... is not
  allowed to be used with pipeline event pull_request"), whatever its YAML
  says.

`client.sh` adds a check on every run: a read-only step probes a write first,
and fails if the store accepts it. A store that does not answer the probe
within 10 s leaves the step uncached. One that stops answering mid-build turns
each lookup into a local compile once the connection fails, or after sccache's
60 s lookup timeout if it accepts connections and never replies.
`test_policy.py` keeps every workflow to the table above and keeps both steps
computing the same cache keys.

Woodpecker 3.16 filters secrets by event and image, not by branch, so a push
to any branch of this repository whose own pipeline file asks for the writer
gets it. Only accounts with push access can do that; today that is the
repository's one admin, who can also merge to main.

## Integrity on the LAN

The store speaks TLS 1.3 only. `ca.pem` is the CA that signed its
certificate; its key was destroyed after signing, and its name constraints
admit only `192.168.0.133` and no DNS name. `client.sh` installs it, so a
host on the LAN cannot answer for the store and serve forged entries. The CA
and the certificate expire on 2031-10-21.

## Resources and eviction

- Memory 512 MiB, swap none, one CPU, 64 processes; logs rotate at
  3 x 10 MiB.
- Disk: every `CACHE_PRUNE_SECONDS` (30 s) `prune.sh` measures the store. Above
  `CACHE_HIGH_KIB` (40 GiB) it deletes the entries read longest ago until the
  store holds at most `CACHE_LOW_KIB` (32 GiB): least recently used, by access
  time. Node-3's root filesystem is `relatime`, so an entry's access time is
  current to within a day. Between two passes the store can grow by at most
  what the network delivers in 30 s.
- An evicted entry costs one recompile on the next main push, which writes it
  back.

## One store for both agents

Node-2 and Node-3 run the same image, toolchain, workspace path
(`/woodpecker/src/github.com/Flux-Point-Studios/materios`) and environment, so
sccache computes the same keys on both. One store lets a main build on either
agent warm pull requests on both; a store per host would split the hits
between them and double the disk. Both reach it over the LAN; a step on
Node-3 reaches it through Docker's published port.

## Operations (Node-3)

The deployed copy lives in `~/sccache-cache`: `compose.yaml`, `nginx.conf`,
`run.sh` and `prune.sh` from this directory, plus `tls/server.crt`,
`tls/server.key`, `htpasswd-read` and `htpasswd-write`, which never enter git.
Docker on Node-3 needs sudo.

- Deploy or update: copy the four files, then `sudo docker compose up -d` in
  `~/sccache-cache`.
- Rotate a password: write a new `htpasswd-*` line (`openssl passwd -6 -stdin`),
  restart the container, update the matching Woodpecker repo secret.
- Rotate the certificate: generate a new CA and certificate, sign, destroy the
  CA key, replace `ca.pem` here by pull request and deploy `tls/` when it
  merges. Until both match, builds run uncached.
- Empty the cache: `sudo docker compose down`,
  `rm -rf ~/sccache-cache/store/data`, `sudo docker compose up -d`.
- Remove it: `sudo docker compose down` in `~/sccache-cache`, then
  `rm -rf ~/sccache-cache`. `client.sh` builds uncached when the store does
  not answer, so CI keeps working. The repo secrets `sccache_reader_password`
  and `sccache_writer_password` go only after the steps that name them, since
  Woodpecker refuses a pipeline that names a missing secret.
