# Shared sccache store

`check-test` in `.woodpecker/rust.yaml` compiles through
[sccache](https://github.com/mozilla/sccache) against one store on Node-3,
`https://192.168.0.133:3910`. Pull requests read it; only pushes to main
write it, and those read nothing from it: `client.sh` sets `SCCACHE_RECACHE`
for the writer, so a main build compiles every crate itself and replaces its
entry. No pull request can plant a compiled artifact that a main build
reuses, and no main result depends on what the store holds.

## Write policy

| Pipeline | Step | Credential | Reads entries | Store answer to a write |
|---|---|---|---|---|
| `pull_request` to main | `check-test` | `sccache-reader` (`sccache_reader_password`, events push and pull_request) | yes | 401 |
| `push` to main | `check-test-main` | `sccache-writer` (`sccache_writer_password`, event push only) | no | 201/204 |

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
and fails if the store accepts it. A writer whose write the store refuses
builds uncached, since sccache would otherwise fall back to reading the
store. A store that does not answer the probe within 10 s leaves the step
uncached. One that stops answering mid-build turns
each lookup into a local compile once the connection fails, or after sccache's
60 s lookup timeout if it accepts connections and never replies.
`test_policy.py` keeps every workflow to the table above and keeps both steps
computing the same cache keys. `test_e2e.sh` plants an entry under a key a
main build computes and checks that the main build compiles its own while a
pull request's build reads the plant.

Woodpecker 3.16 filters secrets by event and image, not by branch, so a push
to any branch of this repository whose own pipeline file asks for the writer
gets it. Only accounts with push access can do that; today that is the
repository's one admin, who can also merge to main. What such a push stores
reaches pull request builds until the next main build recompiles that key;
it never reaches a main build.

The writer's password is stored in one place, the Woodpecker secret on
Node-2. Node-3 holds only its hash, and no operator host keeps a copy.

## Integrity on the LAN

The store speaks TLS 1.3 only. `ca.pem` is the CA that signed its
certificate; its key was destroyed after signing, and its name constraints
admit only `192.168.0.133` and no DNS name. The server's key exists only in
`~/sccache-cache/tls` on Node-3. `client.sh` installs the CA, so no other
host on the LAN can answer for the store and serve forged entries. The CA and
the certificate expire on 2031-10-21.

## Resources and eviction

- Memory 512 MiB, swap none, one CPU, 64 processes; logs rotate at
  3 x 10 MiB.
- Disk: every `CACHE_PRUNE_SECONDS` (30 s) `prune.sh` measures the store. Above
  `CACHE_HIGH_KIB` (40 GiB) it deletes the entries read longest ago until the
  store holds at most `CACHE_LOW_KIB` (32 GiB): least recently used, by access
  time. Node-3's root filesystem is `relatime`, so an entry's access time is
  current to within a day. Between two passes the store can grow by at most
  what the network delivers in 30 s.
- An evicted entry costs pull requests one recompile until the next main
  push writes it back.

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
- Rotate a password: generate it in memory (`openssl rand -hex 32` into a
  shell variable, never a file), send its `openssl passwd -6 -stdin` hash to
  Node-3 and the value to the Woodpecker repo secret
  (`PATCH /api/repos/26/secrets/<name>`), then restart the container. The
  writer's line is in both `htpasswd-read` and `htpasswd-write`; the reader's
  only in `htpasswd-read`.
- Rotate the certificate: generate a new CA and certificate on Node-3, sign,
  destroy the CA key, replace `ca.pem` here by pull request and deploy `tls/`
  when it merges. Until both match, builds run uncached.
- Empty the cache: `sudo docker compose stop`,
  `rm -rf ~/sccache-cache/store/data ~/sccache-cache/store/incoming`,
  `sudo docker compose start`. Stop and start keep the container, and with it
  the access log of every write.
- Remove it: `sudo docker compose down` in `~/sccache-cache`, then
  `rm -rf ~/sccache-cache`. `client.sh` builds uncached when the store does
  not answer, so CI keeps working. The repo secrets `sccache_reader_password`
  and `sccache_writer_password` go only after the steps that name them, since
  Woodpecker refuses a pipeline that names a missing secret.
