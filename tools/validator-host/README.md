# Validator host

What one mainnet validator's operator runs on their own host: make the keys
there, hand out the row and a proof, and start the release node from the
signed manifest entry under systemd. `docs/launch/GENESIS-DAY.md` is the order
of the whole launch; this file is one host's part of it.

No secret leaves the host. The coordinator is given public keys, a peer id and
signatures, and the host's own record goes to the candidates list from the
host's screen, never through the coordinator.

## What the host needs

- The release node, built by `tools/runtime-build/build.sh --node <commit>
  release`, and its published sha256.
- python3 3.10 or newer and the launch preflight's hash-pinned packages, in a
  virtual environment:

  ```
  python3 -m venv /opt/materios/venv
  /opt/materios/venv/bin/pip install --no-cache-dir -r tools/launch-preflight/requirements.txt
  ```

  `V` below stands for `/opt/materios/venv/bin/python tools/validator-host/validator_host.py`.
- A user the node runs as (`materios`), and these paths:

  | Path | Holds | Owner, mode |
  |---|---|---|
  | `/usr/local/bin/materios-node` | the release binary | root, 0755 |
  | `/srv/materios/spec/mainnet-raw.json` | the chain spec; nothing else is ever written under `/srv/materios/spec` once the node runs | root, 0644 |
  | `/var/lib/materios` | the base path, empty but for the keystore | materios, 0700 |
  | `/etc/materios/node-key` | the libp2p node key | materios, 0600 |
  | `/etc/materios/validator.env` | the follower's database URL, with its password | root, 0600 |

## Before the day

### 1. The binary

```
install -m 0755 materios-node /usr/local/bin/materios-node
sha256sum /usr/local/bin/materios-node      # the published sha256, or this host does not start
```

### 2. The keys

As the node's user:

```
V keygen --keystore /var/lib/materios/chains/materios_mainnet/keystore --node-key /etc/materios/node-key
```

It makes an aura key (sr25519), a grandpa key (ed25519) and a partner-chain
key (ECDSA), each from its own 32 random bytes, and a node key, and prints:

```
aura key: 0x…
grandpa key: 0x…
partner-chain key: 0x…
peer id: 12D3KooW…
candidates row: <partner-chain key>:<aura key>:<grandpa key>
```

- Each keystore file is named `<hex of the key type><hex of the public key>`
  and holds its seed as the JSON string `"0x…"`, mode 0600, in a 0700
  directory. The key types are `aura`, `gran` and `crch`.
- `keygen` never writes into a keystore that holds an entry or over a node
  key. `V show` with the same two options prints the five lines again, from
  the files, and refuses a keystore that holds anything but one key of each
  type, each named by the public key its secret derives.
- The keystore and the node key are the only copies. Back them up where the
  validator's backup is kept, or not at all: a lost validator key is replaced
  through the candidates list, a leaked one cannot be.
- The node has no `key` subcommand, and `subkey` 20.0.0 is published neither
  as a binary nor as an image, so a host would have to compile it. The seeds
  here derive the public keys sp-core derives from them
  (`seeded_pair_should_work` for each scheme is a test vector).

### 3. The record and the proof

```
python3 -I candidates.py record val-1 <partner-chain key> <aura key> <grandpa key>
V prove --keystore /var/lib/materios/chains/materios_mainnet/keystore --name val-1 > val-1.proof.json
```

- The record (the Cardano setup kit's `candidates.py`) is what whoever builds
  the candidates list reads off this host's own screen.
- The proof holds the name, the three public keys and a signature by each key
  over `materios-validator-host-pop-v1`, the name and the candidates row. It
  is public: send it, with the five lines of step 2, to the coordinator, who
  runs `V verify val-1.proof.json` before the keys go into the manifest.
  `verify` prints the row it proved; a refusal means the keystore does not
  hold what the row says.

### 4. The network

- The peer-to-peer port (30333/tcp) is the only one opened to the internet. A
  host behind NAT forwards it and gives its public address in the manifest
  argv as `--public-addr /ip4/<address>/tcp/30333`.
- RPC and Prometheus listen on loopback. Never `--rpc-external`,
  `--unsafe-rpc-external` or `--rpc-methods unsafe` on a validator:
  `--unsafe-rpc-external` also opens a second listener on a random port,
  which a firewall rule for the RPC port misses.
- **NOT REHEARSED** (needs root): `ufw default deny incoming`, `ufw allow
  <ssh port>/tcp`, `ufw allow 30333/tcp`, `ufw enable`. Step 8 checks the
  listeners whatever the firewall is.

### 5. The manifest entry

Send the coordinator the host's name, addresses and paths. The entry's argv,
for the layout above:

```
/usr/local/bin/materios-node --validator --chain /srv/materios/spec/mainnet-raw.json
  --base-path /var/lib/materios --name val-1 --node-key-file /etc/materios/node-key
  --listen-addr /ip4/0.0.0.0/tcp/30333 --rpc-port 9944 --rpc-methods safe
  --prometheus-port 9615 --no-telemetry --no-mdns
  --reserved-nodes /ip4/<address>/tcp/30333/p2p/<peer id> …      (every other validator)
```

argv[0] is the absolute path: the launch gate compares the running process
with the manifest word for word.

## On the day

### 6. Receive

`mainnet-raw.json` at `/srv/materios/spec/`, the launch manifest, and the two
sha256 of GENESIS-DAY steps 0 and 7:

```
sha256sum /srv/materios/spec/mainnet-raw.json /usr/local/bin/materios-node
ls -A /var/lib/materios/chains/materios_mainnet      # keystore, and nothing else
```

Read this host's own entry in the manifest: its three keys are step 2's, its
`argv` and `env` are what this host runs, its follower's database above all.

### 7. The unit

```
printf 'DB_SYNC_POSTGRES_CONNECTION_STRING=postgres://<user>:<password>@<host>:<port>/<database>\n' \
    > /etc/materios/validator.env                                  # root, umask 077
V unit --launch launch.json --name val-1 --user materios --env-file /etc/materios/validator.env \
    > /etc/systemd/system/materios-validator.service
systemd-analyze verify /etc/systemd/system/materios-validator.service
systemctl daemon-reload
```

- `ExecStart` is the manifest's argv and each `Environment=` line one of its
  settings, so the launch gate's rule 8 finds what the manifest declares. The
  database URL alone comes from the environment file: the manifest holds it
  as `<host>:<port>/<database>`, with no user and no password.
- `unit` refuses an entry it cannot write exactly: a relative argv[0], or a
  word with a quote, a backslash, `%`, `$`, a control or a non-ASCII
  character, which systemd would rewrite.
- `RestartSec=120` is the wait before a crashed GRANDPA voter votes again.
  `systemctl restart` skips it: to restart a validator by hand,
  `systemctl stop`, wait 120 seconds, `systemctl start`.
- Without `--user` the unit names no user and is wanted by `default.target`:
  a user manager's unit, as the rehearsal ran it.

### 8. Start, and the first checks

```
systemctl start materios-validator
journalctl -u materios-validator -o cat | grep -E 'Local node identity|Running JSON-RPC|Strict Ariadne'
ss -ltnp | grep materios-node
curl -s -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"system_peers","params":[]}' http://127.0.0.1:9944
```

- The identity is step 2's peer id. The JSON-RPC line names loopback and the
  manifest's port: a busy port moves the listener to a random one.
- `ss` lists the peer-to-peer port, and RPC and Prometheus on loopback, and
  nothing else.
- `system_peers` answers `-32601 RPC call is unsafe to be called externally`:
  the proof of safe mode (`rpc_methods` lists every method in either mode).
- Then GENESIS-DAY step 16 (the genesis hash, authoring, finality) and step
  17 (the captures), with the PID of `systemctl show -p MainPID
  materios-validator`.

### 9. Watching it

Prometheus, on loopback: `substrate_block_height{status="finalized"}` must
rise, `substrate_finality_grandpa_round` must rise (a stalled round with a
rising best block is a finality stall), `substrate_sub_libp2p_peers_count`
must not be 0. The chain-wide custody watch is the operator kit's
(`materios-operator-kit`, `docs/CUSTODY_WATCH.md`), run once for the chain,
not on each validator.

## What was rehearsed

On one machine, with throwaway keys and the release binary: four hosts, each
through steps 1 to 3 and 6 to 8 as written, under a user manager (no `User=`,
paths under one scratch directory), on the mock Cardano follower. The chain
authored and finalized from keystores `keygen` wrote; the launch preflight
read each running process's argv as its manifest entry's, word for word; a
killed node came back after the 120 seconds and authored again; a stopped
one left the other three finalizing.

Not rehearsed: a system unit with `User=` and the root-owned paths, the
firewall, more than one machine, a real follower database.

## Tests

```
python3 -m pytest -q -p no:cacheprovider tools/validator-host/test_validator_host.py
```
