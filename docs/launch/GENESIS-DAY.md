# Genesis day: the operator's runbook

The steps of a Materios mainnet launch, in the one order that works. A wrong
genesis is permanent, and the keyholders sign offline, so the order is built
to find every refusal before a node starts and to send no keyholder back to
their device for a change that does not touch genesis.

`P` stands for `python3 tools/launch-preflight/launch_preflight.py`, run from
a checkout of the commit that pins the launch key. Paths are examples. The
preflight's rules and inputs are in `tools/launch-preflight/README.md`; this
file is the order to run things in.

**What was rehearsed.** Every step below was run end to end on one machine
with throwaway keys, four validators on loopback, the mock Cardano follower,
and stand-ins for Kupo and the public RPC filter, except the steps marked
**NOT REHEARSED AGAINST CARDANO**. Those need a rehearsal on Cardano preprod
before the launch; the last section lists what the mock could not show. The
rehearsal made its validator keys with a script, so the `subkey` commands of
step 2 were not run in it: run them once on a throwaway key before the day.

**Who signs what.** Each keyholder of the Root and guardian multisigs signs
a proof that binds the genesis and the genesis-bound fields of the manifest.
The launch key signs the whole manifest. A change to a host, port, path,
peer, RPC URL, capture location, a node's follower database or the lock's
output id needs a new launch signature (step 12) and no keyholder. A change
to a role, a key, the dust, the economics, the Cardano scripts, an
authority's keys or the node binary means a new spec and every proof again
(back to step 6).

## Before the day

### 0. One node build for every validator

```
sha256sum materios-node            # the release build, on the machine that built it
sha256sum materios-node            # on each validator, on the file it received
```

- **Proves:** every validator runs the one binary the keyholders sign for.
  The manifest pins this hash as each authority's `exe_sha256`, each proof
  of possession binds it, and `check` hashes the binary each node process
  runs.
- **If the hashes differ:** that validator does not start. Send the file
  again. If the release is built again and its hash changes, every proof of
  step 11 is void, since each binds the hash, and if the runtime it embeds
  changed, so is the genesis: everything from step 6 is redone. A debug
  build embeds another runtime than a release build, so it builds another
  genesis.

### 1. Cardano setup: NOT REHEARSED AGAINST CARDANO

`docs/GOVERNANCE.md`, steps 1 to 4: governance init spends the genesis UTXO,
and the D-parameter (every seat permissioned, none registered) and the
permissioned candidates outputs are created, one unit of each token, none
burnt. `get-scripts` on the genesis UTXO prints the manifest's
`partner_chain` values.

- **Proves:** nothing yet; `check` reads these outputs in steps 13 and 18.
- **Timing:** both outputs must be two Cardano epochs old when block 1 is
  authored. Rule 9 names the earliest launch epoch and when its first
  session starts.
- **If it fails:** the genesis UTXO is spent once. A setup that goes wrong
  after governance init needs a new genesis UTXO and so new `partner_chain`
  values.

### 2. Validator keys, on each validator

Each validator needs an aura key (sr25519), a grandpa key (ed25519), a
cross-chain key (ECDSA, 33 bytes compressed) and a libp2p node key. The node
has no `key` subcommand; use `subkey` 20.0.0 and `jq`. `subkey generate` and
`subkey inspect` print the secret phrase with the public key, so neither is
run with its output on the terminal: the first writes to a file only the
validator's user reads, and the others go through `jq`, which prints the
public key alone.

```
umask 077
subkey generate --scheme sr25519 --output-type json > val-1.key.json    # prints nothing
jq -r .secretPhrase val-1.key.json > val-1.phrase                        # the secret URI, in a private file
jq -r .publicKey val-1.key.json                                          # the aura public key
subkey inspect --scheme ed25519 --output-type json val-1.phrase | jq -r .publicKey    # the grandpa public key
subkey inspect --scheme ecdsa --output-type json val-1.phrase | jq -r .publicKey      # the cross-chain public key
subkey generate-node-key --file node-key                                 # prints the peer id
```

Keystore files go in `<base path>/chains/materios_mainnet/keystore/`, each
named `<hex of the key type><hex of the public key>` and holding the secret
URI as a JSON string (`jq -R . val-1.phrase > <keystore file>`, under the
same umask). The key types are `aura`, `gran` and `crch`. Remove
`val-1.key.json` once the keystore files are written; keep `val-1.phrase`
wherever the validator's backup is kept, and nowhere else.

- **Proves:** nothing; the manifest takes the three public keys.
- **If a validator has no node key:** it exits at start with
  `NetworkKeyNotFound`. Give `--node-key-file`.

### 3. Role keys, offline

The three sudo keyholders, the two guardian keyholders (none of them a sudo
keyholder), the enactor, the anchor signer, the gateway sponsor, three to
sixteen oracles, the attestors, the recovery friends and rescuers, and the
dust pool. `docs/MAINNET-GENESIS.md` gives each role's dust floor.

### 4. The launch key

```
P launch-key new --out launch.key        # offline; prints the public key and nothing else
P launch-key public --key launch.key     # prints it again
```

Then a reviewed pull request sets `tools/launch-preflight/launch_keys.json`
to `{"keys": ["0x<public key>"]}`, and the reviewer confirms the key with
its holder over another channel.

- **Proves:** which key may sign off a launch. `check` reads the pin from
  the checkout it runs in, and prints the key and that file on PASS.
- **If it fails:** `launch-key new` never overwrites a file; choose another
  name. Until a key is pinned, every `check` refuses under rule 6.
- **Record:** the commit id that pins the key. Genesis day runs `P` from a
  checkout of exactly that commit. Never pass `--manifest-key` for the
  launch.

### 5. The operator's table of exposed keys

`exposed-keys.json`, kept outside the repository: every retired key whose
secret was exposed, under all three schemes, or `{"keys": []}` (README,
"Well-known keys"). `check` requires it.

## The genesis artifacts

Each step is forced by what the next one hashes.

### 6. Write the launch manifest

`launch.json`, from `tools/launch-preflight/fixtures/mainnet-launch.json`:
the roles, with every multisig member as `{"key": "5..."}`; `dust`; the
authorities with their three keys and the published `exe_sha256`;
`attestation_threshold`; `economics`; `partner_chain`; `slots_per_epoch`;
`settlement`; `cardano_follower`; `supply.genesis_lock` with its address
and native script and, for now, a placeholder `utxo`
(`0000...0000#0`); each node's `argv`, `env` and capture paths;
`rpc_proxies`; `public_rpc`.

Each validator's `env` holds the seven Cardano settings and:

```
"MAIN_CHAIN_FOLLOWER": "db-sync",
"DB_SYNC_POSTGRES_CONNECTION_STRING": "db-sync.internal:5432/cexplorer",
"BLOCK_STABILITY_MARGIN": "0",
"SIDECHAIN_BLOCK_BENEFICIARY": "0x<32 bytes: the validator's aura public key>"
```

- The connection string is written as `<host>:<port>/<database>`. **Never
  put a user or a password in the manifest:** it is signed and handed round.
  The URL the node itself is given must name its host, port and database.
- A validator with no `SIDECHAIN_BLOCK_BENEFICIARY` starts, syncs and never
  authors. One with no connection string or stability margin exits at start.
- `--chain` names a path whose directories nothing writes to once the node
  runs: `/srv/materios/spec/mainnet-raw.json`, with the base path elsewhere,
  or a path relative to the unit's working directory. A path under `/home`
  or `/tmp` fails rule 8 sooner or later (README, "The spec a running node
  read").
- Choose fixed ports outside the kernel's ephemeral range (32768 to 60999).
  A busy RPC port does not stop the node: it moves the listener to a random
  port. Check the log line `Running JSON-RPC server: addr=` after start.
- `public_rpc` is `[]` unless a deny-by-default method filter already
  serves the URL (README, "Public RPC probe"). A URL that reaches a node
  directly refuses.

### 7. Build the raw spec, on two machines

```
materios-node build-spec --chain mainnet:launch.json --raw --disable-default-bootnode > mainnet-raw.built.json
sha256sum mainnet-raw.built.json
materios-node chain-id --chain mainnet-raw.built.json
cp mainnet-raw.built.json mainnet-raw.json
sha256sum mainnet-raw.json
```

- **Proves:** the build is deterministic and both machines hold the same
  manifest and binary. `chain-id` prints the genesis hash, and settlement's
  and the oracle's chain ids, which must equal it.
- **Two files, two hashes.** `mainnet-raw.built.json` is the node's own
  output and is never edited: its sha256 is the one the two machines
  compare here, and the one step 9 compares a rebuild with.
  `mainnet-raw.json` is the spec the launch uses. Add `bootNodes` to it now
  if the launch uses any: it is the one field an operator may add. Its
  sha256, taken after that edit, is the one every validator checks its copy
  against in step 14. With no boot node added, the two files are the same
  bytes.
- **If the hashes differ:** compare the two manifests and the two binaries'
  `sha256sum`; do not go on.
- **If `build-spec` refuses:** it names the manifest field. Fix it and
  build again.

### 7a. A dry run of the genesis stage, before the lock and before any proof

The launch key holder signs the draft, and the genesis stage runs on it with
no Kupo. Nothing here is kept: the lock's id is still the placeholder, and
step 12 signs again.

```
P sign --spec mainnet-raw.json --launch launch.json --key launch.key --out draft-signed.json
P check --stage genesis --spec mainnet-raw.json --launch launch.json \
    --signed-manifest draft-signed.json --node-binary ./materios-node \
    --subwasm ./subwasm --extra-well-known exposed-keys.json
```

- **Expected: it refuses, exit 1, under rule 10 alone**, one reason for each
  multisig member, since nobody has signed a proof yet:

  ```
  MAINNET LAUNCH PREFLIGHT (genesis stage): REFUSE (5 reasons)
    [10 possession] roles.guardian[0].members[0] gives no pop: its holder has not signed its challenge (challenge --role guardian --index 0 0), so no one has shown they hold its key
    [10 possession] roles.guardian[0].members[1] gives no pop: ...
    [10 possession] roles.sudo[0].members[0] gives no pop: ...
    [10 possession] roles.sudo[0].members[1] gives no pop: ...
    [10 possession] roles.sudo[0].members[2] gives no pop: ...
    not run: ...        (four lines for what needs a running node, three for what needs a Kupo)
  This is not the launch gate: run check without --stage once every authority's node runs, and announce the genesis hash only after it passes.
  ```

- **Proves:** apart from the proofs, and from Cardano, which it did not
  read, the manifest, the spec and the binary pass every rule that needs no
  running node: the keys, the dust and economics, the committee, each
  validator's argv and settings, that the spec is what the binary builds
  from the manifest, and that the binary builds this genesis from the spec
  and holds its hash as its chain ids.
- **Any other reason, or exit 2:** fix it now, and build again from step 7
  if it touches a genesis-bound field. This is the cheap moment: the lock
  does not exist yet, and no keyholder has been asked for anything.
- **The runtime against the source:** `tools/runtime-build/build.sh <commit>`
  rebuilds the release commit's runtime and prints its blake2-256. It must
  be the `code_hash` in `draft-signed.json`. If it is not, the binary embeds
  another runtime than the reviewed commit's: stop.

### 8. Create the genesis lock on Cardano: NOT REHEARSED AGAINST CARDANO

Build and submit the cMATRA lock: an output at the manifest's lock address,
holding at least the genesis issuance, whose inline datum is the genesis
hash as a Plutus bytestring (CBOR `5820` followed by the 32 bytes).

- **Proves:** this genesis, and no other, is backed by that output: the
  datum binds one genesis hash.
- **Why here:** the datum is the genesis hash, which exists only after step
  7.
- **If it fails:** build the transaction again. The lock's output id is a
  deployment field, so a lock created again later voids no proof; it needs
  step 12 again.

### 9. Put the lock's id in the manifest

Set `supply.genesis_lock.utxo` to `<tx id>#<index>`, then build once more
and compare with the node's own output of step 7:

```
materios-node build-spec --chain mainnet:launch.json --raw --disable-default-bootnode | sha256sum
sha256sum mainnet-raw.built.json
```

- **Proves:** the spec does not depend on the lock's id: the two hashes are
  equal. The file to compare with is `mainnet-raw.built.json`, not
  `mainnet-raw.json`, which differs from every build once boot nodes were
  added to it.
- **If the hash changed:** something else in the manifest changed. Find it
  before going on.

### 10. Freeze the genesis-bound fields

From here the roles, `dust`, `attestation_threshold`, `economics`,
`partner_chain`, `slots_per_epoch`, `settlement`, `cardano_follower`, the
lock's `address` and `native_script`, and each authority's `aura`,
`grandpa`, `cross_chain` and `exe_sha256` do not change. Any change to one
of them voids every proof of step 11. The other fields may still move.

### 11. Proofs of possession, one for each multisig member

Each of the five keyholders, on their own device, from the spec and manifest
they reviewed:

```
P challenge --spec mainnet-raw.json --launch launch.json --role sudo --index 0 <i>
subkey sign --suri <secret URI file> --hex --message <the challenge, 0x included>
```

(`--role guardian --index 0 <i>` for a guardian keyholder.) Each signature
goes in the manifest as that member's `"pop"`, in any order.

- **Proves:** a secret signed for each member's key, for this chain, this
  genesis and these genesis-bound fields: no member is the address of a
  multisig nobody declared.
- **If a holder is handed the hex:** they run `challenge` themselves and
  compare. A key signs whatever it is given.
- **If a proof does not verify** (rule 10, step 13): the holder signed for
  another spec or manifest, or a genesis-bound field changed since. Print
  the challenge again from the current files and sign again; the refusal
  names the command.

### 12. The launch signature

```
P sign --spec mainnet-raw.json --launch launch.json --key launch.key --out signed.json
```

On the machine that holds the launch key, which needs a checkout of the
pinning commit, the preflight's Python packages, the spec and the manifest.

- **Proves:** the launch key holder signs off this exact spec file and this
  whole manifest, deployment included.
- **Run it again** after any edit of the manifest or the spec. It needs no
  keyholder.
- **Before signing**, and before starting: each validator's operator reads
  their own node's `argv` and `env` in the manifest, its follower's
  database above all. The launch signature is the only signature on those.

### 13. The verdict before any node starts

```
P check --stage genesis --spec mainnet-raw.json --launch launch.json \
    --signed-manifest signed.json --node-binary ./materios-node \
    --kupo http://<mainnet kupo>:1442 --subwasm ./subwasm \
    --extra-well-known exposed-keys.json
```

It needs subwasm v0.21.3 and the release binary, runnable on this machine.
With `--kupo` it also needs a Kupo on Cardano mainnet that indexes the lock
address and both committee policies (**NOT REHEARSED AGAINST CARDANO**:
rehearsed against a stand-in).

- **Proves:** every rule that needs no running node passes: the manifest,
  the keys, the proofs, the launch signature, the economics and dust, the
  committee, the settlement binding, each validator's listeners and
  settings as its manifest entry gives them, and of the release binary, run
  offline: that the spec is what it builds from the manifest, that it
  builds this genesis from the spec as each validator's argv launches it,
  and that its runtime holds the genesis hash as its chain ids and the
  Cardano ids the spec stores. With `--kupo`: the lock, the committee
  datums and their age. It gives every reason step 18 gives that needs no
  running node.
- **Passes as:** `MAINNET LAUNCH PREFLIGHT (genesis stage): PASS`, then a
  `not run:` line for each rule it left out, then that it is not the launch
  gate.
- **If it refuses (exit 1):** every reason is printed. A reason that names a
  genesis-bound field sends the launch back to step 6; a reason that names a
  deployment field is fixed in the manifest and signed again (step 12).
- **If an input cannot be read (exit 2):** every such input is named in the
  one run. Fix them all and run again.
- **Do not start a node until this passes.** A refusal after the start
  means stopping a chain whose genesis hash every peer has already seen.

### 14. Distribute

To each validator: `mainnet-raw.json`, at the path its `--chain` names, at
least a few seconds before the start, its `sha256sum` checked there against
the one step 7 took of that file; the binary, checked as in step 0; its own
entry of the signed manifest. Its base path is empty: a base path that
holds a database of the chain id `materios_mainnet` starts that old genesis
whatever `--chain` names.

## The start

### 15. Start every validator

With exactly its manifest argv and env. GRANDPA finalizes with more than two
thirds of the authorities: three of four, four of five.

- A validator with no peer authors nothing. Block 1 comes at the first slot
  of a validator that has a peer and whose follower serves the epoch's
  committee data.
- The first committee draw is refused once, by design, and the genesis
  committee stays seated.
- **If nothing is authored:** look for `Unable to author block in slot` (the
  beneficiary), `Failed to create ... main chain follower` (the database or
  the stability margin), `NetworkKeyNotFound` (the node key), and whether
  the committee outputs are two Cardano epochs old (step 1).

### 16. First checks, on every validator

```
curl -s -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"chain_getBlockHash","params":[0]}' http://127.0.0.1:<rpc port>
```

- **Proves:** the node runs the signed genesis: the answer is the genesis
  hash of step 7.
- Then: every authority authors within one round of slots,
  `chain_getFinalizedHead` advances, `Balances.TotalIssuance` equals
  `OrinqReceipts.FixedIssuance`, and the log names the Ariadne rule
  (`Drawing committees under the Strict Ariadne rule`).
- **If a node serves another genesis:** stop it. Its base path held an old
  database, or its `--chain` names another file.

### 17. Captures, on each validator

With the node's own PID (`systemctl show -p MainPID <unit>`, or
`docker inspect -f '{{.State.Pid}}' <container>`), as root or the node's
user, for `--chain /srv/materios/spec/mainnet-raw.json`:

```
cat /proc/<pid>/cmdline > val-1.cmdline
python3 capture_environ.py <pid> val-1.cmdline.environ
cp /proc/<pid>/exe val-1.exe
cp /proc/<pid>/root/srv/materios/spec/mainnet-raw.json val-1.chain.json
cat /proc/<pid>/stat > val-1.stat
cat /proc/stat > val-1.proc-stat
(cd /proc/<pid>/root && stat -c '%Z %f %n' srv srv/materios srv/materios/spec \
    srv/materios/spec/mainnet-raw.json) > val-1.chain.stat
for call in 'chain_getBlockHash:[0]:genesis' 'system_chain:[]:chain-name' \
            'system_chainType:[]:chain-type' 'system_properties:[]:properties'; do
  method="${call%%:*}"; rest="${call#*:}"; params="${rest%%:*}"; name="${rest#*:}"
  curl -s -H 'Content-Type: application/json' \
      -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" \
      http://127.0.0.1:<rpc port> > "val-1.$name.json"
done
```

The loop is plain POSIX shell, for bash, dash and zsh alike: each call is
quoted, so no shell reads `[0]` or `[]` as a file pattern, and it is split
with parameter expansions alone. For a relative `--chain`, copy
from and run `stat` in `/proc/<pid>/cwd`. The environment capture names the
process it read, and `check` holds it to `val-1.stat`: after a restart, take
both again, with the new PID.
`capture_environ.py` is the one file `tools/launch-preflight/capture_environ.py`
and needs python3 alone. It writes the settings the preflight reads, the
database as `<host>:<port>/<database>`, and prints their names: no value and
no password leaves the validator. **Do not send `cat /proc/<pid>/environ`:**
it holds every setting, the database password among them, and `check`
refuses it.

Collect each validator's files where `check` runs, at the paths the manifest
names; the environment capture sits next to the cmdline capture, with
`.environ` after its name.

### 18. The launch gate

```
P check --spec mainnet-raw.json --launch launch.json --signed-manifest signed.json \
    --kupo http://<mainnet kupo>:1442 --subwasm ./subwasm --extra-well-known exposed-keys.json
```

It needs what step 13 needs, every authority's binary runnable on this
machine, the public RPC behind its filter if `public_rpc` names one, and a
Kupo on Cardano mainnet (**NOT REHEARSED AGAINST CARDANO**).

- **Proves:** every rule passes on what runs: each validator's argv and
  settings are the manifest's, none runs the mock follower, each runs the
  pinned binary on the checked spec file and serves the signed genesis.
- **Passes as:** `MAINNET LAUNCH PREFLIGHT: PASS`, then the launch key that
  signed and the file that pins it. Keep the output, the signed manifest and
  the commit id in the launch record.
- **What can still refuse here.** Step 13 gave every reason this run gives
  that needs no running node, so after a PASS there a refusal here is about
  what runs: what a validator's node serves, the binary, spec file, argv or
  settings it runs with, when its `--chain` path last changed, or what a
  public RPC URL serves. Or it is about something that changed since step
  13: a file, the manifest, an output on Cardano.
- **If it refuses on a validator's deployment** (its settings, its argv, its
  spec path, its binary, its RPC): fix that validator, restart it, take its
  captures again. If the manifest was what was wrong, edit it and sign again
  (step 12). No keyholder is needed and the genesis stands.
- **If it refuses on the genesis itself,** with a reason step 13 also gives
  when run again now: something changed since step 13 passed. Stop every
  validator, wipe every base path, and go back to step 6. The genesis hash
  changes.
- **If an input cannot be read (exit 2):** every missing or unreadable
  capture of every validator is listed in the one run.

### 19. Announce

Publish the genesis hash only after step 18 passes.

## The first hour

Rehearsed on the local chain; the calls and the delay classes are in
`docs/GOVERNANCE.md`, "Root Timelock".

20. Two sudo keyholders set the sudo account's recovery configuration
    (`Recovery.create_recovery`, the friends sorted by account).
21. Two sudo keyholders schedule Root's first batch through
    `RootTimelock.schedule`: `Oracle.register_attestor(pair, account)` for
    each oracle and pair, and any `Balances.force_transfer` of dust from the
    dust pool to a signer admitted later. It waits the standard delay of
    seven days; the enactor then submits `RootTimelock.enact`.
22. TEE attestation ships disabled. Releasing it is scheduled, then waits
    seven days or the guardian's `fast_track`, then is enacted. The
    kill-switch, `TeeAttestation.set_disabled(true)`, runs at once.
23. A guardian drill: both guardian keyholders cancel a scheduled task.

## What the rehearsal's mock could not show

To rehearse on Cardano preprod before the launch:

- the committee Ariadne draws from real D-parameter and permissioned
  candidates datums, through db-sync and through yaci-store, and the two
  agreeing;
- the two-epoch lag: block 1 only once the outputs are two epochs old, and
  the first rotation that reads real data;
- governance init, the D-parameter and permissioned candidates
  transactions, and the genesis lock;
- `check` and `check --stage genesis` against a real Kupo: its tip age, the
  outputs' `created_at`, a single unspent token output;
- the native-token observation's inherent against a real follower;
- a follower outage or lag on one validator while the chain runs, and every
  full node needing its own follower;
- a release build (its genesis hash, code size and timings differ from a
  debug build's), systemd units or containers (the `--chain` path rule and
  mount points), the public RPC behind a real filter, and more than one
  machine.
