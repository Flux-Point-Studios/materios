# Mainnet launch preflight

Refuses a Materios mainnet genesis or launch unless every rule passes. It is the
genesis counterpart of the runtime-upgrade ceremony gate: that gate diffs an
upgrade against the live runtime, this one checks the artifacts a launch starts
from.

It reads:

- the **raw chain spec** (`build-spec --raw`), the exact storage every node loads;
- the **runtime metadata**, extracted from that spec's own `:code` with
  [subwasm](https://github.com/chevdor/subwasm) v0.21.3;
- **Cardano mainnet through a Kupo index**: the cMATRA lock that backs genesis,
  and the permissioned candidates datum, which sets the committee after the
  first rotation;
- **each public RPC URL, live**: the methods it lists and whether it answers
  an unsafe one, over HTTP and over a WebSocket;
- **each authority's running node argv**: a copy of its
  `/proc/<pid>/cmdline`;
- **each authority's node binary and chain spec file**: copies of its
  `/proc/<pid>/exe` and of the file its `--chain` names, and that binary run
  offline to build the genesis it would start from (see
  [Node attestation](#node-attestation));
- **the genesis each authority's running node serves**: its answer to
  `chain_getBlockHash [0]`, saved from its local RPC;
- a **launch manifest**: who holds each role, the economics, where the genesis
  lock is, each node's launch command, the RPC proxy configs and the public RPC
  URLs;
- a **signed launch manifest**: the genesis hash, runtime code hash, chain-spec
  hash and launch manifest hash, signed with an ed25519 launch key that
  `launch_keys.json` pins.

## Rules

| Rule | Refuses when |
|---|---|
| 1 dev-keys | A well-known key appears in genesis storage, in the runtime code, in a role or any member of a role's multisig, in a Cardano permissioned candidate, in a node's launch command or environment (`--alice`, `--dev`, any bare `//Path` URI such as `//Bob` or `//Oracle`, with or without a `///password`, a setting named for a secret URI (`SIGNER_URI`, `--suri`: a name holding uri, seed, mnemonic, phrase or secret, and not ending in file, path or dir) whose value has no phrase, such as the soft path `/Attestor0`, the dev mnemonic, or the dev seed in 0x-hex), or as the manifest signing key. `Sudo.Key` is not the account `roles.sudo` declares, `roles.sudo` does not need two keyholders to act (see [Multisig roles](#multisig-roles)), or a genesis account is not the account of any declared role, so who holds it is unchecked. A role in `sudo`, `anchor_signer`, `attestors`, `oracle` is not declared, or `anchor_signer` or `attestors` is empty. The chain spec's `chainType` is not `Live`, or its name reads as a test network: the anchor worker would then accept a dev signer. Genesis `Grandpa.Authorities` is not exactly the `grandpa` keys of the authorities whose `aura` key genesis `Aura.Authorities` lists, each once with weight 1 as build-spec writes them: a voter no authority declares finalizes unchecked, and a weight above 1 or a key listed twice counts as several voters. A Cardano permissioned candidate's `gran` key is not the `grandpa` key that the authority with its `aura` key declares, or it carries none: the candidates vote on finality with those keys from the first committee rotation. |
| 2 rewards | `economics` does not declare the attestor reward per signer, era cap base and era cap baseline, or genesis does not store exactly those values; or it does not declare the validator reward per era and the treasury emission share (perbill), or they differ from the runtime constants `OrinqReceipts.ValidatorRewardPerEra` and `OrinqReceipts.TreasuryEmissionShare`. |
| 3 rpc | A public RPC URL, probed live, lists in `rpc_methods` a method outside the safe set or answers `system_peers`, an unsafe method that changes nothing (see [Public RPC probe](#public-rpc-probe)); the launch does not declare `public_rpc`; an authority's running node process, read from its `cmdline` capture, serves unsafe RPC methods (`unsafe`, or the `auto` default on a loopback listener) on an external listener or behind a proxy route; a node runs `--validator` without being declared an authority; or a block author (a genesis `Aura.Authorities` key or a Cardano permissioned candidate's aura key) has no authority node in the manifest, so its listeners go unchecked. Every listener counts: the default one (`--rpc-port`, `--rpc-external`, `--rpc-methods`) and each `--experimental-rpc-endpoint listen-addr=...,methods=...`, including every value one `--experimental-rpc-endpoint` takes up to the next option, with each option trimmed as the node trims it. |
| 4 supply | `roles.attestors` is empty, an attestor is endowed below `BondRequirement + ExistentialDeposit + fee_buffer`, `Balances.TotalIssuance` differs from what the genesis accounts hold (free plus reserved), or genesis issuance plus the runtime's emission reserves exceeds the cMATRA the genesis lock holds on Cardano: the reserve would be counted both as cMATRA and as MATRA. The lock must be an unspent output at the declared mainnet address, which pays to the declared native script; that script must need at least two key holders to spend it (a well-known key counts as anyone's, a time bound as met), and the output's inline datum must be this genesis hash, so one lock cannot back two genesis attempts. A Plutus lock is refused: the preflight cannot evaluate one. The reserves are read from the metadata constants `OrinqReceipts.ValidatorEmissionReserve` and `OrinqReceipts.AttestationRewardReserve`; a runtime that does not declare them is refused, since what it mints after genesis cannot be bounded. Genesis sets storage outside `GENESIS_STORAGE`, each pallet's storage version and `:code`/`:extrinsic_index`: any other item (a billing withdrawal, a credit entry, a key no runtime item declares) can hold a claim on MATRA the bound does not count. |
| 5 pallets | `PerpEngine` is in the runtime metadata, under its own name or any other (its `pallet_perp_engine` types give it away). |
| 6 checkpoint | The genesis hash, runtime code hash, chain-spec hash or launch manifest hash differs from the signed launch manifest, the signature does not verify under a key `launch_keys.json` pins (or no key is pinned, or the key given with `--manifest-key` is not pinned), the spec carries `codeSubstitutes`, or an authority runs `--wasm-runtime-overrides`, which would replace the signed code. Genesis may store `System.LastRuntimeUpgrade` only as build-spec writes it for its code, that code's spec version and spec name, or not at all: frame-executive runs a runtime's migrations when its spec version is above the stored one or its name differs, so another value runs them at block 1 or skips them at a later upgrade. Also refuses a genesis that sets the `NativeTokenManagement` observation scripts. The launch plan's checkpoint canary runs the real observation from the genesis checkpoint and requires zero transfers from the genesis-lock transaction and at least one from a canary deposit made after it. This runtime's observation has no checkpoint: until its first non-zero transfer it asks for every transfer since Cardano genesis, so it would count the genesis lock and the canary cannot pass. |
| 7 timelock | Genesis sets no `RootTimelock.Guardian`, or one that is `Sudo.Key`; `roles.guardian` does not declare exactly one guardian whose account is the genesis guardian, or that guardian does not need two keyholders to act or has a multisig as a member (see [Multisig roles](#multisig-roles)); or any account in the guardian, the multisig or a member at any depth, is also the sudo multisig, one of its members or `Sudo.Key`: the guardian vetoes the sudo key's queued Root calls, so its keyholders must be apart from the sudo key's. Genesis sets no `RootTimelock.Delays`, or a delay below the runtime's mainnet delay for its class (`RootTimelock.DefaultDelays`: 1, 7 and 30 days), a long delay above `RootTimelock.MaxDelay` (90 days), or delays out of the runtime's order 0 < recovery <= standard <= long. Both constants are read from the runtime metadata; a runtime that does not declare them is refused. The preprod genesis fails this rule: its delays are minutes, and its guardian is the sudo keyholders' 3-of-3. |
| 8 node | An authority's running node serves another genesis than the one the preflight computes, which the manifest signs and the lock's datum binds; its own node binary, run offline on the options its node process runs with, builds another genesis than that one; the binary is not the one `exe_sha256` pins; the file its `--chain` names, as captured, is not the checked spec byte for byte; or its `--chain` names a chain built into the node, or is not given (the node then loads its built-in `local`, or `dev` under `--dev`). An option the preflight does not know, a node that cannot run here or builds no genesis from the checked spec, and a spec that names `telemetryEndpoints` refuse as unreadable. See [Node attestation](#node-attestation). |

Every reason is printed. Exit 0 means every rule passed, 1 means at least one
refused, 2 means an input could not be read (also a refusal), including hex in
another spelling (see [Hex](#hex)), a number genesis stores at another width
than its type (see [Stored numbers](#stored-numbers)), a node option the
preflight does not know or a node that builds no genesis from the checked spec
(see [Node attestation](#node-attestation)), a proxy
config with no route the preflight can read, a Kupo that is unreachable,
behind its node or does not index the permissioned candidates token, and a
public RPC URL whose answers the probe cannot resolve.

## Usage

```
pip install -r requirements.txt

# The launch key holder signs the hashes of the exact raw spec and launch manifest.
python3 launch_preflight.py sign --spec mainnet-raw.json --launch launch.json --key launch.key --out signed.json

python3 launch_preflight.py check --spec mainnet-raw.json --launch launch.json \
    --signed-manifest signed.json \
    --kupo http://<mainnet kupo>:1442 --subwasm ./subwasm \
    --extra-well-known ~/exposed-keys.json
```

`sign` reads only the spec and the manifest, so the manifest can be signed
before the nodes start, with each authority's node binary pinned by its sha256. Its `--key` file holds the 32-byte ed25519 seed as
0x-hex, and at most the newline that ends its line. `check` also reads each
authority's `cmdline`, `exe`, `chain_spec` and `served_genesis` captures, runs each authority's
node binary offline, and calls each URL in `public_rpc`, so it runs once the
launch's nodes and proxies are up, on a machine that can run each authority's
binary (the same architecture, or one with qemu-user binfmt for it).

The signature must verify under a key `launch_keys.json` pins (`{"keys":
["0x<ed25519 public key>"]}`), committed with the launch key holder's review.
No key is pinned until the launch key is minted, and until then every run
refuses. `--manifest-key` checks against a key given on the command line
instead, for a rehearsal: a key that is not pinned is itself a refusal, so a
rehearsal shows every other reason next to that one.

The genesis hash is computed here (Substrate trie root of the raw storage at the
runtime's state version, then the genesis header), so the check does not trust a
node to report it. The chain-spec and launch manifest hashes are blake2-256 of
their canonical JSON (sorted keys, no whitespace).

The Kupo must follow Cardano mainnet and index the genesis lock address and the
permissioned candidates policy, the third policy id in genesis
`SessionCommitteeManagement.MainChainScriptsConfiguration`:

```
kupo --match <lock address> --match '<permissioned candidates policy>.*' ...
```

The preflight trusts that Kupo for what Cardano holds, and refuses when it is
more than 300 slots behind its node.

## Hex

Every hex value is read in one spelling: lowercase digits, two a byte, and
nothing else. The raw spec's storage keys and values (`:code` included), the
launch manifest's hex keys and `native_script`, the signed manifest,
`launch_keys.json`, `--manifest-key` and the `sign --key` file start it with
`0x`, as build-spec and `sign` write it. The key tables and Kupo's datums have
no `0x`, as `gen_well_known_keys.py` writes a table and the anchor worker reads
it. Any other spelling refuses as unreadable, and so does a JSON object in the
spec, a manifest, `launch_keys.json` or a key table that names a key twice, in
any JSON escape.

The node reads a raw spec with impl-serde's `from_hex`, which also takes upper
case and hex with no `0x`, and skips a space, tab, CR or LF while still
counting it toward nibble alignment; FRAME then ignores the bytes a value has
left over. So a value written `0x 1122...` loads as `0x0112...`, one with no
`0x` loads the two digits a reader that strips `0x` drops, and a key followed
by two spaces loads as that key and a zero byte: a guardian, a delay or a
balance read one way would launch as another, or not at all. build-spec writes
the one spelling, so its output loads unchanged.

## Stored numbers

Each number the preflight reads from genesis must be exactly as long as its
type: `OrinqReceipts.AttestationRewardPerSigner`, `OrinqReceipts.EraCapBase`,
`OrinqReceipts.BondRequirement` and `Balances.TotalIssuance` 16 bytes (u128),
`OrinqReceipts.EraCapBaselineAttestorCount` 4 (u32), and every `System.Account`
value 80 (`AccountInfo`: four u32 counters, then free, reserved, frozen and
flags as u128), filed under blake2_128 of its account followed by the account.
FRAME reads a value too short for its type as the item's default, zero, and
ignores the bytes past its type, and the runtime reads an account at that one
key only. So a baseline of 32 written as the single byte `0x20` would read as
32 here and launch as 0, which lifts the per-era attestor reward cap to the
whole `EraCapBase`. build-spec writes each at its width and key; anything else
refuses as unreadable.

## Runtime code

`:code` is the runtime WASM, or that WASM compressed as one whole zstd frame
after the 8-byte prefix `0x52bc537646db8e05`, as the runtime's build writes it.
The node's decoder reads every frame, skips a skippable one, and refuses a
frame cut short or bytes after the last frame, where zstandard's readers stop
at the end of the first frame or of the input. So a dev key in a second frame
would run on chain unscanned. Any other framing refuses as unreadable.

The genesis hash takes the trie layout from the code as the node does. The
node decodes the `runtime_version` custom section with the Core API version
that the first `runtime_apis` section declares, or else the one the version
lists itself. It reads a state version only from Core 4 on and takes any
state version but 0 as V1. A version section the node cannot decode refuses.

## Launch manifest

```json
{
  "roles": {
    "sudo": [{"threshold": 2, "members": ["5D...", "5H...", "5C..."]}],
    "guardian": [{"threshold": 2, "members": ["5E...", "5F...", "5G..."]}],
    "anchor_signer": ["5F..."],
    "attestors": ["5G..."],
    "oracle": [],
    "endowed": ["5E...", {"threshold": 2, "members": ["5A...", "5B..."]}]
  },
  "economics": {
    "attestation_reward_per_signer": 1000000,
    "era_cap_base": 50000000000,
    "era_cap_baseline_attestor_count": 32,
    "validator_reward_per_era": 102739726,
    "treasury_emission_share_perbill": 150000000,
    "fee_buffer": 100000000
  },
  "supply": {
    "genesis_lock": {"utxo": "<tx id>#<index>", "address": "addr1w...", "native_script": "0x8303..."}
  },
  "nodes": [
    {"name": "val-1", "host": "val-1", "addresses": ["10.0.0.11"], "authority": true,
     "aura": "0x<aura public key>", "grandpa": "0x<grandpa public key>",
     "argv": ["materios-node", "--validator", "--chain", "/srv/materios/mainnet-raw.json", "--rpc-methods", "safe"],
     "exe_sha256": "0x<sha256 of the node binary>",
     "cmdline": "captures/val-1.cmdline", "exe": "captures/val-1.exe", "chain_spec": "captures/val-1.chain.json",
     "served_genesis": "captures/val-1.genesis.json", "env": {}},
    {"name": "edge-1", "host": "edge-1", "addresses": ["10.0.0.2"], "authority": false}
  ],
  "rpc_proxies": [
    {"name": "public-rpc", "node": "edge-1", "kind": "nginx-dump", "config": "nginx-T.txt",
     "other_targets": ["status.example.org:443"]}
  ],
  "public_rpc": ["https://rpc.example.org/rpc"]
}
```

- `roles` maps a role name to entries. An entry is a public key (SS58, or
  0x-hex 32-byte account or 33-byte ECDSA key), never a secret URI, or a
  multisig `{"threshold": k, "members": [...]}` whose members are entries too;
  its account is pallet_multisig's for those members and threshold, and every
  member is checked. A flat entry asserts one key that its holder alone
  controls: the preflight cannot see inside an address, so a multisig written
  as the address a wallet shows has its members unchecked. Declare every
  multisig by its members. `sudo`, `anchor_signer`, `attestors` and `oracle`
  must be present; an empty `oracle` states that no oracle signer runs.
  `roles.sudo` must name exactly the genesis `Sudo.Key` (or be empty when
  genesis sets none), and `roles.guardian` exactly the genesis
  `RootTimelock.Guardian`, each as a multisig role (below); no account in
  the guardian, at any depth, may also be in `roles.sudo` or be `Sudo.Key`. Every
  genesis account must be the account of some entry; `endowed` holds the ones
  no other role names. `attestors` are the accounts that bond at genesis and
  get the endowment floor check.
- Every `economics` value is a non-negative integer in the smallest unit; an
  unknown field or any other value refuses as unreadable.
- `supply.genesis_lock` is the Cardano output holding the cMATRA that backs
  Materios issuance, and `native_script` the CBOR of the native script its
  address pays to, as 0x-hex. The backing is the cMATRA amount Kupo reports at
  that output; the manifest carries no backing figure. Create the lock after
  building the raw spec, with the genesis hash as its inline datum: a Plutus
  bytestring, CBOR `5820` followed by the 32 bytes.
- `nodes` lists every machine that runs a launch process or a proxy. Each
  declares `authority` as `true` or `false`, and an authority its `aura` and
  `grandpa` public keys. `argv` is a list: the words the process receives, as
  `/proc/<pid>/cmdline` lists them. A command line given as one string
  refuses as unreadable, since systemd rewrites an `ExecStart` line before
  it runs it (`\xNN` escapes, `%` specifiers such as `%i`, an `@` prefix, a
  `;` word that starts another command) and a shell or a container runtime
  splits one by its own rules. A `sh -c` wrapper, as a systemd unit or a
  container entrypoint writes it, is opened, its script split at `;`, `&&`
  and newlines, and an authority's last command must start `materios-node`
  or `materios-node-spo`. Before it, an authority's launch may run only
  `set`, `export`, `cd`, `umask`, `ulimit` and `mkdir`, as bare words, and
  the node subcommands `build-spec` and `purge-chain`, which open no chain
  database: any other program could start a node whose listeners go
  unchecked, and any other subcommand (`export-blocks`, `check-block`,
  `export-state`, `import-blocks`, `revert`) writes the genesis of its own
  `--chain` into the base path, which the node then starts from whatever
  its `--chain` names. A launch the preflight would
  have to evaluate refuses as unreadable: a `$VAR` or backtick expansion, a
  NUL byte in a word or setting (execve ends each one there), a script word
  the shell rewrites (brace expansion, a `*`, `?` or `[` glob, a `~`, a word
  starting with `#`, which is a comment) or a backslash line continuation,
  quoted or not, a pipe, redirection, subshell or `||`, a script file, a
  file the shell runs on its own (a login or interactive shell's startup
  files, `.` or `source`, zsh, which always reads its zshenv, and bash
  without `--norc` before its short options: under `-c` it runs
  `~/.bashrc` and `/etc/bash.bashrc` first when `SSH_CLIENT` is set or its
  stdin is a socket), a shell option other than `-a`, `-e` and `-u` (on the
  shell or through `set`: `-x` runs `$PS4` as code), or several arguments in
  one word.
- An authority's `cmdline` is the path of a copy of its running node
  process's `/proc/<pid>/cmdline`: the argv the kernel holds, each word
  ended by a NUL byte (`cat /proc/<pid>/cmdline > val-1.cmdline` on its
  machine, with the node's own PID: a container's
  `docker inspect -f '{{.State.Pid}}'`, a unit's `MainPID` when the unit
  runs the node itself). `check` reads it and `sign` does not, so the
  manifest can be signed before the nodes start. Rule 3 checks the listeners
  of that argv, which must be word for word the argv the preflight reads the
  launch to run: a node started another way, or a launch the preflight
  misread, refuses as unreadable. Only an authority takes one.
- An authority's `exe_sha256` pins the sha256 of the node binary it runs, as
  0x-hex. `exe` is the path of a copy of its node process's
  `/proc/<pid>/exe`, and `chain_spec` of a copy of the file its `--chain`
  names, taken on its machine (`/proc/<pid>/root` followed by an absolute
  path, `/proc/<pid>/cwd/` followed by a relative one). `served_genesis`
  is the path of its running node's answer to `chain_getBlockHash [0]` on
  its local RPC, saved on its machine once the node runs:
  `curl -s -H 'Content-Type: application/json' -d
  '{"jsonrpc":"2.0","id":1,"method":"chain_getBlockHash","params":[0]}'
  http://127.0.0.1:9944 > val-1.genesis.json`, at the node's own RPC port.
  It must be a JSON-RPC 2.0 answer whose result is the block hash in
  0x-prefixed lowercase hex, as the node writes it. `check` reads all three,
  and `sign` none. Only an authority takes them.
- `env` holds the settings a node's unit or container definition gives it
  (`Environment=` and `EnvironmentFile=`, `docker run -e`, a compose file's
  `environment:`) as the process receives them: systemd decodes escapes and
  expands specifiers in an `Environment=` line first. The settings the
  service manager or container runtime adds on its own (`PATH`, `LANG`,
  `HOME`, `HOSTNAME`, `INVOCATION_ID`, `JOURNAL_STREAM`, `SYSTEMD_EXEC_PID`),
  which `/proc/<pid>/environ` always lists, are left out: the preflight
  takes the service manager's defaults as given. Assignments in a script
  (`NAME=value`, `export NAME=value`) count the same, and so does a setting
  any word hands a program: a `NAME=value` word, or one inside a word after
  whitespace, a quote or `=` (`systemd-run --setenv=NAME=value`, a settings
  string) or after a short option (`docker run -eNAME=value`). No node may
  set what the shell or the dynamic loader acts on: `BASH_ENV`, a
  `BASH_FUNC_` import, `PS4`, `ENV`, `SHELLOPTS`, `BASHOPTS`, `PATH` or any
  `LD_` setting. No node's launch may run `env -S` (`--split-string`), which
  splits a string into settings and arguments by env's own quoting and
  escapes, or `.`, `source`, `eval` or `trap`, also behind `builtin` or
  `command`, which run a file or a string the preflight does not open. An
  authority may set only logging (`RUST_LOG`, `RUST_BACKTRACE`,
  `RUST_LIB_BACKTRACE`), `TZ` and the node's Cardano follower settings
  (`MAIN_CHAIN_FOLLOWER`, `DB_SYNC_POSTGRES_CONNECTION_STRING`,
  `CARDANO_SECURITY_PARAMETER`, `CARDANO_ACTIVE_SLOTS_COEFF`,
  `BLOCK_STABILITY_MARGIN`, `SIDECHAIN_BLOCK_BENEFICIARY`, the four `MC__`
  epoch settings, `MITHRIL_AGGREGATOR_ENDPOINT`,
  `MITHRIL_GENESIS_VERIFICATION_KEY`); any other setting could run code or
  change the node beyond its argv, such as a module path or the mock
  follower. The preflight takes a program to be what its name says; it reads
  no binary but each authority's node binary (rule 8), and nothing else on
  the machine. For a node that is not
  an authority, that trust covers what its programs and the shell's other
  builtins do with their arguments: `printf -v NAME` under `set -a`, for
  one, exports a setting that no word names. An authority's launch runs only
  the setup commands above before its node, so this does not reach it.
- A proxy is `nginx`, `nginx-dump` or `cloudflared`. `nginx` is a config
  file: each `include` is read from disk in its place, a relative name from
  the config's directory, and an include pattern's only wildcard may be `*`:
  nginx matches a pattern with glob(3), which reads `?`, `[...]` and a
  backslash apart from the preflight (`[^x]` negates, `?` matches one byte),
  so a pattern with one of them refuses as unreadable. `nginx-dump` is what `nginx -T` prints on stdout,
  every file nginx read under its `# configuration file <name>:` line, and
  each include it names must be there. The manifest declares the kind, since
  in a config file such a line is a comment like any other. nginx is read token
  by token as nginx reads it: quotes and backslash escapes, a `#` that
  starts a comment only at the start of a token, outside quotes and not
  escaped (so `a#b` and `"#"` are values), and a `}` or a `${` that ends
  nothing inside a token. A directive counts by its unquoted name, so
  `"proxy_pass"` is `proxy_pass`. Every forwarding directive counts
  (`proxy_pass`, including a `stream` block's, `grpc_pass`, `fastcgi_pass`,
  `uwsgi_pass`, `scgi_pass`, `memcached_pass`), as does each cloudflared
  `url` and ingress `service`. Any other directive whose name ends in
  `_pass` forwards through a module nginx does not ship and refuses as
  unreadable. A config that loads a dynamic module
  (`load_module`) or uses a scripting module's directives (`js_*`, `perl*`,
  `*_by_lua*`, `lua_*`) refuses as unreadable: that code can open its own
  connections, which no forwarding directive shows. A forward to an upstream
  reaches every server of every upstream block of that name, in any case,
  `http` and `stream` alike. A `server` outside an upstream block refuses as
  unreadable: a dump shows an included file apart from the block that
  includes it, and a comment in a file can read as a file header, so keep
  each upstream's servers in its own block when giving a dump. A proxy's
  `node` names the declared node it runs on. A route reaches a node when it
  targets the node's `host` or any of its `addresses`; a loopback or
  unspecified target, in any spelling (`LOCALHOST`, `127.1`,
  `::ffff:127.0.0.1`, `0.0.0.0`), reaches every node on the proxy's machine
  (every node sharing an address with the proxy's node). A route to anything
  else must be listed as `host:port` in the proxy's `other_targets`, which
  states that it reaches no launch node; otherwise it refuses as unreadable,
  as do a unix socket, a variable target, an upstream with no server, an
  upstream server with any parameter but `weight=`, `max_conns=`,
  `max_fails=`, `fail_timeout=`, `backup` and `down` (nginx takes a
  `service=` server's port and host from DNS SRV, and looks a `resolve`
  server's name up again, while it runs), quotes or braces nginx would not
  parse, a cloudflared bastion mode, SOCKS origin
  or warp-routing, and a config with no route.

- `public_rpc` lists every URL that serves the chain's RPC to the public,
  as `http`, `https`, `ws` or `wss` with no user, password or fragment, or
  is `[]` when the launch serves none. Leaving it out refuses.

## Multisig roles

`roles.sudo` holds Root and `roles.guardian` can veto it, so each must need
two keyholders to act, and pallet_multisig must let it sign. Rule 1 refuses a
sudo entry, and rule 7 the guardian, that:

- is a single key, a multisig's flat address included, whose members would
  go unchecked;
- has threshold 1;
- has a key that meets its threshold alone. A key signs as itself and, through
  pallet_multisig, as every nested multisig whose threshold the accounts it
  signs as meet, wherever that multisig's account is a member. So
  `{"threshold": 2, "members": [C, {"threshold": 1, "members": [C, D]}]}` is
  C's alone, as is a 2-of-2 of two 1-of-2 multisigs that share C, or one whose
  member is the flat address of another multisig declared in it;
- has, at any depth, a multisig with more members than the runtime's
  `Multisig.MaxSignatories` (10): pallet_multisig refuses every call signed
  through it. The bound is read from the metadata of the genesis code, and a
  runtime that does not declare it is refused.

Rule 7 also refuses a guardian with a multisig among its members. The runtime
takes the guardian's veto ahead of every fee-paying call only when the
guardian signs it, or a member key through one `as_multi`; a nested member
wraps one `as_multi` in another, so its veto competes on fees and a stolen
sudo key could crowd it out of blocks. The runtime test
`a_veto_through_a_nested_multisig_member_is_not_taken_first` pins that.

The preflight cannot see inside a flat member address: one that is the account
of a multisig not declared in the role (of the other role's keyholders, of
well-known keys, or of the role's own members) reads as one more key, as does
a key its holder shares with another member's, and as a guardian member its
veto goes unprioritized unseen. The manifest's word on who holds each key is
trusted.

## Public RPC probe

For each URL in `public_rpc` the preflight calls, over HTTP POST and over a
WebSocket at the same address (`https://` and `wss://`, `http://` and
`ws://`), two methods and nothing else:

- `rpc_methods`. Every method it lists must be in `SAFE_RPC_METHODS`: what a
  node built from polkadot-stable2409-4 serves under `--rpc-methods safe`,
  its `rpc_methods` less each method whose handler calls `check_if_safe`. A
  node lists every method it registers, the unsafe ones included, even under
  `--rpc-methods safe`, so a URL that reaches a node directly refuses: serve
  it through a deny-by-default filter that lists only what it serves. A
  method the set does not name refuses too, until it is classified.
- `system_peers`, whose handler calls `check_if_safe` and then only reads the
  peer list. An answer with a result refuses; a JSON-RPC error `-32601` is
  the refusal expected (sc-rpc answers an unsafe call with it where unsafe
  methods are denied, and a filter an unknown method).

Anything else is an input the preflight cannot resolve: no connection, a
redirect or any HTTP status but 200, a refused WebSocket upgrade, a body that
is not a JSON-RPC 2.0 answer to the call, `rpc_methods` without a list of
methods, or `system_peers` refused with another error code. The probe uses no
proxy from the environment and verifies TLS certificates. It sees each URL as
the machine it runs on does, so run it from outside the launch's own network.

## Node attestation

Rule 8 makes each authority's node the judge of the genesis it starts from,
so any way the preflight reads a spec apart from the node (its JSON, hex,
numbers, trie or runtime code) shows as another genesis hash. For each
authority, `check`:

- hashes the `exe` capture as it copies it to a private directory, and runs
  that copy only when its sha256 is the one `exe_sha256` pins;
- requires the `chain_spec` capture to be the checked spec byte for byte;
- runs `materios-node export-blocks --from 0 --to 0 --binary`, which builds
  genesis as the node does at startup (the same `--chain` resolution, the same
  genesis builder), twice. As launched: with the chain, logging, pruning and
  database options of the authority's running argv, as given, in an empty
  working directory. On its spec: the same options with the `--chain` value
  swapped for the checked spec. The hash of the block 0 header the node
  exports must be the genesis hash the preflight computes, the one the signed
  manifest and the genesis lock's datum bind.

Where the `--chain` value names no file on this host, the as-launched run
tells a file from a chain built into the node: a node that builds a genesis
from a name with no file behind it took it as built in, which refuses
whatever that genesis is (`--chain preprod` builds preprod's own genesis
hash). A file it takes to be one it fails to open, with sc-chain-spec's
``Error opening spec file `<path>`: No such file or directory``; any other
failure refuses as unreadable, since it cannot say which. Where the value
names a file here, it must be the checked spec, and the node must build the
checked genesis from it.

The node reads every option by sc-cli's definitions (polkadot-stable2409-4),
which `NODE_OPTIONS` lists with the values each takes. export-blocks gets the
ones it shares with the run command, as given: `--chain`, `--dev`, the logging
options, `--state-pruning`, `--blocks-pruning`, `--database` and `--db-cache`,
with their aliases. The base path gives way to a fresh directory. The rest
(network, RPC, telemetry, Prometheus, keystore, role, transaction pool,
offchain workers and executor) set up what the running node does, not the
genesis it builds, and export-blocks does not take them. An option the table
does not list, a word no option takes, a repeated `--chain` or `--dev` with
`--chain` refuses as unreadable. The node's environment is the mock Cardano
follower, which connects to nothing, and Cardano mainnet's epoch layout: no
other setting, no network option, no keystore. A spec that names
`telemetryEndpoints` refuses, since the node would connect to them.

The attestation builds genesis on a fresh base path, which shows what a start
from the authority's argv and spec builds, not what its node runs. A node
whose base path already holds a database for the spec's chain `id` (a
rehearsal's, or one a setup command wrote) starts from the genesis in that
database, whatever its `--chain` names, and a node keeps the genesis it
started from when its spec file is overwritten afterwards. So the genesis the
running node serves as block 0, its `served_genesis` capture, must be the
computed genesis too. The real-node tests start the node offline on a base
path that holds another genesis, and on a spec file overwritten once it runs,
and both refuse.

`check` cannot pass without running every authority's binary and reading
what its running node serves: a missing or unreadable capture, a
`served_genesis` that is not a JSON-RPC answer with a 32-byte block hash, a
binary this host cannot run, or a node that builds no genesis from the
checked spec refuses as unreadable. The tests in `test_node_attestation.py`
run the real binary (`MATERIOS_NODE`), which CI builds from this tree, and
check `NODE_OPTIONS` against its `--help`.

## Test networks

`test_networks.json` holds what the anchor worker reads as a test network: a
`system_chainType` of Development or Local, or a `system_chain` name matching
`name_pattern` (case-insensitive, ASCII). The anchor worker ships the same file,
so rule 1 refuses exactly the chain names that would let it sign with a dev key.

## Well-known keys

`well_known_keys.json` holds public keys only: the dev keys, keys whose secret
a public repo commits, and retired keys whose secret was published. A key whose
exposure is not yet public knowledge must not be named here; list it in an
operator table kept outside the repo and pass it with `--extra-well-known`
(repeatable). That table has the same shape, each key in lowercase hex with no
`0x`:

```json
{"keys": [{"label": "exposed multisig member", "scheme": "sr25519", "public": "<32 or 33 bytes of hex>"}]}
```

A 33-byte ECDSA key also matches the blake2-256 account it maps to. Regenerate
the public table from a polkadot-sdk checkout, which supplies `DEV_PHRASE`, and a
directory holding a clone of each repo in the generator's `PUBLIC_REPOS` (the
public repos with Substrate key code or configuration):

```
pip install substrate-interface ecdsa mnemonic
python3 gen_well_known_keys.py <polkadot-sdk> <clones> > well_known_keys.json
```

The generator sweeps every commit of those repos for secrets committed as string
literals (a BIP39 phrase with a valid checksum, a 0x-hex seed under a name that
marks it secret, a bare `//Path` URI) and writes the public keys each derives
under sr25519, ed25519 and ecdsa. A clone made with `--filter=blob:limit=1m` is
enough: larger blobs are runtimes and chain specs. The anchor worker ships a
copy of this table; copy the regenerated file there too.

The table holds the dev phrase and its seed only as blake2-256 hashes, which
the launch-config scan compares against. The tests pin the table to sp-keyring's
hard-coded sr25519 and ed25519 keys, to the published ECDSA `//Alice` key, to
keys a Substrate keystore committed to partner-chains names by public key, and
to dev-phrase paths, numeric ones included, checked against @polkadot/keyring.

## Tests

```
SUBWASM=./subwasm python3 -m pytest test_launch_preflight.py
```

The CLI tests run the real subwasm, a local server that answers like Kupo, one
that answers JSON-RPC over HTTP and a WebSocket like a node or a filter, and a
script that answers `export-blocks` like the node. The rule 8 tests against
the real node take its path:

```
MATERIOS_NODE=../../partnerchain/target/debug/materios-node SUBWASM=./subwasm \
    python3 -m pytest test_node_attestation.py
```

The preprod v6 fixture is the published preprod raw chain spec, and the
genesis-hash test checks the computed hash against the one the live network
reports.

The spec 239 fixtures are the preprod genesis that spec 239 (transaction version
5, the Root timelock, no PerpEngine) builds, without its code, and that
runtime's metadata, trimmed to what the preflight reads. They come from a
`materios-node` built at 9ca67a3, which is main at 7b8fd07 with the timelock's
`DefaultDelays` and `MaxDelay` declared as metadata constants; a build of
7b8fd07 itself gives the same genesis byte for byte, and metadata without those
two constants. From `partnerchain/`, with subwasm v0.21.3 and jq (`build-spec` runs
offline, and the scratch base path takes the network key it writes):

```
materios-node build-spec --chain preprod --raw --disable-default-bootnode --base-path "$(mktemp -d)" > raw.json
jq 'del(.genesis.raw.top["0x3a636f6465"])' raw.json > fixtures/preprod-spec239-raw.json
jq -r '.genesis.raw.top["0x3a636f6465"][2:]' raw.json | xxd -r -p > runtime.wasm
subwasm metadata runtime.wasm --format json | jq -jcS '{V14: {pallets: [.V14.pallets[]
  | {name, constants: [.constants[] | {name, value}], storage: (.storage | if . == null
  then null else {prefix, entries: [.entries[] | {name}]} end)}], types: {types:
  [.V14.types.types[] | select(.type.path | length > 0) | {id, type: {path: .type.path}}]}}}' \
  > fixtures/spec239-metadata.json
```

The same trim of the preprod v6 runtime's metadata gives
`fixtures/preprod-v6-metadata.json` byte for byte.
