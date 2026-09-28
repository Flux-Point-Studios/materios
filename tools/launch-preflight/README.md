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
- a **launch manifest**: who holds each role, the economics, where the genesis
  lock is, each node's launch command and the RPC proxy configs;
- a **signed launch manifest**: the genesis hash, runtime code hash, chain-spec
  hash and launch manifest hash, signed with an ed25519 launch key that
  `launch_keys.json` pins.

## Rules

| Rule | Refuses when |
|---|---|
| 1 dev-keys | A well-known key appears in genesis storage, in the runtime code, in a role or any member of a role's multisig, in a Cardano permissioned candidate, in a node's launch command or environment (`--alice`, `--dev`, any bare `//Path` URI such as `//Bob` or `//Oracle`, with or without a `///password`, a setting named for a secret URI (`SIGNER_URI`, `--suri`: a name holding uri, seed, mnemonic, phrase or secret, and not ending in file, path or dir) whose value has no phrase, such as the soft path `/Attestor0`, the dev mnemonic, or the dev seed in 0x-hex), or as the manifest signing key. `Sudo.Key` is not the account `roles.sudo` declares, `roles.sudo` is not a multisig with a threshold of at least 2, or a genesis account is not the account of any declared role, so who holds it is unchecked. A role in `sudo`, `anchor_signer`, `attestors`, `oracle` is not declared, or `anchor_signer` or `attestors` is empty. The chain spec's `chainType` is not `Live`, or its name reads as a test network: the anchor worker would then accept a dev signer. |
| 2 rewards | `economics` does not declare the attestor reward per signer, era cap base and era cap baseline, or genesis does not store exactly those values; or it does not declare the validator reward per era and the treasury emission share (perbill), or they differ from the runtime constants `OrinqReceipts.ValidatorRewardPerEra` and `OrinqReceipts.TreasuryEmissionShare`. |
| 3 rpc | An authority serves unsafe RPC methods (`unsafe`, or the `auto` default on a loopback listener) on an external listener or behind a proxy route; a node runs `--validator` without being declared an authority; or a block author (a genesis `Aura.Authorities` key or a Cardano permissioned candidate's aura key) has no authority node in the manifest, so its listeners go unchecked. Every listener counts: the default one (`--rpc-port`, `--rpc-external`, `--rpc-methods`) and each `--experimental-rpc-endpoint listen-addr=...,methods=...`, including every value one `--experimental-rpc-endpoint` takes up to the next option, with each option trimmed as the node trims it. |
| 4 supply | `roles.attestors` is empty, an attestor is endowed below `BondRequirement + ExistentialDeposit + fee_buffer`, `Balances.TotalIssuance` differs from what the genesis accounts hold (free plus reserved), or genesis issuance plus the runtime's emission reserves exceeds the cMATRA the genesis lock holds on Cardano: the reserve would be counted both as cMATRA and as MATRA. The lock must be an unspent output at the declared mainnet address, which pays to the declared native script; that script must need at least two key holders to spend it (a well-known key counts as anyone's, a time bound as met), and the output's inline datum must be this genesis hash, so one lock cannot back two genesis attempts. A Plutus lock is refused: the preflight cannot evaluate one. The reserves are read from the metadata constants `OrinqReceipts.ValidatorEmissionReserve` and `OrinqReceipts.AttestationRewardReserve`; a runtime that does not declare them is refused, since what it mints after genesis cannot be bounded. Genesis sets storage outside `GENESIS_STORAGE`, each pallet's storage version and `:code`/`:extrinsic_index`: any other item (a billing withdrawal, a credit entry, a key no runtime item declares) can hold a claim on MATRA the bound does not count. |
| 5 pallets | `PerpEngine` is in the runtime metadata, under its own name or any other (its `pallet_perp_engine` types give it away). |
| 6 checkpoint | The genesis hash, runtime code hash, chain-spec hash or launch manifest hash differs from the signed launch manifest, the signature does not verify under a key `launch_keys.json` pins (or no key is pinned, or the key given with `--manifest-key` is not pinned), the spec carries `codeSubstitutes`, or an authority runs `--wasm-runtime-overrides`, which would replace the signed code. Also refuses a genesis that sets the `NativeTokenManagement` observation scripts. The launch plan's checkpoint canary runs the real observation from the genesis checkpoint and requires zero transfers from the genesis-lock transaction and at least one from a canary deposit made after it. This runtime's observation has no checkpoint: until its first non-zero transfer it asks for every transfer since Cardano genesis, so it would count the genesis lock and the canary cannot pass. |

Every reason is printed. Exit 0 means every rule passed, 1 means at least one
refused, 2 means an input could not be read (also a refusal), including a proxy
config with no route the preflight can read and a Kupo that is unreachable,
behind its node or does not index the permissioned candidates token.

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

## Launch manifest

```json
{
  "roles": {
    "sudo": [{"threshold": 2, "members": ["5D...", "5H...", "5C..."]}],
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
    "genesis_lock": {"utxo": "<tx id>#<index>", "address": "addr1w...", "native_script": "8303..."}
  },
  "nodes": [
    {"name": "val-1", "host": "val-1", "addresses": ["10.0.0.11"], "authority": true,
     "aura": "0x<aura public key>",
     "argv": ["materios-node", "--validator", "--chain", "mainnet-raw.json", "--rpc-methods", "safe"],
     "env": {}},
    {"name": "edge-1", "host": "edge-1", "addresses": ["10.0.0.2"], "authority": false}
  ],
  "rpc_proxies": [
    {"name": "public-rpc", "node": "edge-1", "kind": "nginx-dump", "config": "nginx-T.txt",
     "other_targets": ["status.example.org:443"]}
  ]
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
  genesis sets none), as a multisig with a threshold of at least 2. Every
  genesis account must be the account of some entry; `endowed` holds the ones
  no other role names. `attestors` are the accounts that bond at genesis and
  get the endowment floor check.
- Every `economics` value is a non-negative integer in the smallest unit; an
  unknown field or any other value refuses as unreadable.
- `supply.genesis_lock` is the Cardano output holding the cMATRA that backs
  Materios issuance, and `native_script` the CBOR (hex) of the native script
  its address pays to. The backing is the cMATRA amount Kupo reports at that
  output; the manifest carries no backing figure. Create the lock after
  building the raw spec, with the genesis hash as its inline datum: a Plutus
  bytestring, CBOR `5820` followed by the 32 bytes.
- `nodes` lists every machine that runs a launch process or a proxy. Each
  declares `authority` as `true` or `false`, and an authority its `aura`
  public key. `argv` is a list: the words the process receives, as
  `/proc/<pid>/cmdline` lists them. A command line given as one string
  refuses as unreadable, since systemd rewrites an `ExecStart` line before
  it runs it (`\xNN` escapes, `%` specifiers such as `%i`, an `@` prefix, a
  `;` word that starts another command) and a shell or a container runtime
  splits one by its own rules. A `sh -c` wrapper, as a systemd unit or a
  container entrypoint writes it, is opened, its script split at `;`, `&&`
  and newlines, and an authority's last command must start `materios-node`
  or `materios-node-spo`. Before it, an authority's launch may run only
  `set`, `export`, `cd`, `umask`, `ulimit` and `mkdir`, as bare words, and
  node subcommands (`build-spec`, `purge-chain`): any other program could
  start a node whose listeners go unchecked. A launch the preflight would
  have to evaluate refuses as unreadable: a `$VAR` or backtick expansion, a
  NUL byte in a word or setting (execve ends each one there), a script word
  the shell rewrites (brace expansion, a `*`, `?` or `[` glob, a `~`, a word
  starting with `#`, which is a comment) or a backslash line continuation,
  quoted or not, a pipe, redirection, subshell or `||`, a script file, a
  file the shell runs on its own (a login or interactive shell's startup
  files, `.` or `source`, and zsh, which always reads its zshenv), a shell
  option other than `-a`, `-e` and `-u` (on the shell or through `set`: `-x`
  runs `$PS4` as code), or several arguments in one word.
- `env` holds a node's settings as the process receives them, as
  `/proc/<pid>/environ` lists them (systemd decodes escapes and expands
  specifiers in an `Environment=` line first); assignments in a script
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
  follower. The preflight takes a program to be what its name says; it does
  not read binaries or anything else on the machine. For a node that is not
  an authority, that trust covers what its programs and the shell's other
  builtins do with their arguments: `printf -v NAME` under `set -a`, for
  one, exports a setting that no word names. An authority's launch runs only
  the setup commands above before its node, so this does not reach it.
- A proxy is `nginx`, `nginx-dump` or `cloudflared`. `nginx` is a config
  file: each `include` is read from disk in its place, a relative name from
  the config's directory. `nginx-dump` is what `nginx -T` prints on stdout,
  every file nginx read under its `# configuration file <name>:` line, and
  each include it names must be there. The kind is declared, not guessed: in
  a config file such a line is a comment like any other. nginx is read token
  by token as nginx reads it: quotes and backslash escapes, a `#` that
  starts a comment only at the start of a token, outside quotes and not
  escaped (so `a#b` and `"#"` are values), and a `}` or a `${` that ends
  nothing inside a token. A directive counts by its unquoted name, so
  `"proxy_pass"` is `proxy_pass`. Every forwarding directive counts
  (`proxy_pass`, including a `stream` block's, `grpc_pass`, `fastcgi_pass`,
  `uwsgi_pass`, `scgi_pass`, `memcached_pass`), as does each cloudflared
  `url` and ingress `service`. A forward to an upstream reaches every server
  of every upstream block of that name, in any case, `http` and `stream`
  alike. A `server` outside an upstream block refuses as unreadable: a dump
  shows an included file apart from the block that includes it, and a
  comment in a file can read as a file header, so keep each upstream's
  servers in its own block when giving a dump. A proxy's `node` names the
  declared node it runs on. A route reaches a node when it targets the
  node's `host` or any of its `addresses`; a loopback or unspecified target,
  in any spelling (`LOCALHOST`, `127.1`, `::ffff:127.0.0.1`, `0.0.0.0`),
  reaches every node on the proxy's machine (every node sharing an address
  with the proxy's node). A route to anything else must be listed as
  `host:port` in the proxy's `other_targets`, which states that it reaches
  no launch node; otherwise it refuses as unreadable, as do a unix socket, a
  variable target, an upstream with no server, quotes or braces nginx would
  not parse, a cloudflared bastion mode, SOCKS origin or warp-routing, and a
  config with no route.

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
(repeatable). That table has the same shape:

```json
{"keys": [{"label": "exposed multisig member", "scheme": "sr25519", "public": "0x..."}]}
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

The CLI tests run the real subwasm and a local server that answers like Kupo.
The preprod v6 fixture is the published preprod raw chain spec, and the
genesis-hash test checks the computed hash against the one the live network
reports.
