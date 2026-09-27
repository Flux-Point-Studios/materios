# Mainnet launch preflight

Refuses a Materios mainnet genesis or launch unless every rule passes. It is the
genesis counterpart of the runtime-upgrade ceremony gate: that gate diffs an
upgrade against the live runtime, this one checks the artifacts a launch starts
from.

It reads:

- the **raw chain spec** (`build-spec --raw`), the exact storage every node loads;
- the **runtime metadata**, extracted from that spec's own `:code` with
  [subwasm](https://github.com/chevdor/subwasm) v0.21.3;
- a **launch manifest**: role keys, economics and supply backing that genesis
  cannot show, plus each authority's launch command and the RPC proxy configs;
- a **signed launch manifest**: the genesis hash, runtime code hash and
  chain-spec hash, signed with the pinned ed25519 launch key.

## Rules

| Rule | Refuses when |
|---|---|
| 1 dev-keys | A well-known key appears in genesis storage, in the runtime code, in a role, in an authority's launch command or environment (`--alice`, `--dev`, `//Bob`, the dev mnemonic), or as the manifest signing key. "Well-known" is every sp-keyring key (`//Alice` .. `//Ferdie`, their `//stash` accounts, `//One`, `//Two`) and the dev-phrase root under sr25519, ed25519 and ecdsa, retired keys whose secret was published, keys whose seed a public repo commits, and every key in an `--extra-well-known` table. |
| 2 rewards | `economics` does not declare the attestor reward per signer, era cap base and era cap baseline, or genesis does not store exactly those values; or it does not declare the validator reward per era and the treasury emission share (perbill), or they differ from the runtime constants `OrinqReceipts.ValidatorRewardPerEra` and `OrinqReceipts.TreasuryEmissionShare`. |
| 3 rpc | An authority serves unsafe RPC methods (`unsafe`, or the `auto` default on a loopback listener) on an external listener or behind a proxy route, or a node runs `--validator` without being declared an authority. Every listener counts: the default one (`--rpc-port`, `--rpc-external`, `--rpc-methods`) and each `--experimental-rpc-endpoint listen-addr=...,methods=...`. |
| 4 supply | `roles.attestors` is empty, an attestor is endowed below `BondRequirement + ExistentialDeposit + fee_buffer`, `Balances.TotalIssuance` differs from what the genesis accounts hold (free plus reserved), or genesis issuance plus the runtime's emission reserves exceeds the cMATRA locked on Cardano to back it: the reserve would be counted both as cMATRA and as MATRA. The reserves are read from the metadata constants `OrinqReceipts.ValidatorEmissionReserve` and `OrinqReceipts.AttestationRewardReserve`; a runtime that does not declare them is refused, since what it mints after genesis cannot be bounded. |
| 5 pallets | `PerpEngine` is in the runtime metadata. |
| 6 checkpoint | The genesis hash, runtime code hash or chain-spec hash differs from the signed launch manifest, the signature does not verify under the pinned key, or the spec carries `codeSubstitutes`. Also refuses a genesis that sets the `NativeTokenManagement` observation scripts: that observation has no checkpoint, so its first run counts every transfer to the watched address since Cardano genesis, the genesis lock included. |

Every reason is printed. Exit 0 means every rule passed, 1 means at least one
refused, 2 means an input could not be read (also a refusal).

## Usage

```
pip install -r requirements.txt

# The launch key holder signs the hashes of the exact raw spec to launch.
python3 launch_preflight.py sign --spec mainnet-raw.json --key launch.key --out signed.json

python3 launch_preflight.py check --spec mainnet-raw.json --launch launch.json \
    --signed-manifest signed.json --manifest-key 0x<launch key> --subwasm ./subwasm \
    --extra-well-known ~/exposed-keys.json
```

The genesis hash is computed here (Substrate trie root of the raw storage at the
runtime's state version, then the genesis header), so the check does not trust a
node to report it. The chain-spec hash is blake2-256 of the spec's canonical
JSON (sorted keys, no whitespace).

## Launch manifest

```json
{
  "roles": {
    "anchor_signer": ["5F..."],
    "attestors": ["5G..."],
    "oracle": ["0x..."],
    "multisig_members": ["5D...", "5H...", "5C..."]
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
    "cardano_backing": 975000000000
  },
  "nodes": [
    {"name": "val-1", "host": "val-1", "addresses": ["10.0.0.11"], "authority": true,
     "argv": "materios-node --validator --chain mainnet-raw.json --rpc-methods safe",
     "env": {}}
  ],
  "rpc_proxies": [
    {"name": "public-rpc", "host": "edge-1", "config": "nginx/public-rpc.conf"}
  ]
}
```

- `roles` maps any role name to public keys (SS58, or 0x-hex 32-byte accounts
  and 33-byte ECDSA keys). Never a secret URI. `attestors` are the accounts that
  bond at genesis and get the endowment floor check; it must not be empty.
- Every node declares `authority` as `true` or `false`.
- `supply.cardano_backing` is the cMATRA locked on Cardano for Materios issuance.
- A proxy route matches an authority when its `proxy_pass` target (or nginx
  `upstream` server) is the authority's RPC port on its `host` or on any of its
  `addresses` (every name or IP a proxy can reach it by, such as a container
  bridge gateway); a loopback target means the proxy's own host.

## Well-known keys

`well_known_keys.json` holds public keys only: the dev keys, retired keys whose
secret was published, and keys whose seed a public repo commits as a test
fixture. A key whose exposure is not yet public knowledge must not be named
here; list it in an operator table kept outside the repo and pass it with
`--extra-well-known` (repeatable). That table has the same shape:

```json
{"keys": [{"label": "exposed multisig member", "scheme": "sr25519", "public": "0x..."}]}
```

A 33-byte ECDSA key also matches the blake2-256 account it maps to. Regenerate
the public table from a polkadot-sdk checkout, which supplies `DEV_PHRASE`:

```
python3 gen_well_known_keys.py <polkadot-sdk> > well_known_keys.json
```

The tests pin the table to sp-keyring's hard-coded sr25519 and ed25519 keys and
to the published ECDSA `//Alice` key.

## Tests

```
SUBWASM=./subwasm python3 -m pytest test_launch_preflight.py
```

The CLI tests run the real subwasm. The preprod v6 fixture is the published
preprod raw chain spec, and the genesis-hash test checks the computed hash
against the one the live network reports.
