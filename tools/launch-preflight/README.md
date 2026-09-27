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
| 1 dev-keys | A well-known key appears in genesis storage, in the runtime code, in a role, in an authority's launch command or environment (`--alice`, `--dev`, `//Bob`, the dev mnemonic), or as the manifest signing key. "Well-known" is every sp-keyring key (`//Alice` .. `//Ferdie`, their `//stash` accounts, `//One`, `//Two`) and the dev-phrase root under sr25519, ed25519 and ecdsa, plus retired keys whose secret was published. |
| 2 rewards | `economics` does not declare the attestor reward per signer, era cap base and era cap baseline, or genesis does not store exactly those values. |
| 3 rpc | An authority serves unsafe RPC methods (`--rpc-methods unsafe`, or the default on a loopback listener) on an external listener or behind a proxy route. |
| 4 supply | An attestor is endowed below `BondRequirement + ExistentialDeposit + fee_buffer`, or genesis issuance plus runtime emission exceeds the cMATRA locked on Cardano to back it: the reserve would be counted both as cMATRA and as MATRA. |
| 5 pallets | `PerpEngine` is in the runtime metadata. |
| 6 checkpoint | The genesis hash, runtime code hash or chain-spec hash differs from the signed launch manifest, the signature does not verify under the pinned key, or the spec carries `codeSubstitutes`. |

Every reason is printed. Exit 0 means every rule passed, 1 means at least one
refused, 2 means an input could not be read (also a refusal).

## Usage

```
pip install -r requirements.txt

# The launch key holder signs the hashes of the exact raw spec to launch.
python3 launch_preflight.py sign --spec mainnet-raw.json --key launch.key --out signed.json

python3 launch_preflight.py check --spec mainnet-raw.json --launch launch.json \
    --signed-manifest signed.json --manifest-key 0x<launch key> --subwasm ./subwasm
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
    "fee_buffer": 100000000
  },
  "supply": {
    "cardano_backing": 975000000000,
    "runtime_emission_cap": 0
  },
  "nodes": [
    {"name": "val-1", "host": "val-1", "authority": true,
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
  bond at genesis and get the endowment floor check.
- `supply.cardano_backing` is the cMATRA locked on Cardano for Materios issuance;
  `supply.runtime_emission_cap` is what the runtime can mint after genesis.
- A proxy route matches an authority when its `proxy_pass` target (or nginx
  `upstream` server) is the authority's host and RPC port; a loopback target
  means the proxy's own host.

## Well-known keys

`well_known_keys.json` holds public keys only. Regenerate it from a
polkadot-sdk checkout, which supplies `DEV_PHRASE`:

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
