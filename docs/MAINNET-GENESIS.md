# Mainnet genesis

The mainnet chain spec is built by the node from the launch manifest the launch
preflight checks the launch against (`tools/launch-preflight`):

```bash
materios-node build-spec --chain mainnet:launch.json --raw --disable-default-bootnode > mainnet-raw.json
```

`--chain mainnet:<path>` reads the manifest at `<path>` and builds the spec
from it, or refuses the manifest and names the field. The build is
deterministic: the same manifest, in any key or list order, builds the same
genesis. Nodes start from the raw spec file, never from `mainnet:`: the
preflight refuses a node whose `--chain` names a chain built into the node.

`tools/launch-preflight/fixtures/mainnet-launch.json` is a complete manifest
of freshly generated public keys, whose `partner_chain` values are the ones
partner-chains v1.8.0 derives from its genesis UTXO. The node's tests build
it, and the preflight's tests check the raw spec it builds
(`fixtures/mainnet-launch-raw.json`, without its code).

## Order of a launch

1. The Cardano setup of [GOVERNANCE.md](GOVERNANCE.md), steps 1 to 4: the
   genesis UTXO `G` is spent by governance init, and the D-parameter and
   permissioned candidates datums are published. `get-scripts` prints the
   values of the manifest's `partner_chain`, all functions of `G`.
2. The manifest is written: roles, dust, authorities with their three keys
   and the sha256 of the one release binary they all run, the attestation
   committee, and `partner_chain`, with the genesis lock's output id still a
   placeholder.
3. `build-spec` writes the raw spec. Its genesis hash is the chain's id. The
   spec does not depend on the lock's output id or on any other deployment
   field of the manifest.
4. The cMATRA genesis lock is created on Cardano with the genesis hash as
   its datum, which is why it comes after the spec, and its output id goes
   into the manifest.
5. The genesis-bound fields of the manifest are frozen, and each keyholder of
   the sudo and guardian multisigs signs a proof of possession that binds the
   genesis and those fields.
6. The launch key signs the spec and the whole manifest. A deployment field
   that changes after this (a host, a port, a path, the lock's output id)
   needs this signature again and no keyholder.
7. `check --stage genesis` gives the preflight's verdict before any node
   starts; the nodes then start from the raw spec, their captures are taken,
   and `check`, the launch gate, runs on what runs. The genesis hash is
   announced only after it passes.
8. The sudo multisig schedules `Oracle.register_attestor(pair, account)`
   through RootTimelock for each `roles.oracle` entry's account and each pair
   the chain prices, and the enactor enacts each call once its standard
   delay (7 days) has passed. Genesis has no field for the oracle roster, so
   no price is written before then: a pair's price needs
   `OracleMinAttestorThreshold` (3) registered attestors submitting for the
   same slot, and the builder refuses a manifest with fewer than 3 or more
   than `OracleMaxAttestors` (16) oracles.

[launch/GENESIS-DAY.md](launch/GENESIS-DAY.md) is the operator's runbook for
steps 2 to 7: each step with its command, what it proves and what to do when
it fails. The preflight README says what a proof binds and what the launch
key signs ("What a proof binds, and what the launch key signs").

## The launch manifest

The builder reads the preflight's manifest format (see the preflight README,
"Launch manifest") and adds the fields genesis needs and the preflight does
not read:

| Field | What it holds |
|---|---|
| `dust` | `role -> account -> base units`: the MATRA each role account holds at genesis. An account is named by its key (SS58 or 0x-hex), or by its account for a multisig entry. Every name must be an entry of that role. |
| `attestation_threshold` | How many of `roles.attestors` certify a receipt. |
| `partner_chain` | `genesis_utxo` (`<tx hash>#<index>`, the index at most 32767, the most partner-chains' `UtxoIndex` reads), `committee_candidate_address` (lowercase bech32, see below), `d_parameter_policy_id` and `permissioned_candidates_policy_id` (0x-hex, 28 bytes). |
| `nodes[].cross_chain` | Each authority's ECDSA partner-chain key, 33 bytes compressed, 0x-hex. |

and these roles, besides `sudo`, `guardian`, `anchor_signer`, `attestors`,
`oracle` and `endowed`:

| Role | Signs |
|---|---|
| `enactor` | `RootTimelock.enact` of each task once its delay has passed, an upgrade among them. |
| `gateway_sponsor` | Receipts submitted on behalf of the gateway's users. |
| `recovery_friends` | `Recovery.vouch_recovery` for the sudo account. |
| `recovery_rescuers` | A recovery of the sudo account (`initiate_recovery`, `claim_recovery`, `as_recovered`). |
| `dust_pool` | Nothing. Holds dust for signers admitted after genesis: no signed call moves MATRA and none is minted, so Root's force transfer out of this pool is how a later signer gets the provider it needs. |

The builder reads none of a node's `argv`, `env`, `host` or capture paths.
The preflight does: each authority's `env` must give its node
`SIDECHAIN_BLOCK_BENEFICIARY`, without which a validator never authors, and
its follower's backend, database and stability margin, without which it does
not start (the preflight README, "Launch manifest", `env`).

`endowed` lists the sudo and guardian keyholders' own keys, which hold dust
of their own. The preflight counts an account as declared when it is a role
entry's account, and a multisig member is no entry.

`roles` names no other role, and every object of the manifest holds only the
fields the preflight or the builder reads: the top level, `economics`,
`partner_chain`, `settlement`, `cardano_follower`, `supply` and its
`genesis_lock`, each `nodes` and `rpc_proxies` entry, and each role entry (a
multisig's `threshold` and `members`, a member's `key` and `pop`). No object
names a key twice, however the key is escaped. A misspelt optional field
would otherwise be read by no one.

`committee_candidate_address` must be, checksum and all, Cardano mainnet's
enterprise script address (header `0x71`) of the committee candidate
validator `genesis_utxo` parameterises. The builder derives it as
partner-chains v1.8.0 does: the validator of
partner-chains-smart-contracts v8.1.0 (`raw-scripts`), applied to the UTXO
as Plutus data `Constr 0 [Constr 0 [tx hash], index]`, hashed as a Plutus V2
script. Preprod's genesis UTXO derives the address preprod's genesis
stores, which the node's tests pin. The two policy ids also follow from
`genesis_utxo` but go through the version oracle's scripts; the builder takes
them as given, and the launch preflight's rule 9 derives all three from
`genesis_utxo` and refuses a manifest or a genesis that names others.

## What genesis holds

| Pallet | Genesis |
|---|---|
| Balances | The `dust` endowments, and the Treasury's existential deposit, which the Treasury's genesis endows itself. Under one MATRA in all. |
| OrinqReceipts | `fixedIssuance` = the sum of every endowment plus the Treasury's existential deposit. Attestation reward 0; the receipt fee, its floor and the bond are left at zero, as a fixed-issuance genesis stores them. The attestation committee is `roles.attestors` behind `attestation_threshold`, from block zero. `eraCapBase` and `eraCapBaselineAttestorCount` from `economics`. |
| Sudo | The `roles.sudo` multisig's account, as pallet_multisig and the preflight's `role_account` derive it. |
| RootTimelock | Guardian: the `roles.guardian` multisig's account. Delays: the runtime's mainnet `DefaultDelays` (1, 7 and 30 days). |
| Sidechain | `genesisUtxo` = `G`; `slotsPerEpoch` = 600 (an hour of six-second slots, 120 sessions a Cardano epoch). |
| SessionCommitteeManagement | `initialAuthorities`: every `authority: true` node's partner-chain, aura and grandpa keys, ascending by partner-chain key. `mainChainScripts`: `committee_candidate_address` as the hex of the bech32 text, and the two policy ids. These three field names are snake_case: the type derives serde plainly, and a camelCase name is dropped without an error, leaving the all-zero default. |
| Motra | MOTRA's default parameters with `generationPerMatraPerBlock` = 10^10 (default 10^5). |
| IntentSettlement | `cardanoIds`: Cardano mainnet's network magic (764824073) and Shelley genesis hash, with the Aegis policy `settlement.aegis_policy_v1_script_hash` declares, or none where it declares null for Root to bind after launch. |

`MateriosChainId` is the genesis hash, and `NetworkMagic` comes from
`cardanoIds`, so neither is a separate genesis value.

## Dust and MOTRA

MATRA's issuance is fixed at genesis, so the dust is not money: it is what
lets an account sign. Each account that signs or pays a deposit must hold at
least its floor, or the builder refuses the manifest:

- the existential deposit (500 base units), the provider `CheckNonce` needs;
- the deposits its role reserves: `DepositBase + DepositFactor x threshold`
  (2,000 for a 2-of-n) for a multisig keyholder who opens a call,
  `ConfigDepositBase + FriendDepositFactor x friends` (1,000 + 500 per friend)
  for the sudo account's recovery configuration, `RecoveryDeposit` (1,000)
  for a rescuer;
- working dust that generates the MOTRA its calls cost: a day of its calls,
  generated in a day, and for a role that carries a runtime, enough to settle
  at twice the fee of a block-long call (5 MiB, the runtime's block length),
  so an upgrade of any size the chain accepts can be paid within half a day.

A MOTRA fee below the congestion target is `1e9 + 1e6 x bytes` base units
(15 decimals). One MATRA generates 10^10 MOTRA base units a block, 1.44 x
10^14 a day, and a balance keeps 99.99% a block, so it settles at 10^4 blocks
of generation.

| Role account | Load sized for | Floor (base units) | MOTRA a day at the floor | Fees a day at the floor | Settled MOTRA at the floor |
|---|---|---|---|---|---|
| sudo keyholder | 24 calls of 512 B, and an upgrade | 107,630 | 1.52e13 | 10,060 | 1.06e13 |
| guardian keyholder | 64 vetoes of 384 B | 3,116 | 1.61e11 | 116 | 1.12e11 |
| enactor | 64 calls of 512 B, and an upgrade | 106,050 | 1.53e13 | 10,100 | 1.06e13 |
| anchor_signer | 1,000 calls of 512 B | 11,000 | 1.58e12 | 1,047 | 1.10e12 |
| gateway_sponsor | 2,000 receipts of 512 B | 21,500 | 3.10e12 | 2,047 | 2.15e12 |
| oracle | 4,800 prices of 512 B | 50,900 | 7.33e12 | 4,848 | 5.09e12 |
| attestor | 100 calls of 256 B; attests are feeless | 1,373 | 1.98e11 | 157 | 1.37e11 |
| recovery friend | 8 calls of 256 B | 570 | 8.21e10 | 65 | 5.70e10 |
| recovery rescuer | 24 calls of 512 B | 1,752 | 1.08e11 | 71 | 7.52e10 |
| sudo account | the recovery configuration deposit | 3,000 | | | |

A sudo keyholder's or the enactor's upgrade fee is 5.24e12 at the block
length; its floor settles at twice that. The node's tests hold each role, at
exactly its floor with its deposits reserved, to paying a day of its calls
as they come due, and the upgrade half a day in, through the runtime's own
MOTRA pallet; and each role's call, signed and on the wire, to no more bytes
than its load names, at the fee the runtime charges.

## Refusals

The builder refuses a manifest, naming the field, when:

- the manifest names a key twice in one object, a field no reader of the
  manifest knows, or a role other than those above;
- a field is missing or not of its type, or hex is not `0x` and lowercase
  with two digits a byte and exactly the bytes its field holds;
- a key is a well-known development key (`//Alice` to `//Ferdie`, their
  `//stash`, `//One`, `//Two`, under sr25519, ed25519 and ECDSA, and an ECDSA
  key's account), any account, key, script or Cardano value preprod's genesis
  names, or all zero;
- two role entries share an account; a multisig lists a member twice; the
  guardian shares a keyholder with the sudo key; two authorities share a key;
- `roles.sudo` or `roles.guardian` is not exactly one multisig of keys with a
  threshold of at least 2, or has more than `MaxSignatories` members;
- `roles.anchor_signer` is empty, `roles.attestors` is empty or larger than
  the committee, `attestation_threshold` is outside 1 to the attestors,
  `roles.oracle` names fewer than `OracleMinAttestorThreshold` or more than
  `OracleMaxAttestors`, or `roles.recovery_friends` names more than
  `MaxFriends`;
- fewer than 4 or more than `MaxValidators` authorities; a partner-chain key
  is not compressed;
- `slots_per_epoch` is not 600, `cardano_follower` is not Cardano mainnet's,
  `partner_chain.genesis_utxo` names an output above 32767,
  `partner_chain.committee_candidate_address` is not lowercase bech32 with a
  valid checksum, not `addr`, not on network 1, not an enterprise script
  address, or not the address of the validator `genesis_utxo`
  parameterises, or `economics.attestation_reward_per_signer` is not 0;
- a role account that signs or pays a deposit holds no dust or less than its
  floor, `dust` names an account that is no entry of its role, endows an
  account the builder sizes nothing for, or endows one below the existential
  deposit; or the issuance reaches one MATRA.

The runtime's genesis builder refuses in turn a declared issuance other than
what genesis holds, a committee member with no provider, a member listed
twice, a threshold outside 1 to the committee, and a timelock guardian that
is the sudo key or a development account.

## What the launch preflight holds it to

The preflight reads the same manifest and genesis apart from the builder (see
the preflight README's rules), and accepts the fixture's raw spec on every rule
that reads only the spec, its metadata and the manifest. Its rule 8 also runs
each authority's pinned node binary on `build-spec --chain mainnet:<manifest>
--raw` and refuses a checked spec that differs from that build in anything but
its boot nodes: so the rules hold the builder to the manifest, and the builder
holds the spec to what the rules do not read.

- **Input**: `dust`, `attestation_threshold`, `partner_chain` and each
  authority's `cross_chain` are read, and the roles above; any other field or
  role, or a key named twice, refuses.
- **Rule 1**: the Treasury's account is declared; a 33-byte role key that is no
  compressed ECDSA key, a point on secp256k1, refuses;
  `OrinqReceipts.CommitteeMembers` must be `roles.attestors`, each once in
  ascending order as SCALE encodes a set, and `AttestationThreshold` the
  declared threshold.
- **Rule 4**: genesis must fix its issuance, at `Balances.TotalIssuance`, at
  what the accounts hold, and at the `dust` plus the Treasury's existential
  deposit, under one MATRA, each account holding exactly its declared dust in
  the `System.Account` the Balances genesis writes (no nonce, consumer,
  sufficient or frozen balance, one provider), with the attestation reward,
  fee, floor and bond zero; no emission reserve counts against the genesis
  lock. No backup signer is named, and each pallet's storage version and
  every other value no rule reads is the one the builder writes.
- **Rule 9**: the genesis committee's and each Cardano candidate's partner-chain
  key must be the `cross_chain` key its authority declares; genesis
  `Sidechain.GenesisUtxo` must be `partner_chain.genesis_utxo`, and the
  committee candidate address and both policy ids, declared and stored, the
  ones it derives; the committee outputs must be two Cardano epochs older
  than the epoch the launch's first session starts in.
- **Rule 11**: settlement's lifetimes and signer threshold are the runtime's
  defaults, and its pool utilization, storage version and cutovers the ones
  its genesis writes.
- **Rule 12**: genesis `Motra.Params` is mainnet's, byte for byte, and every
  endowed account has its MOTRA checkpoint. Every role signer has a provider
  and holds at least the deposits its roles reserve and, left free, the larger
  of the existential deposit and its working dust. The preflight sizes that
  working dust apart from the builder, for the loads tabled above: from the
  balance each load holds an account's MOTRA below, with the existential
  deposit counted as dust that generates, and an upgrade at twice the genesis
  runtime's length. The builder's floors above cover the preflight's for every
  role and any runtime a block holds (the preflight README tables both).
