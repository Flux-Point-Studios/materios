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
  and the D-parameter and permissioned candidates datums, which the runtime
  draws the committee from at each rotation, with the slot each was created in
  and the slot Kupo's node is at. A draw that fails, as a fresh chain's first
  one does, seats the genesis committee again (rule 9);
- the **partner-chains-smart-contracts v8.1.0 scripts** the genesis UTXO
  parameterises, vendored in `partner_chains_scripts.json` (see
  [Partner chain scripts](#partner-chain-scripts));
- **each public RPC URL, live**: the methods it lists and whether it answers
  an unsafe one, over HTTP and over a WebSocket;
- **each authority's running node argv**: a copy of its
  `/proc/<pid>/cmdline`;
- **each authority's node binary and chain spec file**: copies of its
  `/proc/<pid>/exe` and of the file its `--chain` names, and that binary run
  offline to build the genesis it would start from (see
  [Node attestation](#node-attestation));
- **what each authority's running node serves**: its answers to
  `chain_getBlockHash [0]`, `system_chain`, `system_chainType` and
  `system_properties`, saved from its local RPC;
- **when each authority's node started, and when its chain spec path last
  changed**: copies of its `/proc/<pid>/stat` and its machine's `/proc/stat`,
  and `stat` of each step of its `--chain` path;
- a **launch manifest**: who holds each role, with each multisig member's
  holder's proof of possession of its key, the economics, where the genesis
  lock is, how many slots each session lasts, the Cardano settings every
  authority's follower runs with, the Aegis policy deployed on Cardano
  mainnet (or that Root binds it after genesis), each node's launch command,
  the RPC proxy configs and the public RPC URLs;
- a **signed launch manifest**: the genesis hash, runtime code hash, chain-spec
  hash and launch manifest hash, signed with an ed25519 launch key that
  `launch_keys.json` pins.

## Rules

| Rule | Refuses when |
|---|---|
| 1 dev-keys | A well-known key appears in genesis storage, in the runtime code, in a role or any member of a role's multisig, in a Cardano permissioned candidate, in a node's launch command or environment (`--alice`, `--dev`, any bare `//Path` URI such as `//Bob` or `//Oracle`, with or without a `///password`, a setting named for a secret URI (`SIGNER_URI`, `--suri`: a name holding uri, seed, mnemonic, phrase or secret, and not ending in file, path or dir) whose value has no phrase, such as the soft path `/Attestor0`, the dev mnemonic, or the dev seed in 0x-hex), or as the manifest signing key. A role, or any member of a role's multisig, is the all-zero key, whose sr25519 signature of any message needs no secret (see [Proof of possession](#proof-of-possession)), or an ed25519 key of small order, whose ed25519 signature of any message needs none either, so anyone can sign as its account. An authority key anyone can sign for (see [Keys anyone can sign for](#keys-anyone-can-sign-for)): an aura key that is the all-zero key, or a grandpa key that is an ed25519 key of small order, in genesis `Aura.Authorities`, `Grandpa.Authorities`, `SessionCommitteeManagement.CurrentCommittee` or `Session.ValidatorsAndKeys`, as a declared authority's `aura` or `grandpa`, or as a Cardano permissioned candidate's `aura` or `gran`. A role key of 33 bytes, or a multisig member's, whose first byte is not `0x02` or `0x03`, or whose other 32 are the x of no point on secp256k1, as about half of all values are: it is no compressed ECDSA key, and its account, blake2-256 of those bytes, is one no key signs as. An authority's `cross_chain` key that is no such point refuses as unreadable, and a Cardano permissioned candidate's partner chains key under rule 9. The curve test is the preflight's own arithmetic (x below the field prime, x³ + 7 a square), which a test holds to libsecp256k1. `Sudo.Key` is not the account `roles.sudo` declares, `roles.sudo` does not need two keyholders to act (see [Multisig roles](#multisig-roles)), or a genesis account is not the account of any declared role or the Treasury's (the `modl` account of the runtime's `Treasury.PalletId`, which the Treasury's genesis endows its existential deposit), so who holds it is unchecked. Genesis `OrinqReceipts.CommitteeMembers`, the attestation committee seated from block zero, is not exactly the accounts `roles.attestors` declares, written as SCALE encodes a set and build-spec writes it, a compact count and then each account once in ascending order with nothing after, or lists more entries than the runtime's `OrinqReceipts.MaxCommitteeSize`: the runtime counts every listed entry against that bound before it drops the repeats, so 97 entries of three attestors decode as no committee at all, and no receipt is certified; or `OrinqReceipts.AttestationThreshold` is not the declared `attestation_threshold`, is unset, or is outside 1 to the committee's size; or the launch declares no `attestation_threshold`. A role in `sudo`, `anchor_signer`, `attestors`, `oracle` is not declared, or `anchor_signer` or `attestors` is empty. The chain spec's `chainType` is not `Live`, or its name reads as a test network: the anchor worker would then accept a dev signer. |
| 2 rewards | `economics` does not declare the attestor reward per signer, era cap base and era cap baseline, or genesis does not store exactly those values; or it does not declare the validator reward per era and the treasury emission share (perbill), or they differ from the runtime constants `OrinqReceipts.ValidatorRewardPerEra` and `OrinqReceipts.TreasuryEmissionShare`. Genesis `OrinqReceipts.ReceiptExpiryBlocks` is not the 14,400 blocks, a day, that the runtime's genesis writes (see [Genesis values no other rule reads](#genesis-values-no-other-rule-reads)). |
| 3 rpc | A public RPC URL, probed live, lists in `rpc_methods` a method outside the safe set or answers `system_peers`, an unsafe method that changes nothing (see [Public RPC probe](#public-rpc-probe)); the launch does not declare `public_rpc`; an authority's running node process, read from its `cmdline` capture, serves unsafe RPC methods (`unsafe`, or the `auto` default on a loopback listener) on an external listener or behind a proxy route; a node runs `--validator` without being declared an authority; or a block author (a genesis `Aura.Authorities` key or a Cardano permissioned candidate's aura key) has no authority node in the manifest, so its listeners go unchecked. Every listener counts: the default one (`--rpc-port`, `--rpc-external`, `--rpc-methods`) and each `--experimental-rpc-endpoint listen-addr=...,methods=...`, including every value one `--experimental-rpc-endpoint` takes up to the next option, with each option trimmed as the node trims it. |
| 4 supply | Genesis does not fix its issuance: it sets no `OrinqReceipts.FixedIssuance`, so the runtime would mint its emission reserves after genesis. `OrinqReceipts.FixedIssuance` differs from `Balances.TotalIssuance`, `Balances.TotalIssuance` from what the genesis accounts hold (free plus reserved), or the fixed issuance from what the launch declares genesis endows: the launch's `dust` and the Treasury's existential deposit. A genesis account holds other than its declared dust, free and with nothing reserved, the Treasury other than `Balances.ExistentialDeposit`, an account no `dust` entry declares holds anything, or a `dust` entry names a role the launch does not declare, an account that is no entry of its role, or an account another entry endows, or endows less than `Balances.ExistentialDeposit`, under which the Balances genesis endows no account; the launch declares no `dust`. The rest of a genesis account's `System.Account` is not what the Balances genesis writes for an account it endows: nonce 0, no consumer, one provider, no sufficient, nothing frozen, and the flags `0x80000000000000000000000000000000` (pallet_balances' new-logic flag alone). A keyholder whose balance is frozen can reserve no multisig deposit, so its multisig never acts; a nonce refuses its first calls; and a reference count nothing took keeps or drops the account apart from its balance. Genesis issues one MATRA (10^6 base units, the runtime's `MATRA`) or more: a mainnet genesis issues dust. `OrinqReceipts.AttestationRewardPerSigner`, `ReceiptSubmissionFee`, `ReceiptSubmissionFeeFloor` or `BondRequirement` is unset or other than 0, as a fixed-issuance genesis stores them. The issuance exceeds the cMATRA the genesis lock holds on Cardano; no emission reserve counts against the lock, since a fixed issuance mints none. The lock must be an unspent output at the declared mainnet address, which pays to the declared native script; that script must need at least two key holders to spend it (a well-known key counts as anyone's, a time bound as met), and the output's inline datum must be this genesis hash, so one lock cannot back two genesis attempts. A Plutus lock is refused: the preflight cannot evaluate one. Genesis sets storage outside `GENESIS_STORAGE`, each pallet's storage version and `:code`/`:extrinsic_index`: any other item (a billing withdrawal, a credit entry, a key no runtime item declares) can hold a claim on MATRA the bound does not count. `OrinqReceipts.BackupSigners` and `BackupSignerDelay` are outside it: build-spec writes neither, and Root names backup signers after genesis. So is a key that starts with the 32-byte key of an allowlisted item that is no map, such as `Sudo.Key` followed by another byte: the runtime reads a storage value at its own key alone. A pallet's storage version, or another value no rule reads, is not the one build-spec writes (see [Genesis values no other rule reads](#genesis-values-no-other-rule-reads)). |
| 5 pallets | `PerpEngine` is in the runtime metadata, under its own name or any other (its `pallet_perp_engine` types give it away). |
| 6 checkpoint | The genesis hash, runtime code hash, chain-spec hash or launch manifest hash differs from the signed launch manifest, the signature does not verify under a key `launch_keys.json` pins (or no key is pinned, or the key given with `--manifest-key` is not pinned), the spec carries `codeSubstitutes`, or an authority runs `--wasm-runtime-overrides`, which would replace the signed code. Genesis may store `System.LastRuntimeUpgrade` only as build-spec writes it for its code, that code's spec version and spec name, or not at all: frame-executive runs a runtime's migrations when its spec version is above the stored one or its name differs, so another value runs them at block 1 or skips them at a later upgrade. Also refuses a genesis that sets the `NativeTokenManagement` observation scripts, or stores them as anything but the empty configuration build-spec writes. The launch plan's checkpoint canary runs the real observation from the genesis checkpoint and requires zero transfers from the genesis-lock transaction and at least one from a canary deposit made after it. This runtime's observation has no checkpoint: until its first non-zero transfer it asks for every transfer since Cardano genesis, so it would count the genesis lock and the canary cannot pass. |
| 7 timelock | Genesis sets no `RootTimelock.Guardian`, or one that is `Sudo.Key`; `roles.guardian` does not declare exactly one guardian whose account is the genesis guardian, or that guardian does not need two keyholders to act or has a multisig as a member (see [Multisig roles](#multisig-roles)); or any account in the guardian, the multisig or a member at any depth, is also the sudo multisig, one of its members or `Sudo.Key`: the guardian vetoes the sudo key's queued Root calls, so its keyholders must be apart from the sudo key's. Genesis sets no `RootTimelock.Delays`, or a delay below the runtime's mainnet delay for its class (`RootTimelock.DefaultDelays`: 1, 7 and 30 days), a long delay above `RootTimelock.MaxDelay` (90 days), or delays out of the runtime's order 0 < recovery <= standard <= long. Both constants are read from the runtime metadata; a runtime that does not declare them is refused. The preprod genesis fails this rule: its delays are minutes, and its guardian is the sudo keyholders' 3-of-3. |
| 8 node | An authority's running node serves another genesis than the one the preflight computes, which the manifest signs and the lock's datum binds; its own node binary, run offline on the options its node process runs with, builds another genesis than that one; the binary is not the one `exe_sha256` pins; the file its `--chain` names, as captured, is not the checked spec byte for byte; or its `--chain` names a chain built into the node, or is not given (the node then loads its built-in `local`, or `dev` under `--dev`). Its running node answers `system_chain`, `system_chainType` or `system_properties` with other than the checked spec's name, chain type (`Live` when the spec names none) or properties (none as `{}`), or a step of its `--chain` path (a directory on it, or the file) last changed less than a full second before its node process started: the node reads its spec once, at its start, and keeps it when the file is replaced, and a spec can hold the checked genesis under another name, or with a code substitute that runs other code. An option the preflight does not know, a node that cannot run here or builds no genesis from the checked spec, and a spec that names `telemetryEndpoints` refuse as unreadable. Also refuses a spec whose runtime, run by the authority's node binary at block one, holds a chain id other than the genesis hash: any metadata constant whose name holds `ChainId` or `GenesisHash`; or whose genesis `IntentSettlement.CardanoIds`, as that node reads it with the runtime's own types, is not what the preflight reads from the raw spec, so rule 11 would have checked other ids than the chain binds. The checked spec is not the one the authority's pinned node binary builds from the launch manifest, run offline on `build-spec --chain mainnet:<manifest> --raw`: a genesis storage key or value differs (each named, by pallet and item), the runtime code is not the one the binary embeds, genesis holds child storage or anything besides its top storage, or a field other than `bootNodes` differs or is one the node's build does not write (`codeSubstitutes`, `forkBlocks`, `badBlocks`, `forkId` among them); or the binary refuses the manifest. See [Node attestation](#node-attestation) and [The node's own build](#the-nodes-own-build). |
| 9 committee | Genesis `SessionCommitteeManagement.CurrentCommittee` is not exactly the declared authorities' `aura` and `grandpa` key pairs, each once, two of its members share a cross-chain key, or it lists more members than the runtime's `SessionCommitteeManagement.MaxValidators`, read from the runtime metadata (a runtime that does not declare it is refused). The runtime seats this committee at every rotation whose Cardano draw fails, and a fresh chain's first draw fails, since the live-quorum floor counts no candidate that has not authored yet: an empty committee halts the chain there (GRANDPA refuses an empty authority set), an undeclared member authors and finalizes unchecked, and a committee past MaxValidators does not decode and reads as empty. The committee serves another epoch than the 0 build-spec writes: the node takes only an epoch-0 committee as the genesis one, and otherwise asks Cardano at block 1 for the committee of the epoch after it instead of the current one's, which it cannot derive for an epoch that began before Cardano's first, so the chain never authors block 1. Genesis `Aura.Authorities` or `Grandpa.Authorities` is not exactly the declared authorities' `aura` or `grandpa` keys, each once, a voter at weight 1 as build-spec writes them: a key listed twice, or a weight above 1, counts as several authors or voters. Genesis `Grandpa.CurrentSetId` is set and not 0, or `Grandpa.SetIdSession` is not build-spec's one entry, set 0 beginning in session 0: every GRANDPA client starts the genesis authority set at set id 0, and a node that warp- or state-syncs takes the runtime's set id instead, so it would hold another set id than the one its peers sign votes and justifications under. `Session.ValidatorsAndKeys` is not the committee as the session genesis writes it (each member's account, blake2-256 of its cross-chain key, with its session keys, in the committee's order), or `PalletSession.QueuedKeys` or `PalletSession.Validators` is not the empty list build-spec writes: the session keys they hold would go unchecked. Two authorities declare the same `aura` or `grandpa` key: two nodes that sign with one key equivocate. A Cardano permissioned candidate's `gran` key is not the `grandpa` key that the authority with its `aura` key declares: the candidates vote on finality with those keys once the committee is drawn from Cardano. A declared authority's `aura` key is on no permissioned candidate: Ariadne seats every candidate when all fit, so the first committee drawn from Cardano leaves that authority out, and a datum of 2 of 4 authorities seats a committee of 2, which GRANDPA needs both of to finalize, so it tolerates no fault. The permissioned candidates datum holds a candidate Ariadne drops (a partner chains key not 33 bytes, an `aura` or `gran` key not 32), one that repeats an earlier candidate's key (the runtime keeps the first), or fewer than two candidates the runtime can seat: from fewer than two it draws no committee, and every rotation seats the genesis committee again. The D-parameter seats registered candidates (a Cardano stake pool that registers would join the committee, and the preflight reads no registration), fewer permissioned seats than the datum's candidates (Ariadne would draw the seats at random, with repeats, so a declared authority could be left out), or more than `MaxValidators` (the runtime refuses a whole draw past a cap of its own that its metadata does not declare). The node reads both datums with partner-chains v1.5.1's decoder: a legacy datum or version 0 of the versioned one; any other version refuses as unreadable. A genesis committee member's cross-chain key, or a Cardano permissioned candidate's partner chains key, is not the `cross_chain` key the authority with its aura and grandpa keys (a candidate: its aura key) declares: genesis would seat it under a partner-chain key no declared authority holds, and file its session keys under that key's account, and a committee drawn from Cardano would seat it so. The launch declares no `partner_chain`, genesis `Sidechain.GenesisUtxo` is not its `genesis_utxo`, or `partner_chain.committee_candidate_address`, `d_parameter_policy_id` or `permissioned_candidates_policy_id`, or genesis `SessionCommitteeManagement.MainChainScriptsConfiguration`'s address or policies, are not what the genesis UTXO derives (see [Partner chain scripts](#partner-chain-scripts)): a genesis that names other scripts draws its committee from datums the setup never made. The D-parameter or permissioned candidates output was created in a Cardano epoch later than two before the launch epoch: the followers serve an epoch's committee from the data of the epoch two before it, so for a chain whose first block is authored now the output is not there, the follower finds no data and no node authors block 1 until Cardano reaches the output's epoch plus two. The launch epoch is the one in which the session that holds the tip of Kupo's node started: block 1 asks for the committee of the Cardano epoch its session started in, and a session, genesis `Sidechain.SlotsPerEpoch` slots of the runtime's `Aura.SlotDuration`, starts at a multiple of its length since the Unix epoch. A Cardano epoch starts at 21:44:51 UTC and an hour's session on the hour, so for the first 909 seconds of an epoch the launch epoch is the one before the tip's. The refusal names the earliest valid launch epoch and when its first session starts. A candidate's partner chains key that is 33 bytes and no compressed secp256k1 point refuses: its seat would be filed under an account no one holds. Epochs are Cardano mainnet's Shelley layout (epoch 208 from slot 4,492,800 at 2020-07-29T21:44:51Z, 432,000 one-second slots each); a slot before it refuses as unreadable, and so does a committee output Kupo gives no `created_at` slot for. The launch declares no `slots_per_epoch`, genesis `Sidechain.SlotsPerEpoch` is absent (the runtime then reads partner-chains' default of 60) or not that declared length, it is 0 (the runtime divides each block's slot by it as it initializes the block, so block 1 traps), or a session of that many slots of the runtime's `Aura.SlotDuration` does not divide Cardano's 432,000-second epoch, as partner-chains' sidechain-slots requires: a session longer than a Cardano epoch skips the committees Cardano holds for the epochs it spans, and in a session that began before Cardano's first epoch, as one of 2^32-1 slots did, the node cannot draw block 1's committee, so the chain never authors it. A runtime whose metadata declares no `Aura.SlotDuration` is refused. The launch declares no `cardano_follower`, or one other than Cardano mainnet's (see [Launch manifest](#launch-manifest)); or an authority does not set each of those settings, or sets one, in its `env` or anywhere in its launch, to any other value or spelling than the declared one: every node derives Cardano's epochs and slots, and which Cardano blocks are stable, from them, so an authority whose settings differ from its peers' draws another committee or judges another Cardano block stable, and refuses the committee changes and blocks they make. A launch that declares none is held to Cardano mainnet's. |
| 10 possession | A member of a multisig, in any role and at any depth, is not proven held: it is a bare key or the all-zero key, it gives no `pop`, or its `pop` is not its key's signature (sr25519, or ECDSA for a 33-byte key) of its challenge, which binds the domain, the chain spec's name and id, the genesis hash, the launch manifest hash, its role and its position. A member no one proves to hold can be the address of a multisig no one declared, which no secret signs for, so the multisig it is in needs fewer keyholders, or other ones, than it reads. See [Proof of possession](#proof-of-possession). |
| 11 settlement | Genesis `IntentSettlement.CardanoIds`, the Cardano network settlement binds, is absent (settlement then refuses every voucher, settlement and expiry), holds a network magic other than Cardano mainnet's 764824073 or a Shelley genesis hash other than mainnet's `1a3be38bcbb7911969283716ad7aa550250226b76a61fc51cc9a9a35d9276d81`, or binds an `aegis_policy_v1` script hash other than the one `settlement.aegis_policy_v1_script_hash` declares, none where it declares one, or any where it declares null; or the launch declares neither. The policy takes the chain's genesis hash as a parameter, so a launch may bind it only after genesis: it declares null, genesis binds none, and Root binds the deployed hash with `IntentSettlement.bind_aegis_policy_v1`, which binds one only while none is bound; until then settlement refuses every voucher, settlement and expiry on Cardano mainnet. Every voucher the committee signs commits to the network magic and the Aegis policy, and all settlement and expiry evidence must name the Shelley genesis, so a chain launched with another network's ids settles against that network. The preflight holds every launch to Cardano mainnet (rule 9). Mainnet's ids are those its published environment gives (book.world.dev.cardano.org/environments/mainnet): the `networkMagic` of its `shelley-genesis.json`, and that file's blake2b-256, which its `config.json` publishes as `ShelleyGenesisHash`; `fixtures/cardano-mainnet-*.json` are those files, and a test holds the preflight to them. Genesis `IntentSettlement.IntentTTL`, `ClaimTTL` or `MinSignerThreshold` is not the runtime's own default (its metadata constants `DefaultIntentTTL`, `DefaultClaimTTL` and `DefaultMinSignerThreshold`, which its genesis stores), or `PoolUtilization`, `SettlementStorageVersion`, `StcaCutoverBlock` or `PolicyExpireCutoverBlock` is not what the settlement genesis writes (see [Genesis values no other rule reads](#genesis-values-no-other-rule-reads)). |
| 12 dust | A role signer has no provider at genesis (no `System.Account`, or one with no provider), or holds free less than its floor: the deposits its roles reserve, each read from the runtime metadata (`Multisig.DepositBase` and `DepositFactor`, `Recovery.ConfigDepositBase`, `FriendDepositFactor` and `RecoveryDeposit`), and, left free once they are reserved, the larger of `Balances.ExistentialDeposit`, which keeps the account, and its working dust, which generates the MOTRA its role's calls cost, a runtime upgrade among a sudo keyholder's and the enactor's (see [MOTRA and working dust](#motra-and-working-dust)). A runtime that does not declare one of those constants, or `Aura.SlotDuration`, is refused. The signers are each keyholder, at any depth, of a `sudo` or `guardian` multisig, or of a multisig entry of a signing role, who reserves `DepositBase + DepositFactor x threshold` when it opens a call; the sudo account, which reserves `ConfigDepositBase + FriendDepositFactor x friends` for its recovery configuration when the launch names `recovery_friends`; each `recovery_rescuers` entry, which reserves `RecoveryDeposit`; and each `anchor_signer`, `attestors`, `oracle`, `enactor`, `gateway_sponsor` and `recovery_friends` entry. An account in several needs all their deposits and carries all their calls. No signed call moves MATRA and none is minted after genesis, so a signer below its floor can never sign, never pay its role's deposit, or never pay for its role's calls. Genesis `Motra.Params` is not mainnet's, byte for byte, or genesis does not hold a `Motra.AccrualCheckpoint` for exactly the accounts it endows, each the account's free balance held since block 0: the runtime generates an account's MOTRA from its checkpoint, so an account with none generates nothing. |

Every reason is printed. Exit 0 means every rule passed, 1 means at least one
refused, 2 means an input could not be read (also a refusal), including hex in
another spelling (see [Hex](#hex)), a number genesis stores at another width
than its type (see [Stored numbers](#stored-numbers)), a node option the
preflight does not know or a node that builds no genesis from the checked spec
(see [Node attestation](#node-attestation)), a proxy
config with no route the preflight can read, a Kupo that is unreachable,
behind its node, whose node's tip is not Cardano's now, or that does not index
the permissioned candidates token, a node binary that prints no raw chain spec
for the launch manifest (see [The node's own build](#the-nodes-own-build)), genesis
committee scripts the runtime cannot decode (see [Usage](#usage)), and a
public RPC URL whose answers the probe cannot resolve.

## Usage

```
pip install -r requirements.txt

# Each multisig member's holder signs its challenge offline (see Proof of possession).
python3 launch_preflight.py challenge --spec mainnet-raw.json --launch launch.json --role sudo --index 0 1

# The launch key holder signs the hashes of the exact raw spec and launch manifest.
python3 launch_preflight.py sign --spec mainnet-raw.json --launch launch.json --key launch.key --out signed.json

python3 launch_preflight.py check --spec mainnet-raw.json --launch launch.json \
    --signed-manifest signed.json \
    --kupo http://<mainnet kupo>:1442 --subwasm ./subwasm \
    --extra-well-known ~/exposed-keys.json
```

`--extra-well-known` is required: a mainnet launch is checked against the
operator's table of exposed keys (see [Well-known keys](#well-known-keys)),
and a table of no keys, `{"keys": []}`, is given as one when there is none.

`sign` reads only the spec and the manifest, so the manifest can be signed
before the nodes start, with each authority's node binary pinned by its sha256. Its `--key` file holds the 32-byte ed25519 seed as
0x-hex, and at most the newline that ends its line. `check` also reads each
authority's `cmdline`, `exe`, `chain_spec` and `served_genesis` captures, runs each authority's
node binary offline (on `export-blocks`, `chain-id` and `build-spec`), and calls each URL in `public_rpc`, so it runs once the
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
their canonical JSON (sorted keys, no whitespace), the launch manifest's without
its `pop` fields: each multisig member's holder signs that hash, so the launch
key can sign before, while or after their proofs come in.

`requirements.txt` pins every package, each one's dependencies included, by
sha256, so pip installs no file but the ones pinned. It is `pip-compile`
(pip-tools) output from `requirements.in`, the direct dependencies, regenerated
with the command its header names.

The Kupo must follow Cardano mainnet and index the genesis lock address and the
D-parameter and permissioned candidates policies, the two policy ids after the
committee candidate address in genesis
`SessionCommitteeManagement.MainChainScriptsConfiguration`. That address must
be at most 120 bytes, the bound of partner-chains' `MainchainAddress`, and
nothing may follow the second policy id, as build-spec writes it: the runtime
reads the item with a longer address as undecodable, so as its default, whose
all-zero policies mark no D-parameter, and the node's follower then fails
every block's committee inputs. The address must also be UTF-8 with no NUL
byte: both followers format it as text (`String::from_utf8(..).expect(..)` in
`MainchainAddress`'s Display) for the Postgres query that finds registrations
at it, so bytes that are not UTF-8 panic the node, and Postgres refuses a NUL in
text, which fails every block's committee inputs. Each of these refuses as
unreadable.

```
kupo --match <lock address> --match '<D-parameter policy>.*' \
    --match '<permissioned candidates policy>.*' ...
```

The preflight trusts that Kupo for what Cardano holds, and refuses when it is
more than 300 slots behind its node, or when its node's tip is more than 600
seconds from the clock of the host `check` runs on, either way: a Kupo in step
with a node that has itself stopped following Cardano lists every output as it
stood at that node's tip. Cardano makes a block every 20 seconds on average, so
a tip ten minutes old is a stopped node or a wrong clock; keep the host's clock
set. The session that holds its node's tip gives the epoch rule 9 takes a
launch to start in, so a committee output must be two epochs older than it:
run `check` in the epoch the chain starts. It reads each committee datum from the one
unspent output that holds its policy's token under the empty asset name; a
token held by no unspent output, or by several, refuses as unreadable. The
node's follower reads the output created last that holds the token, spent or
not. The two are the same output unless a unit of the token that a later
output held has been burnt, which the preflight does not see: mint one unit of
each token and burn none. The follower reads each datum as it stood in the
Cardano epoch it takes its data from, and the preflight as it stands at the
check: change neither datum between that epoch and the launch.

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
`OrinqReceipts.EraCapBaselineAttestorCount` and `Sidechain.SlotsPerEpoch` 4
(u32), `Grandpa.CurrentSetId` 8 (u64), `IntentSettlement.CardanoIds` 64 (a u32
network magic, then the 32-byte Shelley genesis hash and the 28-byte
`aegis_policy_v1` script hash), and every `System.Account` value 80 (`AccountInfo`: four u32 counters,
then free, reserved, frozen and flags as u128), filed under blake2_128 of its
account followed by the account. FRAME reads a value too short for its type as
the item's default (zero, and 60 slots for `Sidechain.SlotsPerEpoch`), and
ignores the bytes past its type, and the runtime reads an account at that one
key only. So a baseline of 32 written as the single byte `0x20` would read as
32 here and launch as 0, which lifts the per-era attestor reward cap to the
whole `EraCapBase`. build-spec writes each at its width and key; anything else
refuses as unreadable.

A list's length, a SCALE compact integer, must be written in the fewest bytes
its value needs, as parity-scale-codec requires: the runtime reads a list whose
length is written in more bytes as undecodable, so as its default, and an
empty genesis committee or no authors would launch where the preflight read
the declared ones. Such a list refuses as unreadable.

## Genesis values no other rule reads

Rule 4's allowlist says which items genesis may set, and the other rules read
what most of them hold. The rest are values the runtime's genesis builds
hard-code, or its own defaults. Every node's genesis hash covers them, and a
runtime upgrade reads the storage versions, so genesis must hold each one as
build-spec writes it; a value that is absent, or of another length, refuses
like another value.

| Storage | Value build-spec writes | Rule |
|---|---|---|
| `:extrinsic_index` | 0, a u32 | 4 |
| `System.UpgradedToU32RefCount`, `System.UpgradedToTripleRefCount` | set (`0x01`) | 4 |
| `System.ParentHash`, `System.BlockHash[0]` | 32 bytes of `0x45`, frame_system's hash of block 0; `BlockHash` holds no other entry | 4 |
| `Vesting.StorageVersion` | V1 (`0x01`) | 4 |
| each pallet's `:__STORAGE_VERSION__:` | 5 for `Grandpa`; 1 for `Balances`, `Motra`, `Multisig` and `TeeAttestation`; 0 for every other pallet the metadata lists, as a u16 | 4 |
| `NativeTokenManagement.MainChainScriptsConfiguration` | no policy, asset name or address: 30 zero bytes | 6 |
| `OrinqReceipts.ReceiptExpiryBlocks` | 14,400, a day of blocks | 2 |
| `IntentSettlement.IntentTTL`, `ClaimTTL`, `MinSignerThreshold` | the runtime metadata's `DefaultIntentTTL` (600), `DefaultClaimTTL` (28,800) and `DefaultMinSignerThreshold` (1) | 11 |
| `IntentSettlement.PoolUtilization` | target 5,000 and cap 7,500 basis points, over a pool value and an outstanding coverage of 0 | 11 |
| `IntentSettlement.SettlementStorageVersion` | 5 | 11 |
| `IntentSettlement.StcaCutoverBlock`, `PolicyExpireCutoverBlock` | block 0, which closes the legacy settle and expire calls | 11 |

A storage version below the one a pallet's code declares makes a later runtime
upgrade run that pallet's migrations against storage already in the new
layout, and one above it skips them. The versions are the preflight's own
table: a runtime that bumps one is a new runtime to pin here. A test holds the
table to the fixture the node builds, and a node test to the build of the
real binary, read with that runtime's whole metadata.

## MOTRA and working dust

A signed call is paid in MOTRA, which an account's free MATRA generates.
Rule 12 holds genesis `Motra.Params` to mainnet's parameters, byte for byte,
since every dust floor is worked under them:

| Field | Value |
|---|---|
| `min_fee` | 10^9 MOTRA base units (15 decimals), a u128 |
| `congestion_rate` | 0, a u128: the weight of a call costs nothing until blocks run more than half full |
| `target_fullness` | 500,000,000 parts per billion, a u32 |
| `decay_rate_per_block` | 999,900,000 parts per billion, a u32: a balance keeps 99.99% a block |
| `generation_per_matra_per_block` | 10^10, a u128: one MATRA (10^6 base units) generates 10^10 a block, a base unit 10^4 |
| `max_balance` | 10^18, a u128 |
| `max_congestion_step` | 10^9, a u128 |
| `length_fee_per_byte` | 10^6, a u128 |
| `congestion_smoothing` | 100,000,000 parts per billion, a u32 |

These are `MotraParams::default()` with the generation a mainnet launch runs
on; an absent `Motra.Params` reads as all zero, which generates nothing. The
runtime generates an account's MOTRA from its `Motra.AccrualCheckpoint`, the
free MATRA it has held since a block, so genesis must hold one for exactly the
accounts it endows, the Treasury among them, each the account's free balance
held since block 0, as the Balances genesis writes it. A missing checkpoint
generates nothing; a lower one generates less than the dust does.

Under those parameters a call of n bytes costs `10^9 + 10^6 x n` while the
congestion rate is the 0 it starts at, and a balance that generates g a block
settles at `g / (1 - 0.9999)`: 10^8 MOTRA for each free base unit of MATRA.
MOTRA comes of free MATRA alone, so the preflight counts what an account has
left once its deposits are reserved, the existential deposit included, and
requires that its MOTRA never runs out under its role's calls, evenly spaced
over a day of the runtime's blocks, and, for a key that signs an upgrade,
never falls below the fee of the call that carries one. A fee f paid every k
blocks holds a balance below where it settles by at most `f / (1 - 0.9999^k)`,
right after a call; several roles' calls by at most the sum. The preflight
bounds that in whole fractions (`0.9999^k <= 1 - x + x²/2` for `x = k / 10^4`,
and a call may land a block early), and a test runs the pallet's rule block by
block against it: at the working dust the balance holds, at 2% less it does
not. Each key that signs for a role carries the role's calls: the entry's own
key, or each key of its multisig at any depth, since the key that signs pays
the fee of a call its multisig makes.

| A key that signs for | Calls a day, bytes of one | Working dust (base units) |
|---|---|---|
| `sudo` | 24 of 512, and an upgrade | 260 and the upgrade's |
| `guardian` | 64 of 384 | 623 |
| `enactor` | 64 of 512, and an upgrade | 680 and the upgrade's |
| `anchor_signer` | 1,000 of 512 | 10,509 |
| `gateway_sponsor` | 2,000 of 512 | 21,010 |
| `oracle` | 4,800 of 512 | 50,413 |
| `attestors` | 100 of 256 (attests are feeless) | 879 |
| `recovery_friends` | 8 of 256 | 77 |
| `recovery_rescuers` | 24 of 512 | 260 |

The loads are the ones `docs/MAINNET-GENESIS.md` sizes each role's dust for.
The call that carries an upgrade is sized at twice the genesis runtime code,
as genesis stores it, so a later runtime may be twice as long: for a code of
886,000 bytes that is a fee of 1.773 x 10^12 and 17,730 base units, a sudo
keyholder's working dust 17,990 and the enactor's 18,410. A floor is the
deposits and, left free, the larger of the existential deposit (500) and the
working dust: a 2-of-n sudo keyholder's is 2,000 + 17,990 there. Before this
rule counted working dust a keyholder at its floor was left 500 base units
free once its deposit was reserved, which settle at 5 x 10^10 MOTRA, a
thirty-fifth of that upgrade's fee.

The node's builder sizes the same loads another way (a day's fees generated
in a day, on top of the existential deposit, and twice the fee of a 5 MiB
call, the longest a block takes, for an upgrade), and its floors cover the
preflight's for every role, whatever runtime a block can hold: a test sets
each role account to the floor `docs/MAINNET-GENESIS.md` tables, with a 5 MiB
genesis runtime, and rule 12 passes.

| Role account | Builder's floor | Preflight's floor, 886,000-byte runtime | Preflight's floor, 5 MiB runtime |
|---|---|---|---|
| sudo keyholder (2-of-n) | 107,630 | 19,990 | 107,128 |
| guardian keyholder (2-of-n) | 3,116 | 2,623 | 2,623 |
| enactor | 106,050 | 18,410 | 105,548 |
| anchor_signer | 11,000 | 10,509 | 10,509 |
| gateway_sponsor | 21,500 | 21,010 | 21,010 |
| oracle | 50,900 | 50,413 | 50,413 |
| attestor | 1,373 | 879 | 879 |
| recovery friend | 570 | 500 | 500 |
| recovery rescuer | 1,752 | 1,500 | 1,500 |
| sudo account, 3 friends | 3,000 | 3,000 | 3,000 |

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
    "sudo": [{"threshold": 2, "members": [{"key": "5D...", "pop": "0x..."}, {"key": "5H...", "pop": "0x..."},
                                          {"key": "5C...", "pop": "0x..."}]}],
    "guardian": [{"threshold": 2, "members": [{"key": "5E...", "pop": "0x..."}, {"key": "5F...", "pop": "0x..."},
                                              {"key": "5G...", "pop": "0x..."}]}],
    "anchor_signer": ["5J..."],
    "attestors": ["5K..."],
    "oracle": [],
    "endowed": ["5L...", {"threshold": 2, "members": [{"key": "5A...", "pop": "0x..."},
                                                      {"key": "5B...", "pop": "0x..."}]}]
  },
  "economics": {
    "attestation_reward_per_signer": 0,
    "era_cap_base": 0,
    "era_cap_baseline_attestor_count": 32,
    "validator_reward_per_era": 102739726,
    "treasury_emission_share_perbill": 150000000,
    "fee_buffer": 0
  },
  "supply": {
    "genesis_lock": {"utxo": "<tx id>#<index>", "address": "addr1w...", "native_script": "0x8303..."}
  },
  "slots_per_epoch": 600,
  "settlement": {"aegis_policy_v1_script_hash": "0x<28-byte script hash>"},
  "cardano_follower": {
    "MC__FIRST_EPOCH_TIMESTAMP_MILLIS": "1596059091000", "MC__EPOCH_DURATION_MILLIS": "432000000",
    "MC__FIRST_EPOCH_NUMBER": "208", "MC__FIRST_SLOT_NUMBER": "4492800", "MC__SLOT_DURATION_MILLIS": "1000",
    "CARDANO_SECURITY_PARAMETER": "2160", "CARDANO_ACTIVE_SLOTS_COEFF": "0.05"
  },
  "nodes": [
    {"name": "val-1", "host": "val-1", "addresses": ["10.0.0.11"], "authority": true,
     "aura": "0x<aura public key>", "grandpa": "0x<grandpa public key>",
     "cross_chain": "0x<33-byte compressed ECDSA partner-chain key>",
     "argv": ["materios-node", "--validator", "--chain", "/srv/materios/mainnet-raw.json", "--rpc-methods", "safe"],
     "exe_sha256": "0x<sha256 of the node binary>",
     "cmdline": "captures/val-1.cmdline", "exe": "captures/val-1.exe", "chain_spec": "captures/val-1.chain.json",
     "served_genesis": "captures/val-1.genesis.json",
     "env": {"MC__FIRST_EPOCH_TIMESTAMP_MILLIS": "1596059091000", "MC__EPOCH_DURATION_MILLIS": "432000000",
             "MC__FIRST_EPOCH_NUMBER": "208", "MC__FIRST_SLOT_NUMBER": "4492800", "MC__SLOT_DURATION_MILLIS": "1000",
             "CARDANO_SECURITY_PARAMETER": "2160", "CARDANO_ACTIVE_SLOTS_COEFF": "0.05"}},
    {"name": "edge-1", "host": "edge-1", "addresses": ["10.0.0.2"], "authority": false}
  ],
  "rpc_proxies": [
    {"name": "public-rpc", "node": "edge-1", "kind": "nginx-dump", "config": "nginx-T.txt",
     "other_targets": ["status.example.org:443"]}
  ],
  "public_rpc": ["https://rpc.example.org/rpc"],
  "dust": {"anchor_signer": {"5J...": 20000}, "attestors": {"5K...": 5000}, "endowed": {"5L...": 5000}},
  "attestation_threshold": 1,
  "partner_chain": {"genesis_utxo": "<tx id>#<index>", "committee_candidate_address": "addr1w...",
                    "d_parameter_policy_id": "0x<28 bytes>", "permissioned_candidates_policy_id": "0x<28 bytes>"}
}
```

`fixtures/mainnet-launch.json` is a complete manifest the node builds a
mainnet genesis from (see `docs/MAINNET-GENESIS.md`).

- `roles` maps a role name to entries. An entry is a public key (SS58, or
  0x-hex 32-byte account or 33-byte ECDSA key), never a secret URI, or a
  multisig `{"threshold": k, "members": [...]}`; its account is
  pallet_multisig's for those members and threshold, and every member is
  checked. A member is a multisig in turn, declared by its members, or a key
  given with its holder's proof of possession, `{"key": "5D...", "pop":
  "0x..."}`, with no `pop` until its holder signs (see
  [Proof of possession](#proof-of-possession)). Rule 10 refuses a member given
  as a bare key, so a multisig written as the address a wallet shows refuses
  until it is declared by its members. An entry that is no multisig asserts
  one key its holder alone controls. The roles are `sudo`, `guardian`,
  `anchor_signer`, `attestors`, `oracle`, `enactor`, `gateway_sponsor`,
  `recovery_friends`, `recovery_rescuers`, `endowed` and `dust_pool`, what
  the node's mainnet builder gives a meaning; any other refuses as
  unreadable. `sudo`, `anchor_signer`, `attestors` and `oracle`
  must be present; an empty `oracle` states that no oracle signer runs.
  `roles.sudo` must name exactly the genesis `Sudo.Key` (or be empty when
  genesis sets none), and `roles.guardian` exactly the genesis
  `RootTimelock.Guardian`, each as a multisig role (below); no account in
  the guardian, at any depth, may also be in `roles.sudo` or be `Sudo.Key`. Every
  genesis account must be the account of some entry, or the Treasury's;
  `endowed` holds the ones no other role names, a multisig's keyholders among
  them, since a multisig member is no entry. `attestors` are the attestation
  committee genesis seats (rule 1), and every signing role's entry and every
  multisig keyholder holds its dust floor (rule 12).
- `dust` maps a role to the accounts of its entries, each named by its key
  (SS58 or 0x-hex) or, for a multisig entry, by its account, and to the base
  units it holds at genesis, a u128. Rule 4 holds every genesis account to it.
  Another shape refuses as unreadable.
- `attestation_threshold` is how many of `roles.attestors` certify a
  receipt, a u32 genesis `OrinqReceipts.AttestationThreshold` must store.
- `partner_chain` holds exactly `genesis_utxo` (`<64 lowercase hex>#<index>`,
  the index in decimal with no leading zero and at most 32767, the most
  partner-chains' `UtxoIndex` reads), `committee_candidate_address`, and
  `d_parameter_policy_id` and `permissioned_candidates_policy_id` (0x-hex,
  28 bytes): what partner-chains' setup spent and derived on Cardano (rule
  9). Another shape refuses as unreadable.
- Every `economics` value is a non-negative integer in the smallest unit; an
  unknown field or any other value refuses as unreadable. Genesis stores the
  attestation reward as 0 (rule 4), so the declared one is 0 (rule 2).
  `fee_buffer` is accepted and read by no rule: a signer's floor is the
  deposits the runtime reserves and its working dust (rule 12).
- `supply.genesis_lock` is the Cardano output holding the cMATRA that backs
  Materios issuance, and `native_script` the CBOR of the native script its
  address pays to, as 0x-hex. The backing is the cMATRA amount Kupo reports at
  that output; the manifest carries no backing figure. Create the lock after
  building the raw spec, with the genesis hash as its inline datum: a Plutus
  bytestring, CBOR `5820` followed by the 32 bytes.
- `slots_per_epoch` is how many slots each session lasts, a u32 genesis
  `Sidechain.SlotsPerEpoch` must store: the committee rotates at each session
  boundary. The preflight refuses 0 and a length whose sessions do not divide
  Cardano's epoch (rule 9), and takes any other as the signers' choice. The
  runtime lets the sudo key set a `Grandpa.note_stalled` delay of at most a
  twentieth of a session without the timelock, and at most 30 blocks, the
  delay the recovery tooling uses: a session under 600 slots lowers that
  bound.
- `settlement.aegis_policy_v1_script_hash` is the blake2b-224 script hash of
  the `aegis_policy_v1` validator deployed on Cardano mainnet, as 0x-hex of 28
  bytes: genesis `IntentSettlement.CardanoIds` must bind it (rule 11). Or it
  is null, for a policy applied to the chain's own genesis hash: genesis then
  binds none, and Root binds the deployed hash after launch with
  `IntentSettlement.bind_aegis_policy_v1`. A launch that declares neither
  refuses; another spelling or width, or the all-zero hash, refuses as
  unreadable.
- `cardano_follower` maps each Cardano follower setting every authority's
  node must run with to the string it is given: Cardano mainnet's Shelley-era
  layout (`MC__FIRST_EPOCH_TIMESTAMP_MILLIS` 1596059091000, the start of epoch
  `MC__FIRST_EPOCH_NUMBER` 208 at slot `MC__FIRST_SLOT_NUMBER` 4492800,
  `MC__EPOCH_DURATION_MILLIS` 432000000 and `MC__SLOT_DURATION_MILLIS` 1000)
  and the `securityParam` and `activeSlotsCoeff` of mainnet's
  `shelley-genesis.json` (`CARDANO_SECURITY_PARAMETER` 2160,
  `CARDANO_ACTIVE_SLOTS_COEFF` 0.05). It must name exactly these seven, each a
  string, or it refuses as unreadable, and hold Cardano mainnet's value for
  each, in that spelling, or rule 9 refuses. partner-chains v1.5.1 builds the
  one-second Cardano slot in and does not read `MC__SLOT_DURATION_MILLIS`;
  later releases read it, so every authority still sets it. Each authority
  must set every one of them, in its `env` or its launch, to exactly the
  declared string, and to nothing else anywhere in its launch. The preflight
  compares the strings, so another spelling of the same number (`0208`,
  `+208`) refuses too.
- `nodes` lists every machine that runs a launch process or a proxy. Each
  declares `authority` as `true` or `false`, and an authority its `aura` and
  `grandpa` public keys, and its `cross_chain` key, the ECDSA partner-chain key
  genesis seats it under, 33 bytes compressed (`0x02` or `0x03` first) as
  0x-hex; a node that is no authority takes none. A field no reader of the
  manifest knows refuses as unreadable. The authorities are the genesis committee (rule 9). `argv` is a list: the words the process receives, as
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
  0x-prefixed lowercase hex, as the node writes it. `served_chain`,
  `served_chain_type` and `served_properties` are its answers to
  `system_chain`, `system_chainType` and `system_properties`, saved the same
  way with `"params":[]`.
- An authority's `process_stat` is the path of a copy of its node process's
  `/proc/<pid>/stat`, `system_stat` of a copy of its machine's `/proc/stat`,
  and `chain_spec_stat` of what `stat -c '%Z %f %n'` prints for each step of
  the lookup of its `--chain` path, run in `/proc/<pid>/root` for an absolute
  path and in `/proc/<pid>/cwd` for a relative one, each on its machine once
  the node runs. For `--chain /srv/materios/mainnet-raw.json`:

  ```
  cat /proc/<pid>/stat > val-1.stat
  cat /proc/stat > val-1.proc-stat
  cd /proc/<pid>/root && stat -c '%Z %f %n' srv srv/materios srv/materios/mainnet-raw.json > val-1.chain.stat
  ```

  See [The spec a running node read](#the-spec-a-running-node-read).
  `check` reads every capture, and `sign` none. Only an authority takes
  them.
- `env` holds the settings a node's unit or container definition gives it
  (`Environment=` and `EnvironmentFile=`, `docker run -e`, a compose file's
  `environment:`) as the process receives them: systemd decodes escapes and
  expands specifiers in an `Environment=` line first. The settings the
  service manager or container runtime adds on its own (`PATH`, `LANG`,
  `HOME`, `HOSTNAME`, `INVOCATION_ID`, `JOURNAL_STREAM`, `SYSTEMD_EXEC_PID`),
  which `/proc/<pid>/environ` always lists, are left out: the preflight
  takes the service manager's defaults as given. Assignments in a script
  (`NAME=value`, `export NAME=value`, and one before a nested shell, whose
  script's commands inherit it) count the same, and so does a setting
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
  `BLOCK_STABILITY_MARGIN`, `SIDECHAIN_BLOCK_BENEFICIARY`, the five `MC__`
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
- has a key that meets its threshold alone with the keys anyone can sign as,
  or whose threshold those keys meet with no keyholder at all. Anyone can sign
  as a well-known key, whose secret is public (see
  [Well-known keys](#well-known-keys)), and as an ed25519 key of small order,
  since any account also signs with ed25519 (see
  [Keys anyone can sign for](#keys-anyone-can-sign-for)). The all-zero account
  is the exception: frame_system's `CheckNonZeroSender` refuses it as a signer,
  so it approves nothing. So a 2-of-2 of C and the ristretto basepoint, whose
  secret scalar is 1, is C's alone;
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

## Proof of possession

Every member of every multisig, in any role and at any depth, is a multisig
declared by its members or a key given with its `pop`: its holder's signature
of the member's challenge. Rule 10 refuses a member given as a bare key, one
with no `pop`, and a `pop` that does not verify. A `pop` verifies only with its
key's secret, but for one key, which rules 1 and 10 refuse: the all-zero key is
the ristretto identity, and schnorrkel, in the node as here, verifies its
sr25519 signature with R and s zero (63 zero bytes, then `0x80`) of any
message, which takes no secret. So every other member that proves possession
is a key whose secret someone signed with, never the address of a multisig no
one declared, which no secret signs for: each multisig needs as many keys as
its threshold says, at every depth, and rules 1 and 7 see every one of them.
A `pop` does not show who holds a key: not that its secret is kept private
(rule 1 refuses only keys whose secret is public: published, or a small
scalar or a trivial mini-secret, see [Well-known keys](#well-known-keys)), nor
that two keys have two holders, since one person can hold two members' keys
and sign both challenges. The ceremony keeps the holders apart: each signs on
their own device, and no one sees another's secret.

The challenge is these bytes, which `challenge` prints as 0x-hex:

| Bytes | Holds |
|---|---|
| `materios-launch-pop-v1` | the domain: nothing else a launch has a key sign starts with it |
| SCALE string | the chain spec's `name` |
| SCALE string | the chain spec's `id` |
| 32 | the genesis hash the preflight computes |
| 32 | the launch manifest hash, which leaves every `pop` out |
| SCALE string | the role |
| SCALE `Vec<u32>` | the position: the multisig's index in the role, then the member's index in each multisig down to it |

A SCALE string is its UTF-8 length as a compact integer, then its UTF-8. So
`roles.sudo[0].members[2].members[1]` signs role `sudo` at position 0 2 1, and
its `pop` proves nothing for another chain, genesis, launch manifest, role or
position.

A 32-byte key proves possession with sr25519 under Substrate's signing
context, as `subkey sign` signs. The manifest says no more of a 32-byte key
than that it is an account, and sr25519 is Substrate's default for one, so an
ed25519 signature does not verify. A 33-byte key is ECDSA's: its `pop` is the
65-byte signature sp_core's ECDSA makes over blake2-256 of the challenge, whose
signer, recovered by its recovery id, must be the key. A signer that wraps
what it signs, as polkadot.js `signRaw` wraps it in `<Bytes>`, signs another
message, which does not verify. sr25519 is verified with py-sr25519-bindings,
schnorrkel's binding, which the operator kit's multisig aggregator also
verifies with, and ECDSA with coincurve, libsecp256k1's, the library sp_core's
ECDSA calls in the node.

The ceremony step, once the spec and every other field of the manifest are
final, since the challenge binds both:

1. Give each multisig member as `{"key": "5D..."}`. A member still given as a
   bare key has no challenge: `challenge` refuses it as unreadable, since
   giving it as `{"key": ...}` changes the launch manifest hash its challenge
   binds.
2. Each holder prints their member's challenge from the spec and manifest
   they reviewed, for `roles.sudo[0].members[1]`:

   ```
   python3 launch_preflight.py challenge --spec mainnet-raw.json --launch launch.json --role sudo --index 0 1
   ```

   or checks that the hex they are handed is exactly what this prints. A key
   signs whatever bytes it is given, so hex taken on trust could be a signing
   payload of another chain the key holds funds or power on, passed off as a
   challenge.

3. Its holder signs it offline on their own device, with their secret URI in a
   file only they can read, and `--scheme ecdsa` for a 33-byte key, giving the
   challenge exactly as `challenge` prints it, `0x` included (subkey refuses
   hex with a second `0x` in front):

   ```
   subkey sign --suri <secret URI file> --hex --message <challenge>
   ```

4. Put each signature subkey prints in as its member's `pop`. The launch
   manifest hash leaves every `pop` out, so the proofs go in in any order, and
   a launch key signature made before them still verifies.

Each rule 10 refusal names the `challenge` command that prints the member's
challenge.

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
- runs `materios-node chain-id --chain <checked spec>` once per binary, with
  an empty environment. The node builds the spec's genesis state and hash as
  at startup, initialises block one on it, which stores that hash as
  `System.BlockHash(0)`, and reads the metadata of the spec's own runtime
  code there. The genesis it reports must be the one the preflight computes,
  and each metadata constant whose name holds `ChainId` or `GenesisHash`, in
  any case, must be that hash: signed payloads bind these ids, so a runtime
  that pins another chain's fails every signature this chain's committee and
  attestors make (settlement's and the oracle's `MateriosChainId` are two).
  Metadata read with no chain state, as subwasm reads it, holds the
  ids that come from `System.BlockHash(0)` as zero, so only a run on the
  genesis can tell them from a pinned value. The report also gives the
  genesis `IntentSettlement.CardanoIds`, decoded with the node's settlement
  types (null when genesis stores none), which must be the network magic,
  Shelley genesis hash and Aegis policy hash the preflight reads from the raw
  spec for rule 11. A binary with no `chain-id`, or a report the preflight
  cannot read, refuses as unreadable.

Where the `--chain` value names no file on this host, the as-launched run
tells a file from a chain built into the node: a node that builds a genesis
from a name with no file behind it took it as built in, which refuses
whatever that genesis is (`--chain preprod` builds preprod's own genesis
hash). A file it takes to be one it fails to open, with sc-chain-spec's
``Error opening spec file `<path>`: No such file or directory``; any other
failure refuses as unreadable, since it cannot say which. Where the value
names a file here, it must be the checked spec, and the node must build the
checked genesis from it. A path this host cannot look up or read refuses as
unreadable.

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

### The node's own build

The rules read the launch manifest and the raw spec apart from the node's
chain-spec builder (`partnerchain/node/src/chain_spec_mainnet.rs`) and share
no code with it, so a builder that writes a wrong genesis is held to the
manifest. Whatever the rules do not read, the builder is held to instead. For
each binary the authorities pin, `check` runs

```
materios-node build-spec --chain mainnet:<launch manifest> --raw --disable-default-bootnode --base-path <fresh>
```

offline (an empty working directory, no environment), on the launch manifest
file as `check` was given it, byte for byte, and refuses a checked spec that
is not what the node prints:

- genesis storage must be the same, key for key and value for value. A refusal
  names each key that differs, the first 16 of them, by pallet and item where
  the runtime metadata declares them (`Motra.Params`, `System.Account[0x...]`
  for an entry of a map, `the storage version of Balances`,
  `:extrinsic_index`), and says whether only the checked spec sets it, only
  the node's build does, or their values differ;
- `:code` must be the runtime the binary embeds, which a refusal names apart,
  with both hashes;
- genesis may hold nothing besides that top storage and the empty child
  storage the build writes;
- every other field of the spec must be the build's: `name`, `id`,
  `chainType`, `protocolId`, `properties`, `telemetryEndpoints` and
  `codeSubstitutes`, and no field only one of the two has, so a `forkBlocks`,
  `badBlocks`, `forkId` or `lightSyncState`, which a node may read, refuses,
  and so does a field it would ignore. `bootNodes` alone is the operator's to
  give.

A manifest the node's builder refuses is a refusal that carries the builder's
reason: no node builds a genesis from it. A binary that prints no raw chain
spec refuses as unreadable. An authority whose binary is not its pinned one is
not run; rule 8 refuses it above. A multisig member's `pop` does not change
the build: the builder reads the key and not its proof, and a manifest in
another order builds the same spec.

The spec to check is therefore the node's own output, with at most the boot
nodes added:

```
materios-node build-spec --chain mainnet:launch.json --raw --disable-default-bootnode > mainnet-raw.json
```

### The spec a running node read

A node reads its chain spec once, at its start. It keeps what it read when
the file is replaced, so the captures an operator takes afterwards can show
the checked spec while the node runs another: one that builds the checked
genesis under another name or chain type, or with a code substitute, which
runs other code from genesis on. So:

- its running node's `system_chain`, `system_chainType` and
  `system_properties` must be the checked spec's name, chain type and
  properties, as sc-chain-spec reads them (`Live` for a spec that names no
  chain type, `{}` for one with no properties);
- each step of the lookup of its `--chain` path must have last changed (its
  ctime) a full second before its node process started. The start is its
  machine's boot time (`btime` in `/proc/stat`) plus the process's
  `starttime` (`/proc/<pid>/stat`, in hundredths of a second after boot); the
  kernel rounds both down, and a ctime to the second, so the preflight takes
  the earliest start and the latest change each could be. Replacing the file,
  renaming a directory on its path, or re-pointing an entry there changes the
  ctime of what the path then names: a rename or a link sets it on the entry
  moved, and a new file or directory has its creation's.

The lookup starts at the process's root directory for an absolute path and
at its working directory for a relative one, which the process holds open,
so neither is a step. The steps are each directory on the path and the file,
and each must be a directory or, last, a regular file: the node follows a
symbolic link, which can be re-pointed with no trace on what it names, so a
path through one refuses as unreadable, as does a path with `..`. Keep the
spec where nothing changes once the node starts: not in its base path or a
directory the node, its container runtime or anything else adds entries to
(a container runtime that creates a mount point in a directory on the path
changes that directory). A path whose steps show no change passes; the
preflight trusts the machine's clock and mount table, which only root
changes, as it trusts the captures.

## Test networks

`test_networks.json` holds what the anchor worker reads as a test network: a
`system_chainType` of Development or Local, or a `system_chain` name matching
`name_pattern` (case-insensitive, ASCII). The anchor worker ships the same file,
so rule 1 refuses exactly the chain names that would let it sign with a dev key.

## Well-known keys

`well_known_keys.json` holds public keys only: the dev keys, keys whose secret
a public repo commits, retired keys whose secret was published, and keys whose
secret anyone can name without a leak. Those last are k·B, sr25519's ristretto
basepoint times each scalar k from 1 to 1024, and k·G, secp256k1's generator
times it, compressed to 33 bytes, each labelled `secret scalar k, public`; and
the keys of the mini-secrets of one repeated byte (`0x00`, `0x01` and `0xff`)
under each scheme that takes them, labelled `mini-secret 0x00*32, public` and
so on (secp256k1 takes neither zero nor `0xff..ff` as a secret key). A key
already in a row keeps that row's label: partner-chains commits the seeds of
the ECDSA scalars 1 and 513 to 517 as test keys.

`exposed_keys.json` holds retired keys whose secrets were exposed, each with a
neutral label: every key preprod's genesis names (its accounts and keyholders,
in its chain-spec source, its spec 244 build and the published v6 spec, and
its authorities' aura, grandpa and cross-chain keys), and every key a
permissioned candidates datum of preprod's ever named on Cardano preprod
(`fixtures/preprod-permissioned-candidates.json`, read from Koios), but pallet
accounts, which are no key. Rule 1 reads it with the public table, so a launch
that reuses one refuses like one naming a dev key. Tests hold it to every key
the preprod genesis and those datums name.

A key whose exposure is not yet public knowledge must not be named here; list
it in an operator table kept outside the repo and pass it with
`--extra-well-known`, which `check` requires (repeatable; a table of no keys
when the operator has none). That table has the same shape, each key in
lowercase hex with no `0x`:

```json
{"keys": [{"label": "exposed multisig member", "scheme": "sr25519", "public": "<32 bytes of hex>"},
          {"label": "exposed multisig member", "scheme": "ed25519", "public": "<32 bytes of hex>"},
          {"label": "exposed multisig member", "scheme": "ecdsa", "public": "<33 bytes of hex>"}]}
```

A table names public keys, and a secret is not one key: a phrase or a seed
derives an sr25519, an ed25519 and an ECDSA key, and whoever holds an exposed
one can sign under each. So list all three for every exposed secret, as above:
`subkey inspect --scheme sr25519`, `--scheme ed25519` and `--scheme ecdsa` of
the secret print them. The public table does so for every secret its generator
derives from (the dev phrase and each path of it, every phrase and seed a
public repo commits), which a test holds it to; the exceptions are a small
scalar, which is a secret key of sr25519 and secp256k1 only, and the
mini-secrets of `0x00` and `0xff` bytes, which secp256k1 takes as no key.

Two sets of rows cannot be completed here, because the repo holds their public
keys and not their secrets: the `retired validator key, mnemonic published
on-chain` rows of the public table (the sr25519 and ed25519 keys it ran
under), and `exposed_keys.json` (each retired preprod key under the one scheme
it was used with). The other schemes' keys of those secrets are in no table,
so a launch that reused one of those secrets under another scheme would pass
rule 1. Whoever holds a retired secret derives its other two public keys and
adds them to the operator table before a mainnet launch is checked.

A 33-byte ECDSA key also matches the blake2-256 account it maps to. Rules 1 and
7 count a multisig member that a table names as a key anyone can sign as (see
[Multisig roles](#multisig-roles)). The all-zero key and the ed25519 keys of
small order are not rows: a row matches anywhere in genesis storage and the
runtime code, and both hold runs of 32 zero bytes, and `0x01` followed by 31
zero bytes, so rule 1 refuses them where a key signs (see
[Keys anyone can sign for](#keys-anyone-can-sign-for)).

Rule 1 finds the table keys a storage value or the runtime code holds in one
pass over its 8-byte blocks, whatever the table's size: every key is at least
32 bytes, so a key the data holds covers a whole block that starts at a
multiple of 8, at one of the key's first 8 offsets, and only the keys indexed
under that block are compared.

Regenerate the public table from a polkadot-sdk checkout, which supplies
`DEV_PHRASE`, and a directory holding a clone of each repo in the generator's
`PUBLIC_REPOS` (the public repos with Substrate key code or configuration):

```
pip install substrate-interface ecdsa mnemonic
python3 gen_well_known_keys.py <polkadot-sdk> <clones> > well_known_keys.json
```

The generator is the table's source: the table is its output for the clones it
swept, byte for byte, and a sweep of the same clones writes the same bytes. It
sweeps every commit of those repos for secrets committed as string literals (a
BIP39 phrase with a valid checksum, a 0x-hex seed under a name that marks it
secret, a bare `//Path` URI) and writes the public keys each derives under
sr25519, ed25519 and ecdsa. A clone made with `--filter=blob:limit=1m` is
enough: larger blobs are runtimes and chain specs. The anchor worker ships a
copy of this table; copy the regenerated file there too.

The table holds the dev phrase and its seed only as blake2-256 hashes, which
the launch-config scan compares against. The tests pin the table to sp-keyring's
hard-coded sr25519 and ed25519 keys, to the published ECDSA `//Alice` key, to
keys a Substrate keystore committed to partner-chains names by public key, to
dev-phrase paths, numeric ones included, checked against @polkadot/keyring, to
RFC 9496's multiples of the ristretto generator and SEC 2's G, to every k·B and
k·G (as py-sr25519-bindings and libsecp256k1 compute them), and to the trivial
mini-secrets' keys as subkey 20.0.0 derives them.

## Partner chain scripts

The committee candidate validator, the D-parameter policy and the permissioned
candidates policy are functions of the partner chain's genesis UTXO, derived as
partner-chains v1.8.0 derives them (`get-scripts`), from the scripts of
partner-chains-smart-contracts v8.1.0 `raw-scripts` (commit `08bc5346`), which
`partner_chains_scripts.json` vendors byte for byte. The preflight applies each
script to its parameters as Plutus data, as the uplc crate partner-chains links
applies them (`[term (con data ...)]`, flat-encoded): the genesis UTXO as
`Constr 0 [Constr 0 [tx hash], index]` to every script; the version oracle
policy then the version oracle validator's address; the D-parameter and
permissioned candidates validators then the version oracle policy's id; and
their policies the version oracle policy's id and their validator's address,
an address being `Constr 0 [Constr 1 [script hash], Constr 1 []]`. Each script
hash is blake2b-224 of `0x02` and the applied script, a Plutus V2 script's. The
committee candidate address is Cardano mainnet's enterprise script address
(header `0x71`) of the validator. Preprod's genesis UTXO derives the scripts
preprod's genesis stores, and the mainnet fixture's genesis UTXO the values its
manifest names; the tests pin both, and the vendored committee candidate
validator to the one the node's builder applies.

## Keys anyone can sign for

Two kinds of key verify a signature of any message that took no secret, so
anyone can sign as one, whoever made it:

- the all-zero key under sr25519. It is the ristretto identity, which no other
  bytes encode, and schnorrkel verifies its signature with R and s zero (63
  zero bytes, then `0x80`);
- an ed25519 key of small order. ed25519-zebra, which the node verifies every
  ed25519 signature with (GRANDPA votes, and any account's), checks
  8·s·B = 8·R + 8·k·A, so under a key A whose 8·A is the identity, R the
  identity and s zero (`0x01`, then 63 zero bytes) verify. It reads a key as
  curve25519-dalek decompresses it: y is the low 255 bits taken mod the prime,
  so y plus the prime decodes too, and the top bit gives x's sign, also when x
  is 0. So the 8 points of small order have 14 encodings. The preflight
  enumerates them from the curve, as each encoding of each multiple of a point
  of order 8; they are libsodium's small-order list with either top bit, and
  the all-zero key is one of them.

Rule 1 refuses an aura key (sr25519) that is the all-zero key, and a grandpa
key (ed25519) of small order, wherever an authority's key is: genesis
`Aura.Authorities`, `Grandpa.Authorities`,
`SessionCommitteeManagement.CurrentCommittee` and `Session.ValidatorsAndKeys`,
each declared authority's `aura` and `grandpa`, and each Cardano permissioned
candidate's `aura` and `gran`. sr25519 reads an ed25519 key of small order as
another ristretto point or none, so as an aura key it is no key anyone can sign
for. A role key or a multisig member is an account, which signs with sr25519
and with ed25519, so rule 1 refuses both kinds there.

## Tests

```
SUBWASM=./subwasm python3 -m pytest test_launch_preflight.py
```

The CLI tests run the real subwasm, a local server that answers like Kupo, one
that answers JSON-RPC over HTTP and a WebSocket like a node or a filter, and a
script that answers `export-blocks`, `chain-id` and `build-spec` like the node:
its `build-spec` prints the checked spec, as a node that builds it would,
unless a test has it build another or refuse the manifest. The host's clock
reads five seconds after the tip the Kupo stand-in serves. Every `pop` in the tests is
signed by an sr25519 or ECDSA key the test generates, never a dev or well-known
key, over a challenge the tests build apart from the preflight, and the CLI
tests' launches carry one for each multisig member. The CLI tests' clean launch
is the mainnet genesis the node builds from `fixtures/mainnet-launch.json`, with
the preprod v6 runtime as its code and spec 244's metadata, its Root and
guardian moved to multisigs of keys the tests generate, so their holders can
sign. The tests against the real
node take its path: rule 8's, on its `export-blocks`, `chain-id` and
`build-spec`; every rule that reads only the spec, on the mainnet spec that
binary builds from the fixture manifest, with its runtime's whole metadata;
and the whole launch end to end, where the binary builds the spec from the
clean launch's manifest, the tests' keyholders sign for that genesis, and
`check` passes it, then refuses it with one value unset:

```
MATERIOS_NODE=../../partnerchain/target/debug/materios-node SUBWASM=./subwasm \
    python3 -m pytest test_node_attestation.py
```

The preprod v6 fixture is the published preprod raw chain spec, and the
genesis-hash test checks the computed hash against the one the live network
reports.

The spec 244 fixtures are the preprod genesis that spec 244 (transaction version
7, MOTRA holding checkpoints, the Root timelock, bonded settlement requests,
settlement's Cardano ids in genesis storage, no PerpEngine) builds, without
its code, and that runtime's metadata, trimmed to what the preflight reads.
A test holds both fixtures to the spec and transaction versions the runtime
source declares.
From `partnerchain/`, with subwasm v0.21.3 and jq
(`build-spec` runs offline, and the scratch base path takes the network key it
writes):

```
materios-node build-spec --chain preprod --raw --disable-default-bootnode --base-path "$(mktemp -d)" > raw.json
jq 'del(.genesis.raw.top["0x3a636f6465"])' raw.json > fixtures/preprod-spec244-raw.json
jq -r '.genesis.raw.top["0x3a636f6465"][2:]' raw.json | xxd -r -p > runtime.wasm
subwasm metadata runtime.wasm --format json | jq -jcS '{V14: {pallets: [.V14.pallets[]
  | {name, constants: [.constants[] | {name, value}], storage: (.storage | if . == null
  then null else {prefix, entries: [.entries[] | {name}]} end)}], types: {types:
  [.V14.types.types[] | select(.type.path | length > 0) | {id, type: {path: .type.path}}]}}}' \
  > fixtures/spec244-metadata.json
```

The same trim of the preprod v6 runtime's metadata gives
`fixtures/preprod-v6-metadata.json` byte for byte.

`fixtures/mainnet-launch.json` is a launch manifest of freshly generated
public keys with the fields the node's mainnet chain-spec builder reads, and
`fixtures/mainnet-launch-raw.json` the raw spec the node builds from it (see
`docs/MAINNET-GENESIS.md`), without its code; a node test holds it to the
spec this source builds. Every rule that reads only the spec, its metadata and
the manifest passes it, and the tests of rules 1, 2, 4, 9, 11 and 12 change it one
value at a time:

```
materios-node build-spec --chain mainnet:../tools/launch-preflight/fixtures/mainnet-launch.json --raw \
    --disable-default-bootnode --base-path "$(mktemp -d)" > raw.json
jq 'del(.genesis.raw.top["0x3a636f6465"])' raw.json > ../tools/launch-preflight/fixtures/mainnet-launch-raw.json
```

The historical preprod v6 fixture leaves
`SessionCommitteeManagement.CurrentCommittee` empty and seeds Aura and GRANDPA
directly, and rule 9 refuses that. The spec-244 fixture and the mainnet fixture
seat their authorities as the genesis committee:
the committee, then the Aura authors, GRANDPA voters and session validators
the session genesis takes from it.
