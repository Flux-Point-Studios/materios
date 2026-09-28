# Materios Governance & D-Parameter Configuration

## Overview

Materios uses the Partner Chains governance model for validator management and chain parameter control. This document describes the governance initialization procedure and ongoing operations.

## Key Concepts

### Governance UTXO
- Governance is initialized by spending a **one-time genesis UTXO** on Cardano mainchain/preprod
- This UTXO encodes the governance keys and threshold
- Once spent, the governance authority is established — this operation cannot be repeated
- The governance committee controls: D-parameter, permissioned candidates, reserves, governed maps

### D-Parameter
Controls the validator selection mix:
- **D = (permissioned_count, registered_count)**
- Example: D = (3, 0) means 3 permissioned validators, 0 registered SPOs
- Start fully permissioned: D = (N, 0)
- Gradually shift: D = (2, 1), then D = (1, 2), etc.
- Full decentralization: D = (0, N)

### Ariadne Protocol
The committee selection protocol that uses the D-parameter to compose the block-producing committee each epoch from:
1. Permissioned candidates (controlled by governance)
2. Registered SPO candidates (via mainchain registration)

## Initialization Procedure

### Prerequisites
- Cardano preprod fully synced (db-sync at tip)
- Partner chain node built
- Governance keys generated

### Step 1: Generate Governance Keys
```bash
materios-node wizards generate-keys
```
This produces:
- ECDSA cross-chain key pair
- Ed25519 Grandpa key pair
- Sr25519 Aura key pair
Stored in `partner-chains-node-data/` by default.

### Step 2: Prepare Configuration
```bash
materios-node wizards prepare-configuration
```
Interactive wizard that collects:
- Cardano payment signing key path
- Mainchain node socket path
- DB Sync Postgres connection
- D-parameter initial values (recommended: fully permissioned)
- Governance keys threshold (e.g., 2-of-3)

### Step 3: Create Chain Spec
```bash
materios-node wizards create-chain-spec
```
Generates the genesis chain spec with:
- Initial authorities
- Genesis accounts and balances (MATRA distribution)
- MOTRA parameters
- Protocol parameters

### Step 4: Setup Mainchain State
```bash
materios-node wizards setup-main-chain-state
```
**This is the irreversible step.** It:
- Spends the genesis UTXO
- Registers governance committee on mainchain
- Publishes the initial D-parameter
- Sets up the native token reserve (if applicable)

### Step 5: Wait for Registration
Wait **2 Cardano epochs** (~10 days on mainnet, ~2 days on preprod) for:
- Committee registration to be confirmed
- Governance parameters to be readable by nodes

### Step 6: Start Partner Chain
```bash
materios-node wizards start-node
```
Or manually:
```bash
materios-node \
  --chain preprod \
  --base-path /data/materios \
  --validator \
  --name "materios-validator-1" \
  --cardano-socket-path /data/cardano/node.socket
```

### Step 7: Verify
```bash
# Health check
curl -s localhost:9944 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"system_health","params":[],"id":1}' | jq

# Verify block production
curl -s localhost:9944 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"system_syncState","params":[],"id":1}' | jq
```

## D-Parameter Migration Plan

### Phase 1: Genesis (Fully Permissioned)
- D = (3, 0) -- 3 permissioned validators, no external SPOs
- All validators are team-operated
- Focus: stability, testing, debugging

### Phase 2: Hybrid (Gradual Opening)
- D = (2, 1) -- 2 permissioned + 1 registered SPO
- External validators begin onboarding
- Governance monitors chain health metrics

### Phase 3: Majority External
- D = (1, 2) -- 1 permissioned + 2 registered SPOs
- Most block production by community validators
- Governance retains 1 seat for emergency

### Phase 4: Full Decentralization
- D = (0, 3+) -- all registered SPOs
- Governance only controls parameter updates
- Permissioned seats eliminated

## Changing D-Parameter

Requires governance transaction on Cardano:
```bash
# Via the governance tooling (details TBD per toolkit version)
materios-node wizards update-d-parameter \
  --permissioned 2 \
  --registered 1 \
  --governance-key path/to/key
```
Changes take effect after the next epoch transition.

## MATRA Token Reserve

### Current Status (MVP)
- MATRA exists only on the partner chain (pallet_balances)
- No Cardano-side reserve or bridge
- Pre-funded at genesis

### Future: Cardano Bridge
The Partner Chains toolkit supports native token reserve management:
- Lock MATRA (or a Cardano native token) on mainchain
- Mint equivalent on partner chain
- Requires reserve management governance

This is not implemented in MVP but the governance structure supports it.

## Root Timelock

The sudo key reaches Root at once only for a short list of safety calls. Every
other Root call is scheduled in `RootTimelock` and waits the delay of its
class, during which the guardian can veto it. A multisig, a utility batch and
an account recovered through `pallet_recovery` all dispatch through the same
call filter, so none of them is a way around the delay.

### Calls the sudo key may dispatch at once

| Call | Why it may skip the delay |
|------|---------------------------|
| `Grandpa.note_stalled` with a delay of at most 30 blocks and at most a twentieth of the session (`slots_per_epoch / 20`) | Finality break-glass. It forces the GRANDPA set the session already selected at the next session boundary; it cannot choose that set. The bound keeps the forced change, and GRANDPA's refusal of another one for twice the delay, inside a tenth of a session, so a stall never blocks the next rotation even with nine tenths of the session's slots empty. Preprod's 600-slot sessions allow 30 blocks, the delay the recovery tooling uses; the 60-slot dev chain allows 3. A longer stall is scheduled. |
| `TeeAttestation.set_disabled(true)` | Kill-switch, stopping direction only. |
| `Billing.governance_set_debits_enabled(false)` | Kill-switch, stopping direction only. |
| `Treasury.remove_approval`, `Treasury.void_spend` | Withdraw a spend before it pays out. |
| `RootTimelock.schedule` | Starts the delay. |
| `RootTimelock.enact_approved` | Runs only the one call the guardian approved, and only a recovery or authority-recovery call, which the guardian could have fast-tracked. |
| `RootTimelock.cancel` of the pending guardian change | Keeps the current guardian in place. After a stolen key is rotated out, the new key withdraws the guardian change the thief scheduled, so it never lands. |
| `RootTimelock.cancel`, `cancel_all` of any task, only while no guardian is set | Without a guardian nothing can veto the sudo key's tasks, so its own veto gives it nothing new; it lets the operators withdraw a task they abandoned. |
| `Utility.batch`, `batch_all`, `force_batch` | Only when every call inside is on this list. |

Anything else wrapped in `Sudo.sudo` fails with `CallFiltered`, as do
`Sudo.sudo_unchecked_weight`, `Sudo.sudo_as`, `Sudo.set_key` and
`Sudo.remove_key`. `sudo_unchecked_weight` is refused even for an exempt
call: it would let the key declare any weight and fill the blocks the
guardian's veto needs.

The last-finalized hint in `note_stalled` is taken on trust: the runtime
cannot see finality. A hint at or above a standard change the client still
has pending makes the client refuse the forced change
(`ForcedAuthoritySetChangeDependencyUnsatisfied`), and a stale one bases the
new set on an old block. The recovery tooling refuses to fire unless the hint
sits at or just below the finalized head.

### Delay classes

| Class | Mainnet | Preprod and dev | Calls |
|-------|---------|-----------------|-------|
| Recovery | 1 day | 30 blocks | Levers that cannot fix who holds authority: `Grandpa.note_stalled` within the exempt bound above, and `OrinqReceipts.clear_pinned_committee`, `set_break_glass_floor_enabled`, `set_core_eviction_enabled`, `set_contribution_window_enabled`, `set_slack_invariant_enabled`, `reset_candidate_liveness`, which change how the committee is drawn from the Cardano-registered candidates. Also `RootTimelock.set_delay` raising a delay or keeping it as it is, which only slows Root down. The guardian may co-sign them. |
| Authority recovery | the standard delay | the standard delay | Levers that can fix who holds authority: `OrinqReceipts.set_pinned_committee` (installed verbatim, bypassing the draw and every floor), `OrinqReceipts.set_break_glass_aura_keys` (decides which draws the floor accepts), `Grandpa.note_stalled` with a longer delay (can freeze rotation), and `Sudo.set_key` (the defence against a stolen key). Also restarting what a kill-switch stopped: `TeeAttestation.set_disabled(false)` and `Billing.governance_set_debits_enabled(true)`. The guardian may co-sign them; without its co-sign the sudo key alone installs authors or a new key, or restarts a service, no sooner than it could mint. |
| Standard | 7 days | 300 blocks | Everything not listed elsewhere, including `System.set_code`, `System.authorize_upgrade`, `System.set_storage`, the `Balances` force calls, treasury spends, `OrinqReceipts.set_committee` and `join_committee`, the emission setters, `Recovery.set_recovered`, and lowering the standard or recovery delay. |
| Long | 30 days | 1,200 blocks | The dedicated bridge and supply levers (`NativeTokenManagement.set_main_chain_scripts`, lowering `IntentSettlement.set_min_signer_threshold`), `RootTimelock.set_guardian`, lowering the long delay, and `Sudo.remove_key`. |

A wrapper (`Utility.batch`, `batch_all`, `force_batch`, `with_weight`,
`Sudo.sudo`) waits the longest class inside it. A call dispatched under
another origin (`Utility.dispatch_as`, `Sudo.sudo_as`) waits at least the
standard delay. The delays live in storage: genesis sets them, preprod stores
the short ones on the upgrade that adds the pallet, and
`0 < recovery <= standard <= long <= MaxDelay` always holds. Authority
recovery has no delay of its own; it waits the standard one.

### What the long class does and does not bound

The long class is a commitment about the dedicated levers: loosening a bridge
or supply parameter through its own call waits 30 days, in public. It is not
a bound against a stolen sudo key. `System.set_code` can change anything, and
`set_storage`, the `Balances` force calls, `Sudo.sudo_as`, the attestation
committee that deposit attestations count (`OrinqReceipts.set_committee`) and
the emission setters reach the same ends. All of them wait the standard delay.
Against a stolen key the bound is the standard delay and the guardian's veto:
Root, after that delay, is the ultimate override, and it is disclosed as one.

### Flow

1. The multisig dispatches `Sudo.sudo(RootTimelock.schedule(call))`. The
   `Scheduled { id, call_hash, class, ready_at }` event is the public notice;
   publish the call itself alongside it.
2. Until the call is enacted the guardian may `RootTimelock.cancel(id)`, or
   `cancel_all` to veto every pending task in one call. The one exception is
   a task whose call is `RootTimelock.set_guardian` itself, which the guardian
   cannot veto; the sudo key may withdraw it instead. `set_guardian` is
   therefore scheduled on its own: `schedule` refuses a wrapper that carries
   it, so a batch can neither hand the guardian a veto over its replacement
   nor carry other calls past the veto.
3. From `ready_at`, and for `EnactmentWindow` (7 days) after it, any signed
   account may submit `RootTimelock.enact(id, call)`. The call must hash to
   the scheduled hash and must not now classify into a longer class than the
   one it waited. If the call fails the task stays, so it can be retried.
4. At most 64 vetoable tasks are stored at once, expired ones included, and
   at most one guardian change beside them. Once either is full `schedule`
   fails with `TooManyTasks`, so no burst of scheduling can outrun the
   guardian's `cancel_all`. Anyone may `prune(id)` a task whose enactment
   window has closed.

A recovery or authority-recovery call that the guardian has approved is not
scheduled at all: `Sudo.sudo(RootTimelock.enact_approved(call))` runs it at
once and takes no place in the queue, so a full queue cannot hold off a
co-signed key rotation.

Because anyone may enact a ready task, and at a time of their choosing, calls
whose order matters go into one `Utility.batch_all` task, never into separate
tasks.

### Runtime upgrades

1. Schedule `System.authorize_upgrade(code_hash)` and publish the WASM with
   the recipe that reproduces its hash.
2. After the standard delay, `enact` the task.
3. Submit `System.apply_authorized_upgrade(code)` as an unsigned transaction.

`System.set_code` can also be scheduled directly, but then the whole WASM is
carried twice, once in `schedule` and once in `enact`.

Ceremony tooling has to check event results, because inclusion proves
nothing. Through
`Multisig.as_multi` a filtered or failed call still lands in a block; the
failure shows only in the `MultisigExecuted` and `Sudid` results. Each leg
asserts `Sudid(Ok)` and the `Scheduled` event, and later the `Enacted` event
for its task id.

### The guardian

The guardian is one signed account, normally a multisig held apart from the
sudo custody, stored in `RootTimelock.Guardian`. It can veto (`cancel`,
`cancel_all`) and co-sign a recovery or authority-recovery call in one of two
ways. `fast_track(id)` makes a pending task ready at once. `approve(call_hash)`
lets Root run that one call at once through `enact_approved`, without
scheduling it. An approval is used once, lasts `EnactmentWindow` (7 days), is
replaced by the next one and ends when the guardian changes; `approve(None)`
withdraws it. A fast-track only brings a task forward: it cannot extend a
ready task's enactment window or revive an expired one. The guardian cannot
schedule, bring forward or approve anything outside those two classes, or
veto its own replacement.

The guardian's calls are Operational, so a block full of Normal extrinsics
cannot keep out a single-key guardian. A multisig guardian submits them
through `Multisig.as_multi`, which is Normal, so its calls compete for
inclusion with whatever fills the Normal space of the block.

Root cannot cancel a vetoable task while a guardian is set: a compromised
sudo key would otherwise veto every attempt to replace it. It may withdraw
the one pending guardian change, which leaves the current guardian in place.
While no guardian is set the sudo key may cancel any task, since nothing else
can. On a chain that gains this pallet by upgrade, as preprod does, the first
task after the upgrade should be the `set_guardian` that appoints one; until
it lands (the long delay) the timelock gives notice but no independent veto.

A new chain sets the guardian at genesis. The runtime's
`GenesisBuilder::build_state`, which turns a chain spec's genesis config into
storage (and so builds every raw spec generated from one), refuses a genesis
whose `rootTimelock.guardian` is missing unless it also sets
`rootTimelock.unguarded: true`. It refuses a guardian equal to the sudo key,
and a guardian that is a well-known sr25519 development account (`//Alice` to
`//Ferdie`, their `//stash` accounts, `//One`, `//Two`) unless the sudo key is
one too, as on a development chain. Only a test network sets `unguarded` (the
preprod spec and the benchmarking preset do). A raw spec written by hand never
passes through `build_state`; the mainnet launch preflight has to apply the
same checks to it.

A compromised guardian can veto every task except its own replacement, which
waits the long delay: up to 30 days in which nothing but the exempt calls
runs, security upgrades included. The only faster route is off-chain: a
runtime override (`--wasm-runtime-overrides`) that every validator runs.

### A stolen sudo key

The threat the guardian is for: someone copies the sudo key while the
operators still hold it and the guardian stays honest. The operators' answer,
in the block after the thief acts:

1. The guardian, in one `Utility.batch_all`, calls `cancel_all`, which vetoes
   every task the thief scheduled except a guardian change, and `approve`s
   the hash of `Sudo.set_key(new key)`.
2. The operators dispatch
   `Sudo.sudo(RootTimelock.enact_approved(Sudo.set_key(new key)))`. It takes
   no place in the queue, so no refill of the queue can hold the rotation
   off. A thief that runs the approved call first only does what the
   operators asked.
3. Once the rotation has landed, the guardian calls `cancel_all` again. It
   vetoes whatever the thief scheduled between step 1 and the rotation.
4. The new key withdraws the thief's pending guardian change with an exempt
   `Sudo.sudo(RootTimelock.cancel(id))`.
5. If the thief stopped TEE attestation or billing debits, the guardian
   approves `Utility.batch_all([TeeAttestation.set_disabled(false),
   Billing.governance_set_debits_enabled(true)])` and the new key runs it
   with `enact_approved`.

Nothing the thief scheduled then takes effect, the thief never holds the
guardian seat, the delays are as they were, and the stopped services run
again the same day. A property test runs this answer with randomly generated
stolen-key extrinsics before each of its steps (floods of tasks and guardian
changes, delay raises, stalls, kill-switches, withdrawals, running the
approved rotation itself), and another test runs it through a 2-of-3
`Multisig.as_multi`.

What remains:

- The thief can halt finality until the rotation and one session beyond it.
  The last-finalized hint in an exempt `Grandpa.note_stalled` is taken on
  trust, and a stale hint can freeze the GRANDPA voters until a corrective
  stall lands at a later session boundary. A `Grandpa.Stalled` set outside a
  ceremony should raise an alert.
- The thief can withdraw approved treasury spends (`remove_approval`,
  `void_spend`); approving them again waits the standard delay.
- The thief can withdraw a guardian change the operators scheduled;
  scheduling it again restarts its long delay.
- The thief pays MOTRA for its extrinsics like anyone else, but while it
  keeps paying to fill the Normal space of every block, a multisig
  guardian's `as_multi` and the operators' `Sudo.sudo` compete with it for
  inclusion. A single-key guardian's calls are Operational and do not.
- On a chain with no guardian, the thief and the operators can each cancel
  the other's tasks, so neither side's change lands. That is why only a test
  network may start unguarded.

### Changing a delay

`RootTimelock.set_delay(class, blocks)` is always scheduled. Raising a delay,
or keeping it as it is, waits the recovery delay, and the guardian may
co-sign it. Lowering one waits the class's current delay; lowering the
recovery delay waits the standard delay, so the guardian cannot bring it
forward. A raise that has become a lowering by the time it is enacted fails
with `ClassRaised`. Tasks already scheduled keep the `ready_at` they were
given, and no delay exceeds `MaxDelay` (90 days).

A raise is not exempt. An immediate raise would let a stolen key raise every
delay to `MaxDelay` in one extrinsic before it is rotated out, and every
repair after the rotation (restoring the delays, restarting a stopped
service, a security upgrade) would then wait up to 90 days, with no
co-signature able to bring it forward.

A scheduled raise that nobody vetoes lands after the recovery delay, so the
guardian has that long (one day on mainnet) to veto it, as it has for every
recovery-class task. After a raise to `MaxDelay` lands, every standard
change, a security upgrade included, waits up to 90 days, and lowering the
delay back waits as long. Only recovery and authority-recovery calls still
run at once, with the guardian's co-sign.

### Treasury

`MaxSpend` bounds the treasury spends Root approves in one extrinsic to
15,000 MATRA. pallet-treasury counts every spend inside one dispatch against
that cap, so a batch of smaller spends in one enactment is bounded too.
Moving more takes several scheduled tasks, each public for the whole delay
and each vetoable on its own. The `Balances` force calls can still move
treasury funds, after the standard delay.

## Security Considerations

1. **Genesis UTXO is irreversible** -- test on preprod first
2. **Governance keys are critical** -- use HSM or multisig in production
3. **Root is delayed, not bounded** -- after its delay a scheduled `set_code` can change anything; the guardian's veto and public review of every `Scheduled` event are what stand in front of it
4. **D-parameter changes are epoch-delayed** -- plan ahead
5. **DB Sync must be at tip** -- stale sync causes consensus failures
