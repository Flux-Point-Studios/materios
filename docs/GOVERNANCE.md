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
| `Grandpa.note_stalled` with a delay of at most 100 blocks | Finality break-glass. It forces the GRANDPA set the session already selected at the next session boundary; it cannot choose that set. In a session of at least 200 blocks the bound keeps the forced change, and GRANDPA's refusal of another one for twice the delay, inside one session, so a stall never blocks the next rotation. Preprod sessions are 600 slots; the 60-slot dev chain does not meet this. A longer stall is scheduled. |
| `TeeAttestation.set_disabled(true)` | Kill-switch, stopping direction only. |
| `Billing.governance_set_debits_enabled(false)` | Kill-switch, stopping direction only. |
| `Treasury.remove_approval`, `Treasury.void_spend` | Withdraw a spend before it pays out. |
| `RootTimelock.schedule` | Starts the delay. |
| `RootTimelock.set_delay` raising a delay | Only slows Root down, and never past `MaxDelay` (90 days). |
| `RootTimelock.cancel`, `cancel_all`, only while no guardian is set | Without a guardian nothing can veto the sudo key's tasks, so its own veto gives it nothing new; it lets the operators withdraw a task they abandoned. |
| `Utility.batch`, `batch_all`, `force_batch` | Only when every call inside is on this list. |

Anything else wrapped in `Sudo.sudo` fails with `CallFiltered`, as do
`Sudo.sudo_as`, `Sudo.set_key` and `Sudo.remove_key`.

The last-finalized hint in `note_stalled` is taken on trust: the runtime
cannot see finality. A hint at or above a standard change the client still
has pending makes the client refuse the forced change
(`ForcedAuthoritySetChangeDependencyUnsatisfied`), and a stale one bases the
new set on an old block. The recovery tooling refuses to fire unless the hint
sits at or just below the finalized head.

### Delay classes

| Class | Mainnet | Preprod and dev | Calls |
|-------|---------|-----------------|-------|
| Recovery | 1 day | 30 blocks | Levers that cannot fix who holds authority: `Grandpa.note_stalled` with a delay of at most 100 blocks, and `OrinqReceipts.clear_pinned_committee`, `set_break_glass_floor_enabled`, `set_core_eviction_enabled`, `set_contribution_window_enabled`, `set_slack_invariant_enabled`, `reset_candidate_liveness`. They change how the committee is drawn from the Cardano-registered candidates. The guardian may fast-track them. |
| Authority recovery | the standard delay | the standard delay | Levers that can fix who holds authority: `OrinqReceipts.set_pinned_committee` (installed verbatim, bypassing the draw and every floor), `OrinqReceipts.set_break_glass_aura_keys` (decides which draws the floor accepts), and `Grandpa.note_stalled` with a longer delay (can freeze rotation). The guardian may fast-track them, which is its co-signature; without it the sudo key alone installs authors no sooner than it could mint. |
| Standard | 7 days | 300 blocks | Everything not listed elsewhere, including `System.set_code`, `System.authorize_upgrade`, `System.set_storage`, the `Balances` force calls, treasury spends, `OrinqReceipts.set_committee` and `join_committee`, the emission setters, `Sudo.set_key`, `Recovery.set_recovered`, and lowering the standard or recovery delay. |
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
   cannot veto. `set_guardian` is therefore scheduled on its own: `schedule`
   refuses a wrapper that carries it, so a batch can neither hand the
   guardian a veto over its replacement nor carry other calls past the veto.
3. From `ready_at`, and for `EnactmentWindow` (7 days) after it, any signed
   account may submit `RootTimelock.enact(id, call)`. The call must hash to
   the scheduled hash and must not now classify into a longer class than the
   one it waited. If the call fails the task stays, so it can be retried.
4. At most 64 tasks are stored at once, expired ones included, so no burst of
   scheduling can outrun the guardian: once the queue is full `schedule`
   fails with `TooManyTasks`. Anyone may `prune(id)` a task whose enactment
   window has closed.

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
`cancel_all`) and co-sign a recovery or authority-recovery call
(`fast_track`, which makes a pending task ready at once). A fast-track only
brings a task forward: it cannot extend a ready task's enactment window or
revive an expired one. The guardian cannot schedule, enact early anything
outside those two classes, or veto its own replacement.

Root cannot cancel while a guardian is set: a compromised sudo key would
otherwise veto every attempt to replace it. While no guardian is set the sudo
key may cancel, since nothing else can. On a chain that gains this pallet by
upgrade, as preprod does, the first task after the upgrade should be the
`set_guardian` that appoints one; until it lands (the long delay) the
timelock gives notice but no independent veto. Mainnet sets the guardian at
genesis.

A compromised guardian can veto every task except its own replacement, which
waits the long delay: up to 30 days in which nothing but the exempt calls
runs, security upgrades included. The only faster route is off-chain: a
runtime override (`--wasm-runtime-overrides`) that every validator runs.

### Changing a delay

`RootTimelock.set_delay(class, blocks)` takes effect at once when it raises a
delay. Lowering one has to be scheduled, and waits the class's current delay;
lowering the recovery delay waits the standard delay, so the guardian cannot
fast-track it. Tasks already scheduled keep the `ready_at` they were given.

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
