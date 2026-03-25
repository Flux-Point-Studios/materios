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

## Security Considerations

1. **Genesis UTXO is irreversible** -- test on preprod first
2. **Governance keys are critical** -- use HSM or multisig in production
3. **D-parameter changes are epoch-delayed** -- plan ahead
4. **DB Sync must be at tip** -- stale sync causes consensus failures
