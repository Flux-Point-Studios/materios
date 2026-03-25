# Midnight Proof Demo -- Risk Score Threshold

## What This Proves

**Statement**: "The risk score for receipt R, computed under monitor config C, is at least T."

**What's public** (visible on-chain):
- Receipt ID
- Threshold value T
- Boolean result (pass/fail)
- Verifiable ZK proof

**What's private** (never revealed):
- Actual risk score value
- Raw AI trace data
- Monitor configuration details

## Why This Matters

Gaming operators and AI auditors need to prove compliance without exposing proprietary data:

1. **Gaming**: "This game session's risk assessment passed the regulator's threshold"
   - Without revealing: player behavior patterns, fraud detection algorithms, scoring details

2. **AI Audit**: "This AI model's safety evaluation met the required standard"
   - Without revealing: actual prompts/responses, safety check internals, proprietary evaluation criteria

## Demo Flow

### Prerequisites
- Receipt committed on Midnight (via `submitCommitment`)
- Proof server running (`docker compose up` in midnight/)

### Step 1: Commit Receipt
```bash
# Submit receipt roots to Midnight
pnpm submit-commitment out/receipt.json
```

### Step 2: Generate ZK Proof
```bash
# Prove risk_score >= 75, where actual score is 92
# The "92" is PRIVATE -- it's a witness input that never appears on-chain
pnpm prove-risk \
  0xaabb...ccdd \  # receipt ID
  75 \             # threshold (public)
  92 \             # actual score (PRIVATE)
  0xeeff...1122    # config hash (must match commitment)
```

### Step 3: Verify Claim
```bash
# Anyone can check that a verified proof exists
pnpm query 0xaabb...ccdd
# Output: risk_proof: true (the proof was verified)
```

## Circuit Logic

```
proveRiskThreshold(receiptId, threshold):
  1. Assert commitment exists for receiptId
  2. Get committed config_hash from ledger
  3. Get private score from witness (NEVER on-chain)
  4. Get private config from witness (NEVER on-chain)
  5. Assert private config == committed config  <- integrity check
  6. Assert private score >= threshold           <- THE CLAIM
  7. Store proof result on ledger               <- public Boolean
```

## Fee Considerations

- Midnight uses DUST tokens (wrapped NIGHT) for transaction fees
- Proof generation has computational cost (measured in proof server time)
- ledger-7.0.0 pricing overhaul affects fee estimation
- Budget ~1-5 DUST per proof transaction (subject to network conditions)

## Limitations (MVP)

1. **No recursive proofs**: Each receipt needs its own proof transaction
2. **Witness trust model**: The prover must have access to the actual data
3. **Config verification is hash-based**: We verify the config hash matches, but don't verify the config itself was applied correctly (that would require a more complex circuit)
4. **Single threshold per receipt**: MVP stores one proof per receipt ID; multiple threshold proofs for the same receipt would need a different key scheme

## Next Steps

1. **Batch proofs**: Prove multiple receipts in one transaction
2. **Recursive composition**: Prove statements about aggregates of receipts
3. **Config execution proof**: Prove the config was actually applied (not just hash-matched)
4. **Cross-chain verification**: Verify Midnight proof on the partner chain
