# materios-verify

End-to-end checkpoint verifier for the Materios Partner Chain. Proves a receipt was:
1. Submitted and stored on-chain
2. Certified by the attestation committee (2-of-2 threshold)
3. Bound to a context-specific checkpoint leaf
4. Included in a Merkle tree anchored on-chain
5. Corroborated by an AvailabilityCertified event

## Install

```bash
pip install .
# or with pipx for isolated install:
pipx install .
```

## Quick Start

```bash
# Verify a receipt (requires RPC access to a Materios node)
materios-verify 0x0acf71bf7751b1172e6a73b70df1fd8ff5630a6d27ee4abcd517690d91e1f0a4

# Custom RPC endpoint
materios-verify 0x0acf71bf... --rpc-url wss://materios.fluxpointstudios.com/rpc

# JSON output (for scripting)
materios-verify 0x0acf71bf... --json

# Verbose mode (show all hash fields)
materios-verify 0x0acf71bf... --verbose

# Wider scan window for older receipts
materios-verify 0x0acf71bf... --scan-window 5000
```

## Programmatic Usage

```python
from materios_verify.core import verify_receipt, VerificationResult

report = verify_receipt(
    receipt_id="0x0acf71bf7751b1172e6a73b70df1fd8ff5630a6d27ee4abcd517690d91e1f0a4",
    rpc_url="ws://127.0.0.1:9944",
)

if report.result == VerificationResult.FULLY_VERIFIED:
    print("Receipt fully verified!")
    print(f"Cert hash: {report.cert_hash}")
    print(f"Anchor block: #{report.anchor['block_num']}")

# Get structured JSON
print(report.to_dict())
```

## Verification Steps

| Step | What it checks |
|------|----------------|
| 0 | Connect to Materios chain, detect genesis hash |
| 1 | Query receipt from on-chain storage |
| 2 | Check availability certificate (cert_hash != zero) |
| 3 | Compute checkpoint leaf: `SHA256("materios-checkpoint-v1" \|\| chain_id \|\| receipt_id \|\| cert_hash)` |
| 4 | Search for checkpoint anchor in recent blocks |
| 5 | Verify Merkle inclusion (single-leaf exact match or multi-leaf proof) |
| 6 | Verify manifest hash integrity |
| 7 | Locate and cross-check AvailabilityCertified event |

## Verification Results

- **FULLY_VERIFIED** — All 7 steps pass. Full chain of custody proven.
- **PARTIALLY_VERIFIED** — Receipt and cert valid, but checkpoint not yet flushed to anchor.
- **NOT_VERIFIED** — Receipt not found or cert not issued.

## Sample Receipts

See `examples/sample-receipts.json` for receipt IDs from the staging testnet.

## Web Explorer

A visual explorer is available at `tools/explorer/`:

```bash
cd tools/explorer
pip install -r requirements.txt
python app.py --port 8080
# Open http://localhost:8080
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MATERIOS_RPC_URL` | `ws://127.0.0.1:9944` | Chain RPC endpoint |
| `CHAIN_ID` | auto-detected | Override genesis hash |
