# Materios External Operator Kit

Run your own cert-daemon to participate in the Materios attestation committee — no VPN, Tailscale, or cluster access needed.

## Prerequisites

- Docker (or Podman) with compose
- 1 vCPU, 512 MB RAM, 1 GB disk
- Public internet access (HTTPS + WSS)

## Quick Start

### Step 1: Generate Your Committee Key

```bash
pip install substrate-interface mnemonic
python cert-daemon/scripts/generate_committee_key.py
```

This outputs:
- **Mnemonic** (24 words) — save securely, never share
- **SS58 Address** — your public identity

### Step 2: Register with FPS

Send the following to the FPS team:
- Your SS58 address
- Your preferred label (e.g., "MyOrg-Validator")

You will receive:
- An API key for the blob gateway
- Confirmation that your address was added to the committee
- Confirmation that your account was funded with MATRA

### Step 3: Configure the Daemon

```bash
cp cert-daemon/docker-compose.external.yml docker-compose.yml
```

Edit `docker-compose.yml` and fill in:
- `SIGNER_URI`: Your 24-word mnemonic
- `BLOB_GATEWAY_API_KEY`: API key from FPS team
- `LOCATOR_REGISTRY_API_KEY`: Same API key

### Step 4: Start the Daemon

```bash
docker compose up -d
```

### Step 5: Verify

Check your heartbeat appears on the explorer:
- Visit: https://materios.fluxpointstudios.com/explorer/#/committee
- Your validator should show "Online" with a green badge
- The "Verified" column should show a checkmark (sr25519 signature verified)

Check health locally:
```bash
curl http://localhost:8080/health
curl http://localhost:8080/status
```

### Step 6: (Optional) Run Your Own Watchtower

Monitor committee health independently:

```bash
BLOB_GATEWAY_URL=https://materios.fluxpointstudios.com/blobs \
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_WEBHOOK \
python -m daemon.watchtower
```

The watchtower uses the **public** `/heartbeats/status` endpoint — no API key needed.

## Architecture

```
Your Machine                          FPS Infrastructure
+--------------+                      +----------------------+
| cert-daemon  |--WSS(/rpc)---------->| Materios RPC Node    |
|              |--HTTPS(/blobs)------>| Blob Gateway         |
|              |  (heartbeats +      | (heartbeat store +   |
|              |   blob verification)|  blob storage)       |
+--------------+                      +----------------------+
```

- **RPC**: `wss://materios.fluxpointstudios.com/rpc` — read chain state, submit attestation transactions
- **Blob Gateway**: `https://materios.fluxpointstudios.com/blobs` — fetch blob data for verification, send heartbeats
- **Heartbeats**: Signed with your sr25519 committee key — independently verifiable by anyone

## Security Model

- Your **mnemonic** never leaves your machine
- **API keys** are for rate limiting only — not authentication
- **Heartbeat signatures** prove liveness without trusting FPS infrastructure
- **Attestation transactions** are on-chain — anyone can verify committee activity

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Heartbeat not appearing | API key invalid | Verify API key with FPS team |
| "substrate_connected: false" | RPC unreachable | Check WSS connectivity to materios.fluxpointstudios.com |
| High finality gap (>10) | Chain stalled | Check if block production is healthy on explorer |
| Cert not submitted | Account not funded | Ask FPS team to verify MATRA balance |
