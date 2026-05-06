# Materios External Operator Kit

The cert-daemon and operator tooling are maintained in their own repository:

> **[github.com/Flux-Point-Studios/materios-operator-kit](https://github.com/Flux-Point-Studios/materios-operator-kit)**

## Recommended path: bootstrap script

For nearly every operator, the single-shot installer is the right entry point:

```bash
curl -fsSL https://materios.fluxpointstudios.com/releases/bootstrap-validator.sh | bash
```

The script provisions a validator + cert-daemon, registers heartbeat publishing, and prints the SS58 address you'll send to the FPS team for committee onboarding.

## Manual path

If you'd rather assemble the pieces yourself, follow the README in the operator-kit repo. It covers:

- generating a committee key,
- registering with the FPS team (SS58 address + label),
- configuring `docker-compose.external.yml` (mnemonic + API keys),
- starting the daemon and verifying via the explorer + local `/health`/`/status` endpoints,
- (optional) running an independent watchtower against the public `/heartbeats/status` endpoint.

## Architecture

```
Your Machine                          FPS Infrastructure
+--------------+                      +----------------------+
| cert-daemon  |--WSS(/rpc)---------->| Materios RPC Node    |
|              |--HTTPS(/blobs)------>| Blob Gateway         |
|              |  (heartbeats +       |  (heartbeat store +  |
|              |   blob verification) |   blob storage)      |
+--------------+                      +----------------------+
```

- **RPC**: `wss://materios.fluxpointstudios.com/rpc` — read chain state, submit attestation transactions
- **Blob Gateway**: `https://materios.fluxpointstudios.com/blobs` — fetch blob data for verification, send heartbeats
- **Heartbeats**: signed with your sr25519 committee key — independently verifiable by anyone

## Security model

- Your **mnemonic** never leaves your machine
- **API keys** are for rate limiting only — not authentication
- **Heartbeat signatures** prove liveness without trusting FPS infrastructure
- **Attestation transactions** are on-chain — anyone can verify committee activity

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Heartbeat not appearing | API key invalid | Verify API key with FPS team |
| `substrate_connected: false` | RPC unreachable | Check WSS connectivity to `materios.fluxpointstudios.com` |
| High finality gap (>10) | Chain stalled | Check if block production is healthy on the explorer |
| Cert not submitted | Account not funded | Ask FPS team to verify MATRA balance |
