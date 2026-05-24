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

### Sync stuck at snapshot floor / peer-ban loop

Symptom: your node restored a snapshot, sees `target=#N` (the real chain tip), but stays at `best=#snapshot_floor` indefinitely. Logs show repeating lines like:
```
Report 12D3KooW...: -2147483648 to -2147483648. Reason: Same block request multiple times. Banned, disconnecting.
```
and `Idle (0 peers)` between bans.

This means your node is rejecting every peer that tries to send it new blocks. Your **state is fine** (snapshot integrity is independent of this); the issue is in the sync-protocol handshake.

**Diagnostic 1 — confirm canonical state match.** From a healthy reference (e.g. ask FPS for the canonical hash at your `best` block), then on your node:
```bash
curl -s -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"chain_getBlockHash","params":[<your-best-block-number>],"id":1}' \
  http://127.0.0.1:9944
```
If your hash matches canonical, the snapshot is fine and the issue is sync-protocol (proceed to D2). If it differs, your snapshot is from a forked chain — request a fresh one.

**Diagnostic 2 — isolate sync to a single trusted peer.** Stop the node, edit `/etc/systemd/system/materios-node-spo.service` (the `ExecStart` line), and add:
```
--reserved-nodes /ip4/166.70.250.197/tcp/30333/p2p/12D3KooWPueKoxRAirTTKH4Y2qQAsJDegWMjS4k89Z7izCbZKgkM \
--reserved-only \
--in-peers 50 --out-peers 25
```
Then `systemctl daemon-reload && systemctl restart materios-node-spo.service`.

This forces your node to peer ONLY with the FPS Gemtek validator (bypasses libp2p DHT discovery) and increases peer-slot capacity. If sync progresses past the floor with `--reserved-only`, the bad peer was somewhere in the network and DHT discovery was finding it. Once you're caught up to tip, drop `--reserved-only` so you can serve other peers.

**Diagnostic 3 — verbose sync logs.** Add to the same `ExecStart`:
```
&& RUST_LOG=sync=debug,sub-libp2p=info exec /usr/local/bin/materios-node-spo ...
```
(prepend `RUST_LOG=...` before the `exec` line in the bash invocation). Tail `node-spo.log` and look at the lines just before a "Banned" event. The debug logs will show the exact BlockRequest IDs and timing — if the same request_id arrives twice from the same peer in <1s, you'll see it.

**Common root causes:**

- **Stale libp2p peer in the DHT.** A node that's no longer running but is still advertised. `--reserved-only` is the immediate workaround.
- **Slow inherent-data verification.** If your `cardano-db-sync` postgres is on a slow disk, partner-chain inherent-data lookups during block import can take 1-4s. Peers retry, and your sync layer flags the retry as duplicate. Move postgres to a faster disk (NVMe), or increase postgres's `shared_buffers` and `work_mem`.
- **Binary version skew.** Your `materios-node` binary may be older than the network's current version. Re-run `bootstrap-validator.sh` to pull the latest binary from `/releases/`.

If none of these help, capture the verbose log around 5 ban events and share with FPS.
