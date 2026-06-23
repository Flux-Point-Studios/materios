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

This is almost always the **FPS-side justification-pruning ban-loop**: when your node asks an FPS node for a block range whose per-block GRANDPA justification has been pruned, the FPS node returns nothing, and substrate's sync layer scores the retry as a duplicate request and bans the peer for ~69s — so you cycle between `Idle (0 peers)` and brief `1 peer` windows and never finalize past a floor. Your **state is fine** (snapshot integrity is independent of this).

**Fastest fix — restore the current snapshot to jump to tip.** Re-run `bootstrap-validator.sh`: it restores the current-room snapshot (sha256-verified) and sets the correct bootnode, landing you at the chain tip *past* the pruned heights. After that you only track fresh blocks, whose justifications are not yet pruned, so the loop never recurs:
```bash
curl -fsSL https://materios.fluxpointstudios.com/releases/bootstrap-validator.sh | sudo bash -s -- \
  --db-sync 'postgres://…' --aura-pubkey 0x… --grandpa-pubkey 0x… --operator-label <you>
```
(FPS are also deploying a justification-retaining public sync node so a from-behind sync works without this step.) The diagnostics below help if you want to confirm the cause rather than skip past it.

**Diagnostic 1 — confirm canonical state match.** From a healthy reference (e.g. ask FPS for the canonical hash at your `best` block), then on your node:
```bash
curl -s -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"chain_getBlockHash","params":[<your-best-block-number>],"id":1}' \
  http://127.0.0.1:9944
```
If your hash matches canonical, the snapshot is fine and the issue is sync-protocol (proceed to D2). If it differs, your snapshot is from a forked chain — request a fresh one.

**Diagnostic 2 — isolate sync to a single trusted peer.** Stop the node, edit `/etc/systemd/system/materios-node-spo.service` (the `ExecStart` line), and add:
```
--reserved-nodes /dns4/bootnode.materios.fluxpointstudios.com/tcp/30333/p2p/12D3KooWPueKoxRAirTTKH4Y2qQAsJDegWMjS4k89Z7izCbZKgkM \
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

### Fast-sync your cardano-node with Mithril (days → minutes)

cardano-db-sync indexes a **cardano-node**, and a from-genesis cardano-node sync takes days. Mithril (Cardano's stake-certified snapshot system) restores a verified node DB at tip in ~10–20 min. cardano-node 11.0.1 loads the restored ledger snapshot natively — no `snapshot-converter` step. Do this BEFORE starting db-sync:

```bash
# Preprod Mithril config
export AGGREGATOR_ENDPOINT="https://aggregator.release-preprod.api.mithril.network/aggregator"
export GENESIS_VERIFICATION_KEY=$(curl -fsSL https://raw.githubusercontent.com/input-output-hk/mithril/main/mithril-infra/configuration/release-preprod/genesis.vkey)
export ANCILLARY_VERIFICATION_KEY=$(curl -fsSL https://raw.githubusercontent.com/input-output-hk/mithril/main/mithril-infra/configuration/release-preprod/ancillary.vkey)

# Download + verify the latest certified Cardano DB (v2 backend is the default since 2025-11).
# --include-ancillary pulls the IOG-signed last ledger snapshot + last immutable chunk,
# so node 11.0.1 starts at tip in minutes instead of recomputing ledger state from genesis.
mithril-client cardano-db download latest --include-ancillary --download-dir "$CARDANO_DB_DIR"
```
Then start cardano-node 11.0.1 against `$CARDANO_DB_DIR` and let db-sync index forward. Notes: pin `mithril-client` to a current stable tag (0.13.x); the v1 backend was removed in distribution 2617.0 (don't pass `--backend v1`). **This restores the cardano-node ledger only — it does NOT populate the db-sync Postgres**, which still indexes forward from the restored tip (so the index/tuning steps below still apply).

### Postgres prerequisites for cardano-db-sync

Partner-chains queries hit cardano-db-sync's postgres on every block import. Two things matter beyond a stock db-sync install.

**1. The `idx_ma_tx_out_ident` index.** Partner-chains lazy-creates this on first start, but the build takes 2-5 min on a freshly-restored db-sync. If your node restarts inside that window, the index never finishes and every subsequent block import takes 2.5s+ → sync-layer timeout → peer drop. `bootstrap-validator.sh` now creates the index ahead of time. If you're upgrading an older install or hit this on a fresh restore:
```bash
sudo systemctl stop materios-node-spo.service
psql "$DB_SYNC_CONNECTION_STRING" -c \
  "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ma_tx_out_ident ON ma_tx_out(ident);"
sudo systemctl start materios-node-spo.service
```
Confirm with `\di+ idx_ma_tx_out_ident` in psql — size should be >100 MB on preprod-current data.

**2. Postgres tuning for a 4 vCPU / 8 GB / NVMe baseline.** Defaults assume a much smaller workload than db-sync runs. Append to `/etc/postgresql/15/main/postgresql.conf` (adjust path for your version):
```
shared_buffers = 2GB
effective_cache_size = 6GB
work_mem = 64MB
maintenance_work_mem = 1GB
random_page_cost = 1.1
effective_io_concurrency = 200
```
Then `sudo systemctl restart postgresql && psql "$DB_SYNC_CONNECTION_STRING" -c "ANALYZE;"`. Scale up proportionally for larger hosts.

If you see `sqlx::query: slow statement ... elapsed=2.5s` warnings in your node log AND repeated peer disconnects, this section is the fix.
