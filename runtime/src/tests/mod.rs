//! Integration test suite for Materios runtime.
//!
//! Verifies the integration of IOG Partner Chains v1.5.1 pallets, and the
//! v5.1 tokenomics foundation (treasury + fee router + vesting).
//!
//! TDD approach: tests are written *before* the pallets are added to
//! `construct_runtime!`, so they will fail to compile until the integration
//! work is done.

mod spo_integration_tests;

// v5.1 tokenomics foundation
mod treasury_integration;
// `fee_router` tests deleted at spec 202 alongside the fee-router itself —
// MATRA is no longer charged on transactions. See `motra_only_fees` below.
mod vesting_schedule;

// Midnight-style fees (2026-04-21): MATRA no longer charged, MOTRA only.
mod motra_only_fees;
mod treasury_drip_migration;

// Track A throughput tuning (2026-04-26): BlockWeights ref_time/proof_size bump.
mod block_weights_throughput;

// Spec 205 consolidated upgrade (2026-04-26): IntentSettlement default-
// signer-threshold bump 1 → 2 to match Aegis 2-of-4 expectation.
mod intent_settlement_threshold;

// Spec 208 / Track-B B3 (2026-04-27): MaxXBatch widening 256 → 1024 with
// per-call worst-case weight assertions against the live class budgets.
mod intent_settlement_max_batch;
