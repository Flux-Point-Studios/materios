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
mod fee_router;
mod vesting_schedule;
