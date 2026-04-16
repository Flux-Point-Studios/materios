//! Integration test suite for IOG Partner Chains v1.5.1 pallet integration.
//!
//! These tests verify that the six IOG pallets are correctly wired into the
//! Materios runtime alongside the existing Motra and OrinqReceipts pallets.
//!
//! TDD approach: these tests are written *before* the pallets are added to
//! `construct_runtime!`, so they will fail to compile until the integration
//! work is done.

mod spo_integration_tests;
