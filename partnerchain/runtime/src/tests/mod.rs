//! Integration tests for the Materios runtime.

use crate::{opaque::SessionKeys, CrossChainPublic};
use sp_core::{ecdsa, ed25519, sr25519, Pair};

mod spo_integration_tests;
mod treasury_integration;
mod vesting_schedule;
mod motra_only_fees;
mod treasury_drip_migration;
mod tee_attestation_integration;
mod pinned_committee;
mod recovery_second_root;
mod perp_engine_removal;
mod root_timelock;
mod committee_inherent;

/// A committee member: its cross-chain key and its session keys.
type Authority = (CrossChainPublic, SessionKeys);

/// The authority whose keys all derive from `//{seed}`.
fn authority(seed: &str) -> Authority {
    let uri = format!("//{seed}");
    let cross_chain = ecdsa::Pair::from_string(&uri, None).unwrap().public();
    let aura = sr25519::Pair::from_string(&uri, None).unwrap().public();
    let grandpa = ed25519::Pair::from_string(&uri, None).unwrap().public();
    (cross_chain.into(), (aura, grandpa).into())
}
