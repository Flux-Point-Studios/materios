//! Reconstruction round-trip for the emergency pinned committee (#491).
//!
//! `select_authorities` installs a pinned committee by rebuilding each member's
//! `(CrossChainPublic, SessionKeys)` tuple from raw stored keys. If that rebuild
//! did not preserve the exact key bytes the operator pinned, the session pallet
//! would map validators to keys no node holds — a self-inflicted production halt,
//! the very failure the pin exists to prevent. These tests pin the byte-exact
//! round trip so a future edit to `reconstruct_pinned_member` cannot regress it.

use crate::reconstruct_pinned_member;
use pallet_orinq_receipts::types::PinnedMember;
use parity_scale_codec::Encode;

#[test]
fn reconstruct_pinned_member_round_trips_raw_keys() {
    let m = PinnedMember { cross_chain: [0x11; 33], aura: [0x22; 32], grandpa: [0x33; 32] };
    let (account, keys) = reconstruct_pinned_member(&m);

    // CrossChainPublic (app-crypto ecdsa) encodes as its 33 raw key bytes.
    assert_eq!(account.encode(), m.cross_chain.to_vec());

    // SessionKeys encodes as its fields in declaration order: aura(32) then
    // grandpa(32), each as raw key bytes.
    let mut expected = m.aura.to_vec();
    expected.extend_from_slice(&m.grandpa);
    assert_eq!(keys.encode(), expected);
}

#[test]
fn reconstruct_pinned_member_distinct_keys_stay_distinct() {
    let (acc_a, keys_a) =
        reconstruct_pinned_member(&PinnedMember { cross_chain: [1; 33], aura: [2; 32], grandpa: [3; 32] });
    let (acc_b, keys_b) =
        reconstruct_pinned_member(&PinnedMember { cross_chain: [9; 33], aura: [8; 32], grandpa: [7; 32] });
    assert_ne!(acc_a.encode(), acc_b.encode());
    assert_ne!(keys_a.encode(), keys_b.encode());
}
