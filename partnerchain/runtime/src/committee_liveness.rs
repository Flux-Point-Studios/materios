//! Liveness filtering of trustless (registered) committee candidates.
//!
//! A registered SPO that is selected into the committee but never produces
//! blocks still counts toward GRANDPA's authority set N, inflating the
//! finality quorum above the live-voter count. Two permanently-dead SPO
//! registrations doing exactly this wedged preprod finality for ~6 days
//! (2026-06). This module drops such candidates from selection so a dead
//! registration cannot poison quorum.
//!
//! Pure and storage-blind by design: the per-candidate liveness facts are
//! injected via a `lookup` closure that the runtime backs with
//! `pallet_orinq_receipts` storage (`CandidateFirstSelected` /
//! `LastAuthoredBlock`) and tests back with a map. Only the *registered*
//! candidates are filtered — the permissioned (FPS) backbone is never
//! touched, so a briefly-down trusted node is never evicted.

use authority_selection_inherents::authority_selection_inputs::AuthoritySelectionInputs;
use sidechain_domain::AuraPublicKey;

/// Per-candidate liveness facts, keyed by the candidate's Aura account
/// (the 32-byte Aura public key, which `pallet_orinq_receipts` uses as the
/// block-author `AccountId`). `None` means "no record".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CandidateLiveness {
    /// Block at which this account was first seen in a selected committee.
    /// `None` = never selected, so it has never had a chance to author.
    pub first_selected: Option<u32>,
    /// Block of this account's most recently authored block. `None` = never
    /// authored one.
    pub last_authored: Option<u32>,
}

/// Decide whether a registered candidate is dead and must be dropped.
///
/// - never selected (`first_selected == None`) → keep (no chance to author yet)
/// - selected within the last `grace_blocks` → keep (new-joiner grace)
/// - past grace and never authored → DEAD (the dead-SPO case)
/// - past grace and last authored more than `window_blocks` ago → DEAD
pub fn is_dead(c: &CandidateLiveness, now: u32, grace_blocks: u32, window_blocks: u32) -> bool {
    match c.first_selected {
        None => false,
        Some(first_selected) => {
            if now.saturating_sub(first_selected) <= grace_blocks {
                false
            } else {
                match c.last_authored {
                    None => true,
                    Some(last_authored) => now.saturating_sub(last_authored) > window_blocks,
                }
            }
        }
    }
}

/// The 32-byte liveness account from a SCALE-encoded 32-byte key.
///
/// Mirrors `pallet_orinq_receipts::find_block_author`, which takes the first
/// 32 bytes of the encoded Aura authority key as the `AccountId32`. Both the
/// filter (candidate `aura_pub_key`) and the runtime's first-selected stamp
/// (committee member's `SessionKeys::aura`) route through here so all three
/// touch points key on the identical account. Returns `None` for a malformed
/// (short) key so the caller fails open rather than mis-keying.
pub fn account_bytes_from_encoded(encoded: &[u8]) -> Option<[u8; 32]> {
    if encoded.len() >= 32 {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&encoded[..32]);
        Some(bytes)
    } else {
        None
    }
}

/// Liveness account for a registration's `AuraPublicKey` (raw 32-byte key).
pub fn aura_account_bytes(aura: &AuraPublicKey) -> Option<[u8; 32]> {
    account_bytes_from_encoded(&aura.0)
}

/// Drop dead registered candidates. An outer `CandidateRegistrations` entry
/// is kept if *any* of its registrations maps to a live (or unmappable)
/// Aura account. Returns the filtered inputs and the number of outer
/// entries dropped. Permissioned candidates are left untouched.
pub fn filter_dead_registered<F>(
    mut inputs: AuthoritySelectionInputs,
    now: u32,
    grace_blocks: u32,
    window_blocks: u32,
    mut lookup: F,
) -> (AuthoritySelectionInputs, u32)
where
    F: FnMut([u8; 32]) -> CandidateLiveness,
{
    let mut dropped: u32 = 0;
    inputs.registered_candidates.retain(|outer| {
        let mut any_alive = false;
        for r in outer.registrations.iter() {
            let alive = match aura_account_bytes(&r.aura_pub_key) {
                Some(acct) => !is_dead(&lookup(acct), now, grace_blocks, window_blocks),
                None => true,
            };
            if alive {
                any_alive = true;
                break;
            }
        }
        if !any_alive {
            dropped = dropped.saturating_add(1);
        }
        any_alive
    });
    (inputs, dropped)
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use sidechain_domain::{
        AuraPublicKey, CandidateRegistrations, CrossChainPublicKey, CrossChainSignature,
        DParameter, EpochNonce, GrandpaPublicKey, MainchainPublicKey, MainchainSignature,
        McBlockNumber, McEpochNumber, McSlotNumber, McTxHash, McTxIndexInBlock,
        PermissionedCandidateData, RegistrationData, SidechainPublicKey, SidechainSignature,
        StakeDelegation, UtxoId, UtxoIndex, UtxoInfo,
    };

    const GRACE: u32 = 14_400; // 1 era
    const WINDOW: u32 = 28_800; // 2 eras

    fn live(first_selected: Option<u32>, last_authored: Option<u32>) -> CandidateLiveness {
        CandidateLiveness { first_selected, last_authored }
    }

    // ── is_dead branch coverage ──────────────────────────────────────

    #[test]
    fn never_selected_is_kept() {
        assert!(!is_dead(&live(None, None), 1_000_000, GRACE, WINDOW));
    }

    #[test]
    fn within_grace_is_kept_even_if_never_authored() {
        let now = 1_000_000 + GRACE / 2;
        assert!(!is_dead(&live(Some(1_000_000), None), now, GRACE, WINDOW));
    }

    #[test]
    fn past_grace_never_authored_is_dead() {
        // The TrueAiData / Runir case: selected long ago, zero blocks ever.
        let now = 1_000_000 + GRACE + 1;
        assert!(is_dead(&live(Some(1_000_000), None), now, GRACE, WINDOW));
    }

    #[test]
    fn past_grace_authored_within_window_is_kept() {
        let now = 2_000_000;
        assert!(!is_dead(
            &live(Some(1_000_000), Some(now - (WINDOW - 1))),
            now,
            GRACE,
            WINDOW
        ));
    }

    #[test]
    fn past_grace_authored_beyond_window_is_dead() {
        let now = 2_000_000;
        assert!(is_dead(
            &live(Some(1_000_000), Some(now - (WINDOW + 1))),
            now,
            GRACE,
            WINDOW
        ));
    }

    #[test]
    fn exactly_at_window_boundary_is_kept() {
        let now = 2_000_000;
        assert!(!is_dead(
            &live(Some(1_000_000), Some(now - WINDOW)),
            now,
            GRACE,
            WINDOW
        ));
    }

    #[test]
    fn exactly_at_grace_boundary_is_kept() {
        let now = 1_000_000 + GRACE; // now - first_selected == GRACE, not > grace.
        assert!(!is_dead(&live(Some(1_000_000), None), now, GRACE, WINDOW));
    }

    // ── account_bytes_from_encoded / aura_account_bytes ──────────────

    #[test]
    fn account_bytes_takes_first_32() {
        let mut enc = alloc::vec![9u8; 40];
        enc[32] = 0xff; // a trailing byte must be ignored
        assert_eq!(account_bytes_from_encoded(&enc), Some([9u8; 32]));
    }

    #[test]
    fn maps_full_length_aura_key() {
        let aura = AuraPublicKey(alloc::vec![7u8; 32]);
        assert_eq!(aura_account_bytes(&aura), Some([7u8; 32]));
    }

    #[test]
    fn rejects_short_aura_key() {
        let aura = AuraPublicKey(alloc::vec![7u8; 31]);
        assert_eq!(aura_account_bytes(&aura), None);
    }

    // ── filter_dead_registered ───────────────────────────────────────

    fn reg(aura: u8) -> RegistrationData {
        let u = UtxoId { tx_hash: McTxHash([aura; 32]), index: UtxoIndex(0) };
        RegistrationData {
            registration_utxo: u,
            sidechain_signature: SidechainSignature(alloc::vec![0; 64]),
            mainchain_signature: MainchainSignature(alloc::vec![0; 64]),
            cross_chain_signature: CrossChainSignature(alloc::vec![]),
            sidechain_pub_key: SidechainPublicKey(alloc::vec![aura; 33]),
            cross_chain_pub_key: CrossChainPublicKey(alloc::vec![]),
            utxo_info: UtxoInfo {
                utxo_id: u,
                epoch_number: McEpochNumber(1),
                block_number: McBlockNumber(1),
                slot_number: McSlotNumber(1),
                tx_index_within_block: McTxIndexInBlock(0),
            },
            tx_inputs: alloc::vec![u],
            aura_pub_key: AuraPublicKey(alloc::vec![aura; 32]),
            grandpa_pub_key: GrandpaPublicKey(alloc::vec![aura; 32]),
        }
    }

    fn cand(mc: u8, aura: u8) -> CandidateRegistrations {
        CandidateRegistrations {
            mainchain_pub_key: MainchainPublicKey([mc; 32]),
            registrations: alloc::vec![reg(aura)],
            stake_delegation: Some(StakeDelegation(1_000)),
        }
    }

    fn inputs_with(registered: Vec<CandidateRegistrations>) -> AuthoritySelectionInputs {
        AuthoritySelectionInputs {
            d_parameter: DParameter {
                num_permissioned_candidates: 1,
                num_registered_candidates: registered.len() as u16,
            },
            permissioned_candidates: alloc::vec![PermissionedCandidateData {
                sidechain_public_key: SidechainPublicKey(alloc::vec![1; 33]),
                aura_public_key: AuraPublicKey(alloc::vec![11; 32]),
                grandpa_public_key: GrandpaPublicKey(alloc::vec![21; 32]),
            }],
            registered_candidates: registered,
            epoch_nonce: EpochNonce(alloc::vec![7; 32]),
        }
    }

    #[test]
    fn drops_dead_keeps_live() {
        // aura 0x44 = dead (selected long ago, never authored).
        // aura 0x55 = live (authored recently).
        let now = 2_000_000;
        let inputs = inputs_with(alloc::vec![cand(0x40, 0x44), cand(0x50, 0x55)]);
        let (out, dropped) = filter_dead_registered(inputs, now, GRACE, WINDOW, |acct| {
            if acct == [0x44u8; 32] {
                live(Some(1_000_000), None) // dead
            } else {
                live(Some(1_000_000), Some(now - 10)) // live
            }
        });
        assert_eq!(dropped, 1);
        assert_eq!(out.registered_candidates.len(), 1);
        assert_eq!(out.registered_candidates[0].mainchain_pub_key.0[0], 0x50);
    }

    #[test]
    fn keeps_all_when_all_live() {
        let now = 2_000_000;
        let inputs = inputs_with(alloc::vec![cand(0x40, 0x44), cand(0x50, 0x55)]);
        let (out, dropped) = filter_dead_registered(inputs, now, GRACE, WINDOW, |_acct| {
            live(Some(1_000_000), Some(now - 10))
        });
        assert_eq!(dropped, 0);
        assert_eq!(out.registered_candidates.len(), 2);
    }

    #[test]
    fn keeps_never_selected_newcomer() {
        let now = 2_000_000;
        let inputs = inputs_with(alloc::vec![cand(0x40, 0x44)]);
        let (out, dropped) =
            filter_dead_registered(inputs, now, GRACE, WINDOW, |_acct| live(None, None));
        assert_eq!(dropped, 0);
        assert_eq!(out.registered_candidates.len(), 1);
    }

    #[test]
    fn permissioned_candidates_are_never_touched() {
        let now = 2_000_000;
        let inputs = inputs_with(alloc::vec![cand(0x40, 0x44)]);
        let before = inputs.permissioned_candidates.clone();
        // lookup marks everything dead; permissioned list must still be intact.
        let (out, _dropped) =
            filter_dead_registered(inputs, now, GRACE, WINDOW, |_acct| live(Some(1), None));
        assert_eq!(out.permissioned_candidates, before);
    }

    #[test]
    fn unmappable_aura_key_fails_open() {
        // A candidate whose only registration has a short aura key is kept
        // (we cannot map it to a liveness record, so we must not drop it).
        let now = 2_000_000;
        let mut bad = cand(0x60, 0x66);
        bad.registrations[0].aura_pub_key = AuraPublicKey(alloc::vec![0x66; 16]);
        let inputs = inputs_with(alloc::vec![bad]);
        let (out, dropped) =
            filter_dead_registered(inputs, now, GRACE, WINDOW, |_acct| live(Some(1), None));
        assert_eq!(dropped, 0);
        assert_eq!(out.registered_candidates.len(), 1);
    }
}
