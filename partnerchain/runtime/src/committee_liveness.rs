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
//!
//! The candidate filter alone cannot stop Ariadne from *seating* a set whose
//! live members fall short of the GRANDPA quorum (permissioned seats are
//! drawn with replacement; twice on 2026-06-12 such draws wedged finality).
//! `passes_live_quorum_floor` judges the *selected* set after the draw so the
//! runtime can refuse it and keep the current committee for one more epoch.

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

/// Drop dead registered candidates. For each outer `CandidateRegistrations`
/// entry only the registration the selector will actually install is judged:
/// the vendor's `select_latest_valid_candidate` picks the registration with
/// the greatest `utxo_info.ordering_key()`, so an older live registration must
/// not rescue a newer dead one (and vice-versa). An unmappable or missing key
/// fails open (kept). Returns the filtered inputs and the number of outer
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
        let latest = outer
            .registrations
            .iter()
            .max_by_key(|r| r.utxo_info.ordering_key());
        let alive = match latest {
            Some(r) => match aura_account_bytes(&r.aura_pub_key) {
                Some(acct) => !is_dead(&lookup(acct), now, grace_blocks, window_blocks),
                None => true,
            },
            None => true,
        };
        if !alive {
            dropped = dropped.saturating_add(1);
        }
        alive
    });
    (inputs, dropped)
}

/// GRANDPA finality quorum for an authority set of size `n`:
/// `n − ⌊(n−1)/3⌋`, the smallest vote count a Byzantine-safe supermajority
/// accepts (1→1, 4→3, 6→5, 7→5). `n = 0` → 0.
pub fn grandpa_quorum_threshold(n: usize) -> usize {
    n.saturating_sub(n.saturating_sub(1) / 3)
}

/// Count selected members whose `last_authored` lies within `window_blocks`
/// of `now`. Keys are SCALE-encoded Aura keys, mapped to liveness accounts
/// via `account_bytes_from_encoded`. Never-authored and unmappable keys count
/// NOT live — the opposite polarity of `filter_dead_registered`'s fail-open:
/// the floor is a safety check, so unknowns must not satisfy it.
pub fn live_member_count<K, F>(
    selected_aura_keys: &[K],
    now: u32,
    window_blocks: u32,
    mut lookup: F,
) -> usize
where
    K: AsRef<[u8]>,
    F: FnMut([u8; 32]) -> CandidateLiveness,
{
    selected_aura_keys
        .iter()
        .filter(|key| {
            account_bytes_from_encoded(key.as_ref())
                .and_then(|acct| lookup(acct).last_authored)
                .is_some_and(|last_authored| now.saturating_sub(last_authored) <= window_blocks)
        })
        .count()
}

/// Can the known-live members of a selected committee carry the GRANDPA
/// quorum? `false` means the caller must refuse the rotation (returning
/// `None` from `select_authorities` keeps the current committee for one more
/// epoch via the session pallet's create_inherent fallback). An empty
/// selection never passes.
pub fn passes_live_quorum_floor<K, F>(
    selected_aura_keys: &[K],
    now: u32,
    window_blocks: u32,
    lookup: F,
) -> bool
where
    K: AsRef<[u8]>,
    F: FnMut([u8; 32]) -> CandidateLiveness,
{
    !selected_aura_keys.is_empty()
        && live_member_count(selected_aura_keys, now, window_blocks, lookup)
            >= grandpa_quorum_threshold(selected_aura_keys.len())
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

    #[test]
    fn drops_when_latest_registration_dead_even_if_older_live() {
        // The selector installs the registration with the greatest utxo
        // ordering key; an older live key must not rescue a newer dead one.
        let now = 2_000_000;
        let mut c = cand(0x70, 0x71); // reg #1: aura 0x71, the OLDER registration
        let mut newer = reg(0x72); // reg #2: aura 0x72, dominates utxo ordering
        newer.utxo_info.utxo_id = UtxoId { tx_hash: McTxHash([0xFFu8; 32]), index: UtxoIndex(9) };
        newer.utxo_info.epoch_number = McEpochNumber(9);
        newer.utxo_info.block_number = McBlockNumber(999);
        newer.utxo_info.slot_number = McSlotNumber(999);
        newer.utxo_info.tx_index_within_block = McTxIndexInBlock(9);
        c.registrations.push(newer);
        let inputs = inputs_with(alloc::vec![c]);
        let (out, dropped) = filter_dead_registered(inputs, now, GRACE, WINDOW, |acct| {
            if acct == [0x72u8; 32] {
                live(Some(1_000_000), None) // newest registration = dead
            } else {
                live(Some(1_000_000), Some(now - 10)) // older = live
            }
        });
        assert_eq!(dropped, 1);
        assert!(out.registered_candidates.is_empty());
    }

    // ── grandpa_quorum_threshold ─────────────────────────────────────

    #[test]
    fn quorum_threshold_matches_grandpa_supermajority() {
        assert_eq!(grandpa_quorum_threshold(0), 0);
        assert_eq!(grandpa_quorum_threshold(1), 1);
        assert_eq!(grandpa_quorum_threshold(2), 2);
        assert_eq!(grandpa_quorum_threshold(3), 3);
        assert_eq!(grandpa_quorum_threshold(4), 3);
        assert_eq!(grandpa_quorum_threshold(5), 4);
        assert_eq!(grandpa_quorum_threshold(6), 5);
        assert_eq!(grandpa_quorum_threshold(7), 5);
    }

    // ── passes_live_quorum_floor ─────────────────────────────────────

    const NOW: u32 = 2_000_000;

    /// Encoded 32-byte aura key whose every byte is `b`.
    fn key(b: u8) -> Vec<u8> {
        alloc::vec![b; 32]
    }

    /// Floor lookup keyed on the account's high nibble: `0x1_` authored 10
    /// blocks ago (live), `0xD_` authored one block beyond the window (dead),
    /// anything else has no record (unknown / never authored).
    fn floor_lookup(acct: [u8; 32]) -> CandidateLiveness {
        match acct[0] >> 4 {
            0x1 => live(Some(1_000), Some(NOW - 10)),
            0xD => live(Some(1_000), Some(NOW - (WINDOW + 1))),
            _ => live(None, None),
        }
    }

    #[test]
    fn floor_rejects_wedge_shape_four_live_of_six() {
        // The 2026-06-12 incident shape: a 6-seat draw with only 4 live
        // members (one dead, one never authored). Quorum 5 > 4 live → refuse.
        let keys = alloc::vec![
            key(0x10),
            key(0x11),
            key(0x12),
            key(0x13),
            key(0xD0),
            key(0x00)
        ];
        assert!(!passes_live_quorum_floor(&keys, NOW, WINDOW, floor_lookup));
    }

    #[test]
    fn floor_seats_never_authored_newcomer_with_live_quorum() {
        // 4 live cores + 1 never-authored newcomer: quorum(5) = 4 ≤ 4 live,
        // so a fresh joiner can still be seated.
        let keys = alloc::vec![key(0x10), key(0x11), key(0x12), key(0x13), key(0x00)];
        assert!(passes_live_quorum_floor(&keys, NOW, WINDOW, floor_lookup));
    }

    #[test]
    fn floor_rejects_three_live_of_five() {
        let keys = alloc::vec![key(0x10), key(0x11), key(0x12), key(0x00), key(0x01)];
        assert!(!passes_live_quorum_floor(&keys, NOW, WINDOW, floor_lookup));
    }

    #[test]
    fn floor_passes_all_live_four() {
        let keys = alloc::vec![key(0x10), key(0x11), key(0x12), key(0x13)];
        assert!(passes_live_quorum_floor(&keys, NOW, WINDOW, floor_lookup));
    }

    #[test]
    fn floor_passes_three_live_one_dead_of_four() {
        // quorum(4) = 3 ≤ 3 live: one dead seat is tolerable at n=4.
        let keys = alloc::vec![key(0x10), key(0x11), key(0x12), key(0xD0)];
        assert!(passes_live_quorum_floor(&keys, NOW, WINDOW, floor_lookup));
    }

    #[test]
    fn floor_counts_exact_window_boundary_as_live() {
        // last_authored == now - window is LIVE, matching is_dead's
        // exact-equal-kept boundary.
        let keys = alloc::vec![key(0x10)];
        assert!(passes_live_quorum_floor(&keys, NOW, WINDOW, |_| live(
            Some(1_000),
            Some(NOW - WINDOW)
        )));
        assert!(!passes_live_quorum_floor(&keys, NOW, WINDOW, |_| live(
            Some(1_000),
            Some(NOW - WINDOW - 1)
        )));
    }

    #[test]
    fn floor_rejects_all_unknown_cold_start() {
        // A draw with zero authoring history (cold start) is refused; the
        // keep-current fallback is the bootstrapping path.
        let keys = alloc::vec![key(0x00), key(0x01), key(0x02), key(0x03)];
        assert!(!passes_live_quorum_floor(&keys, NOW, WINDOW, floor_lookup));
    }

    #[test]
    fn floor_counts_unmappable_key_not_live() {
        // A short (unmappable) key still occupies a seat (n = 2, quorum 2)
        // but must not count live, even though its lookup would say live:
        // 1 live < 2 → refuse. If the short key were skipped from n or
        // counted live, this draw would pass.
        let keys = alloc::vec![alloc::vec![0x10u8; 16], key(0x10)];
        assert!(!passes_live_quorum_floor(&keys, NOW, WINDOW, floor_lookup));
    }

    #[test]
    fn floor_rejects_empty_selection() {
        let keys: Vec<Vec<u8>> = Vec::new();
        assert!(!passes_live_quorum_floor(&keys, NOW, WINDOW, floor_lookup));
    }
}
