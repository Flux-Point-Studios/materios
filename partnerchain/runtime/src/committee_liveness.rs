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

/// Drop dead permissioned (FPS core) candidates before the Ariadne draw — the
/// `filter_dead_registered` sibling for the trusted backbone (Residual #2).
///
/// Cores are exempt from the registered filter by design, so a genuinely-dead
/// core would otherwise stay in the authority set forever, inflating the GRANDPA
/// quorum `q = n − ⌊(n−1)/3⌋` above the live-voter count until finality wedges
/// and the only remedy is the forbidden L1 D-param re-shrink. Removing the dead
/// core from `permissioned_candidates` lets the remaining permissioned draws
/// redistribute over the live cores; the vendor's dedup then collapses the
/// distinct committee, so `n` — and `q` — shrink WITHOUT touching the L1
/// D-parameter (the count stays `(P, R)`; only the runtime candidate pool
/// shrinks, computed deterministically from on-chain liveness state).
///
/// Four independent bounds keep eviction from ever stranding the FPS backstop:
///  - `break_glass_keys` are EXEMPT outright (#534): while the break-glass floor
///    is armed, a draw seating none of them is refused, so evicting the last
///    holder would freeze rotation permanently — and since `is_dead` reads
///    `LastAuthoredBlock`, which only a seated node writes, the evicted core
///    could never author its way back;
///  - core-specific `grace_blocks`/`window_blocks` MUCH longer than the
///    registered ones, so no reboot, deploy, or snapshot restore flaps a healthy
///    core out — only a multi-day silence reads as dead (the caller passes
///    `CORE_LIVENESS_GRACE_BLOCKS`/`CORE_LIVENESS_WINDOW_BLOCKS`);
///  - `cap`, the per-selection rate limit: at most `cap` cores leave in one
///    epoch, deterministically the *stalest* first (greatest `now −
///    last_authored`; a selected-past-grace core that never authored ranks
///    maximally stale; ties broken by Aura-key bytes) so every honest node drops
///    the identical core and a buggy or hostile predicate cannot collapse the
///    backbone in a single rotation;
///  - the unchanged `passes_live_quorum_floor` downstream, which refuses any
///    shrunk set whose known-live members cannot carry quorum (keep-current),
///    so a shrink that would strand quorum is never installed.
///
/// Eviction is therefore *preventive*: a standard scheduled set-change that
/// enacts only while the OLD set still finalizes it (the GRANDPA SetId handoff).
/// It cannot un-wedge a chain whose finality is already frozen — that is R1's
/// `Grandpa::note_stalled` break-glass — but at a rung with positive slack
/// (n=16: 12 ext ≥ q=11) every shrink step enacts, where at 0 slack (n=13:
/// 9 ext == q=9) a single concurrent external fault wedges the step.
///
/// An unmappable (short) Aura key fails open (kept), mirroring
/// `filter_dead_registered`. Registered candidates are never touched here.
/// Returns the filtered inputs and the number of cores dropped.
pub fn filter_dead_permissioned<F>(
    mut inputs: AuthoritySelectionInputs,
    now: u32,
    grace_blocks: u32,
    window_blocks: u32,
    cap: usize,
    break_glass_keys: &[[u8; 32]],
    mut lookup: F,
) -> (AuthoritySelectionInputs, u32)
where
    F: FnMut([u8; 32]) -> CandidateLiveness,
{
    if cap == 0 {
        return (inputs, 0);
    }
    // Rank every dead core by staleness (greatest first), ties by key bytes, so
    // the choice of which core to drop is identical on every node — a forced
    // node-local choice would risk divergent committees across the network.
    // Break-glass holders currently in the pool. The exemption below is scoped
    // to these, and only where it is load-bearing.
    let holders_in_pool: alloc::vec::Vec<[u8; 32]> = inputs
        .permissioned_candidates
        .iter()
        .filter_map(|c| aura_account_bytes(&c.aura_public_key))
        .filter(|a| break_glass_keys.contains(a))
        .collect();

    let mut dead: alloc::vec::Vec<([u8; 32], u32)> = alloc::vec::Vec::new();
    for cand in inputs.permissioned_candidates.iter() {
        if let Some(acct) = aura_account_bytes(&cand.aura_public_key) {
            // #534, NARROWED to the case its justification actually covers.
            // Evicting the LAST break-glass holder is absorbing: the armed floor
            // then refuses every draw, and `is_dead` reads `LastAuthoredBlock`,
            // which only a SEATED node writes, so the evicted core can never
            // author its way back. That argument covers the last holder and
            // nothing else. With a second holder in the pool the floor stays
            // satisfiable, so a dead holder MUST still be shed — exempting every
            // holder would silently disable eviction for exactly the FPS cores
            // it exists to drop, re-opening the q(n)-inflation wedge with no
            // operator signal at all (`cores_dropped` stays 0, so the caller's
            // warn never fires).
            //
            // Skipped BEFORE the staleness ranking rather than filtered after,
            // because a never-authored core ranks maximally stale and would
            // otherwise consume the whole `cap` and shield a genuinely dead core
            // standing behind it.
            if holders_in_pool.len() <= 1 && break_glass_keys.contains(&acct) {
                continue;
            }
            let liveness = lookup(acct);
            if is_dead(&liveness, now, grace_blocks, window_blocks) {
                let staleness = match liveness.last_authored {
                    Some(last) => now.saturating_sub(last),
                    None => u32::MAX, // selected past grace, never authored: maximally stale
                };
                dead.push((acct, staleness));
            }
        }
    }
    if dead.is_empty() {
        return (inputs, 0);
    }
    dead.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    dead.truncate(cap);
    let mut evict: alloc::vec::Vec<[u8; 32]> = dead.into_iter().map(|(acct, _)| acct).collect();

    // Cap-independent backstop: at least one break-glass holder must survive
    // every selection. The skip above already protects a lone holder, but with
    // `cap > 1` and several all-dead holders the ranking could take the last one
    // out in a single pass, which is the absorbing state again. Retaining the
    // LEAST stale holder — the tail of the staleness-ordered list — is
    // deterministic, so every node retains the same one.
    if !holders_in_pool.is_empty() && holders_in_pool.iter().all(|h| evict.contains(h)) {
        if let Some(pos) = evict.iter().rposition(|a| holders_in_pool.contains(a)) {
            evict.remove(pos);
        }
    }

    let mut dropped: u32 = 0;
    inputs.permissioned_candidates.retain(|cand| {
        let drop = aura_account_bytes(&cand.aura_public_key)
            .map(|acct| evict.contains(&acct))
            .unwrap_or(false);
        if drop {
            dropped = dropped.saturating_add(1);
        }
        !drop
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

/// Count selected members with no `last_authored` stamp — seats we have no
/// evidence about in either direction. An undecodable key is NOT counted: it is
/// not a newcomer owed benefit-of-the-doubt, and it already counts NOT live, so
/// `passes_live_quorum_floor` is what catches it.
pub fn unproven_member_count<K, F>(selected_aura_keys: &[K], mut lookup: F) -> usize
where
    K: AsRef<[u8]>,
    F: FnMut([u8; 32]) -> CandidateLiveness,
{
    selected_aura_keys
        .iter()
        .filter(|key| {
            account_bytes_from_encoded(key.as_ref())
                .is_some_and(|acct| lookup(acct).last_authored.is_none())
        })
        .count()
}

/// Effective-slack invariant (mainnet-resilience #505). Composes with
/// `passes_live_quorum_floor`, which still runs first and is unchanged: this
/// adds a condition only on draws that GROW the authority set.
///
/// A larger `n` raises `q(n)`, so growth spends finality slack. Paid for by a
/// live voter that is fine; paid for by a seat we have never seen author, the
/// chain ends the rotation closer to a wedge than it started. The rule:
///
/// ```text
/// n <= n_current                                          (always allowed)
///   OR ( unproven <= unproven_credit
///        AND live >= q(n) + min(margin, sigma_current) )
/// ```
///
/// TWO PROPERTIES CARRY THE DESIGN, and both are load-bearing:
///
/// The credit is a CARDINALITY CAP, not an arithmetic bonus. Expressed as a
/// bonus — `live + min(unproven, credit) >= q(n) + margin` — it cancels to
/// exactly `live >= q(n)` whenever credit == margin and any unproven seat is
/// present. Every growth draw seats a newcomer by construction, so that form is
/// a no-op on the whole of its intended traffic while reading as a guard, and it
/// charges the same for one unproven seat as for ten. Pinned by
/// `growth_invariant_is_not_the_base_floor`.
///
/// `min(margin, sigma_current)` makes refusal impossible from a baseline that is
/// already at or below the margin. Combined with the `n <= n_current` exemption,
/// this gate can never be the reason a degraded chain stops rotating: it does
/// not block the shrink that restores slack, and it asks nothing extra of a
/// chain that has none to protect. That matters because every floor here is
/// refusal-only — a permanent refusal freezes the committee where it stands.
pub fn passes_growth_slack_invariant<K, F>(
    selected_aura_keys: &[K],
    n_current: usize,
    live_current: usize,
    now: u32,
    window_blocks: u32,
    unproven_credit: usize,
    margin: usize,
    lookup: F,
) -> bool
where
    K: AsRef<[u8]>,
    F: FnMut([u8; 32]) -> CandidateLiveness + Copy,
{
    let n = selected_aura_keys.len();
    if n <= n_current {
        return true;
    }
    if unproven_member_count(selected_aura_keys, lookup) > unproven_credit {
        return false;
    }
    let sigma_current = live_current.saturating_sub(grandpa_quorum_threshold(n_current));
    let required = if margin < sigma_current { margin } else { sigma_current };
    live_member_count(selected_aura_keys, now, window_blocks, lookup)
        >= grandpa_quorum_threshold(n).saturating_add(required)
}

/// Largest registered-candidate pool the currently-proven-live voters can carry
/// (mainnet-resilience #505, the D-parameter ramp guard).
///
/// This half is a CLAMP, never a verdict: it returns a seat count, so it cannot
/// contribute a `None` from `select_authorities`. The floors are already
/// refusal-only, and a second way to refuse is a second way to freeze rotation.
/// It is bounded below by `ext_current` — the externals the chain already seats,
/// counted from the current committee rather than inferred as `n_current -
/// permissioned_pool`, which is only the same number while the permissioned pool
/// is unchanged and silently shrinks one-for-one when an L1 core upsert grows it,
/// turning "never de-seat a live external" into its opposite.
///
/// Growth must clear, for `n = permissioned_pool + r`:
///
/// - `live_current >= q(n) + margin` — the new shape is carried by voters we have
///   actually seen author, with slack to spare;
/// - `q(n) <= q(n_current) + 1` — at most one quorum step per rotation, the
///   growth-direction mirror of the eviction rate cap;
/// - and while `sigma_current <= margin` (the chain has no slack to spend),
///   `q(n) <= q(n_current)` — growth is confined to the rungs where `q` is flat.
///
/// That last clause is what refuses the #441 shape: at 4 live cores, growing to
/// n=5 raises `q` 3 → 4 while live stays 4, i.e. straight to zero slack. #441 was
/// "recurring n=5 zero-slack", so the rule reproduces an incident that happened.
/// The flat rungs are `n ≡ 1 (mod 3)` — q(6)=q(7), q(15)=q(16) — and they are the
/// ramp's road: the final step to trustless finality costs no quorum at all.
///
/// Every predicate is monotone-decreasing in `r` because `q` is monotone in `n`,
/// so scanning upward and stopping at the first failure finds the true maximum.
pub fn registered_pool_cap(
    requested_r: usize,
    permissioned_pool: usize,
    ext_current: usize,
    n_current: usize,
    live_current: usize,
    margin: usize,
    max_validators: usize,
) -> usize {
    let hard = requested_r.min(max_validators.saturating_sub(permissioned_pool));
    let r_floor = ext_current.min(hard);
    let q_current = grandpa_quorum_threshold(n_current);
    let degraded = live_current.saturating_sub(q_current) <= margin;

    let mut cap = r_floor;
    for r in (r_floor.saturating_add(1))..=hard {
        let q = grandpa_quorum_threshold(permissioned_pool.saturating_add(r));
        if live_current < q.saturating_add(margin) {
            break;
        }
        if q > q_current.saturating_add(1) {
            break;
        }
        if degraded && q > q_current {
            break;
        }
        cap = r;
    }
    cap
}

/// Break-glass floor (mainnet-resilience #490). Does the drawn committee
/// contain at least one FPS-held break-glass Aura key? When the floor is armed
/// and this returns `false`, the caller refuses the rotation exactly as it does
/// for `passes_live_quorum_floor` — returning `None` from `select_authorities`
/// keeps the current committee for one more epoch via the session pallet's
/// create_inherent fallback. The two floors compose: a rotation must clear both.
///
/// The invariant this enforces, inductively while armed: the ENACTED committee
/// can never drop to zero FPS-controlled seats, so a break-glass recovery
/// (`Grandpa::note_stalled`, an emergency runtime upgrade) always has an FPS
/// author left to include the recovering block. It closes the trustless-majority
/// reset corner where a Cardano D-parameter that zeroes the permissioned count
/// would otherwise strand FPS with no enacted key and no way to author the fix.
/// Because it only ever refuses a draw (keep-current), it can never itself
/// install an unsafe committee — the base case (current committee already holds
/// an FPS key) must hold when the floor is armed, which is why arming precedes
/// the seat ramp.
///
/// `selected_aura_keys` are the SCALE-encoded Aura keys of the drawn committee
/// (the same slice fed to `passes_live_quorum_floor`), normalized to the 32-byte
/// account via `account_bytes_from_encoded`; `break_glass_keys` are the raw
/// 32-byte FPS Aura public keys set by Root. Empty `break_glass_keys` means the
/// floor is unconfigured and every committee passes — so the caller MUST also
/// gate on the on-chain enabled flag, and Root MUST seed the keys before arming.
pub fn committee_covers_break_glass<K>(
    selected_aura_keys: &[K],
    break_glass_keys: &[[u8; 32]],
) -> bool
where
    K: AsRef<[u8]>,
{
    if break_glass_keys.is_empty() {
        return true;
    }
    selected_aura_keys.iter().any(|key| {
        account_bytes_from_encoded(key.as_ref())
            .is_some_and(|acct| break_glass_keys.iter().any(|bg| &acct == bg))
    })
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

    const GRACE: u32 = 1_800; // ~3h @ 6s
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

    #[test]
    fn grace_is_three_hours_not_an_era() {
        // spec-231: grace is 1_800 blocks (~3h @ 6s), not the spec-229 era.
        // Pins the value so a future edit cannot silently widen it back toward
        // a day and let a dead reg hold a committee seat for ~24h again.
        assert_eq!(GRACE, 1_800);
        // A never-authoring dead reg first selected at block N is still kept at
        // ~3h but evicted one block later.
        assert!(!is_dead(&live(Some(0), None), 1_800, GRACE, WINDOW));
        assert!(is_dead(&live(Some(0), None), 1_801, GRACE, WINDOW));
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
    fn contribution_window_sheds_silent_external_that_full_window_keeps() {
        // R1 Lever 1 (Residual #1 / spec-233): the registered filter is already
        // parameterized by `window_blocks`. An external that authored inside the
        // full ~48h window but is silent past the short ~3h CONTRIBUTION window is
        // KEPT under the full window and DROPPED under the short one — exactly the
        // behavior `select_authorities` arms when `ContributionWindowEnabled` is
        // on, so NextCommittee sheds a >f silently-failed external within ~1 epoch
        // (giving R1's note_stalled break-glass a cores-only fire target fast).
        const CONTRIBUTION_WINDOW: u32 = 1_800; // == runtime LIVENESS_CONTRIBUTION_WINDOW
        let now = 2_000_000;
        // authored ~2h ago: inside the 48h window, outside the 3h contribution one.
        let last = Some(now - (CONTRIBUTION_WINDOW + 600));

        let inputs = inputs_with(alloc::vec![cand(0x40, 0x44)]);
        let (out, dropped) =
            filter_dead_registered(inputs, now, GRACE, WINDOW, |_| live(Some(1_000_000), last));
        assert_eq!(dropped, 0);
        assert_eq!(out.registered_candidates.len(), 1);

        let inputs = inputs_with(alloc::vec![cand(0x40, 0x44)]);
        let (out, dropped) = filter_dead_registered(
            inputs,
            now,
            GRACE,
            CONTRIBUTION_WINDOW,
            |_| live(Some(1_000_000), last),
        );
        assert_eq!(dropped, 1);
        assert!(out.registered_candidates.is_empty());
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

    // ── passes_growth_slack_invariant (#505) ─────────────────────────

    const CREDIT: usize = 1;
    const MARGIN: usize = 1;

    /// Four live cores, the live preprod backbone.
    fn cores() -> Vec<Vec<u8>> {
        alloc::vec![key(0x10), key(0x11), key(0x12), key(0x13)]
    }

    #[test]
    fn growth_invariant_exempts_shrink_and_same_size() {
        // The frozen-rotation answer: a restorative eviction must NEVER be
        // refused by this gate, however degraded the shape. n <= n_current is
        // the business of passes_live_quorum_floor alone.
        let three = alloc::vec![key(0x10), key(0x11), key(0xD0)];
        assert!(passes_growth_slack_invariant(
            &three, 6, 4, NOW, WINDOW, CREDIT, MARGIN, floor_lookup
        ));
        let four = cores();
        assert!(passes_growth_slack_invariant(
            &four, 4, 4, NOW, WINDOW, CREDIT, MARGIN, floor_lookup
        ));
    }

    #[test]
    fn growth_invariant_caps_unproven_seats_by_cardinality() {
        // TWO never-authored seats in one growth draw exceeds the credit and is
        // refused even though live members alone still carry quorum:
        // n=6, q(6)=5, 4 live cores + 2 unproven -> L=4 < 5 would fail the base
        // floor anyway, so use 5 live + 2 unproven: n=7, q(7)=5, L=5 >= 5.
        let mut keys = cores();
        keys.push(key(0x14)); // 5th live
        keys.push(key(0x00)); // unproven
        keys.push(key(0x01)); // unproven
        assert!(passes_live_quorum_floor(&keys, NOW, WINDOW, floor_lookup));
        assert!(!passes_growth_slack_invariant(
            &keys, 5, 5, NOW, WINDOW, CREDIT, MARGIN, floor_lookup
        ));
    }

    #[test]
    fn growth_invariant_is_not_the_base_floor() {
        // ANTI-TAUTOLOGY LOCK. The reviewed design expressed the credit as an
        // arithmetic bonus, `L + min(A, C) >= q(n) + 1`, which at C = 1 cancels
        // to exactly `L >= q(n)` for every draw carrying an unproven seat — and
        // every growth draw carries one by construction, so the gate was a no-op
        // on 100% of its target traffic. This pins the difference: a draw the
        // base floor ACCEPTS that the growth invariant must REFUSE.
        //
        // Live preprod shape grown by one: n_cur=5 (4 cores + 1 live external),
        // sigma_cur = 5 - q(5) = 1. Draw n=6 seating one unproven newcomer:
        // L = 5, q(6) = 5. Base floor: 5 >= 5 PASSES. Growth: required =
        // min(MARGIN, sigma_cur) = 1, so 5 >= 5 + 1 is false -> REFUSE.
        let mut keys = cores();
        keys.push(key(0x14)); // the live external
        keys.push(key(0x00)); // the unproven newcomer
        assert_eq!(keys.len(), 6);
        assert!(
            passes_live_quorum_floor(&keys, NOW, WINDOW, floor_lookup),
            "precondition: the base floor accepts this draw"
        );
        assert!(
            !passes_growth_slack_invariant(
                &keys, 5, 5, NOW, WINDOW, CREDIT, MARGIN, floor_lookup
            ),
            "growth to zero slack must be refused — if this passes, the gate has \
             collapsed back into passes_live_quorum_floor"
        );
    }

    #[test]
    fn growth_invariant_admits_a_newcomer_that_keeps_slack() {
        // Growth onto a q-flat rung: n_cur=6 -> n=7 costs no quorum
        // (q(6) = q(7) = 5), so one unproven seat still leaves slack.
        // 6 live + 1 unproven: L=6 >= q(7)=5 + 1.
        let mut keys = cores();
        keys.push(key(0x14));
        keys.push(key(0x15));
        keys.push(key(0x00));
        assert_eq!(keys.len(), 7);
        assert!(passes_growth_slack_invariant(
            &keys, 6, 6, NOW, WINDOW, CREDIT, MARGIN, floor_lookup
        ));
    }

    #[test]
    fn growth_invariant_cannot_out_refuse_the_base_floor_when_degraded() {
        // Anti-freeze: from a baseline that is ITSELF at zero slack, required
        // clamps to min(MARGIN, 0) = 0, so this gate demands nothing beyond the
        // base floor and can never be the reason a degraded chain stops
        // rotating. n_cur=6 with live_current=5 -> sigma_cur = 5 - q(6) = 0.
        let mut keys = cores();
        keys.push(key(0x14));
        keys.push(key(0x15));
        keys.push(key(0x00));
        assert!(passes_growth_slack_invariant(
            &keys, 6, 5, NOW, WINDOW, CREDIT, MARGIN, floor_lookup
        ));
    }

    // ── registered_pool_cap (#505 ramp guard) ────────────────────────

    const MAXV: usize = 32;

    #[test]
    fn ramp_cap_is_never_a_refusal_and_never_de_seats() {
        // The guard is a CLAMP, not a verdict: it returns a number, and never
        // one below the external seats the chain already holds. A refusal here
        // would be a second way to freeze rotation.
        for requested in 0..8 {
            let cap = registered_pool_cap(requested, 4, 3, 7, 7, MARGIN, MAXV);
            assert!(cap <= requested.max(3), "cap {cap} exceeded request {requested}");
            assert!(cap >= 3.min(requested), "cap {cap} de-seated a held external");
        }
    }

    #[test]
    fn ramp_cap_refuses_quorum_growth_while_degraded_the_441_shape() {
        // #441, the incident that actually happened: "recurring n=5 zero-slack".
        // 4 cores, no externals seated, all 4 live -> sigma_cur = 4 - q(4) = 1,
        // which is AT the margin, so growth may not raise quorum. Going to n=5
        // raises q 3 -> 4 while live stays 4, i.e. slack 0. Must not be offered.
        assert_eq!(grandpa_quorum_threshold(4), 3);
        assert_eq!(grandpa_quorum_threshold(5), 4);
        assert_eq!(registered_pool_cap(1, 4, 0, 4, 4, MARGIN, MAXV), 0);
    }

    #[test]
    fn ramp_cap_allows_a_q_flat_rung_while_degraded() {
        // q is flat across n = 1 (mod 3): q(6) = q(7) = 5. Growth onto a flat
        // rung adds a seat without adding quorum, so slack cannot fall and the
        // degraded clause permits it. This is the rung the ramp rides.
        assert_eq!(grandpa_quorum_threshold(6), grandpa_quorum_threshold(7));
        assert_eq!(registered_pool_cap(3, 4, 2, 6, 6, MARGIN, MAXV), 3);
    }

    #[test]
    fn ramp_cap_rate_limits_quorum_to_one_step() {
        // 6 live cores, n_cur = 6 (sigma 1). Asking for 10 externals would be
        // n = 14, q = 10 — five quorum steps in one rotation. Capped to a shape
        // at most one quorum step above the current one.
        let cap = registered_pool_cap(10, 4, 2, 6, 6, MARGIN, MAXV);
        let q_new = grandpa_quorum_threshold(4 + cap);
        assert!(
            q_new <= grandpa_quorum_threshold(6) + 1,
            "cap {cap} -> n {} q {q_new} jumped more than one quorum step",
            4 + cap
        );
    }

    #[test]
    fn ramp_cap_growth_is_reachable_from_every_rung() {
        // THE TEST THAT WAS MISSING. Every other ramp test asks "is this growth
        // SAFE"; none asked "is any growth REACHABLE". They pass identically
        // whether the guard is prudent or catatonic.
        //
        // `live_current <= n_current` always — a committee has no more live
        // members than seats. So growth n -> n+1 needs `n >= q(n+1) + margin`,
        // and at n=4 that is `4 >= 4 + margin`: ANY margin above zero makes
        // growth off a small committee unsatisfiable forever, which is a
        // permanent freeze wearing the costume of a safety check. Shipped as
        // margin=1 in spec-236 and deadlocked the live chain at n=5.
        //
        // Asserted at the DEPLOYED margin (0), from a fully-live committee.
        const DEPLOYED_MARGIN: usize = 0;
        for n_cur in 4..=12usize {
            let cap = registered_pool_cap(
                /* requested_r  */ n_cur + 1 - 4,
                /* p_eff        */ 4,
                /* ext_current  */ n_cur - 4,
                n_cur,
                /* live_current */ n_cur,
                DEPLOYED_MARGIN,
                MAXV,
            );
            assert!(
                4 + cap > n_cur,
                "n_cur={n_cur}: guard offers r_cap={cap} (n={}) — no growth is \
                 reachable from a FULLY LIVE committee, so the ramp is frozen",
                4 + cap
            );
        }
    }

    #[test]
    fn ramp_cap_still_refuses_growth_a_degraded_committee_cannot_carry() {
        // Margin=0 must not become a rubber stamp. A committee that has ALREADY
        // lost a member cannot buy a bigger quorum: n_cur=6 with only 5 live is
        // at sigma 0, so growth to 7 (q=5) is allowed only because q is flat
        // there, while growth to 8 (q=6 > 5 live) is refused.
        let cap = registered_pool_cap(4, 4, 2, 6, 5, 0, MAXV);
        assert!(4 + cap <= 7, "degraded committee grew to n={} on 5 live", 4 + cap);
    }

    #[test]
    fn ramp_cap_honours_max_validators() {
        let cap = registered_pool_cap(usize::MAX, 4, 0, 4, 4, MARGIN, MAXV);
        assert!(4 + cap <= MAXV);
    }

    #[test]
    fn ramp_cap_grows_from_a_healthy_baseline() {
        // Undegraded: 8 live of n_cur = 8 -> sigma = 8 - q(8) = 2 > MARGIN, so
        // the degraded clause is off and the rate limit governs. q(9) = 7 is one
        // step above q(8) = 6 and 8 live >= 7 + 1, so one more seat is offered.
        assert_eq!(grandpa_quorum_threshold(8), 6);
        assert_eq!(grandpa_quorum_threshold(9), 7);
        assert_eq!(registered_pool_cap(5, 4, 4, 8, 8, MARGIN, MAXV), 5);
    }

    #[test]
    fn unproven_member_count_ignores_undecodable_keys() {
        // An unmappable key is not a newcomer we owe benefit-of-the-doubt to:
        // it must not consume the credit. It already counts NOT live, so the
        // base floor is what catches it.
        let keys = alloc::vec![key(0x00), alloc::vec![0xAB; 8], key(0x10)];
        assert_eq!(unproven_member_count(&keys, floor_lookup), 1);
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

    // ── filter_dead_permissioned (dead-CORE eviction, Residual #2) ────
    //
    // Mirrors the chaos-harness Group J model (materios-chaos test_room_model.py
    // / chaos_harness.py filter_dead_permissioned): the runtime is the reference
    // implementation, the harness the executable spec. Core constants here equal
    // the harness CORE_GRACE_BLOCKS / CORE_WINDOW_BLOCKS and the live runtime
    // CORE_LIVENESS_* constants.

    const CORE_GRACE: u32 = 14_400; // ~24h @ 6s — must exceed registered GRACE
    const CORE_WINDOW: u32 = 100_800; // ~7d @ 6s — must exceed registered WINDOW

    fn perm(aura: u8) -> PermissionedCandidateData {
        PermissionedCandidateData {
            sidechain_public_key: SidechainPublicKey(alloc::vec![aura; 33]),
            aura_public_key: AuraPublicKey(alloc::vec![aura; 32]),
            grandpa_public_key: GrandpaPublicKey(alloc::vec![aura; 32]),
        }
    }

    fn inputs_with_perms(perms: Vec<PermissionedCandidateData>) -> AuthoritySelectionInputs {
        AuthoritySelectionInputs {
            d_parameter: DParameter {
                num_permissioned_candidates: perms.len() as u16,
                num_registered_candidates: 0,
            },
            permissioned_candidates: perms,
            registered_candidates: Vec::new(),
            epoch_nonce: EpochNonce(alloc::vec![7; 32]),
        }
    }

    #[test]
    fn core_constants_are_longer_than_registered() {
        // The anti-flap guarantee: a reboot/deploy/snapshot-restore must never
        // evict a healthy core, so the core thresholds dwarf the registered ones.
        assert!(CORE_GRACE > GRACE);
        assert!(CORE_WINDOW > WINDOW);
        assert_eq!(CORE_GRACE, 14_400);
        assert_eq!(CORE_WINDOW, 100_800);
    }

    #[test]
    fn a_dead_holder_is_evicted_when_another_holder_survives() {
        // The exemption is justified ONLY by the absorbing state: evicting the
        // LAST holder leaves the armed floor unsatisfiable forever. With a
        // second live holder in the pool that argument does not apply — the
        // floor stays satisfiable — so a dead holder must still be shed, or
        // eviction is silently disabled for exactly the cores it exists to drop.
        let now = 2_000_000;
        let bg_dead = [0xC0u8; 32];
        let bg_live = [0xC1u8; 32];
        let inputs = inputs_with_perms(alloc::vec![perm(0xC0), perm(0xC1)]);
        let (out, dropped) = filter_dead_permissioned(
            inputs, now, CORE_GRACE, CORE_WINDOW, 1, &[bg_dead, bg_live],
            |acct| {
                if acct == bg_dead { live(Some(1_000), None) }        // dead
                else { live(Some(1_000), Some(now)) }                  // live
            },
        );
        assert_eq!(dropped, 1, "a dead holder with a LIVE sibling holder must still be evicted");
        assert_eq!(out.permissioned_candidates.len(), 1);
        assert_eq!(out.permissioned_candidates[0].aura_public_key.0, alloc::vec![0xC1u8; 32]);
    }

    #[test]
    fn dead_core_holding_a_break_glass_key_is_never_evicted() {
        // #534. The break-glass floor refuses any draw seating none of these
        // keys, and `is_dead` keys on LastAuthoredBlock, which only a SEATED
        // node writes. So evicting the last break-glass holder from the pool is
        // absorbing: no draw is acceptable, rotation freezes, and the evicted
        // core can never author its way back. Eviction must not be able to
        // reach a break-glass holder, however dead it looks.
        let now = 2_000_000;
        let bg = [0xC0u8; 32];
        let very_dead = live(Some(1_000), None); // past grace, never authored

        let inputs = inputs_with_perms(alloc::vec![perm(0xC0)]);
        let (out, dropped) =
            filter_dead_permissioned(inputs, now, CORE_GRACE, CORE_WINDOW, 1, &[bg], |_| very_dead);
        assert_eq!(dropped, 0, "a break-glass holder was evicted");
        assert_eq!(
            out.permissioned_candidates.len(),
            1,
            "the break-glass holder must stay in the pool"
        );

        // The discriminator: the SAME dead core, not holding a break-glass key,
        // is still evicted. Without this the assertion above would also pass if
        // eviction had simply stopped working.
        let inputs = inputs_with_perms(alloc::vec![perm(0xC0)]);
        let (out, dropped) = filter_dead_permissioned(
            inputs,
            now,
            CORE_GRACE,
            CORE_WINDOW,
            1,
            &[[0xEEu8; 32]],
            |_| very_dead,
        );
        assert_eq!(dropped, 1, "a dead non-break-glass core must still be evicted");
        assert!(out.permissioned_candidates.is_empty());
    }

    #[test]
    fn a_break_glass_holder_does_not_consume_the_eviction_cap() {
        // Exemption must SKIP the holder, not spend the per-selection budget on
        // it. Ranking is stalest-first, and a never-authored core ranks
        // maximally stale, so a naive filter-after-truncate would let the
        // exempt holder occupy the single slot and silently protect a genuinely
        // dead core standing behind it.
        let now = 2_000_000;
        let bg = [0xC0u8; 32];
        let inputs = inputs_with_perms(alloc::vec![perm(0xC0), perm(0xD0)]);
        let (out, dropped) = filter_dead_permissioned(
            inputs,
            now,
            CORE_GRACE,
            CORE_WINDOW,
            1,
            &[bg],
            |acct| {
                if acct == bg {
                    live(Some(1_000), None) // maximally stale, but exempt
                } else {
                    live(Some(1_000), Some(now - CORE_WINDOW - 1)) // dead, evictable
                }
            },
        );
        assert_eq!(dropped, 1, "the cap was spent on the exempt holder");
        assert_eq!(out.permissioned_candidates.len(), 1);
        assert_eq!(
            out.permissioned_candidates[0].aura_public_key.0,
            alloc::vec![0xC0u8; 32],
            "the surviving core must be the break-glass holder"
        );
    }

    #[test]
    fn permissioned_dead_core_dropped_only_past_core_window() {
        let now = 2_000_000;
        let within = inputs_with_perms(alloc::vec![perm(0xC0)]);
        let (out, dropped) =
            filter_dead_permissioned(within, now, CORE_GRACE, CORE_WINDOW, 1, &[], |_| {
                live(Some(1_000), Some(now - CORE_WINDOW)) // exactly at window = live
            });
        assert_eq!(dropped, 0);
        assert_eq!(out.permissioned_candidates.len(), 1);

        let past = inputs_with_perms(alloc::vec![perm(0xC0)]);
        let (out, dropped) =
            filter_dead_permissioned(past, now, CORE_GRACE, CORE_WINDOW, 1, &[], |_| {
                live(Some(1_000), Some(now - CORE_WINDOW - 1)) // one past window = dead
            });
        assert_eq!(dropped, 1);
        assert!(out.permissioned_candidates.is_empty());
    }

    #[test]
    fn permissioned_core_not_flapped_within_core_window_past_registered_window() {
        // Silent longer than the REGISTERED window (28_800) but within the CORE
        // window (100_800): a registered candidate would be evicted, a core is not.
        let now = 2_000_000;
        let stale = Some(now - (WINDOW + 10));
        assert!(is_dead(&live(Some(1_000), stale), now, GRACE, WINDOW)); // reg WOULD evict
        let inputs = inputs_with_perms(alloc::vec![perm(0xC0)]);
        let (out, dropped) =
            filter_dead_permissioned(inputs, now, CORE_GRACE, CORE_WINDOW, 1, &[], |_| {
                live(Some(1_000), stale)
            });
        assert_eq!(dropped, 0);
        assert_eq!(out.permissioned_candidates.len(), 1);
    }

    #[test]
    fn permissioned_within_core_grace_newcomer_kept() {
        let now = 1_000_000;
        let inputs = inputs_with_perms(alloc::vec![perm(0xC0)]);
        let (out, dropped) =
            filter_dead_permissioned(inputs, now, CORE_GRACE, CORE_WINDOW, 1, &[], |_| {
                live(Some(now - CORE_GRACE / 2), None) // freshly (re)added, within grace
            });
        assert_eq!(dropped, 0);
        assert_eq!(out.permissioned_candidates.len(), 1);
    }

    #[test]
    fn permissioned_live_cores_untouched() {
        let now = 2_000_000;
        let inputs =
            inputs_with_perms(alloc::vec![perm(0xC0), perm(0xC1), perm(0xC2), perm(0xC3)]);
        let (out, dropped) =
            filter_dead_permissioned(inputs, now, CORE_GRACE, CORE_WINDOW, 1, &[], |_| {
                live(Some(1_000), Some(now - 10)) // all live
            });
        assert_eq!(dropped, 0);
        assert_eq!(out.permissioned_candidates.len(), 4);
    }

    #[test]
    fn permissioned_at_most_cap_dropped_per_selection() {
        // Two dead cores + two live, cap=1 → exactly one dropped. Four such calls
        // are needed to drain a 4-core death (the rate-bounded cascade).
        let now = 2_000_000;
        let inputs =
            inputs_with_perms(alloc::vec![perm(0xD0), perm(0xD1), perm(0x10), perm(0x11)]);
        let (out, dropped) =
            filter_dead_permissioned(inputs, now, CORE_GRACE, CORE_WINDOW, 1, &[], |acct| {
                match acct[0] >> 4 {
                    0xD => live(Some(1_000), Some(now - CORE_WINDOW - 1)), // dead
                    _ => live(Some(1_000), Some(now - 10)),                // live
                }
            });
        assert_eq!(dropped, 1);
        assert_eq!(out.permissioned_candidates.len(), 3);
        // exactly one of the two dead cores survives this selection.
        let dead_left = out
            .permissioned_candidates
            .iter()
            .filter(|c| c.aura_public_key.0[0] >> 4 == 0xD)
            .count();
        assert_eq!(dead_left, 1);
    }

    #[test]
    fn permissioned_drops_stalest_dead_core_first() {
        // Among several dead cores the STALEST (greatest now − last_authored) is
        // evicted first — a deterministic choice every node reproduces.
        let now = 2_000_000;
        let inputs = inputs_with_perms(alloc::vec![perm(0xB0), perm(0xA0)]);
        let (out, dropped) =
            filter_dead_permissioned(inputs, now, CORE_GRACE, CORE_WINDOW, 1, &[], |acct| {
                match acct[0] {
                    0xA0 => live(Some(1_000), Some(now - CORE_WINDOW - 1_000)), // stalest
                    0xB0 => live(Some(1_000), Some(now - CORE_WINDOW - 1)),     // dead, fresher
                    _ => live(None, None),
                }
            });
        assert_eq!(dropped, 1);
        assert_eq!(out.permissioned_candidates.len(), 1);
        assert_eq!(out.permissioned_candidates[0].aura_public_key.0[0], 0xB0); // fresher kept
    }

    #[test]
    fn permissioned_never_authored_past_grace_is_maximally_stale() {
        // A core selected past grace that NEVER authored ranks above any
        // authored-but-stale core (the u32::MAX staleness branch).
        let now = 2_000_000;
        let inputs = inputs_with_perms(alloc::vec![perm(0xA0), perm(0xB0)]);
        let (out, dropped) =
            filter_dead_permissioned(inputs, now, CORE_GRACE, CORE_WINDOW, 1, &[], |acct| {
                match acct[0] {
                    0xA0 => live(Some(1_000), Some(now - CORE_WINDOW - 5)), // authored, dead
                    0xB0 => live(Some(1_000), None),                        // never authored
                    _ => live(None, None),
                }
            });
        assert_eq!(dropped, 1);
        assert_eq!(out.permissioned_candidates.len(), 1);
        assert_eq!(out.permissioned_candidates[0].aura_public_key.0[0], 0xA0); // kept
    }

    #[test]
    fn permissioned_filter_leaves_registered_untouched() {
        // The permissioned filter never drops a registered candidate, even one
        // that reads dead — that is filter_dead_registered's job.
        let now = 2_000_000;
        let mut inputs = inputs_with_perms(alloc::vec![perm(0xD0)]);
        inputs.registered_candidates = alloc::vec![cand(0x40, 0x44)];
        let (out, dropped) =
            filter_dead_permissioned(inputs, now, CORE_GRACE, CORE_WINDOW, 1, &[], |_| {
                live(Some(1_000), Some(now - CORE_WINDOW - 1)) // everything reads dead
            });
        assert_eq!(dropped, 1); // only the one core
        assert!(out.permissioned_candidates.is_empty());
        assert_eq!(out.registered_candidates.len(), 1); // registered untouched
    }

    #[test]
    fn permissioned_unmappable_key_fails_open() {
        let now = 2_000_000;
        let mut p = perm(0x66);
        p.aura_public_key = AuraPublicKey(alloc::vec![0x66; 16]); // short, unmappable
        let inputs = inputs_with_perms(alloc::vec![p]);
        let (out, dropped) =
            filter_dead_permissioned(inputs, now, CORE_GRACE, CORE_WINDOW, 1, &[], |_| {
                live(Some(1), None) // would be dead if mappable
            });
        assert_eq!(dropped, 0);
        assert_eq!(out.permissioned_candidates.len(), 1);
    }

    #[test]
    fn permissioned_cap_zero_is_noop() {
        let now = 2_000_000;
        let inputs = inputs_with_perms(alloc::vec![perm(0xD0)]);
        let (out, dropped) =
            filter_dead_permissioned(inputs, now, CORE_GRACE, CORE_WINDOW, 0, &[], |_| {
                live(Some(1_000), Some(now - CORE_WINDOW - 1)) // dead, but cap=0
            });
        assert_eq!(dropped, 0);
        assert_eq!(out.permissioned_candidates.len(), 1);
    }

    #[test]
    fn eviction_quorum_math_n16_plus1_slack_n13_zero_slack() {
        // Runtime-level mirror of the harness slack proof (Group J): evicting a
        // dead core shrinks the distinct committee, so quorum falls. n=16 keeps
        // ≥+1 external slack through the whole 4-core cascade; n=13 runs at 0.
        // n=16: 4 cores + 12 ext, q=11, ext slack 12−11 = 1 before any eviction.
        assert_eq!(grandpa_quorum_threshold(16), 11);
        assert_eq!(12 - grandpa_quorum_threshold(16), 1);
        // after all 4 cores evicted: n=12, q=9, ext slack 12−9 = 3 (monotone up).
        assert_eq!(grandpa_quorum_threshold(12), 9);
        assert_eq!(12 - grandpa_quorum_threshold(12), 3);
        // every cascade rung 16→15→14→13→12 keeps 12 ext ≥ q (slack ≥ 1).
        for n in [16usize, 15, 14, 13, 12] {
            assert!(12 >= grandpa_quorum_threshold(n));
        }
        // n=13: 4 cores + 9 ext, q=9 → ext slack 9−9 = 0 (the 0-slack trap).
        assert_eq!(grandpa_quorum_threshold(13), 9);
        assert_eq!(9 - grandpa_quorum_threshold(13), 0);
        // after the full 13→9 cascade: n=9, q=7, slack 2 — but only reached by
        // surviving the 0-slack window first.
        assert_eq!(grandpa_quorum_threshold(9), 7);
    }

    // ── committee_covers_break_glass (mainnet-resilience #490) ───────

    fn bg_key(b: u8) -> Vec<u8> {
        alloc::vec![b; 32]
    }

    #[test]
    fn break_glass_unconfigured_passes_any_committee() {
        // Empty key set = floor not seeded: every committee passes, byte-identical
        // to pre-#490 behaviour. The caller additionally gates on the enabled flag.
        assert!(committee_covers_break_glass(&[bg_key(1), bg_key(2)], &[]));
        let empty: Vec<Vec<u8>> = Vec::new();
        assert!(committee_covers_break_glass(&empty, &[]));
    }

    #[test]
    fn break_glass_present_in_committee_passes() {
        let bg = [[7u8; 32]];
        assert!(committee_covers_break_glass(&[bg_key(3), bg_key(7), bg_key(9)], &bg));
    }

    #[test]
    fn break_glass_absent_from_committee_refuses() {
        // The reset-corner case: an all-external draw with no FPS key present.
        let bg = [[7u8; 32]];
        assert!(!committee_covers_break_glass(&[bg_key(3), bg_key(4), bg_key(5)], &bg));
    }

    #[test]
    fn break_glass_any_of_several_keys_satisfies() {
        // Multiple FPS cores registered as break-glass; the committee holding any
        // one of them clears the floor.
        let bg = [[1u8; 32], [2u8; 32], [3u8; 32]];
        assert!(committee_covers_break_glass(&[bg_key(9), bg_key(2)], &bg));
        assert!(!committee_covers_break_glass(&[bg_key(9), bg_key(8)], &bg));
    }

    #[test]
    fn break_glass_empty_committee_refuses_when_configured() {
        // An empty draw cannot cover a configured break-glass key.
        let empty: Vec<Vec<u8>> = Vec::new();
        assert!(!committee_covers_break_glass(&empty, &[[7u8; 32]]));
    }

    #[test]
    fn break_glass_short_key_does_not_match() {
        // An unmappable (<32-byte) committee key can never satisfy the floor.
        let bg = [[7u8; 32]];
        let short = alloc::vec![alloc::vec![7u8; 8]];
        assert!(!committee_covers_break_glass(&short, &bg));
    }
}
