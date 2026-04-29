//! Runtime-level sanity checks over `AuthoritySelectionInputs`.
//!
//! IOG's vendored `authority-selection-inherents` already validates
//! *per-entry* correctness (signatures, key length, tx inputs, stake > 0).
//! It does not enforce *whole-input* invariants such as:
//!
//! - A hard cap on the number of registrations per epoch (DoS guard).
//! - Deduplication by `sidechain_pub_key`, `mainchain_pub_key`,
//!   `aura_pub_key`, or `grandpa_pub_key`.
//! - Bounded `epoch_nonce` length.
//! - Sanity bounds on `d_parameter` vs `MaxValidators`.
//!
//! This module is a wrapper layer consumed by `select_authorities` in
//! `lib.rs` *before* the input is handed to IOG's selection logic. Bad
//! individual entries are dropped (fail-open for liveness). Top-level
//! invariant violations cause the whole input to be rejected so the
//! session pallet reuses the previous committee.
//!
//! See `docs/d-param-sanity-checks-design.md` for the threat model and
//! the per-field rationale.

use alloc::vec::Vec;
use authority_selection_inherents::authority_selection_inputs::AuthoritySelectionInputs;
use sidechain_domain::{PermissionedCandidateData, RegistrationData, StakeDelegation};

/// Hard caps. Chosen for preprod.
pub const MAX_PERMISSIONED_CANDIDATES: usize = 64;
/// TODO(mainnet): make governance-settable before the mainnet launch.
/// Mainnet Cardano has ~3000 SPOs; 256 would silently drop 91% of the
/// registration pool. For preprod with ~60 SPOs it's 4x headroom.
pub const MAX_REGISTRATIONS_PER_EPOCH: usize = 256;
pub const MAX_EPOCH_NONCE_BYTES: usize = 64;
/// 45 bn ADA * 1e6 lovelace. Total supply of ADA on mainnet. A
/// registration claiming more stake than this is definitionally
/// corrupt db-sync output.
pub const MAX_PLAUSIBLE_STAKE_LOVELACE: u64 = 45_000_000_000u64 * 1_000_000u64;
/// Upper bound on seats-per-epoch accepted from a Cardano-sourced
/// `AuthoritySelectionInputs.d_parameter`.
///
/// Spec 203 decoupled this from `crate::MAX_VALIDATORS`. Before 203 it
/// was `crate::MAX_VALIDATORS as u16` (= 32), which conflated two
/// distinct concepts:
///   1. The Aura/GRANDPA/session block-producer cap
///      (`pallet_session_validator_management::MaxValidators`).
///   2. The `pallet_orinq_receipts` attestor committee cap
///      (`MaxCommitteeSize`).
///
/// Raising `MaxCommitteeSize` 16 → 64 in spec 203 (then 64 → 256 in spec
/// 212) required this constant to track the pallet cap, not the session
/// cap, otherwise Ariadne d-parameter inputs summing past the session
/// ceiling would be silently rejected at the sanitation layer while the
/// pallet would accept them — creating debug-hostile asymmetry. It's
/// therefore pinned to 256 directly to match the OrinqReceipts cap.
///
/// The compile-time assertion still holds that `MAX_VALIDATORS` fits in
/// u16 (required because `DParameter` uses u16 count fields) but no
/// longer derives the cap.
pub const MAX_COMMITTEE_SIZE: u16 = {
    // Sanity: the session-pallet cap must still fit in u16 because the
    // `select_authorities` return BoundedVec is bounded by MaxValidators
    // and downstream consumers treat counts as u16.
    assert!(crate::MAX_VALIDATORS <= u16::MAX as u32);
    256
};

/// Top-level invariant violations. When any of these fires we discard
/// the whole epoch's input; `pallet_session_validator_management` will
/// fall back to the previous committee.
#[derive(Debug, PartialEq, Eq)]
pub enum SanityError {
    DParamTooLarge { permissioned: u16, registered: u16, cap: u16 },
    EpochNonceTooLong { len: usize, cap: usize },
}

/// Per-entry drop reasons. Informational; used for logging only.
#[derive(Debug, PartialEq, Eq)]
pub enum DropReason {
    ExcessPermissionedCandidate,
    ExcessRegistration,
    DuplicatePermissionedSidechainKey,
    DuplicatePermissionedAuraKey,
    DuplicatePermissionedGrandpaKey,
    DuplicateMainchainPubKey,
    RegistrationDuplicateSidechainKey,
    RegistrationDuplicateAuraKey,
    RegistrationDuplicateGrandpaKey,
    ImplausibleStake,
}

/// Report returned alongside the sanitised inputs. Kept minimal so the
/// runtime caller (which must be `no_std`-friendly) can decide whether
/// to log or ignore.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SanityReport {
    pub drops: Vec<DropReason>,
}

impl SanityReport {
    fn record(&mut self, r: DropReason) {
        self.drops.push(r);
    }
}

/// Apply all checks. Returns a cleaned `AuthoritySelectionInputs` plus a
/// drop report, or `Err` if a top-level invariant was violated.
pub fn sanitize_authority_selection_inputs(
    mut inputs: AuthoritySelectionInputs,
) -> Result<(AuthoritySelectionInputs, SanityReport), SanityError> {
    let mut report = SanityReport::default();

    // ---- top-level invariants (fail-closed) ---------------------------
    let dp = &inputs.d_parameter;
    let sum = dp.num_permissioned_candidates.saturating_add(dp.num_registered_candidates);
    if dp.num_permissioned_candidates > MAX_COMMITTEE_SIZE
        || dp.num_registered_candidates > MAX_COMMITTEE_SIZE
        || sum > MAX_COMMITTEE_SIZE
    {
        return Err(SanityError::DParamTooLarge {
            permissioned: dp.num_permissioned_candidates,
            registered: dp.num_registered_candidates,
            cap: MAX_COMMITTEE_SIZE,
        });
    }
    if inputs.epoch_nonce.0.len() > MAX_EPOCH_NONCE_BYTES {
        return Err(SanityError::EpochNonceTooLong {
            len: inputs.epoch_nonce.0.len(),
            cap: MAX_EPOCH_NONCE_BYTES,
        });
    }

    // ---- permissioned: dedup + cap (drop-entry) -----------------------
    inputs.permissioned_candidates =
        sanitize_permissioned(inputs.permissioned_candidates, &mut report);

    // ---- registered: cap, outer dedup by mainchain_pub_key ------------
    let mut registered = inputs.registered_candidates;
    if registered.len() > MAX_REGISTRATIONS_PER_EPOCH {
        let excess = registered.len() - MAX_REGISTRATIONS_PER_EPOCH;
        registered.truncate(MAX_REGISTRATIONS_PER_EPOCH);
        for _ in 0..excess {
            report.record(DropReason::ExcessRegistration);
        }
    }

    let mut seen_mc_keys: Vec<[u8; 32]> = Vec::new();
    registered.retain(|c| {
        if seen_mc_keys.iter().any(|k| k == &c.mainchain_pub_key.0) {
            report.record(DropReason::DuplicateMainchainPubKey);
            false
        } else {
            seen_mc_keys.push(c.mainchain_pub_key.0);
            true
        }
    });

    // Implausible stake: clamp out any CandidateRegistrations whose
    // reported stake exceeds the total ADA supply.
    registered.retain(|c| match c.stake_delegation {
        Some(StakeDelegation(s)) if s > MAX_PLAUSIBLE_STAKE_LOVELACE => {
            report.record(DropReason::ImplausibleStake);
            false
        }
        _ => true,
    });

    // Cross-registration key dedup. We consider ALL submitted
    // registrations under every remaining outer entry. Permissioned
    // keys participate too — a permissioned candidate who is *also*
    // submitting an SPO registration with the same keys should only
    // count once, and the permissioned slot wins (first seen).
    let mut seen_sc: Vec<Vec<u8>> = inputs
        .permissioned_candidates
        .iter()
        .map(|p| p.sidechain_public_key.0.clone())
        .collect();
    let mut seen_aura: Vec<Vec<u8>> = inputs
        .permissioned_candidates
        .iter()
        .map(|p| p.aura_public_key.0.clone())
        .collect();
    let mut seen_gp: Vec<Vec<u8>> = inputs
        .permissioned_candidates
        .iter()
        .map(|p| p.grandpa_public_key.0.clone())
        .collect();

    for outer in registered.iter_mut() {
        let filtered: Vec<RegistrationData> = outer
            .registrations
            .drain(..)
            .filter_map(|r| {
                if seen_sc.iter().any(|k| k == &r.sidechain_pub_key.0) {
                    report.record(DropReason::RegistrationDuplicateSidechainKey);
                    return None;
                }
                if seen_aura.iter().any(|k| k == &r.aura_pub_key.0) {
                    report.record(DropReason::RegistrationDuplicateAuraKey);
                    return None;
                }
                if seen_gp.iter().any(|k| k == &r.grandpa_pub_key.0) {
                    report.record(DropReason::RegistrationDuplicateGrandpaKey);
                    return None;
                }
                seen_sc.push(r.sidechain_pub_key.0.clone());
                seen_aura.push(r.aura_pub_key.0.clone());
                seen_gp.push(r.grandpa_pub_key.0.clone());
                Some(r)
            })
            .collect();
        outer.registrations = filtered;
    }
    // An outer entry whose last valid registration was stripped is
    // useless; drop it so Ariadne doesn't see a stakeholder with zero
    // surviving registrations.
    registered.retain(|c| !c.registrations.is_empty());

    inputs.registered_candidates = registered;
    Ok((inputs, report))
}

fn sanitize_permissioned(
    mut list: Vec<PermissionedCandidateData>,
    report: &mut SanityReport,
) -> Vec<PermissionedCandidateData> {
    if list.len() > MAX_PERMISSIONED_CANDIDATES {
        let excess = list.len() - MAX_PERMISSIONED_CANDIDATES;
        list.truncate(MAX_PERMISSIONED_CANDIDATES);
        for _ in 0..excess {
            report.record(DropReason::ExcessPermissionedCandidate);
        }
    }

    let mut seen_sc: Vec<Vec<u8>> = Vec::new();
    let mut seen_aura: Vec<Vec<u8>> = Vec::new();
    let mut seen_gp: Vec<Vec<u8>> = Vec::new();

    list.into_iter()
        .filter_map(|c| {
            if seen_sc.iter().any(|k| k == &c.sidechain_public_key.0) {
                report.record(DropReason::DuplicatePermissionedSidechainKey);
                return None;
            }
            if seen_aura.iter().any(|k| k == &c.aura_public_key.0) {
                report.record(DropReason::DuplicatePermissionedAuraKey);
                return None;
            }
            if seen_gp.iter().any(|k| k == &c.grandpa_public_key.0) {
                report.record(DropReason::DuplicatePermissionedGrandpaKey);
                return None;
            }
            seen_sc.push(c.sidechain_public_key.0.clone());
            seen_aura.push(c.aura_public_key.0.clone());
            seen_gp.push(c.grandpa_public_key.0.clone());
            Some(c)
        })
        .collect()
}

/// Thin logging wrapper. Kept separate from the pure function so
/// `sanitize_authority_selection_inputs` stays testable without needing
/// a mock logger. The runtime calls this one.
///
/// Logs a single summary line per sanitisation pass (counts-per-reason)
/// rather than one line per drop — otherwise a 256-entry flood of bad
/// registrations would generate 256 log lines.
pub fn sanitize_and_log(
    inputs: AuthoritySelectionInputs,
) -> Result<AuthoritySelectionInputs, SanityError> {
    match sanitize_authority_selection_inputs(inputs) {
        Ok((cleaned, report)) => {
            if !report.drops.is_empty() {
                let mut excess_permissioned = 0u32;
                let mut excess_registration = 0u32;
                let mut dup_permissioned_sc = 0u32;
                let mut dup_permissioned_aura = 0u32;
                let mut dup_permissioned_gp = 0u32;
                let mut dup_mainchain = 0u32;
                let mut dup_reg_sc = 0u32;
                let mut dup_reg_aura = 0u32;
                let mut dup_reg_gp = 0u32;
                let mut implausible_stake = 0u32;
                for r in &report.drops {
                    match r {
                        DropReason::ExcessPermissionedCandidate => excess_permissioned += 1,
                        DropReason::ExcessRegistration => excess_registration += 1,
                        DropReason::DuplicatePermissionedSidechainKey => dup_permissioned_sc += 1,
                        DropReason::DuplicatePermissionedAuraKey => dup_permissioned_aura += 1,
                        DropReason::DuplicatePermissionedGrandpaKey => dup_permissioned_gp += 1,
                        DropReason::DuplicateMainchainPubKey => dup_mainchain += 1,
                        DropReason::RegistrationDuplicateSidechainKey => dup_reg_sc += 1,
                        DropReason::RegistrationDuplicateAuraKey => dup_reg_aura += 1,
                        DropReason::RegistrationDuplicateGrandpaKey => dup_reg_gp += 1,
                        DropReason::ImplausibleStake => implausible_stake += 1,
                    }
                }
                log::warn!(
                    target: "input_sanity",
                    "sanitizer dropped {} entries — excess_perm={} excess_reg={} \
                     dup_perm_sc={} dup_perm_aura={} dup_perm_gp={} dup_mc={} \
                     dup_reg_sc={} dup_reg_aura={} dup_reg_gp={} implausible_stake={}",
                    report.drops.len(),
                    excess_permissioned,
                    excess_registration,
                    dup_permissioned_sc,
                    dup_permissioned_aura,
                    dup_permissioned_gp,
                    dup_mainchain,
                    dup_reg_sc,
                    dup_reg_aura,
                    dup_reg_gp,
                    implausible_stake,
                );
            }
            Ok(cleaned)
        }
        Err(e) => {
            log::error!(
                target: "input_sanity",
                "rejecting whole AuthoritySelectionInputs: {:?}",
                e
            );
            Err(e)
        }
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use sidechain_domain::{
        AuraPublicKey, CandidateRegistrations, CrossChainPublicKey, CrossChainSignature,
        DParameter, EpochNonce, GrandpaPublicKey, MainchainPublicKey, MainchainSignature,
        McBlockNumber, McEpochNumber, McSlotNumber, McTxHash, McTxIndexInBlock,
        PermissionedCandidateData, RegistrationData, SidechainPublicKey, SidechainSignature,
        StakeDelegation, UtxoId, UtxoIndex, UtxoInfo,
    };

    fn pc(sc: u8, aura: u8, gp: u8) -> PermissionedCandidateData {
        PermissionedCandidateData {
            sidechain_public_key: SidechainPublicKey(vec![sc; 33]),
            aura_public_key: AuraPublicKey(vec![aura; 32]),
            grandpa_public_key: GrandpaPublicKey(vec![gp; 32]),
        }
    }

    fn reg_data(sc: u8, aura: u8, gp: u8) -> RegistrationData {
        let u = UtxoId { tx_hash: McTxHash([sc; 32]), index: UtxoIndex(0) };
        RegistrationData {
            registration_utxo: u,
            sidechain_signature: SidechainSignature(vec![0; 64]),
            mainchain_signature: MainchainSignature(vec![0; 64]),
            cross_chain_signature: CrossChainSignature(vec![]),
            sidechain_pub_key: SidechainPublicKey(vec![sc; 33]),
            cross_chain_pub_key: CrossChainPublicKey(vec![]),
            utxo_info: UtxoInfo {
                utxo_id: u,
                epoch_number: McEpochNumber(1),
                block_number: McBlockNumber(1),
                slot_number: McSlotNumber(1),
                tx_index_within_block: McTxIndexInBlock(0),
            },
            tx_inputs: vec![u],
            aura_pub_key: AuraPublicKey(vec![aura; 32]),
            grandpa_pub_key: GrandpaPublicKey(vec![gp; 32]),
        }
    }

    fn cr(mc: u8, regs: Vec<RegistrationData>, stake: u64) -> CandidateRegistrations {
        CandidateRegistrations {
            mainchain_pub_key: MainchainPublicKey([mc; 32]),
            registrations: regs,
            stake_delegation: Some(StakeDelegation(stake)),
        }
    }

    fn inputs_ok() -> AuthoritySelectionInputs {
        AuthoritySelectionInputs {
            d_parameter: DParameter { num_permissioned_candidates: 3, num_registered_candidates: 2 },
            permissioned_candidates: vec![pc(1, 11, 21), pc(2, 12, 22), pc(3, 13, 23)],
            registered_candidates: vec![
                cr(100, vec![reg_data(4, 14, 24)], 1_000),
                cr(101, vec![reg_data(5, 15, 25)], 2_000),
            ],
            epoch_nonce: EpochNonce(vec![7; 32]),
        }
    }

    #[test]
    fn accepts_well_formed_input() {
        let (cleaned, report) = sanitize_authority_selection_inputs(inputs_ok()).unwrap();
        assert!(report.drops.is_empty());
        assert_eq!(cleaned.permissioned_candidates.len(), 3);
        assert_eq!(cleaned.registered_candidates.len(), 2);
    }

    #[test]
    fn rejects_dparam_over_cap() {
        let mut i = inputs_ok();
        i.d_parameter.num_permissioned_candidates = MAX_COMMITTEE_SIZE + 1;
        let err = sanitize_authority_selection_inputs(i).unwrap_err();
        matches!(err, SanityError::DParamTooLarge { .. });
    }

    #[test]
    fn rejects_dparam_sum_over_cap() {
        let mut i = inputs_ok();
        i.d_parameter.num_permissioned_candidates = MAX_COMMITTEE_SIZE;
        i.d_parameter.num_registered_candidates = 1;
        let err = sanitize_authority_selection_inputs(i).unwrap_err();
        matches!(err, SanityError::DParamTooLarge { .. });
    }

    /// Boundary test: a d_parameter whose permissioned+registered seats sum
    /// exactly to 64 must PASS sanitation. Guards against regressions where
    /// `MAX_COMMITTEE_SIZE` gets silently decoupled from the orinq-receipts
    /// pallet cap. Spec 203 raised both to 64.
    #[test]
    fn input_sanity_accepts_d_param_summing_to_64() {
        let mut i = inputs_ok();
        i.d_parameter.num_permissioned_candidates = 40;
        i.d_parameter.num_registered_candidates = 24;
        assert_eq!(
            i.d_parameter.num_permissioned_candidates + i.d_parameter.num_registered_candidates,
            64,
            "test precondition: d-param must sum to 64"
        );
        let (cleaned, _report) = sanitize_authority_selection_inputs(i).unwrap();
        assert_eq!(cleaned.d_parameter.num_permissioned_candidates, 40);
        assert_eq!(cleaned.d_parameter.num_registered_candidates, 24);
    }

    /// Boundary test: a d_parameter summing to 65 (one over the cap) must
    /// fail. Complements `input_sanity_accepts_d_param_summing_to_64`; the
    /// pair pins the cap at exactly 64.
    #[test]
    fn input_sanity_rejects_d_param_summing_to_65() {
        let mut i = inputs_ok();
        i.d_parameter.num_permissioned_candidates = 40;
        i.d_parameter.num_registered_candidates = 25;
        assert_eq!(
            i.d_parameter.num_permissioned_candidates + i.d_parameter.num_registered_candidates,
            65,
            "test precondition: d-param must sum to 65"
        );
        let err = sanitize_authority_selection_inputs(i).unwrap_err();
        match err {
            SanityError::DParamTooLarge { permissioned, registered, cap } => {
                assert_eq!(permissioned, 40);
                assert_eq!(registered, 25);
                assert_eq!(cap, 64, "cap must report as 64 in the error");
            }
            other => panic!("expected DParamTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn rejects_oversized_epoch_nonce() {
        let mut i = inputs_ok();
        i.epoch_nonce = EpochNonce(vec![0; MAX_EPOCH_NONCE_BYTES + 1]);
        let err = sanitize_authority_selection_inputs(i).unwrap_err();
        matches!(err, SanityError::EpochNonceTooLong { .. });
    }

    #[test]
    fn caps_registrations_per_epoch() {
        let mut i = inputs_ok();
        i.registered_candidates = (0..(MAX_REGISTRATIONS_PER_EPOCH as u16 + 5))
            .map(|n| {
                // mainchain key = low byte; to keep duplicates out we
                // also vary registration content.
                let b = (n & 0xff) as u8;
                let hi = ((n >> 8) & 0xff) as u8;
                let mc = CandidateRegistrations {
                    mainchain_pub_key: MainchainPublicKey({
                        let mut k = [0u8; 32];
                        k[0] = b;
                        k[1] = hi;
                        k
                    }),
                    registrations: vec![{
                        let mut r = reg_data(b ^ 0x55, b ^ 0x5a, b ^ 0x5f);
                        r.aura_pub_key.0[31] = hi;
                        r.grandpa_pub_key.0[31] = hi;
                        r.sidechain_pub_key.0[32] = hi;
                        r
                    }],
                    stake_delegation: Some(StakeDelegation(1_000)),
                };
                mc
            })
            .collect();
        let (cleaned, report) = sanitize_authority_selection_inputs(i).unwrap();
        assert!(cleaned.registered_candidates.len() <= MAX_REGISTRATIONS_PER_EPOCH);
        assert!(report.drops.iter().any(|d| *d == DropReason::ExcessRegistration));
    }

    #[test]
    fn dedups_duplicate_mainchain_pubkey() {
        let mut i = inputs_ok();
        i.registered_candidates = vec![
            cr(42, vec![reg_data(4, 14, 24)], 1_000),
            cr(42, vec![reg_data(5, 15, 25)], 99_999), // duplicate mc key, second dropped
        ];
        let (cleaned, report) = sanitize_authority_selection_inputs(i).unwrap();
        assert_eq!(cleaned.registered_candidates.len(), 1);
        assert_eq!(cleaned.registered_candidates[0].stake_delegation, Some(StakeDelegation(1_000)));
        assert!(report.drops.iter().any(|d| *d == DropReason::DuplicateMainchainPubKey));
    }

    #[test]
    fn dedups_duplicate_sidechain_pubkey_across_outer_entries() {
        let mut i = inputs_ok();
        i.registered_candidates = vec![
            cr(40, vec![reg_data(4, 14, 24)], 1_000),
            cr(41, vec![reg_data(4, 15, 25)], 2_000), // same sc key, different mc
        ];
        let (cleaned, report) = sanitize_authority_selection_inputs(i).unwrap();
        // Second outer entry has had its only registration stripped -> outer dropped too.
        assert_eq!(cleaned.registered_candidates.len(), 1);
        assert!(
            report
                .drops
                .iter()
                .any(|d| *d == DropReason::RegistrationDuplicateSidechainKey)
        );
    }

    #[test]
    fn dedups_permissioned_duplicates() {
        let mut i = inputs_ok();
        i.permissioned_candidates = vec![pc(1, 11, 21), pc(1, 12, 22), pc(2, 11, 23)];
        let (cleaned, report) = sanitize_authority_selection_inputs(i).unwrap();
        assert_eq!(cleaned.permissioned_candidates.len(), 1);
        assert!(
            report
                .drops
                .iter()
                .any(|d| *d == DropReason::DuplicatePermissionedSidechainKey)
        );
        assert!(
            report
                .drops
                .iter()
                .any(|d| *d == DropReason::DuplicatePermissionedAuraKey)
        );
    }

    #[test]
    fn drops_implausible_stake() {
        let mut i = inputs_ok();
        i.registered_candidates = vec![
            cr(50, vec![reg_data(6, 16, 26)], MAX_PLAUSIBLE_STAKE_LOVELACE + 1),
            cr(51, vec![reg_data(7, 17, 27)], 1_000),
        ];
        let (cleaned, report) = sanitize_authority_selection_inputs(i).unwrap();
        assert_eq!(cleaned.registered_candidates.len(), 1);
        assert_eq!(cleaned.registered_candidates[0].mainchain_pub_key.0[0], 51);
        assert!(report.drops.iter().any(|d| *d == DropReason::ImplausibleStake));
    }

    #[test]
    fn permissioned_wins_over_registered_on_key_collision() {
        let mut i = inputs_ok();
        // Registration reuses permissioned sidechain key from pc(1,...).
        i.registered_candidates = vec![cr(60, vec![reg_data(1, 99, 99)], 1_000)];
        let (cleaned, report) = sanitize_authority_selection_inputs(i).unwrap();
        assert_eq!(cleaned.permissioned_candidates.len(), 3);
        assert!(cleaned.registered_candidates.is_empty());
        assert!(
            report
                .drops
                .iter()
                .any(|d| *d == DropReason::RegistrationDuplicateSidechainKey)
        );
    }

    #[test]
    fn caps_excess_permissioned() {
        let mut i = inputs_ok();
        i.permissioned_candidates = (0..(MAX_PERMISSIONED_CANDIDATES as u16 + 3))
            .map(|n| {
                let b = (n & 0xff) as u8;
                let hi = ((n >> 8) & 0xff) as u8;
                let mut c = pc(b, b, b);
                c.sidechain_public_key.0[32] = hi;
                c.aura_public_key.0[31] = hi;
                c.grandpa_public_key.0[31] = hi;
                c
            })
            .collect();
        let (cleaned, report) = sanitize_authority_selection_inputs(i).unwrap();
        assert_eq!(cleaned.permissioned_candidates.len(), MAX_PERMISSIONED_CANDIDATES);
        assert!(
            report.drops.iter().any(|d| *d == DropReason::ExcessPermissionedCandidate)
        );
    }
}
