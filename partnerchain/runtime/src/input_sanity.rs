//! Runtime-level sanity checks over `AuthoritySelectionInputs`.
//!
//! Wraps IOG's vendored `authority-selection-inherents` (which validates
//! per-entry correctness but does NOT enforce whole-input invariants like
//! per-epoch caps, cross-entry key dedup, or `d_parameter` vs
//! `MaxValidators` bounds). Bad individual entries are dropped (fail-open
//! for liveness); top-level invariant violations reject the whole input
//! so the session pallet reuses the previous committee.

use alloc::vec::Vec;
use authority_selection_inherents::authority_selection_inputs::AuthoritySelectionInputs;
use sidechain_domain::{PermissionedCandidateData, RegistrationData, StakeDelegation};

pub const MAX_PERMISSIONED_CANDIDATES: usize = 64;
pub const MAX_REGISTRATIONS_PER_EPOCH: usize = 256;
pub const MAX_EPOCH_NONCE_BYTES: usize = 64;
/// 45 bn ADA × 1e6 lovelace. Total ADA supply; anything above is
/// definitionally corrupt db-sync output.
pub const MAX_PLAUSIBLE_STAKE_LOVELACE: u64 = 45_000_000_000u64 * 1_000_000u64;
/// Upper bound on seats-per-epoch accepted from a Cardano-sourced
/// `AuthoritySelectionInputs.d_parameter`. MUST stay in lockstep with
/// `OrinqReceipts::MaxCommitteeSize` — otherwise Ariadne sanitation
/// silently rejects values the pallet would accept.
pub const MAX_COMMITTEE_SIZE: u16 = {
    // `select_authorities`' return BoundedVec is bounded by MaxValidators
    // and downstream consumers treat counts as u16.
    assert!(crate::MAX_VALIDATORS <= u16::MAX as u32);
    96
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

pub fn sanitize_authority_selection_inputs(
    mut inputs: AuthoritySelectionInputs,
) -> Result<(AuthoritySelectionInputs, SanityReport), SanityError> {
    let mut report = SanityReport::default();

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

    inputs.permissioned_candidates =
        sanitize_permissioned(inputs.permissioned_candidates, &mut report);

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

    registered.retain(|c| match c.stake_delegation {
        Some(StakeDelegation(s)) if s > MAX_PLAUSIBLE_STAKE_LOVELACE => {
            report.record(DropReason::ImplausibleStake);
            false
        }
        _ => true,
    });

    // Permissioned keys participate in cross-registration dedup: a
    // permissioned candidate who also submits an SPO registration with
    // the same keys only counts once — permissioned wins (first seen).
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
    // Outer entries whose last valid registration was stripped get
    // dropped so Ariadne doesn't see a stakeholder with zero surviving
    // registrations.
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

/// Logging wrapper around `sanitize_authority_selection_inputs`. Logs a
/// single summary line per pass (counts-per-reason) so a 256-entry flood
/// of bad registrations doesn't generate 256 log lines.
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

    /// Boundary test: a d_parameter summing exactly to MAX_COMMITTEE_SIZE
    /// (96) must PASS. Pins the cap; complements the `_to_97` test below
    /// against regressions where `MAX_COMMITTEE_SIZE` gets decoupled from
    /// the orinq-receipts pallet cap.
    #[test]
    fn input_sanity_accepts_d_param_summing_to_96() {
        let mut i = inputs_ok();
        i.d_parameter.num_permissioned_candidates = 60;
        i.d_parameter.num_registered_candidates = 36;
        assert_eq!(
            i.d_parameter.num_permissioned_candidates + i.d_parameter.num_registered_candidates,
            96,
            "test precondition: d-param must sum to 96"
        );
        let (cleaned, _report) = sanitize_authority_selection_inputs(i).unwrap();
        assert_eq!(cleaned.d_parameter.num_permissioned_candidates, 60);
        assert_eq!(cleaned.d_parameter.num_registered_candidates, 36);
    }

    /// Boundary test: one over the cap must fail. Complements
    /// `input_sanity_accepts_d_param_summing_to_96`.
    #[test]
    fn input_sanity_rejects_d_param_summing_to_97() {
        let mut i = inputs_ok();
        i.d_parameter.num_permissioned_candidates = 60;
        i.d_parameter.num_registered_candidates = 37;
        assert_eq!(
            i.d_parameter.num_permissioned_candidates + i.d_parameter.num_registered_candidates,
            97,
            "test precondition: d-param must sum to 97"
        );
        let err = sanitize_authority_selection_inputs(i).unwrap_err();
        match err {
            SanityError::DParamTooLarge { permissioned, registered, cap } => {
                assert_eq!(permissioned, 60);
                assert_eq!(registered, 37);
                assert_eq!(cap, 96, "cap must report as 96 in the error");
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
            cr(42, vec![reg_data(5, 15, 25)], 99_999),
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
            cr(41, vec![reg_data(4, 15, 25)], 2_000),
        ];
        let (cleaned, report) = sanitize_authority_selection_inputs(i).unwrap();
        // Second outer entry has its only registration stripped → outer dropped.
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
