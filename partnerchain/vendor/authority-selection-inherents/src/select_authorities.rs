//! Functionality related to selecting the validators from the valid candidates

use crate::authority_selection_inputs::AuthoritySelectionInputs;
use crate::filter_invalid_candidates::{
	filter_invalid_permissioned_candidates, filter_trustless_candidates_registrations, Candidate,
	CandidateWithStake,
};
use alloc::vec::Vec;
use frame_support::BoundedVec;
use log::{info, warn};
use plutus::*;
use selection::{Weight, WeightedRandomSelectionConfig};
use sidechain_domain::{DParameter, ScEpochNumber, UtxoId};
use sp_core::{ecdsa, ed25519, sr25519, Get};

// [materios-patch: ariadne-output-dedup]
// The IOG weighted_selection sampler samples WITH REPLACEMENT, which can emit
// the same validator multiple times in a single committee. GRANDPA treats
// duplicates as one voter, so pathological draws like [MacBook×3, Node-3×1]
// reduce the effective threshold to 1-of-distinct against 2f+1, causing
// finality stalls when the duplicated validator is offline. Observed in
// production 2026-04-21 (finality stuck at #26197 for 4h30m).
//
// Safety floor: if dedup would leave fewer than this many distinct validators,
// `select_authorities` returns None so the pallet's fallback path reuses
// `CurrentCommittee` instead of installing an unsafe rotation.
pub const MIN_DISTINCT_COMMITTEE: usize = 2;

/// Collapse duplicate entries, keeping first occurrence. Order-preserving,
/// deterministic, idempotent. Used to fix Ariadne's with-replacement sampler
/// output before passing to the session pallet.
///
/// [materios-patch: ariadne-output-dedup]
pub fn dedup_committee<K: PartialEq + Clone, V: Clone>(input: Vec<(K, V)>) -> Vec<(K, V)> {
	let mut out: Vec<(K, V)> = Vec::with_capacity(input.len());
	for entry in input {
		if !out.iter().any(|(k, _)| k == &entry.0) {
			out.push(entry);
		}
	}
	out
}

type CandidateWithWeight<A, B> = (Candidate<A, B>, Weight);

/// Pseudo-random selection the authorities for the given sidechain epoch, according to the
/// Ariadne specification: https://input-output.atlassian.net/wiki/spaces/SID/pages/4228612151/Ariadne+-+committee+selection+algorithm
///
/// Seed is constructed from the MC epoch nonce and the sidechain epoch.
///
/// Committee size is P+T, where P (permissioned) and T (trustless) are constituents of the D parameter.
///
/// Committee is a result of the weighted selection with repetition.
///
/// Weight function for trustless candidate is:
///   * let `n` be the number of permissioned candidates from MC data
///   * if `n == 0`, then the weight is `stake_delegation`
///   * otherwise, the weight is `n * T * stake_delegation`
///
/// Weight for each permissioned candidates is:
///   * let `W` be the sum of all stake delegations of trustless candidates
///   * if `W == 0` or `T == 0` (there are no valid trustless candidates, or they are not taken into account), then the weight is `1`
///   * otherwise, the weight is `P * W`
pub fn select_authorities<
	TAccountId: Clone + Ord + TryFrom<sidechain_domain::SidechainPublicKey> + From<ecdsa::Public>,
	TAccountKeys: Clone + From<(sr25519::Public, ed25519::Public)>,
	MaxValidators: Get<u32>,
>(
	genesis_utxo: UtxoId,
	input: AuthoritySelectionInputs,
	sidechain_epoch: ScEpochNumber,
) -> Option<BoundedVec<(TAccountId, TAccountKeys), MaxValidators>> {
	let valid_trustless_candidates = filter_trustless_candidates_registrations::<
		TAccountId,
		TAccountKeys,
	>(input.registered_candidates, genesis_utxo);
	let valid_permissioned_candidates =
		filter_invalid_permissioned_candidates(input.permissioned_candidates);

	let mut candidates_with_weight = trustless_candidates_with_weights(
		&valid_trustless_candidates,
		&input.d_parameter,
		valid_permissioned_candidates.len(),
	);
	candidates_with_weight.extend(permissioned_candidates_with_weights(
		&valid_permissioned_candidates,
		&input.d_parameter,
		&valid_trustless_candidates,
	));
	candidates_with_weight.sort_by(|a, b| a.0.account_id.cmp(&b.0.account_id));

	let random_seed =
		selection::impls::seed_from_nonce_and_sc_epoch(&input.epoch_nonce, &sidechain_epoch);
	let committee_size =
		input.d_parameter.num_registered_candidates + input.d_parameter.num_permissioned_candidates;
	if let Some(validators) =
		weighted_selection(candidates_with_weight, committee_size, random_seed)
	{
		let raw_len = validators.len();
		// [materios-patch: ariadne-output-dedup] Collapse duplicate validators
		// produced by the with-replacement weighted-random sampler. GRANDPA
		// treats duplicates as a single voter; pathological draws such as the
		// 2026-04-21 [MacBook×3, Node-3×1] seat assignment must not reach the
		// session pallet as-is.
		let validators = dedup_committee(validators);
		if validators.len() < raw_len {
			warn!(
				"[materios-patch] ariadne output for epoch {} had {} duplicate seats; deduped to {} distinct validators",
				sidechain_epoch,
				raw_len - validators.len(),
				validators.len()
			);
		}
		// [materios-patch: ariadne-output-dedup] Safety floor. If the distinct
		// set is too small to form a safe committee, refuse the rotation —
		// the pallet fallback reuses `CurrentCommittee`, mirroring the
		// IDP-None behavior documented in feedback_iog_idp_none_panic.md.
		if validators.len() < MIN_DISTINCT_COMMITTEE {
			warn!(
				"[materios-patch] ariadne output for epoch {} has only {} distinct validators (< MIN_DISTINCT_COMMITTEE={}); refusing rotation, pallet will reuse current committee",
				sidechain_epoch,
				validators.len(),
				MIN_DISTINCT_COMMITTEE
			);
			return None;
		}
		let validators = BoundedVec::truncate_from(validators);
		info!("💼 Selected committee of {} seats for epoch {} from {} permissioned and {} registered candidates", validators.len(), sidechain_epoch, valid_permissioned_candidates.len(), valid_trustless_candidates.len());
		Some(validators)
	} else {
		warn!("🚫 Failed to select validators for epoch {}", sidechain_epoch);
		None
	}
}

fn trustless_candidates_with_weights<A: Clone, B: Clone>(
	trustless_candidates: &[CandidateWithStake<A, B>],
	d_parameter: &DParameter,
	permissioned_candidates_count: usize,
) -> Vec<CandidateWithWeight<A, B>> {
	let weight_factor = if permissioned_candidates_count > 0 {
		u128::from(d_parameter.num_registered_candidates) * permissioned_candidates_count as u128
	} else {
		1 // if there are no permissioned candidates, trustless candidates should be selected using unmodified stake
	};
	trustless_candidates
		.iter()
		.map(|c| (c.candidate.clone(), u128::from(c.stake_delegation.0) * weight_factor))
		.collect()
}

fn permissioned_candidates_with_weights<A: Clone, B: Clone>(
	permissioned_candidates: &[Candidate<A, B>],
	d_parameter: &DParameter,
	valid_trustless_candidates: &[CandidateWithStake<A, B>],
) -> Vec<CandidateWithWeight<A, B>> {
	let total_stake: u64 = valid_trustless_candidates.iter().map(|c| c.stake_delegation.0).sum();
	let weight = if total_stake > 0 && d_parameter.num_registered_candidates > 0 {
		u128::from(d_parameter.num_permissioned_candidates) * u128::from(total_stake)
	} else {
		1 // if there are no trustless candidates, permissioned candidates should be selected with equal weight
	};
	permissioned_candidates.iter().map(|c| (c.clone(), weight)).collect::<Vec<_>>()
}

fn weighted_selection<TAccountId: Clone + Ord, TAccountKeys: Clone>(
	candidates: Vec<CandidateWithWeight<TAccountId, TAccountKeys>>,
	size: u16,
	random_seed: [u8; 32],
) -> Option<Vec<(TAccountId, TAccountKeys)>> {
	Some(
		WeightedRandomSelectionConfig { size }
			.select_authorities(candidates, random_seed)?
			.into_iter()
			.map(|c| (c.account_id, c.account_keys))
			.collect(),
	)
}

#[cfg(test)]
mod dedup_tests {
	//! Tests for `dedup_committee`. These tests pin down the exact semantics
	//! required by the Ariadne-output-dedup [materios-patch]:
	//!   - order-preserving (first occurrence wins)
	//!   - deterministic (no randomness)
	//!   - idempotent (dedup(dedup(x)) == dedup(x))
	//!   - length-non-increasing
	//!   - the pathological 2026-04-21 draw `[MacBook×3, Node-3×1]` collapses
	//!     to `[MacBook, Node-3]`, preserving first-occurrence order.
	use super::dedup_committee;

	type K = &'static str;
	type V = u32;

	#[test]
	fn empty_input_returns_empty() {
		let input: Vec<(K, V)> = vec![];
		assert_eq!(dedup_committee(input), Vec::<(K, V)>::new());
	}

	#[test]
	fn no_duplicates_passes_through() {
		let input: Vec<(K, V)> = vec![("alice", 1), ("bob", 2), ("charlie", 3)];
		let expected = input.clone();
		assert_eq!(dedup_committee(input), expected);
	}

	#[test]
	fn all_same_pubkey_collapses_to_one() {
		let input: Vec<(K, V)> =
			vec![("mac", 1), ("mac", 1), ("mac", 1), ("mac", 1)];
		let expected: Vec<(K, V)> = vec![("mac", 1)];
		assert_eq!(dedup_committee(input), expected);
	}

	#[test]
	fn pathological_macbook_times_three_collapses_to_two() {
		// Exact 2026-04-21 Ariadne output that caused the finality stall.
		// MacBook seat #1, #2, #3 (same pubkey) + Node-3 seat #1.
		// Expected: distinct-validator committee = [MacBook, Node-3]
		let input: Vec<(K, V)> =
			vec![("macbook", 10), ("macbook", 10), ("macbook", 10), ("node-3", 20)];
		let expected: Vec<(K, V)> = vec![("macbook", 10), ("node-3", 20)];
		assert_eq!(dedup_committee(input), expected);
	}

	#[test]
	fn mixed_interleaved_keeps_first_occurrence() {
		// Alice, Bob, Alice, Charlie, Bob — first-occurrence wins.
		let input: Vec<(K, V)> =
			vec![("alice", 1), ("bob", 2), ("alice", 1), ("charlie", 3), ("bob", 2)];
		let expected: Vec<(K, V)> = vec![("alice", 1), ("bob", 2), ("charlie", 3)];
		assert_eq!(dedup_committee(input), expected);
	}

	#[test]
	fn dedup_is_idempotent() {
		let input: Vec<(K, V)> =
			vec![("alice", 1), ("bob", 2), ("alice", 1), ("charlie", 3), ("bob", 2)];
		let once = dedup_committee(input.clone());
		let twice = dedup_committee(once.clone());
		assert_eq!(once, twice);
	}

	#[test]
	fn dedup_preserves_first_occurrence_order() {
		// Insert duplicates scattered; the output must keep the first-seen
		// positional order — not alphabetical, not stable-sort, not last-wins.
		let input: Vec<(K, V)> = vec![
			("zebra", 1),
			("alpha", 2),
			("zebra", 1),
			("mike", 3),
			("alpha", 2),
			("mike", 3),
		];
		let expected: Vec<(K, V)> = vec![("zebra", 1), ("alpha", 2), ("mike", 3)];
		assert_eq!(dedup_committee(input), expected);
	}

	#[test]
	fn dedup_never_increases_length() {
		let inputs: Vec<Vec<(K, V)>> = vec![
			vec![],
			vec![("a", 1)],
			vec![("a", 1), ("b", 2)],
			vec![("a", 1), ("a", 1)],
			vec![("a", 1), ("b", 2), ("a", 1), ("c", 3), ("b", 2)],
		];
		for input in inputs {
			let original_len = input.len();
			let out_len = dedup_committee(input).len();
			assert!(
				out_len <= original_len,
				"dedup output length {} exceeds input length {}",
				out_len,
				original_len
			);
		}
	}
}
