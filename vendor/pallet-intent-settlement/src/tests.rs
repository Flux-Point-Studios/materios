//! Unit tests for `pallet_intent_settlement` — happy + sad paths for every
//! extrinsic, plus TTL sweep, idempotency, and fairness-proof invariant tests.

#![cfg(test)]

use crate as pallet_intent_settlement;
use crate::pallet::{IsCommitteeMember, VerifyCommitteeSignature};
use crate::types::*;
use crate::{credit_deposit_payload, request_voucher_payload, settle_claim_payload};
use codec::Encode;
use frame_support::{
    assert_noop, assert_ok, construct_runtime, derive_impl, parameter_types,
    traits::Hooks,
    BoundedVec,
};
use parity_scale_codec as codec;
use sp_core::H256;
use sp_runtime::{
    traits::IdentityLookup,
    BuildStorage,
};

// ---------------------------------------------------------------------------
// Mock runtime
// ---------------------------------------------------------------------------

type Block = frame_system::mocking::MockBlock<Test>;

construct_runtime! {
    pub enum Test {
        System: frame_system,
        IntentSettlement: pallet_intent_settlement,
    }
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
}

parameter_types! {
    pub const MaxCommittee: u32 = 32;
    pub const MaxExpirePerBlock: u32 = 256;
    pub const DefaultIntentTTL: u32 = 600;
    pub const DefaultClaimTTL: u32 = 28_800;
    /// Issue #6: test runtime bound on PendingBatches index.
    pub const MaxPendingBatches: u32 = 16;
    /// Issue #7: preprod default.
    pub const DefaultMinSignerThreshold: u32 = 2;
    /// Task #177: test-runtime bound on `settle_batch_atomic` size.
    /// Mirror the prod default (256) so the unit-test scaling assertions
    /// reflect what the live chain will see.
    pub const MaxSettleBatch: u32 = 256;
    /// Task #211: test-runtime bound on `attest_batch_intents` size.
    pub const MaxAttestBatch: u32 = 256;
    /// Task #212: test-runtime bound on `request_batch_vouchers` size.
    pub const MaxVoucherBatch: u32 = 256;
    /// Task #210: test-runtime bound on `submit_batch_intents` size.
    pub const MaxSubmitBatch: u32 = 256;
}

/// Issue #4 helper: our tests use `u64` AccountIds. Derive a synthetic
/// `CommitteePubkey` by left-padding the u64's little-endian bytes into the
/// 32-byte slot (matches the left-pad semantics of `account_to_bytes`).
pub fn mock_pubkey_of(who: &u64) -> CommitteePubkey {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&who.to_le_bytes());
    out
}

pub fn mock_account_of_pubkey(pubkey: &CommitteePubkey) -> Option<u64> {
    // Reverse the left-pad: first 8 bytes = LE u64.
    let mut lo = [0u8; 8];
    lo.copy_from_slice(&pubkey[..8]);
    let candidate = u64::from_le_bytes(lo);
    if matches!(candidate, 1 | 2 | 3) && pubkey[8..].iter().all(|b| *b == 0) {
        Some(candidate)
    } else {
        None
    }
}

/// Mock committee: fixed threshold 2, members {1, 2, 3}.
pub struct MockCommittee;
impl IsCommitteeMember<u64> for MockCommittee {
    fn is_member(who: &u64) -> bool {
        matches!(*who, 1 | 2 | 3)
    }
    fn threshold() -> u32 {
        2
    }
    fn member_count() -> u32 {
        3
    }
    fn pubkey_of(who: &u64) -> CommitteePubkey {
        mock_pubkey_of(who)
    }
    fn account_of_pubkey(pubkey: &CommitteePubkey) -> Option<u64> {
        mock_account_of_pubkey(pubkey)
    }
}

/// Issue #7: deterministic stub verifier used by the test runtime. Tests
/// exercise the M-of-N + distinct-signer logic (the expensive bit) without
/// having to produce real sr25519 signatures over each canonical payload —
/// a signature is "valid" iff its first byte == pubkey's first byte (the
/// easiest-to-read marker that still lets `test_invalid_signature_rejected`
/// exercise the rejection path).
pub struct MockSigVerifier;
impl VerifyCommitteeSignature for MockSigVerifier {
    fn verify(pubkey: &CommitteePubkey, sig: &CommitteeSig, _msg: &[u8]) -> bool {
        sig[0] == pubkey[0]
    }
}

/// Construct a valid `(pubkey, sig)` pair for a given committee member and
/// payload. The sig is just `[pubkey[0]; 64]` which the `MockSigVerifier`
/// accepts; real sr25519 verification exercises the same code path in prod.
pub fn mock_sig_for(member: u64) -> (CommitteePubkey, CommitteeSig) {
    let pk = mock_pubkey_of(&member);
    let mut sig = [0u8; 64];
    sig[0] = pk[0];
    (pk, sig)
}

/// Build a 2-of-3 signature envelope for `settle_claim` from members 1 and 2.
pub fn mock_settle_sigs() -> Vec<(CommitteePubkey, CommitteeSig)> {
    vec![mock_sig_for(1), mock_sig_for(2)]
}

/// Build a 2-of-3 signature envelope for `credit_deposit` from members 1 and 2.
pub fn mock_credit_sigs() -> Vec<(CommitteePubkey, CommitteeSig)> {
    vec![mock_sig_for(1), mock_sig_for(2)]
}

/// Task #174: build a 2-of-3 signature envelope for `request_voucher` from
/// members 1 and 2. The MockSigVerifier ignores the payload (accepts iff
/// `sig[0] == pubkey[0]`) so the same `mock_sig_for` helper works regardless
/// of which canonical pre-image the pallet hashes — what we're actually
/// exercising in unit tests is the pallet's threshold + caller-binding +
/// distinct-signer + member-only checks. The payload-binding is exercised
/// in `integration.rs` where the IntegrationSigVerifier uses real sr25519
/// over the canonical pre-image.
pub fn mock_voucher_sigs() -> Vec<(CommitteePubkey, CommitteeSig)> {
    vec![mock_sig_for(1), mock_sig_for(2)]
}

impl pallet_intent_settlement::pallet::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type MaxCommittee = MaxCommittee;
    type MaxExpirePerBlock = MaxExpirePerBlock;
    type DefaultIntentTTL = DefaultIntentTTL;
    type DefaultClaimTTL = DefaultClaimTTL;
    type CommitteeMembership = MockCommittee;
    type MaxPendingBatches = MaxPendingBatches;
    type DefaultMinSignerThreshold = DefaultMinSignerThreshold;
    type SigVerifier = MockSigVerifier;
    type MaxSettleBatch = MaxSettleBatch;
    type MaxAttestBatch = MaxAttestBatch;
    type MaxVoucherBatch = MaxVoucherBatch;
    type MaxSubmitBatch = MaxSubmitBatch;
}

pub const ALICE: u64 = 100;
pub const BOB: u64 = 101;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    let mut ext = sp_io::TestExternalities::new(t);
    ext.execute_with(|| {
        System::set_block_number(1);
        pallet_intent_settlement::pallet::IntentTTL::<Test>::put(600u32);
        pallet_intent_settlement::pallet::ClaimTTL::<Test>::put(28_800u32);
        pallet_intent_settlement::pallet::PoolUtilization::<Test>::put(
            PoolUtilizationParams {
                target_bps: 5_000,
                cap_bps: 7_500,
                total_nav_ada: 10_000_000, // 10 ADA
                outstanding_coverage_ada: 0,
            },
        );
        // Issue #7: seed the M-of-N floor (tests default to the preprod 2-of-N).
        pallet_intent_settlement::pallet::MinSignerThreshold::<Test>::put(2u32);
    });
    ext
}

fn bp(id: u8, strike: u64, premium: u64) -> IntentKind {
    IntentKind::BuyPolicy {
        product_id: H256::from([id; 32]),
        strike,
        term_slots: 86_400,
        premium_ada: premium,
        beneficiary_cardano_addr: BoundedVec::try_from(vec![0xA1u8; 57]).unwrap(),
    }
}

fn intent_id_for(account: u64, nonce: u64, kind: &IntentKind, blk: u32) -> IntentId {
    let mut buf = [0u8; 32];
    let enc = account.encode();
    buf[..enc.len()].copy_from_slice(&enc);
    compute_intent_id(&buf, nonce, kind, blk)
}

// ---------------------------------------------------------------------------
// submit_intent — happy + sad
// ---------------------------------------------------------------------------

#[test]
fn submit_intent_happy_path_buy_policy_debits_credit_and_stores_intent() {
    new_test_ext().execute_with(|| {
        pallet_intent_settlement::pallet::Credits::<Test>::insert(ALICE, 1_000_000u64);
        let kind = bp(0xAB, 500_000, 500_000);
        let expected_id = intent_id_for(ALICE, 0, &kind, 1);

        assert_ok!(IntentSettlement::submit_intent(
            RuntimeOrigin::signed(ALICE),
            kind
        ));

        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(expected_id).unwrap();
        assert_eq!(intent.submitter, ALICE);
        assert_eq!(intent.nonce, 0);
        assert_eq!(intent.status, IntentStatus::Pending);
        assert_eq!(intent.submitted_block, 1);
        assert_eq!(intent.ttl_block, 1 + 600);

        assert_eq!(
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE),
            500_000u64
        );
        assert_eq!(
            pallet_intent_settlement::pallet::Nonces::<Test>::get(ALICE),
            1
        );
    });
}

#[test]
fn submit_intent_rejects_buy_policy_without_credit() {
    new_test_ext().execute_with(|| {
        // Alice has no credit
        let kind = bp(0xCD, 1, 1_000_000);
        assert_noop!(
            IntentSettlement::submit_intent(RuntimeOrigin::signed(ALICE), kind),
            pallet_intent_settlement::pallet::Error::<Test>::InsufficientCredit
        );
    });
}

#[test]
fn submit_intent_rejects_pool_utilization_exceeded() {
    new_test_ext().execute_with(|| {
        pallet_intent_settlement::pallet::Credits::<Test>::insert(ALICE, u64::MAX);
        // cap = 7500 bps of 10 ADA NAV = 7.5 ADA max outstanding. Try 9 ADA.
        let kind = bp(0xEF, 1, 9_000_000);
        assert_noop!(
            IntentSettlement::submit_intent(RuntimeOrigin::signed(ALICE), kind),
            pallet_intent_settlement::pallet::Error::<Test>::PoolUtilizationExceeded
        );
    });
}

#[test]
fn submit_intent_request_payout_doesnt_touch_credit() {
    new_test_ext().execute_with(|| {
        let kind = IntentKind::RequestPayout {
            policy_id: H256::from([7u8; 32]),
            oracle_evidence: BoundedVec::try_from(vec![0u8; 32]).unwrap(),
        };
        assert_ok!(IntentSettlement::submit_intent(
            RuntimeOrigin::signed(BOB),
            kind
        ));
        assert_eq!(
            pallet_intent_settlement::pallet::Credits::<Test>::get(BOB),
            0
        );
    });
}

#[test]
fn submit_intent_auto_increments_nonce() {
    new_test_ext().execute_with(|| {
        pallet_intent_settlement::pallet::Credits::<Test>::insert(ALICE, 10_000_000u64);
        for n in 0u64..3 {
            let kind = bp((n as u8).wrapping_add(1), 1, 100_000);
            assert_ok!(IntentSettlement::submit_intent(
                RuntimeOrigin::signed(ALICE),
                kind
            ));
            assert_eq!(
                pallet_intent_settlement::pallet::Nonces::<Test>::get(ALICE),
                n + 1
            );
        }
    });
}

// ---------------------------------------------------------------------------
// attest_intent — happy, threshold-crossing, idempotency, non-member
// ---------------------------------------------------------------------------

fn submit_and_get_id(account: u64) -> IntentId {
    let kind = IntentKind::RequestPayout {
        policy_id: H256::from([11u8; 32]),
        oracle_evidence: BoundedVec::try_from(vec![0u8; 8]).unwrap(),
    };
    let expected = intent_id_for(account, 0, &kind, 1);
    assert_ok!(IntentSettlement::submit_intent(
        RuntimeOrigin::signed(account),
        kind
    ));
    expected
}

#[test]
fn attest_intent_first_signer_keeps_pending() {
    new_test_ext().execute_with(|| {
        let iid = submit_and_get_id(ALICE);
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(1),
            iid,
            mock_pubkey_of(&1),
            [0u8; 64]
        ));
        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
        assert_eq!(intent.status, IntentStatus::Pending);
    });
}

#[test]
fn attest_intent_crosses_threshold_attests() {
    new_test_ext().execute_with(|| {
        let iid = submit_and_get_id(ALICE);
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(1),
            iid,
            mock_pubkey_of(&1),
            [0u8; 64]
        ));
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(2),
            iid,
            mock_pubkey_of(&2),
            [0u8; 64]
        ));
        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
        assert_eq!(intent.status, IntentStatus::Attested);
        let sigs =
            pallet_intent_settlement::pallet::AttestationSigs::<Test>::get(iid).unwrap();
        assert_eq!(sigs.len(), 2);
    });
}

#[test]
fn attest_intent_rejects_non_member() {
    new_test_ext().execute_with(|| {
        let iid = submit_and_get_id(ALICE);
        assert_noop!(
            IntentSettlement::attest_intent(
                RuntimeOrigin::signed(ALICE), // ALICE=100, not in {1,2,3}
                iid,
                mock_pubkey_of(&ALICE),
                [0u8; 64]
            ),
            pallet_intent_settlement::pallet::Error::<Test>::NotCommitteeMember
        );
    });
}

#[test]
fn attest_intent_duplicate_pubkey_is_noop() {
    // Two members can no longer share a pubkey (Issue #4 binds pubkey to
    // caller identity), so this test now exercises the dedup guard via the
    // *same* member retrying: the bundle already has member 1's pubkey, the
    // second call is ignored.
    new_test_ext().execute_with(|| {
        let iid = submit_and_get_id(ALICE);
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(1),
            iid,
            mock_pubkey_of(&1),
            [0u8; 64]
        ));
        // Same member 1 retries — dedup by pubkey makes this a no-op.
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(1),
            iid,
            mock_pubkey_of(&1),
            [0u8; 64]
        ));
        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
        assert_eq!(intent.status, IntentStatus::Pending);
        let b =
            pallet_intent_settlement::pallet::PendingAttestations::<Test>::get(iid);
        assert_eq!(b.len(), 1);
    });
}

#[test]
fn attest_intent_after_attested_is_idempotent() {
    new_test_ext().execute_with(|| {
        let iid = submit_and_get_id(ALICE);
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(1),
            iid,
            mock_pubkey_of(&1),
            [0u8; 64]
        ));
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(2),
            iid,
            mock_pubkey_of(&2),
            [0u8; 64]
        ));
        // Third signer arrives late — pallet must treat as no-op.
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(3),
            iid,
            mock_pubkey_of(&3),
            [0u8; 64]
        ));
        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
        assert_eq!(intent.status, IntentStatus::Attested);
    });
}

// ---------------------------------------------------------------------------
// request_voucher — happy, invariant violations, state mismatch
// ---------------------------------------------------------------------------

fn attested_intent() -> IntentId {
    let iid = submit_and_get_id(ALICE);
    assert_ok!(IntentSettlement::attest_intent(
        RuntimeOrigin::signed(1),
        iid,
        mock_pubkey_of(&1),
        [0u8; 64]
    ));
    assert_ok!(IntentSettlement::attest_intent(
        RuntimeOrigin::signed(2),
        iid,
        mock_pubkey_of(&2),
        [0u8; 64]
    ));
    iid
}

fn good_fairness_proof(iid: IntentId, amount: u64) -> BatchFairnessProof {
    BatchFairnessProof {
        batch_block_range: (1, 1),
        sorted_intent_ids: BoundedVec::try_from(vec![iid]).unwrap(),
        requested_amounts_ada: BoundedVec::try_from(vec![amount]).unwrap(),
        pool_balance_ada: amount.saturating_mul(10),
        pro_rata_scale_bps: 10_000,
        awarded_amounts_ada: BoundedVec::try_from(vec![amount]).unwrap(),
    }
}

fn good_voucher(
    claim_id: ClaimId,
    bfpr: &BatchFairnessProof,
    amount: u64,
) -> Voucher {
    Voucher {
        claim_id,
        policy_id: H256::from([9u8; 32]),
        beneficiary_cardano_addr: BoundedVec::try_from(vec![0xB1u8; 57]).unwrap(),
        amount_ada: amount,
        batch_fairness_proof_digest: compute_fairness_proof_digest(bfpr),
        issued_block: 2,
        expiry_slot_cardano: 100_000,
        committee_sigs: BoundedVec::try_from(vec![
            (mock_pubkey_of(&1), [0u8; 64]),
            (mock_pubkey_of(&2), [0u8; 64]),
        ])
        .unwrap(),
    }
}

#[test]
fn request_voucher_happy_path() {
    new_test_ext().execute_with(|| {
        let iid = attested_intent();
        let claim_id = H256::from([42u8; 32]);
        let bfpr = good_fairness_proof(iid, 1_000_000);
        let voucher = good_voucher(claim_id, &bfpr, 1_000_000);

        assert_ok!(IntentSettlement::request_voucher(
            RuntimeOrigin::signed(1),
            claim_id,
            iid,
            voucher.clone(),
            bfpr.clone(),
            mock_voucher_sigs()
        ));

        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
        assert_eq!(intent.status, IntentStatus::Vouchered);
        assert!(
            pallet_intent_settlement::pallet::Vouchers::<Test>::contains_key(claim_id)
        );
        assert!(
            pallet_intent_settlement::pallet::Claims::<Test>::contains_key(claim_id)
        );
    });
}

#[test]
fn request_voucher_rejects_pending_intent() {
    new_test_ext().execute_with(|| {
        let iid = submit_and_get_id(ALICE); // still Pending
        let claim_id = H256::from([42u8; 32]);
        let bfpr = good_fairness_proof(iid, 1_000);
        let voucher = good_voucher(claim_id, &bfpr, 1_000);
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                claim_id,
                iid,
                voucher,
                bfpr,
                mock_voucher_sigs()
            ),
            pallet_intent_settlement::pallet::Error::<Test>::IntentStatusMismatch
        );
    });
}

#[test]
fn request_voucher_rejects_bad_pro_rata_scale() {
    new_test_ext().execute_with(|| {
        let iid = attested_intent();
        let claim_id = H256::from([7u8; 32]);
        let mut bfpr = good_fairness_proof(iid, 1_000);
        bfpr.pro_rata_scale_bps = 10_001; // >100%
        // awarded now violates invariant even without the scale check
        let voucher = good_voucher(claim_id, &bfpr, 1_000);
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                claim_id,
                iid,
                voucher,
                bfpr,
                mock_voucher_sigs()
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InvalidFairnessProof
        );
    });
}

#[test]
fn request_voucher_rejects_awarded_mismatch() {
    new_test_ext().execute_with(|| {
        let iid = attested_intent();
        let claim_id = H256::from([9u8; 32]);
        let mut bfpr = good_fairness_proof(iid, 1_000);
        // award too high vs requested*scale/10000
        bfpr.awarded_amounts_ada = BoundedVec::try_from(vec![1_500u64]).unwrap();
        let voucher = good_voucher(claim_id, &bfpr, 1_500);
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                claim_id,
                iid,
                voucher,
                bfpr,
                mock_voucher_sigs()
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InvalidFairnessProof
        );
    });
}

#[test]
fn request_voucher_rejects_awarded_exceeds_pool() {
    new_test_ext().execute_with(|| {
        let iid = attested_intent();
        let claim_id = H256::from([11u8; 32]);
        let bfpr = BatchFairnessProof {
            batch_block_range: (1, 1),
            sorted_intent_ids: BoundedVec::try_from(vec![iid]).unwrap(),
            requested_amounts_ada: BoundedVec::try_from(vec![1_000_000u64]).unwrap(),
            pool_balance_ada: 100_000, // only 0.1 ADA in pool
            pro_rata_scale_bps: 10_000,
            awarded_amounts_ada: BoundedVec::try_from(vec![1_000_000u64]).unwrap(),
        };
        let voucher = good_voucher(claim_id, &bfpr, 1_000_000);
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                claim_id,
                iid,
                voucher,
                bfpr,
                mock_voucher_sigs()
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InvalidFairnessProof
        );
    });
}

#[test]
fn request_voucher_rejects_digest_mismatch() {
    new_test_ext().execute_with(|| {
        let iid = attested_intent();
        let claim_id = H256::from([13u8; 32]);
        let bfpr = good_fairness_proof(iid, 1_000_000);
        let mut voucher = good_voucher(claim_id, &bfpr, 1_000_000);
        voucher.batch_fairness_proof_digest = [0xFFu8; 32]; // wrong digest
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                claim_id,
                iid,
                voucher,
                bfpr,
                mock_voucher_sigs()
            ),
            pallet_intent_settlement::pallet::Error::<Test>::FairnessDigestMismatch
        );
    });
}

#[test]
fn request_voucher_rejects_duplicate_claim() {
    // First voucher succeeds. Second attempt on the same claim_id against a
    // *different* attested intent must be rejected with DuplicateVoucher
    // (rather than IntentStatusMismatch) — the duplicate-check fires before
    // the state-transition check.
    new_test_ext().execute_with(|| {
        let iid1 = attested_intent();
        let claim_id = H256::from([99u8; 32]);
        let bfpr1 = good_fairness_proof(iid1, 1_000_000);
        let voucher1 = good_voucher(claim_id, &bfpr1, 1_000_000);
        assert_ok!(IntentSettlement::request_voucher(
            RuntimeOrigin::signed(1),
            claim_id,
            iid1,
            voucher1,
            bfpr1,
            mock_voucher_sigs()
        ));

        // Second attested intent, same claim_id.
        let kind = IntentKind::RequestPayout {
            policy_id: H256::from([22u8; 32]),
            oracle_evidence: BoundedVec::try_from(vec![1u8; 8]).unwrap(),
        };
        let iid2 = intent_id_for(BOB, 0, &kind, 1);
        assert_ok!(IntentSettlement::submit_intent(
            RuntimeOrigin::signed(BOB),
            kind
        ));
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(1),
            iid2,
            mock_pubkey_of(&1),
            [0u8; 64]
        ));
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(2),
            iid2,
            mock_pubkey_of(&2),
            [0u8; 64]
        ));
        let bfpr2 = good_fairness_proof(iid2, 500_000);
        let voucher2 = good_voucher(claim_id, &bfpr2, 500_000);

        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                claim_id,
                iid2,
                voucher2,
                bfpr2,
                mock_voucher_sigs()
            ),
            pallet_intent_settlement::pallet::Error::<Test>::DuplicateVoucher
        );
    });
}

// ---------------------------------------------------------------------------
// settle_claim / expire_policy_mirror / credit_deposit / request_credit_refund
// ---------------------------------------------------------------------------

#[test]
fn settle_claim_happy_path_flips_state_idempotently() {
    new_test_ext().execute_with(|| {
        let iid = attested_intent();
        let claim_id = H256::from([42u8; 32]);
        let bfpr = good_fairness_proof(iid, 1_000_000);
        let voucher = good_voucher(claim_id, &bfpr, 1_000_000);
        assert_ok!(IntentSettlement::request_voucher(
            RuntimeOrigin::signed(1),
            claim_id,
            iid,
            voucher,
            bfpr,
            mock_voucher_sigs()
        ));
        assert_ok!(IntentSettlement::settle_claim(
            RuntimeOrigin::signed(1),
            claim_id,
            [0xFFu8; 32],
            false,
            mock_settle_sigs()
        ));
        let claim =
            pallet_intent_settlement::pallet::Claims::<Test>::get(claim_id).unwrap();
        assert!(claim.settled);
        assert_eq!(claim.cardano_tx_hash, [0xFFu8; 32]);
        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
        assert_eq!(intent.status, IntentStatus::Settled);

        // Calling again is idempotent.
        assert_ok!(IntentSettlement::settle_claim(
            RuntimeOrigin::signed(1),
            claim_id,
            [0xEEu8; 32],
            true,
            mock_settle_sigs()
        ));
        let claim2 =
            pallet_intent_settlement::pallet::Claims::<Test>::get(claim_id).unwrap();
        // tx_hash NOT overwritten (idempotent = first-write-wins)
        assert_eq!(claim2.cardano_tx_hash, [0xFFu8; 32]);
        assert!(!claim2.settled_direct);
    });
}

#[test]
fn settle_claim_unknown_id_fails() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            IntentSettlement::settle_claim(
                RuntimeOrigin::signed(1),
                H256::from([0u8; 32]),
                [0u8; 32],
                false,
                mock_settle_sigs()
            ),
            pallet_intent_settlement::pallet::Error::<Test>::ClaimNotFound
        );
    });
}

#[test]
fn settle_claim_rejects_non_member() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            IntentSettlement::settle_claim(
                RuntimeOrigin::signed(ALICE),
                H256::from([0u8; 32]),
                [0u8; 32],
                false,
                mock_settle_sigs()
            ),
            pallet_intent_settlement::pallet::Error::<Test>::NotCommitteeMember
        );
    });
}

#[test]
fn expire_policy_mirror_flips_to_expired() {
    new_test_ext().execute_with(|| {
        let iid = submit_and_get_id(ALICE);
        assert_ok!(IntentSettlement::expire_policy_mirror(
            RuntimeOrigin::signed(1),
            iid
        ));
        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
        assert_eq!(intent.status, IntentStatus::Expired);
    });
}

#[test]
fn expire_policy_mirror_unknown_policy_fails() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            IntentSettlement::expire_policy_mirror(
                RuntimeOrigin::signed(1),
                H256::from([0u8; 32])
            ),
            pallet_intent_settlement::pallet::Error::<Test>::UnknownPolicy
        );
    });
}

#[test]
fn credit_deposit_happy_and_idempotent() {
    new_test_ext().execute_with(|| {
        let tx = [0xABu8; 32];
        assert_ok!(IntentSettlement::credit_deposit(
            RuntimeOrigin::signed(1),
            ALICE,
            1_500_000,
            tx,
            mock_credit_sigs()
        ));
        assert_eq!(
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE),
            1_500_000
        );
        assert_noop!(
            IntentSettlement::credit_deposit(
                RuntimeOrigin::signed(1),
                ALICE,
                1_500_000,
                tx,
                mock_credit_sigs()
            ),
            pallet_intent_settlement::pallet::Error::<Test>::DepositAlreadyProcessed
        );
    });
}

#[test]
fn credit_deposit_rejects_non_member() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            IntentSettlement::credit_deposit(
                RuntimeOrigin::signed(ALICE),
                ALICE,
                1_000,
                [0u8; 32],
                mock_credit_sigs()
            ),
            pallet_intent_settlement::pallet::Error::<Test>::NotCommitteeMember
        );
    });
}

#[test]
fn request_credit_refund_debits_immediately() {
    new_test_ext().execute_with(|| {
        pallet_intent_settlement::pallet::Credits::<Test>::insert(ALICE, 5_000_000u64);
        assert_ok!(IntentSettlement::request_credit_refund(
            RuntimeOrigin::signed(ALICE),
            2_000_000
        ));
        assert_eq!(
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE),
            3_000_000
        );
    });
}

#[test]
fn request_credit_refund_rejects_insufficient_credit() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            IntentSettlement::request_credit_refund(RuntimeOrigin::signed(ALICE), 1),
            pallet_intent_settlement::pallet::Error::<Test>::InsufficientCredit
        );
    });
}

// ---------------------------------------------------------------------------
// TTL sweep + pool_utilization governance
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Task #245: regression — fallback sweep must terminalize Pending intents
// whose `ExpiryQueue` enqueue silently overflowed the per-block bucket cap.
//
// Bug: `do_submit_intent` enqueues into `ExpiryQueue[ttl_block]` with
// `let _ = queue.try_push(intent_id);` (best-effort). With
// `MAX_EXPIRE_PER_BLOCK = 256` and burst submits sharing one `ttl_block`,
// the 257-th and onward ids are silently dropped — they were never swept,
// so `Intents` and `PendingBatches` retained them indefinitely.
//
// In the test we don't burst 257 intents (MaxPendingBatches=16 in the test
// mock makes that impossible). We instead simulate the post-overflow state
// by clearing the `ExpiryQueue` after submit. The on-chain state is then
// IDENTICAL to a real overflow: intent in `Intents`+`PendingBatches`,
// NOT in `ExpiryQueue`. The fallback sweep MUST terminalize it.
// ---------------------------------------------------------------------------

#[test]
fn ttl_fallback_sweep_recovers_intents_dropped_from_expiry_queue() {
    new_test_ext().execute_with(|| {
        pallet_intent_settlement::pallet::Credits::<Test>::insert(ALICE, 5_000_000u64);
        let kind_a = bp(0xA1, 1, 1_000_000);
        let kind_b = bp(0xB2, 2, 1_500_000);
        let iid_a = intent_id_for(ALICE, 0, &kind_a, 1);
        let iid_b = intent_id_for(ALICE, 1, &kind_b, 1);
        assert_ok!(IntentSettlement::submit_intent(
            RuntimeOrigin::signed(ALICE),
            kind_a
        ));
        assert_ok!(IntentSettlement::submit_intent(
            RuntimeOrigin::signed(ALICE),
            kind_b
        ));
        // Sanity: both in PendingBatches, both Pending, credit fully debited
        // (1M + 1.5M = 2.5M of 5M).
        let pb = pallet_intent_settlement::pallet::PendingBatches::<Test>::get();
        assert_eq!(pb.len(), 2);
        assert!(pb.contains(&iid_a) && pb.contains(&iid_b));
        assert_eq!(
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE),
            2_500_000
        );

        // Simulate the overflow drop: clear the ExpiryQueue bucket for
        // ttl_block = 1 + 600 = 601. After this, the state matches what
        // production saw with 9_300+ leaked intents (per Task #240 sample).
        let ttl_block: u32 = 1 + 600;
        pallet_intent_settlement::pallet::ExpiryQueue::<Test>::remove(ttl_block);

        // PRE-FIX: with the bucket empty, the original on_initialize would
        // never sweep these intents. We advance to ttl_block and run the
        // hook. The fallback sweep MUST pick them up.
        System::set_block_number(ttl_block as u64);
        <IntentSettlement as Hooks<u64>>::on_initialize(ttl_block as u64);

        // Both intents terminalized to Expired.
        let a = pallet_intent_settlement::pallet::Intents::<Test>::get(iid_a).unwrap();
        let b = pallet_intent_settlement::pallet::Intents::<Test>::get(iid_b).unwrap();
        assert_eq!(a.status, IntentStatus::Expired);
        assert_eq!(b.status, IntentStatus::Expired);

        // Both removed from PendingBatches (Issue #6 invariant preserved).
        let pb_after = pallet_intent_settlement::pallet::PendingBatches::<Test>::get();
        assert!(!pb_after.contains(&iid_a));
        assert!(!pb_after.contains(&iid_b));
        assert_eq!(pb_after.len(), 0);

        // Credits refunded (1M + 1.5M back to ALICE → 5M).
        assert_eq!(
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE),
            5_000_000
        );

        // Sweep counter incremented for observability.
        assert_eq!(
            pallet_intent_settlement::pallet::FallbackSweepCount::<Test>::get(),
            2
        );
    });
}

// Negative test: pre-TTL intents are NOT touched by the fallback sweep
// (only past-TTL Pending/Attested entries get terminalized).
#[test]
fn ttl_fallback_sweep_leaves_unexpired_intents_alone() {
    new_test_ext().execute_with(|| {
        pallet_intent_settlement::pallet::Credits::<Test>::insert(ALICE, 5_000_000u64);
        let kind = bp(0xC3, 3, 1_000_000);
        let iid = intent_id_for(ALICE, 0, &kind, 1);
        assert_ok!(IntentSettlement::submit_intent(
            RuntimeOrigin::signed(ALICE),
            kind
        ));

        // Even if the queue is mysteriously empty, an intent whose TTL has
        // NOT elapsed must remain Pending.
        let ttl_block: u32 = 1 + 600;
        pallet_intent_settlement::pallet::ExpiryQueue::<Test>::remove(ttl_block);

        // Run the hook at block 100 (well before TTL).
        System::set_block_number(100u64);
        <IntentSettlement as Hooks<u64>>::on_initialize(100u64);

        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
        assert_eq!(intent.status, IntentStatus::Pending);
        let pb = pallet_intent_settlement::pallet::PendingBatches::<Test>::get();
        assert!(pb.contains(&iid));
        assert_eq!(
            pallet_intent_settlement::pallet::FallbackSweepCount::<Test>::get(),
            0
        );
    });
}

// Bound test: even with PendingBatches at capacity AND every entry past
// TTL AND ExpiryQueue empty, a single block's fallback sweep terminalizes
// at most FALLBACK_SWEEP_PER_BLOCK entries (cost predictability), with
// the cursor advancing so subsequent blocks finish the job.
#[test]
fn ttl_fallback_sweep_is_bounded_per_block_and_cursor_advances() {
    use pallet_intent_settlement::types::FALLBACK_SWEEP_PER_BLOCK;
    new_test_ext().execute_with(|| {
        // Test runtime caps PendingBatches at 16 < FALLBACK_SWEEP_PER_BLOCK,
        // so a single block sweep terminalizes ALL of them and the
        // cursor wraps to 0. The bound is exercised structurally.
        pallet_intent_settlement::pallet::Credits::<Test>::insert(ALICE, 50_000_000u64);
        let mut iids = Vec::new();
        for i in 0..16u8 {
            let k = bp(i, 1, 100_000);
            let iid = intent_id_for(ALICE, i as u64, &k, 1);
            iids.push(iid);
            assert_ok!(IntentSettlement::submit_intent(
                RuntimeOrigin::signed(ALICE),
                k
            ));
        }
        assert_eq!(
            pallet_intent_settlement::pallet::PendingBatches::<Test>::get().len(),
            16
        );
        // Wipe ExpiryQueue to force fallback path.
        let ttl_block: u32 = 1 + 600;
        pallet_intent_settlement::pallet::ExpiryQueue::<Test>::remove(ttl_block);
        System::set_block_number(ttl_block as u64);
        <IntentSettlement as Hooks<u64>>::on_initialize(ttl_block as u64);

        // 16 < FALLBACK_SWEEP_PER_BLOCK (64), so all 16 cleared in one block.
        assert_eq!(
            pallet_intent_settlement::pallet::PendingBatches::<Test>::get().len(),
            0
        );
        assert_eq!(
            pallet_intent_settlement::pallet::FallbackSweepCount::<Test>::get(),
            16
        );
        // Cursor reset to 0 since pb_len went to 0.
        assert_eq!(
            pallet_intent_settlement::pallet::FallbackSweepCursor::<Test>::get(),
            0
        );
        // Sanity: bound constant unchanged.
        assert_eq!(FALLBACK_SWEEP_PER_BLOCK, 64);
    });
}

#[test]
fn ttl_sweep_expires_pending_and_refunds_credit() {
    new_test_ext().execute_with(|| {
        pallet_intent_settlement::pallet::Credits::<Test>::insert(ALICE, 1_000_000u64);
        let kind = bp(0x01, 1, 1_000_000);
        let iid = intent_id_for(ALICE, 0, &kind, 1);
        assert_ok!(IntentSettlement::submit_intent(
            RuntimeOrigin::signed(ALICE),
            kind
        ));
        assert_eq!(
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE),
            0
        );

        // Jump to TTL block and run on_initialize.
        System::set_block_number(1 + 600);
        <IntentSettlement as Hooks<u64>>::on_initialize(1 + 600);

        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
        assert_eq!(intent.status, IntentStatus::Expired);
        assert_eq!(
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE),
            1_000_000
        );
    });
}

#[test]
fn genesis_with_zero_ttl_uses_default() {
    // If genesis provides intent_ttl = 0, build() should fall back to DefaultIntentTTL.
    let mut t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    pallet_intent_settlement::pallet::GenesisConfig::<Test> {
        intent_ttl: 0,
        claim_ttl: 0,
        pool_utilization: PoolUtilizationParams::default(),
        min_signer_threshold: 0,
        _phantom: core::marker::PhantomData,
    }
    .assimilate_storage(&mut t)
    .unwrap();
    let mut ext = sp_io::TestExternalities::new(t);
    ext.execute_with(|| {
        assert_eq!(
            pallet_intent_settlement::pallet::IntentTTL::<Test>::get(),
            600
        );
        assert_eq!(
            pallet_intent_settlement::pallet::ClaimTTL::<Test>::get(),
            28_800
        );
    });
}

#[test]
fn submit_intent_with_ttl_storage_zero_uses_default() {
    new_test_ext().execute_with(|| {
        pallet_intent_settlement::pallet::IntentTTL::<Test>::put(0u32);
        let kind = IntentKind::RequestPayout {
            policy_id: H256::from([0x42; 32]),
            oracle_evidence: BoundedVec::try_from(vec![0u8; 4]).unwrap(),
        };
        let iid = intent_id_for(ALICE, 0, &kind, 1);
        assert_ok!(IntentSettlement::submit_intent(
            RuntimeOrigin::signed(ALICE),
            kind
        ));
        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
        // Default TTL = 600
        assert_eq!(intent.ttl_block, 1 + 600);
    });
}

#[test]
fn set_pool_utilization_requires_root() {
    new_test_ext().execute_with(|| {
        let p = PoolUtilizationParams::default();
        assert_noop!(
            IntentSettlement::set_pool_utilization(RuntimeOrigin::signed(1), p),
            sp_runtime::DispatchError::BadOrigin
        );
        assert_ok!(IntentSettlement::set_pool_utilization(
            RuntimeOrigin::root(),
            p
        ));
    });
}

// ---------------------------------------------------------------------------
// Runtime API helper (get_pending_batches / get_voucher)
// ---------------------------------------------------------------------------

#[test]
fn runtime_api_get_pending_batches_returns_attested_only() {
    new_test_ext().execute_with(|| {
        let iid1 = attested_intent(); // 1 attested
        let _iid2 = submit_and_get_id(BOB); // 1 pending
        let out =
            pallet_intent_settlement::pallet::Pallet::<Test>::get_pending_batches(0, 10);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].intent_id, iid1);
    });
}

#[test]
fn runtime_api_get_pending_batches_since_block_filter_and_max_count() {
    new_test_ext().execute_with(|| {
        let iid1 = attested_intent(); // submitted at block 1, attested
        // Bump the block number so the second attested intent has a newer block.
        System::set_block_number(5);
        let kind = IntentKind::RequestPayout {
            policy_id: H256::from([55u8; 32]),
            oracle_evidence: BoundedVec::try_from(vec![0u8; 4]).unwrap(),
        };
        let iid2 = intent_id_for(BOB, 0, &kind, 5);
        assert_ok!(IntentSettlement::submit_intent(
            RuntimeOrigin::signed(BOB),
            kind
        ));
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(1),
            iid2,
            mock_pubkey_of(&1),
            [0u8; 64]
        ));
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(2),
            iid2,
            mock_pubkey_of(&2),
            [0u8; 64]
        ));

        // since_block = 3 filters out iid1 (block 1), keeps iid2 (block 5).
        let filtered =
            pallet_intent_settlement::pallet::Pallet::<Test>::get_pending_batches(3, 10);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].intent_id, iid2);

        // max_count = 1 returns one entry even though 2 qualify.
        let capped =
            pallet_intent_settlement::pallet::Pallet::<Test>::get_pending_batches(0, 1);
        assert_eq!(capped.len(), 1);

        // ensure iid1 still exists so we exercise the "returns attested only" branch at scale
        assert!(
            pallet_intent_settlement::pallet::Intents::<Test>::contains_key(iid1)
        );
    });
}

#[test]
fn runtime_api_get_voucher_roundtrip() {
    new_test_ext().execute_with(|| {
        let iid = attested_intent();
        let claim_id = H256::from([77u8; 32]);
        let bfpr = good_fairness_proof(iid, 1_000);
        let voucher = good_voucher(claim_id, &bfpr, 1_000);
        assert_ok!(IntentSettlement::request_voucher(
            RuntimeOrigin::signed(1),
            claim_id,
            iid,
            voucher.clone(),
            bfpr,
            mock_voucher_sigs()
        ));
        let got = pallet_intent_settlement::pallet::Pallet::<Test>::get_voucher(
            claim_id,
        )
        .unwrap();
        assert_eq!(got.amount_ada, voucher.amount_ada);
    });
}

// ---------------------------------------------------------------------------
// Additional coverage: error paths on nonexistent intents, max-sig overflow,
// expire-policy idempotency, genesis defaults.
// ---------------------------------------------------------------------------

#[test]
fn attest_intent_on_nonexistent_intent_errors() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            IntentSettlement::attest_intent(
                RuntimeOrigin::signed(1),
                H256::from([0xAA; 32]),
                mock_pubkey_of(&1),
                [0u8; 64]
            ),
            pallet_intent_settlement::pallet::Error::<Test>::IntentNotFound
        );
    });
}

#[test]
fn request_voucher_on_nonexistent_intent_errors() {
    new_test_ext().execute_with(|| {
        let iid = H256::from([0u8; 32]); // no such intent
        let bfpr = good_fairness_proof(iid, 100);
        let voucher = good_voucher(H256::from([8u8; 32]), &bfpr, 100);
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                H256::from([8u8; 32]),
                iid,
                voucher,
                bfpr,
                mock_voucher_sigs()
            ),
            pallet_intent_settlement::pallet::Error::<Test>::IntentNotFound
        );
    });
}

#[test]
fn expire_policy_mirror_idempotent_on_expired() {
    new_test_ext().execute_with(|| {
        let iid = submit_and_get_id(ALICE);
        assert_ok!(IntentSettlement::expire_policy_mirror(
            RuntimeOrigin::signed(1),
            iid
        ));
        // Second call — same intent in Expired state; must be a no-op Ok.
        assert_ok!(IntentSettlement::expire_policy_mirror(
            RuntimeOrigin::signed(1),
            iid
        ));
    });
}

#[test]
fn expire_policy_mirror_rejects_non_member() {
    new_test_ext().execute_with(|| {
        let iid = submit_and_get_id(ALICE);
        assert_noop!(
            IntentSettlement::expire_policy_mirror(
                RuntimeOrigin::signed(ALICE), // not a committee member
                iid
            ),
            pallet_intent_settlement::pallet::Error::<Test>::NotCommitteeMember
        );
    });
}

#[test]
fn request_voucher_rejects_non_member() {
    new_test_ext().execute_with(|| {
        let iid = attested_intent();
        let bfpr = good_fairness_proof(iid, 1_000);
        let voucher = good_voucher(H256::from([1u8; 32]), &bfpr, 1_000);
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(ALICE), // not a committee member
                H256::from([1u8; 32]),
                iid,
                voucher,
                bfpr,
                mock_voucher_sigs()
            ),
            pallet_intent_settlement::pallet::Error::<Test>::NotCommitteeMember
        );
    });
}

#[test]
fn request_voucher_rejects_parallel_vec_mismatch() {
    new_test_ext().execute_with(|| {
        let iid = attested_intent();
        let bfpr = BatchFairnessProof {
            batch_block_range: (1, 1),
            sorted_intent_ids: BoundedVec::try_from(vec![iid]).unwrap(),
            requested_amounts_ada: BoundedVec::try_from(vec![1_000u64, 2_000u64])
                .unwrap(), // extra entry
            pool_balance_ada: 10_000,
            pro_rata_scale_bps: 10_000,
            awarded_amounts_ada: BoundedVec::try_from(vec![1_000u64]).unwrap(),
        };
        let voucher = good_voucher(H256::from([1u8; 32]), &bfpr, 1_000);
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                H256::from([1u8; 32]),
                iid,
                voucher,
                bfpr,
                mock_voucher_sigs()
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InvalidFairnessProof
        );
    });
}

#[test]
fn request_voucher_rejects_unsorted_intent_ids() {
    new_test_ext().execute_with(|| {
        let iid = attested_intent();
        let bfpr = BatchFairnessProof {
            batch_block_range: (1, 1),
            // Reversed / duplicate ordering.
            sorted_intent_ids: BoundedVec::try_from(vec![
                H256::from([2u8; 32]),
                H256::from([1u8; 32]),
            ])
            .unwrap(),
            requested_amounts_ada: BoundedVec::try_from(vec![100u64, 100]).unwrap(),
            pool_balance_ada: 10_000,
            pro_rata_scale_bps: 10_000,
            awarded_amounts_ada: BoundedVec::try_from(vec![100u64, 100]).unwrap(),
        };
        let voucher = good_voucher(H256::from([1u8; 32]), &bfpr, 100);
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                H256::from([1u8; 32]),
                iid,
                voucher,
                bfpr,
                mock_voucher_sigs()
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InvalidFairnessProof
        );
    });
}

#[test]
fn request_voucher_rejects_bad_block_range() {
    new_test_ext().execute_with(|| {
        let iid = attested_intent();
        let bfpr = BatchFairnessProof {
            batch_block_range: (10, 5), // inverted
            sorted_intent_ids: BoundedVec::try_from(vec![iid]).unwrap(),
            requested_amounts_ada: BoundedVec::try_from(vec![1_000u64]).unwrap(),
            pool_balance_ada: 10_000,
            pro_rata_scale_bps: 10_000,
            awarded_amounts_ada: BoundedVec::try_from(vec![1_000u64]).unwrap(),
        };
        let voucher = good_voucher(H256::from([3u8; 32]), &bfpr, 1_000);
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                H256::from([3u8; 32]),
                iid,
                voucher,
                bfpr,
                mock_voucher_sigs()
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InvalidFairnessProof
        );
    });
}

#[test]
fn full_settle_decrements_outstanding_coverage() {
    new_test_ext().execute_with(|| {
        let iid = attested_intent();
        let claim_id = H256::from([42u8; 32]);
        let bfpr = good_fairness_proof(iid, 1_000_000);
        let voucher = good_voucher(claim_id, &bfpr, 1_000_000);
        assert_ok!(IntentSettlement::request_voucher(
            RuntimeOrigin::signed(1),
            claim_id,
            iid,
            voucher,
            bfpr,
            mock_voucher_sigs()
        ));
        let before =
            pallet_intent_settlement::pallet::PoolUtilization::<Test>::get();
        assert!(before.outstanding_coverage_ada > 0);
        assert_ok!(IntentSettlement::settle_claim(
            RuntimeOrigin::signed(1),
            claim_id,
            [0xAA; 32],
            false,
            mock_settle_sigs()
        ));
        let after =
            pallet_intent_settlement::pallet::PoolUtilization::<Test>::get();
        assert!(after.outstanding_coverage_ada < before.outstanding_coverage_ada);
    });
}

// ---------------------------------------------------------------------------
// Issue #4 — attest_intent caller/pubkey binding
// ---------------------------------------------------------------------------

#[test]
fn test_attest_intent_rejects_caller_pubkey_mismatch() {
    // Alice (account 1) tries to attest "from" Bob's (account 2) pubkey — in
    // the pre-fix code this was a silent accept, letting one caller push
    // N committee votes. After Issue #4 it is rejected with
    // `CallerPubkeyMismatch` before any storage mutation.
    new_test_ext().execute_with(|| {
        let iid = submit_and_get_id(ALICE);
        assert_noop!(
            IntentSettlement::attest_intent(
                RuntimeOrigin::signed(1),           // caller = member 1
                iid,
                mock_pubkey_of(&2),                 // pubkey derived from 2
                [0u8; 64]
            ),
            pallet_intent_settlement::pallet::Error::<Test>::CallerPubkeyMismatch
        );
        // PendingAttestations must be empty — rejection is pre-mutation.
        let b = pallet_intent_settlement::pallet::PendingAttestations::<Test>::get(iid);
        assert_eq!(b.len(), 0);
    });
}

#[test]
fn test_attest_intent_accepts_matching_pubkey() {
    // Positive counterpart: same-origin + derived-pubkey is still accepted.
    new_test_ext().execute_with(|| {
        let iid = submit_and_get_id(ALICE);
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(1),
            iid,
            mock_pubkey_of(&1),
            [0u8; 64]
        ));
    });
}

// ---------------------------------------------------------------------------
// Issue #5 — outstanding_coverage accounting symmetry + overflow guard
// ---------------------------------------------------------------------------

#[test]
fn test_outstanding_coverage_symmetric_accounting() {
    // Reproduces the drift scenario from the issue brief: submit many intents,
    // voucher+settle ONE, expire the rest. The pre-fix batch-sum semantics
    // inflated `outstanding_coverage_ada` to sum(awarded), so settle-1 left
    // (N-1)x residue. After Issue #5 the counter is symmetric and settling
    // the only vouchered intent returns it to zero.
    new_test_ext().execute_with(|| {
        let per_intent = 50u64;
        let n = 5u64;

        // Submit N RequestPayout intents (no credit needed, no pool cap impact).
        let mut iids = Vec::with_capacity(n as usize);
        for i in 0..n {
            let kind = IntentKind::RequestPayout {
                policy_id: H256::from([i as u8; 32]),
                oracle_evidence: BoundedVec::try_from(vec![i as u8; 8]).unwrap(),
            };
            let iid = intent_id_for(ALICE, i, &kind, 1);
            assert_ok!(IntentSettlement::submit_intent(
                RuntimeOrigin::signed(ALICE),
                kind
            ));
            iids.push(iid);
        }

        // Attest + voucher+settle only iids[0]. The rest TTL-expire.
        let iid0 = iids[0];
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(1),
            iid0,
            mock_pubkey_of(&1),
            [0u8; 64]
        ));
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(2),
            iid0,
            mock_pubkey_of(&2),
            [0u8; 64]
        ));

        let claim_id = H256::from([0xCC; 32]);
        // Note: fairness_proof sums across ALL sorted intents in the batch,
        // so we pass n * per_intent as the batch total; the SINGLE voucher's
        // amount_ada is just `per_intent`. Pre-fix code added n*per_intent
        // into outstanding_coverage; post-fix adds per_intent.
        let bfpr = BatchFairnessProof {
            batch_block_range: (1, 1),
            sorted_intent_ids: {
                let mut v = iids.clone();
                v.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
                BoundedVec::try_from(v).unwrap()
            },
            requested_amounts_ada: BoundedVec::try_from(vec![per_intent; n as usize])
                .unwrap(),
            pool_balance_ada: per_intent * n * 10,
            pro_rata_scale_bps: 10_000,
            awarded_amounts_ada: BoundedVec::try_from(vec![per_intent; n as usize])
                .unwrap(),
        };
        let voucher = good_voucher(claim_id, &bfpr, per_intent);
        assert_ok!(IntentSettlement::request_voucher(
            RuntimeOrigin::signed(1),
            claim_id,
            iid0,
            voucher,
            bfpr,
            mock_voucher_sigs()
        ));
        let mid = pallet_intent_settlement::pallet::PoolUtilization::<Test>::get();
        assert_eq!(
            mid.outstanding_coverage_ada, per_intent,
            "post-fix: only the single claim's amount is counted, not the full batch sum"
        );

        // Settle the one claim. Counter returns to 0.
        assert_ok!(IntentSettlement::settle_claim(
            RuntimeOrigin::signed(1),
            claim_id,
            [0xDE; 32],
            false,
            mock_settle_sigs()
        ));
        let final_ = pallet_intent_settlement::pallet::PoolUtilization::<Test>::get();
        assert_eq!(
            final_.outstanding_coverage_ada, 0,
            "symmetric: request_voucher(+amount) and settle_claim(-amount) balance exactly"
        );
    });
}

#[test]
fn test_outstanding_coverage_overflow_rejected() {
    // Seed outstanding_coverage near u64::MAX; a voucher whose amount_ada
    // would push it past u64::MAX must be rejected with CoverageOverflow,
    // not silently wrap.
    new_test_ext().execute_with(|| {
        pallet_intent_settlement::pallet::PoolUtilization::<Test>::mutate(|u| {
            u.outstanding_coverage_ada = u64::MAX - 10;
        });

        let iid = attested_intent();
        let claim_id = H256::from([0xAA; 32]);
        // voucher.amount_ada = 1_000 > remaining headroom (10) → overflow.
        let bfpr = good_fairness_proof(iid, 1_000);
        let voucher = good_voucher(claim_id, &bfpr, 1_000);
        let before = pallet_intent_settlement::pallet::PoolUtilization::<Test>::get();
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                claim_id,
                iid,
                voucher,
                bfpr,
                mock_voucher_sigs()
            ),
            pallet_intent_settlement::pallet::Error::<Test>::CoverageOverflow
        );
        let after = pallet_intent_settlement::pallet::PoolUtilization::<Test>::get();
        assert_eq!(
            before.outstanding_coverage_ada, after.outstanding_coverage_ada,
            "no storage mutation on overflow reject"
        );
        // Claim must not exist either.
        assert!(
            !pallet_intent_settlement::pallet::Claims::<Test>::contains_key(claim_id)
        );
    });
}

// ---------------------------------------------------------------------------
// Issue #6 — PendingBatches index maintenance
// ---------------------------------------------------------------------------

#[test]
fn test_pending_batches_index_is_maintained() {
    // Submit 3 intents, voucher one, expire one, the remaining must be the
    // only one in the `PendingBatches` index AND the only one returned by
    // get_pending_batches (after being attested). The prior implementation
    // iterated Intents::iter() which grew with every submit historically;
    // this check proves the index tracks real work, not churn.
    new_test_ext().execute_with(|| {
        // Submit 3.
        let k1 = IntentKind::RequestPayout {
            policy_id: H256::from([1u8; 32]),
            oracle_evidence: BoundedVec::try_from(vec![0u8; 8]).unwrap(),
        };
        let k2 = IntentKind::RequestPayout {
            policy_id: H256::from([2u8; 32]),
            oracle_evidence: BoundedVec::try_from(vec![0u8; 8]).unwrap(),
        };
        let k3 = IntentKind::RequestPayout {
            policy_id: H256::from([3u8; 32]),
            oracle_evidence: BoundedVec::try_from(vec![0u8; 8]).unwrap(),
        };
        let iid1 = intent_id_for(ALICE, 0, &k1, 1);
        let iid2 = intent_id_for(ALICE, 1, &k2, 1);
        let iid3 = intent_id_for(ALICE, 2, &k3, 1);
        assert_ok!(IntentSettlement::submit_intent(RuntimeOrigin::signed(ALICE), k1));
        assert_ok!(IntentSettlement::submit_intent(RuntimeOrigin::signed(ALICE), k2));
        assert_ok!(IntentSettlement::submit_intent(RuntimeOrigin::signed(ALICE), k3));

        // Index now contains all 3.
        let pb = pallet_intent_settlement::pallet::PendingBatches::<Test>::get();
        assert_eq!(pb.len(), 3);
        assert!(pb.contains(&iid1));
        assert!(pb.contains(&iid2));
        assert!(pb.contains(&iid3));

        // Expire iid2 via expire_policy_mirror.
        assert_ok!(IntentSettlement::expire_policy_mirror(
            RuntimeOrigin::signed(1),
            iid2
        ));
        let pb_after_expire =
            pallet_intent_settlement::pallet::PendingBatches::<Test>::get();
        assert_eq!(pb_after_expire.len(), 2);
        assert!(!pb_after_expire.contains(&iid2));

        // Attest + voucher iid1 → transitions out of PendingBatches (Vouchered
        // is beyond the keeper's Attested window).
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(1),
            iid1,
            mock_pubkey_of(&1),
            [0u8; 64]
        ));
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(2),
            iid1,
            mock_pubkey_of(&2),
            [0u8; 64]
        ));
        let claim_id = H256::from([0xAA; 32]);
        let bfpr = good_fairness_proof(iid1, 1_000);
        let voucher = good_voucher(claim_id, &bfpr, 1_000);
        assert_ok!(IntentSettlement::request_voucher(
            RuntimeOrigin::signed(1),
            claim_id,
            iid1,
            voucher,
            bfpr,
            mock_voucher_sigs()
        ));
        let pb_final =
            pallet_intent_settlement::pallet::PendingBatches::<Test>::get();
        assert_eq!(pb_final.len(), 1);
        assert_eq!(pb_final[0], iid3);
    });
}

#[test]
fn test_get_pending_batches_iterates_index_not_intents_map() {
    // Plant a stale Intents entry WITHOUT an index record (simulating what
    // a bad pre-migration state might look like) and confirm that
    // get_pending_batches returns 0 — proving the fn reads the index.
    new_test_ext().execute_with(|| {
        let rogue_id = H256::from([0xEE; 32]);
        let rogue_intent = Intent::<u64> {
            submitter: ALICE,
            nonce: 0,
            kind: IntentKind::RequestPayout {
                policy_id: H256::from([0x77; 32]),
                oracle_evidence: BoundedVec::try_from(vec![0u8; 4]).unwrap(),
            },
            submitted_block: 1,
            ttl_block: 1 + 600,
            status: IntentStatus::Attested,
        };
        pallet_intent_settlement::pallet::Intents::<Test>::insert(
            rogue_id,
            rogue_intent,
        );
        // Index is still empty — no submit_intent was called.
        let out = pallet_intent_settlement::pallet::Pallet::<Test>::get_pending_batches(
            0, 10,
        );
        assert_eq!(
            out.len(), 0,
            "get_pending_batches must read the PendingBatches index, NOT Intents::iter()"
        );
    });
}

#[test]
fn test_pending_batches_bounded() {
    // MaxPendingBatches in the test runtime is 16; submit 16 successfully
    // then the 17th must hit PendingBatchesFull with no state mutation.
    new_test_ext().execute_with(|| {
        for i in 0..16u64 {
            let kind = IntentKind::RequestPayout {
                policy_id: H256::from([(i + 1) as u8; 32]),
                oracle_evidence: BoundedVec::try_from(vec![i as u8; 8]).unwrap(),
            };
            assert_ok!(IntentSettlement::submit_intent(
                RuntimeOrigin::signed(ALICE),
                kind
            ));
        }
        let pb_full = pallet_intent_settlement::pallet::PendingBatches::<Test>::get();
        assert_eq!(pb_full.len(), 16);

        // 17th rejected.
        let kind = IntentKind::RequestPayout {
            policy_id: H256::from([0xFE; 32]),
            oracle_evidence: BoundedVec::try_from(vec![0xFE; 8]).unwrap(),
        };
        assert_noop!(
            IntentSettlement::submit_intent(RuntimeOrigin::signed(ALICE), kind),
            pallet_intent_settlement::pallet::Error::<Test>::PendingBatchesFull
        );
        // Index unchanged — still 16.
        let pb_after =
            pallet_intent_settlement::pallet::PendingBatches::<Test>::get();
        assert_eq!(pb_after.len(), 16);
        // Nonces unchanged past 16 (i.e. the rejected call did not bump it).
        assert_eq!(
            pallet_intent_settlement::pallet::Nonces::<Test>::get(ALICE),
            16
        );
    });
}

// ---------------------------------------------------------------------------
// Issue #7 — M-of-N signature gate on credit_deposit + settle_claim
// ---------------------------------------------------------------------------

#[test]
fn test_credit_deposit_rejects_below_threshold() {
    // With MinSignerThreshold = 2 (preprod default), one signature must
    // fail with InsufficientSignatures.
    new_test_ext().execute_with(|| {
        assert_noop!(
            IntentSettlement::credit_deposit(
                RuntimeOrigin::signed(1),
                ALICE,
                1_000_000,
                [0xAB; 32],
                vec![mock_sig_for(1)] // only 1 signer
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InsufficientSignatures
        );
        // Credits unchanged.
        assert_eq!(
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE),
            0
        );
    });
}

#[test]
fn test_credit_deposit_accepts_threshold() {
    // Two valid signatures from distinct members on the canonical payload.
    new_test_ext().execute_with(|| {
        assert_ok!(IntentSettlement::credit_deposit(
            RuntimeOrigin::signed(1),
            ALICE,
            2_000_000,
            [0xCD; 32],
            vec![mock_sig_for(1), mock_sig_for(2)]
        ));
        assert_eq!(
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE),
            2_000_000
        );
    });
}

#[test]
fn test_settle_claim_rejects_below_threshold() {
    new_test_ext().execute_with(|| {
        let iid = attested_intent();
        let claim_id = H256::from([42u8; 32]);
        let bfpr = good_fairness_proof(iid, 1_000_000);
        let voucher = good_voucher(claim_id, &bfpr, 1_000_000);
        assert_ok!(IntentSettlement::request_voucher(
            RuntimeOrigin::signed(1),
            claim_id,
            iid,
            voucher,
            bfpr,
            mock_voucher_sigs()
        ));
        // Only one signer: rejected.
        assert_noop!(
            IntentSettlement::settle_claim(
                RuntimeOrigin::signed(1),
                claim_id,
                [0xFF; 32],
                false,
                vec![mock_sig_for(1)]
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InsufficientSignatures
        );
        // Claim state NOT mutated.
        let claim = pallet_intent_settlement::pallet::Claims::<Test>::get(claim_id)
            .unwrap();
        assert!(!claim.settled);
    });
}

#[test]
fn test_multisig_duplicate_signers_rejected() {
    // Member 1's sig twice — must be rejected as DuplicateSigner so that
    // "2-of-2 by one caller pasting the same sig" can't pass the bar.
    new_test_ext().execute_with(|| {
        assert_noop!(
            IntentSettlement::credit_deposit(
                RuntimeOrigin::signed(1),
                ALICE,
                100_000,
                [0x11; 32],
                vec![mock_sig_for(1), mock_sig_for(1)]
            ),
            pallet_intent_settlement::pallet::Error::<Test>::DuplicateSigner
        );
    });
}

#[test]
fn test_multisig_caller_must_be_one_of_the_signers() {
    // Member 3 calls the extrinsic but the signature bundle is from 1+2
    // only — even though it's a valid 2-of-3 by signer-count, the origin-
    // binding check rejects it so stale bundles can't be replayed.
    new_test_ext().execute_with(|| {
        assert_noop!(
            IntentSettlement::credit_deposit(
                RuntimeOrigin::signed(3),
                ALICE,
                100_000,
                [0x22; 32],
                vec![mock_sig_for(1), mock_sig_for(2)]
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InsufficientSignatures
        );
    });
}

#[test]
fn test_multisig_non_committee_signer_rejected() {
    // Craft a signature envelope with a pubkey that isn't in the committee.
    new_test_ext().execute_with(|| {
        let rogue = ([0xFFu8; 32], [0xFFu8; 64]);
        assert_noop!(
            IntentSettlement::credit_deposit(
                RuntimeOrigin::signed(1),
                ALICE,
                100_000,
                [0x33; 32],
                vec![mock_sig_for(1), rogue]
            ),
            pallet_intent_settlement::pallet::Error::<Test>::SignerNotCommitteeMember
        );
    });
}

#[test]
fn test_multisig_invalid_signature_rejected() {
    // A signature that fails MockSigVerifier::verify (wrong marker byte) is
    // rejected with InvalidSignature.
    new_test_ext().execute_with(|| {
        let bad = (mock_pubkey_of(&2), [0u8; 64]); // marker mismatch
        assert_noop!(
            IntentSettlement::credit_deposit(
                RuntimeOrigin::signed(1),
                ALICE,
                100_000,
                [0x44; 32],
                vec![mock_sig_for(1), bad]
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InvalidSignature
        );
    });
}

#[test]
fn test_set_min_signer_threshold_root_only() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            IntentSettlement::set_min_signer_threshold(RuntimeOrigin::signed(1), 3),
            sp_runtime::DispatchError::BadOrigin
        );
        assert_ok!(IntentSettlement::set_min_signer_threshold(
            RuntimeOrigin::root(),
            3
        ));
        assert_eq!(
            pallet_intent_settlement::pallet::MinSignerThreshold::<Test>::get(),
            3
        );
    });
}

// Sanity: the canonical payload hashers are deterministic + domain-separated.
#[test]
fn test_multisig_payload_hashers_domain_separated() {
    let a = credit_deposit_payload(&[7u8; 32], 1_000, &[1u8; 32]);
    let b = credit_deposit_payload(&[7u8; 32], 1_000, &[1u8; 32]);
    let c = settle_claim_payload(&H256::from([7u8; 32]), &[1u8; 32], false);
    assert_eq!(a, b);
    assert_ne!(a, c);
}

// ---------------------------------------------------------------------------
// Cross-layer parity fixtures for the multisig payload hashers.
//
// The TS SDK (`sdk/src/multisig.test.ts`) asserts these exact hex digests
// against its `creditDepositPayload` / `settleClaimPayload` helpers, so any
// future drift in either side (endianness, field order, domain tag) fails
// loudly in both Rust and TS CI runs instead of silently sending
// unverifiable bundles to the pallet.
//
// Inputs + expected hex here were produced by `sp_core::hashing::blake2_256`
// running against the domain-tagged canonical bodies defined in
// `lib.rs::credit_deposit_payload` / `settle_claim_payload`. If either
// function's pre-image format changes, regenerate these hex values and the
// matching SDK fixtures in lockstep.
// ---------------------------------------------------------------------------

fn hex_32(h: [u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in h.iter() {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[test]
fn test_credit_deposit_payload_parity_fixture_a() {
    // Fixture A — matches SDK test "creditDepositPayload matches Rust fixture A".
    let target = [0x07u8; 32];
    let amount: u64 = 1_000;
    let tx = [0x01u8; 32];
    let digest = credit_deposit_payload(&target, amount, &tx);
    assert_eq!(
        hex_32(digest),
        "d61b0438a19adc712cd0d01b4fee1174f5a8eb5df931918dac9ae0e2f32d51db",
        "CRDP fixture A digest drifted — regenerate SDK fixtures too"
    );
}

#[test]
fn test_credit_deposit_payload_parity_fixture_b() {
    // Fixture B — structured target/tx, 2M lovelace. Matches SDK test
    // "creditDepositPayload matches Rust fixture B".
    let mut target = [0u8; 32];
    for i in 0..32 {
        target[i] = (i as u8).wrapping_mul(7).wrapping_add(3);
    }
    let amount: u64 = 2_000_000;
    let mut tx = [0u8; 32];
    for i in 0..32 {
        tx[i] = ((i as u8) ^ 0xAB).wrapping_add(1);
    }
    let digest = credit_deposit_payload(&target, amount, &tx);
    assert_eq!(
        hex_32(digest),
        "56e006017231f0f62d48ed5739446e31fbfaab94ad3e68117ca57393b3db8c4f",
        "CRDP fixture B digest drifted — regenerate SDK fixtures too"
    );
}

#[test]
fn test_settle_claim_payload_parity_fixture_c_and_d() {
    // Fixture C/D — same inputs, both booleans, to pin the settled_direct
    // byte in the pre-image. Matches SDK tests
    // "settleClaimPayload matches Rust fixture C/D".
    let claim = H256::from([0x07u8; 32]);
    let tx = [0x01u8; 32];
    let digest_false = settle_claim_payload(&claim, &tx, false);
    let digest_true = settle_claim_payload(&claim, &tx, true);
    assert_eq!(
        hex_32(digest_false),
        "59be22f98eb07437195ca49bda86e1ff6ba495c8d19a0ac11d207e20d2dff285",
        "STCL fixture C (direct=false) digest drifted"
    );
    assert_eq!(
        hex_32(digest_true),
        "ae3761839a7a605a75d9643427e2b768436316e2cdda877e9f4c508ec6374b08",
        "STCL fixture D (direct=true) digest drifted"
    );
    assert_ne!(digest_false, digest_true);
}

#[test]
fn test_settle_claim_payload_parity_fixture_e() {
    // Fixture E — structured claim/tx, both direct flags. Matches SDK test
    // "settleClaimPayload matches Rust fixture E".
    let mut claim_bytes = [0u8; 32];
    for i in 0..32 {
        claim_bytes[i] = ((i as u8).wrapping_mul(5)) ^ 0x5A;
    }
    let claim = H256::from(claim_bytes);
    let mut tx = [0u8; 32];
    for i in 0..32 {
        tx[i] = ((i as u8) ^ 0xCC).wrapping_add(1);
    }
    let digest_false = settle_claim_payload(&claim, &tx, false);
    let digest_true = settle_claim_payload(&claim, &tx, true);
    assert_eq!(
        hex_32(digest_false),
        "7493705c88435cdf3faf46b1f5031281b777c6320ec3b71375ca06bb5b427e4a",
        "STCL fixture E (direct=false) digest drifted"
    );
    assert_eq!(
        hex_32(digest_true),
        "94b4d41f29528f1b00cf3de7df4f5bd22f27521d769f04547bb69f3b459862d6",
        "STCL fixture E (direct=true) digest drifted"
    );
}

// ---------------------------------------------------------------------------
// Test vectors against docs/test-vectors.json
// ---------------------------------------------------------------------------

#[test]
fn test_vectors_match_json() {
    // Validates intent_id + voucher_digest + bfpr_digest + committee_set_digest
    // against fixed vectors so Team B's Aiken side can cross-compare.
    let vectors =
        include_str!("../../../docs/test-vectors.json");
    let v: serde_json::Value = serde_json::from_str(vectors).unwrap();

    // intent_id vector (moved under `teamA_realistic_vectors` namespace in
    // docs/test-vectors.json v1.1 when the three-way voucher_digest_with_address
    // anchor landed — see commit f189092).
    let iv = &v["teamA_realistic_vectors"]["intent_id"];
    let submitter: [u8; 32] = hex::decode(iv["submitter_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let nonce: u64 = iv["nonce"].as_u64().unwrap();
    let blk: u32 = iv["submitted_block"].as_u64().unwrap() as u32;
    let premium: u64 = iv["kind"]["premium_ada"].as_u64().unwrap();
    let strike: u64 = iv["kind"]["strike"].as_u64().unwrap();
    let term: u32 = iv["kind"]["term_slots"].as_u64().unwrap() as u32;
    let product: [u8; 32] =
        hex::decode(iv["kind"]["product_id_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
    let addr: Vec<u8> = hex::decode(iv["kind"]["addr_hex"].as_str().unwrap()).unwrap();
    let kind = IntentKind::BuyPolicy {
        product_id: H256::from(product),
        strike,
        term_slots: term,
        premium_ada: premium,
        beneficiary_cardano_addr: BoundedVec::try_from(addr).unwrap(),
    };
    let got = compute_intent_id(&submitter, nonce, &kind, blk);
    let expected: [u8; 32] = hex::decode(iv["expected_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(got.as_bytes(), &expected, "intent_id vector mismatch");

    // committee_set_digest vector (same relocation as above).
    let cv = &v["teamA_realistic_vectors"]["committee_set_digest"];
    let mut pubkeys = Vec::new();
    for entry in cv["pubkeys_hex"].as_array().unwrap() {
        let b: [u8; 32] = hex::decode(entry.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        pubkeys.push(b);
    }
    let threshold: u32 = cv["threshold"].as_u64().unwrap() as u32;
    let got2 = compute_committee_set_digest(&pubkeys, threshold);
    let expected2: [u8; 32] = hex::decode(cv["expected_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(got2, expected2, "committee_set_digest mismatch");
}

// ---------------------------------------------------------------------------
// Task #177 — settle_batch_atomic unit tests
// ---------------------------------------------------------------------------

/// Build a fresh "vouchered" claim ready for settlement. Submits an intent
/// (RequestPayout, no pool-utilization side-effect), attests it M-of-N,
/// then requests a voucher with `amount`. Returns `(claim_id, intent_id)`.
fn vouchered_claim(claim_seed: u8, amount: u64) -> (ClaimId, IntentId) {
    use pallet_intent_settlement::pallet::PoolUtilization;

    // Bump pool NAV so this voucher fits — use BuyPolicy so we exercise the
    // outstanding_coverage_ada path that settle_batch_atomic must decrement.
    PoolUtilization::<Test>::mutate(|u| {
        u.total_nav_ada = u.total_nav_ada.saturating_add(amount.saturating_mul(2));
    });
    pallet_intent_settlement::pallet::Credits::<Test>::mutate(ALICE, |c| {
        *c = c.saturating_add(amount);
    });
    let kind = bp(claim_seed, 1, amount);
    let nonce = pallet_intent_settlement::pallet::Nonces::<Test>::get(ALICE);
    let blk: u32 = System::block_number().try_into().unwrap();
    let iid = intent_id_for(ALICE, nonce, &kind, blk);
    assert_ok!(IntentSettlement::submit_intent(
        RuntimeOrigin::signed(ALICE),
        kind
    ));
    // Attest M-of-N (threshold = 2 in mock).
    assert_ok!(IntentSettlement::attest_intent(
        RuntimeOrigin::signed(1),
        iid,
        mock_pubkey_of(&1),
        [0u8; 64]
    ));
    assert_ok!(IntentSettlement::attest_intent(
        RuntimeOrigin::signed(2),
        iid,
        mock_pubkey_of(&2),
        [0u8; 64]
    ));
    // Voucher.
    let claim_id = H256::from([claim_seed; 32]);
    let bfpr = good_fairness_proof(iid, amount);
    let voucher = good_voucher(claim_id, &bfpr, amount);
    assert_ok!(IntentSettlement::request_voucher(
        RuntimeOrigin::signed(1),
        claim_id,
        iid,
        voucher,
        bfpr,
        mock_voucher_sigs(),
    ));
    (claim_id, iid)
}

/// Build an STBA-payload sig bundle for `(member 1, member 2)` over `entries`.
fn stba_sigs_for(entries: &[SettleBatchEntry]) -> Vec<(CommitteePubkey, CommitteeSig)> {
    // MockSigVerifier is marker-byte-based, so the actual payload doesn't
    // affect verification; but we still build the digest so the production
    // path (settle_batch_atomic_payload) is exercised.
    let _ = pallet_intent_settlement::settle_batch_atomic_payload(entries);
    vec![mock_sig_for(1), mock_sig_for(2)]
}

#[test]
fn batch_atomic_happy_path_settles_all_and_emits_one_event() {
    new_test_ext().execute_with(|| {
        let (c1, _) = vouchered_claim(0xA1, 200_000);
        let (c2, _) = vouchered_claim(0xA2, 300_000);
        let (c3, _) = vouchered_claim(0xA3, 400_000);
        let outstanding_before =
            pallet_intent_settlement::pallet::PoolUtilization::<Test>::get()
                .outstanding_coverage_ada;
        let entries: Vec<SettleBatchEntry> = vec![
            SettleBatchEntry { claim_id: c1, cardano_tx_hash: [1u8; 32], settled_direct: false },
            SettleBatchEntry { claim_id: c2, cardano_tx_hash: [2u8; 32], settled_direct: true },
            SettleBatchEntry { claim_id: c3, cardano_tx_hash: [3u8; 32], settled_direct: false },
        ];
        let sigs = stba_sigs_for(&entries);
        let bv: BoundedVec<SettleBatchEntry, MaxSettleBatch> =
            BoundedVec::try_from(entries.clone()).unwrap();

        assert_ok!(IntentSettlement::settle_batch_atomic(
            RuntimeOrigin::signed(1),
            bv,
            sigs,
        ));

        for c in [c1, c2, c3].iter() {
            let claim =
                pallet_intent_settlement::pallet::Claims::<Test>::get(*c).unwrap();
            assert!(claim.settled, "claim {:?} not marked settled", c);
        }
        // Outstanding coverage decremented by 200k+300k+400k = 900k.
        let outstanding_after =
            pallet_intent_settlement::pallet::PoolUtilization::<Test>::get()
                .outstanding_coverage_ada;
        assert_eq!(outstanding_before - outstanding_after, 900_000);

        // BatchSettled event emitted with count=3 + settled_direct_count=1.
        let events: Vec<_> = System::events()
            .into_iter()
            .filter_map(|er| match er.event {
                RuntimeEvent::IntentSettlement(
                    pallet_intent_settlement::pallet::Event::BatchSettled {
                        count, settled_direct_count, batch_digest,
                    }
                ) => Some((count, settled_direct_count, batch_digest)),
                _ => None,
            })
            .collect();
        assert_eq!(events.len(), 1);
        let (count, direct, digest) = events[0];
        assert_eq!(count, 3);
        assert_eq!(direct, 1);
        let expected_digest =
            pallet_intent_settlement::settle_batch_atomic_payload(&entries);
        assert_eq!(digest, expected_digest);
    });
}

#[test]
fn batch_atomic_atomic_revert_on_one_bad_claim() {
    new_test_ext().execute_with(|| {
        let (c1, _) = vouchered_claim(0xB1, 100_000);
        let (c2, _) = vouchered_claim(0xB2, 100_000);
        let bogus_claim = H256::from([0xFF; 32]); // never created
        let outstanding_before =
            pallet_intent_settlement::pallet::PoolUtilization::<Test>::get()
                .outstanding_coverage_ada;
        let entries: Vec<SettleBatchEntry> = vec![
            SettleBatchEntry { claim_id: c1, cardano_tx_hash: [1u8; 32], settled_direct: false },
            SettleBatchEntry { claim_id: bogus_claim, cardano_tx_hash: [2u8; 32], settled_direct: false },
            SettleBatchEntry { claim_id: c2, cardano_tx_hash: [3u8; 32], settled_direct: false },
        ];
        let sigs = stba_sigs_for(&entries);
        let bv: BoundedVec<SettleBatchEntry, MaxSettleBatch> =
            BoundedVec::try_from(entries).unwrap();

        assert_noop!(
            IntentSettlement::settle_batch_atomic(
                RuntimeOrigin::signed(1),
                bv,
                sigs,
            ),
            pallet_intent_settlement::pallet::Error::<Test>::ClaimNotFound,
        );
        // Atomic: c1 and c2 NOT settled even though they processed first.
        for c in [c1, c2].iter() {
            let claim =
                pallet_intent_settlement::pallet::Claims::<Test>::get(*c).unwrap();
            assert!(!claim.settled, "claim {:?} mid-batch leak — atomicity broken", c);
        }
        // Outstanding coverage unchanged.
        let outstanding_after =
            pallet_intent_settlement::pallet::PoolUtilization::<Test>::get()
                .outstanding_coverage_ada;
        assert_eq!(outstanding_before, outstanding_after);
    });
}

#[test]
fn batch_atomic_rejects_duplicate_claim_in_batch() {
    new_test_ext().execute_with(|| {
        let (c1, _) = vouchered_claim(0xC1, 100_000);
        let (c2, _) = vouchered_claim(0xC2, 100_000);
        let entries: Vec<SettleBatchEntry> = vec![
            SettleBatchEntry { claim_id: c1, cardano_tx_hash: [1u8; 32], settled_direct: false },
            SettleBatchEntry { claim_id: c2, cardano_tx_hash: [2u8; 32], settled_direct: false },
            SettleBatchEntry { claim_id: c1, cardano_tx_hash: [3u8; 32], settled_direct: false }, // dup
        ];
        let sigs = stba_sigs_for(&entries);
        let bv: BoundedVec<SettleBatchEntry, MaxSettleBatch> =
            BoundedVec::try_from(entries).unwrap();

        assert_noop!(
            IntentSettlement::settle_batch_atomic(RuntimeOrigin::signed(1), bv, sigs),
            pallet_intent_settlement::pallet::Error::<Test>::DuplicateClaimInBatch,
        );
    });
}

#[test]
fn batch_atomic_rejects_already_settled_claim() {
    new_test_ext().execute_with(|| {
        let (c1, _) = vouchered_claim(0xD1, 100_000);
        let (c2, _) = vouchered_claim(0xD2, 100_000);
        // Settle c1 via single-claim path FIRST.
        assert_ok!(IntentSettlement::settle_claim(
            RuntimeOrigin::signed(1),
            c1,
            [9u8; 32],
            false,
            mock_settle_sigs(),
        ));
        // Now try a batch that includes the already-settled c1.
        let entries: Vec<SettleBatchEntry> = vec![
            SettleBatchEntry { claim_id: c1, cardano_tx_hash: [1u8; 32], settled_direct: false },
            SettleBatchEntry { claim_id: c2, cardano_tx_hash: [2u8; 32], settled_direct: false },
        ];
        let sigs = stba_sigs_for(&entries);
        let bv: BoundedVec<SettleBatchEntry, MaxSettleBatch> =
            BoundedVec::try_from(entries).unwrap();
        assert_noop!(
            IntentSettlement::settle_batch_atomic(RuntimeOrigin::signed(1), bv, sigs),
            pallet_intent_settlement::pallet::Error::<Test>::BatchClaimAlreadySettled,
        );
        // c2 still unsettled (atomic).
        let claim2 =
            pallet_intent_settlement::pallet::Claims::<Test>::get(c2).unwrap();
        assert!(!claim2.settled);
    });
}

#[test]
fn batch_atomic_rejects_empty_batch() {
    new_test_ext().execute_with(|| {
        let bv: BoundedVec<SettleBatchEntry, MaxSettleBatch> =
            BoundedVec::default();
        let sigs = vec![mock_sig_for(1), mock_sig_for(2)];
        assert_noop!(
            IntentSettlement::settle_batch_atomic(RuntimeOrigin::signed(1), bv, sigs),
            pallet_intent_settlement::pallet::Error::<Test>::EmptyBatch,
        );
    });
}

#[test]
fn batch_atomic_rejects_non_committee_caller() {
    new_test_ext().execute_with(|| {
        let (c1, _) = vouchered_claim(0xE1, 100_000);
        let entries: Vec<SettleBatchEntry> = vec![SettleBatchEntry {
            claim_id: c1, cardano_tx_hash: [1u8; 32], settled_direct: false,
        }];
        let sigs = stba_sigs_for(&entries);
        let bv: BoundedVec<SettleBatchEntry, MaxSettleBatch> =
            BoundedVec::try_from(entries).unwrap();
        // ALICE (account 100) is NOT a committee member.
        assert_noop!(
            IntentSettlement::settle_batch_atomic(
                RuntimeOrigin::signed(ALICE), bv, sigs
            ),
            pallet_intent_settlement::pallet::Error::<Test>::NotCommitteeMember,
        );
    });
}

#[test]
fn batch_atomic_below_threshold_rejected() {
    new_test_ext().execute_with(|| {
        let (c1, _) = vouchered_claim(0xF1, 100_000);
        let entries: Vec<SettleBatchEntry> = vec![SettleBatchEntry {
            claim_id: c1, cardano_tx_hash: [1u8; 32], settled_direct: false,
        }];
        let bv: BoundedVec<SettleBatchEntry, MaxSettleBatch> =
            BoundedVec::try_from(entries).unwrap();
        // Only 1 sig — threshold is 2.
        assert_noop!(
            IntentSettlement::settle_batch_atomic(
                RuntimeOrigin::signed(1),
                bv,
                vec![mock_sig_for(1)],
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InsufficientSignatures,
        );
    });
}

#[test]
fn batch_atomic_signature_must_match_batch_digest_not_per_entry() {
    // Critical correctness test: the settle_batch_atomic_payload pre-image
    // is over the WHOLE batch. If a caller tried to sign a per-entry STCL
    // payload (the old single-call path) it MUST not be accepted by the
    // batch path. Conversely, the batch payload over the right entries IS
    // accepted.
    new_test_ext().execute_with(|| {
        let (c1, _) = vouchered_claim(0xAA, 100_000);
        let (c2, _) = vouchered_claim(0xAB, 100_000);
        let entries = vec![
            SettleBatchEntry { claim_id: c1, cardano_tx_hash: [1u8; 32], settled_direct: false },
            SettleBatchEntry { claim_id: c2, cardano_tx_hash: [2u8; 32], settled_direct: false },
        ];
        // Compute the canonical pre-image and confirm it differs from the
        // per-entry STCL payloads (the old single-call path). This is a
        // pure-function assertion that doesn't touch the chain.
        let batch_digest = pallet_intent_settlement::settle_batch_atomic_payload(&entries);
        let stcl_for_c1 = pallet_intent_settlement::settle_claim_payload(
            &entries[0].claim_id, &entries[0].cardano_tx_hash, entries[0].settled_direct
        );
        assert_ne!(batch_digest, stcl_for_c1,
            "STBA must domain-separate from STCL — otherwise a per-claim \
             signature could be replayed against the batch path");
        // Different batches must produce different digests.
        let mut wrong_entries = entries.clone();
        wrong_entries[0].cardano_tx_hash = [42u8; 32];
        let wrong_digest =
            pallet_intent_settlement::settle_batch_atomic_payload(&wrong_entries);
        assert_ne!(batch_digest, wrong_digest);
    });
}

#[test]
fn batch_atomic_scales_to_max_batch_size() {
    // Sanity: 256-entry batch settles cleanly with no panics. Doesn't
    // measure weight — that's the benchmark's job — but proves no algorithmic
    // ceiling at the configured MAX.
    new_test_ext().execute_with(|| {
        // 64 max-size in a unit test: building 256 is slow because each
        // helper walks submit/attest/voucher + bumps NAV. 64 is enough to
        // prove the linear loop is sound; the bench harness pushes 256.
        const N: u8 = 64;
        let mut claim_ids: Vec<ClaimId> = Vec::new();
        for i in 0..N {
            let (cid, _) = vouchered_claim(i, 1_000);
            claim_ids.push(cid);
        }
        let entries: Vec<SettleBatchEntry> = claim_ids
            .iter()
            .enumerate()
            .map(|(i, cid)| SettleBatchEntry {
                claim_id: *cid,
                cardano_tx_hash: {
                    let mut h = [0u8; 32];
                    h[0] = i as u8;
                    h
                },
                settled_direct: i % 2 == 0,
            })
            .collect();
        let sigs = stba_sigs_for(&entries);
        let bv: BoundedVec<SettleBatchEntry, MaxSettleBatch> =
            BoundedVec::try_from(entries).unwrap();
        assert_ok!(IntentSettlement::settle_batch_atomic(
            RuntimeOrigin::signed(1),
            bv,
            sigs,
        ));
        for cid in claim_ids.iter() {
            let claim =
                pallet_intent_settlement::pallet::Claims::<Test>::get(*cid).unwrap();
            assert!(claim.settled);
        }
    });
}

#[test]
fn batch_atomic_backward_compat_single_settle_still_works() {
    // Backward-compat: the existing settle_claim path is untouched. A claim
    // settled via the legacy path produces the same terminal state as one
    // settled via the batch path. This is paired with the chain-side
    // backward-compat test that runs against the same runtime live.
    new_test_ext().execute_with(|| {
        let (c1, _) = vouchered_claim(0x77, 100_000);
        // Old single-call path.
        assert_ok!(IntentSettlement::settle_claim(
            RuntimeOrigin::signed(1),
            c1,
            [0xCAu8; 32],
            true,
            mock_settle_sigs(),
        ));
        let claim =
            pallet_intent_settlement::pallet::Claims::<Test>::get(c1).unwrap();
        assert!(claim.settled);
        assert!(claim.settled_direct);
        assert_eq!(claim.cardano_tx_hash, [0xCAu8; 32]);
    });
}

#[test]
fn batch_atomic_payload_hash_pure_function_no_operator_state() {
    // Per `feedback_mofn_hash_determinism.md`: the STBA pre-image must be a
    // pure function of chain-derived inputs, never operator-local state.
    // Two separate calls with the same entries MUST produce the same digest.
    let entries = vec![
        SettleBatchEntry {
            claim_id: H256::from([1u8; 32]),
            cardano_tx_hash: [2u8; 32],
            settled_direct: false,
        },
        SettleBatchEntry {
            claim_id: H256::from([3u8; 32]),
            cardano_tx_hash: [4u8; 32],
            settled_direct: true,
        },
    ];
    let d1 = pallet_intent_settlement::settle_batch_atomic_payload(&entries);
    let d2 = pallet_intent_settlement::settle_batch_atomic_payload(&entries);
    assert_eq!(d1, d2);
    // Order matters (different ordering = different digest).
    let mut reversed = entries.clone();
    reversed.reverse();
    let d3 = pallet_intent_settlement::settle_batch_atomic_payload(&reversed);
    assert_ne!(d1, d3);
}

mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        let s = s.trim_start_matches("0x");
        if s.len() % 2 != 0 {
            return Err(());
        }
        let mut out = Vec::with_capacity(s.len() / 2);
        for chunk in s.as_bytes().chunks(2) {
            let hi = char_to_nib(chunk[0])?;
            let lo = char_to_nib(chunk[1])?;
            out.push((hi << 4) | lo);
        }
        Ok(out)
    }
    fn char_to_nib(c: u8) -> Result<u8, ()> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Task #174 — `request_voucher` M-of-N signature gate
// ---------------------------------------------------------------------------
//
// These tests exercise the new `signatures` parameter on `request_voucher`,
// mirroring the existing M-of-N coverage on `credit_deposit` /
// `settle_claim`. Conventions match the Issue #7 suite above so reviewers
// can grep them side-by-side.
//
// Scenarios (mapped to the brief's 10-item list — those that map cleanly
// to a unit-level mock runtime; payload-determinism + SDK-helper parity
// live in `integration.rs` and `sdk/src/multisig.test.ts` respectively):
//   T2: happy path with M=2
//   T3: below-threshold (1 sig) rejected
//   T4: above-threshold (3 sigs) accepted
//   T5: bad sig rejected (MockSigVerifier marker mismatch)
//   T6: non-committee signer rejected
//   T7: duplicate signer rejected
//   T8: caller-not-in-bundle rejected (proxy for cross-epoch replay; the
//       caller-binding check is the same code path that also makes a
//       rotated-out signer's stale bundle unusable by a current member)
// Test 1 (4-arg decode error) is a wire-format property and is exercised
// at the chain-RPC level in the integration suite, not at unit level —
// the Rust `request_voucher` symbol on this branch only has the new
// 5-arg shape so a 4-arg call is a compile error, not a runtime error.

fn voucher_setup() -> (IntentId, ClaimId, BatchFairnessProof, Voucher, [u8; 32]) {
    // Build an Attested intent + good fairness proof + voucher, plus the
    // canonical request_voucher pre-image digest the bundle should sign.
    let iid = attested_intent();
    let claim_id = H256::from([0x42u8; 32]);
    let bfpr = good_fairness_proof(iid, 1_000_000);
    let voucher = good_voucher(claim_id, &bfpr, 1_000_000);
    let voucher_digest = crate::types::compute_voucher_digest(&voucher);
    let bfpr_digest = crate::types::compute_fairness_proof_digest(&bfpr);
    let payload = request_voucher_payload(&claim_id, &iid, &voucher_digest, &bfpr_digest);
    (iid, claim_id, bfpr, voucher, payload)
}

#[test]
fn test_request_voucher_happy_with_m_of_n_sigs() {
    // T2: 2-of-3 (matches DefaultMinSignerThreshold=2 in mock) → mints voucher.
    new_test_ext().execute_with(|| {
        let (iid, claim_id, bfpr, voucher, _payload) = voucher_setup();
        assert_ok!(IntentSettlement::request_voucher(
            RuntimeOrigin::signed(1),
            claim_id,
            iid,
            voucher,
            bfpr,
            vec![mock_sig_for(1), mock_sig_for(2)]
        ));
        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
        assert_eq!(intent.status, IntentStatus::Vouchered);
        assert!(
            pallet_intent_settlement::pallet::Vouchers::<Test>::contains_key(claim_id)
        );
    });
}

#[test]
fn test_request_voucher_below_threshold_rejected() {
    // T3: only 1 sig with MinSignerThreshold=2 → InsufficientSignatures.
    new_test_ext().execute_with(|| {
        let (iid, claim_id, bfpr, voucher, _payload) = voucher_setup();
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                claim_id,
                iid,
                voucher,
                bfpr,
                vec![mock_sig_for(1)]
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InsufficientSignatures
        );
        // Voucher NOT minted — the new gate fires before any state mutation.
        assert!(
            !pallet_intent_settlement::pallet::Vouchers::<Test>::contains_key(claim_id)
        );
        // Intent stays in Attested (not Vouchered).
        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
        assert_eq!(intent.status, IntentStatus::Attested);
    });
}

#[test]
fn test_request_voucher_above_threshold_accepted() {
    // T4: 3 sigs (full committee) when threshold is 2 → still accepted.
    new_test_ext().execute_with(|| {
        let (iid, claim_id, bfpr, voucher, _payload) = voucher_setup();
        assert_ok!(IntentSettlement::request_voucher(
            RuntimeOrigin::signed(1),
            claim_id,
            iid,
            voucher,
            bfpr,
            vec![mock_sig_for(1), mock_sig_for(2), mock_sig_for(3)]
        ));
        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
        assert_eq!(intent.status, IntentStatus::Vouchered);
    });
}

#[test]
fn test_request_voucher_bad_sig_rejected() {
    // T5: one valid sig + one with a bogus marker byte → InvalidSignature.
    // The MockSigVerifier accepts iff `sig[0] == pubkey[0]`; we use member
    // 2's pubkey but a sig whose first byte is the wrong marker.
    new_test_ext().execute_with(|| {
        let (iid, claim_id, bfpr, voucher, _payload) = voucher_setup();
        let bad = (mock_pubkey_of(&2), [0u8; 64]); // marker mismatch
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                claim_id,
                iid,
                voucher,
                bfpr,
                vec![mock_sig_for(1), bad]
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InvalidSignature
        );
    });
}

#[test]
fn test_request_voucher_non_committee_signer_rejected() {
    // T6: rogue pubkey not in current committee → SignerNotCommitteeMember.
    new_test_ext().execute_with(|| {
        let (iid, claim_id, bfpr, voucher, _payload) = voucher_setup();
        let rogue = ([0xFFu8; 32], [0xFFu8; 64]);
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                claim_id,
                iid,
                voucher,
                bfpr,
                vec![mock_sig_for(1), rogue]
            ),
            pallet_intent_settlement::pallet::Error::<Test>::SignerNotCommitteeMember
        );
    });
}

#[test]
fn test_request_voucher_duplicate_signer_rejected() {
    // T7: same signer twice in the bundle → DuplicateSigner. Defends against
    // "M-of-2 by one operator pasting the same sig twice" attacks.
    new_test_ext().execute_with(|| {
        let (iid, claim_id, bfpr, voucher, _payload) = voucher_setup();
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                claim_id,
                iid,
                voucher,
                bfpr,
                vec![mock_sig_for(1), mock_sig_for(1)]
            ),
            pallet_intent_settlement::pallet::Error::<Test>::DuplicateSigner
        );
    });
}

#[test]
fn test_request_voucher_caller_not_in_bundle_rejected() {
    // T8 (epoch-boundary proxy): caller (member 3) submits a bundle of (1, 2).
    // Even though it's a valid 2-of-3 by signer-count, the origin-binding
    // check rejects it as `InsufficientSignatures` so a stale bundle posted
    // by a non-signing member can't be replayed. This is the same code path
    // that prevents a rotated-out signer's old bundle from being replayed by
    // a current member after a committee rotation.
    new_test_ext().execute_with(|| {
        let (iid, claim_id, bfpr, voucher, _payload) = voucher_setup();
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(3),
                claim_id,
                iid,
                voucher,
                bfpr,
                vec![mock_sig_for(1), mock_sig_for(2)]
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InsufficientSignatures
        );
    });
}

#[test]
fn test_request_voucher_payload_deterministic_and_domain_separated() {
    // T9 (pre-image determinism): same inputs → same digest. Domain-separated
    // from settle_claim and credit_deposit so a sig over one cannot replay
    // onto another.
    let claim_id = H256::from([0x07u8; 32]);
    let intent_id = H256::from([0x11u8; 32]);
    let voucher_d = [0x22u8; 32];
    let bfpr_d = [0x33u8; 32];
    let a = request_voucher_payload(&claim_id, &intent_id, &voucher_d, &bfpr_d);
    let b = request_voucher_payload(&claim_id, &intent_id, &voucher_d, &bfpr_d);
    assert_eq!(a, b, "deterministic");

    // Domain separation: same body bytes but different tag → different digest.
    let c = settle_claim_payload(&claim_id, &voucher_d, false);
    assert_ne!(a, c, "RVCH != STCL");
    let d = credit_deposit_payload(&[0u8; 32], 0, &voucher_d);
    assert_ne!(a, d, "RVCH != CRDP");

    // Field-position sensitivity: swapping voucher_digest <-> bfpr_digest
    // yields a different digest (so an attacker can't pre-compute one
    // sig that works for the swapped pair).
    let e = request_voucher_payload(&claim_id, &intent_id, &bfpr_d, &voucher_d);
    assert_ne!(a, e, "voucher_digest and bfpr_digest are not interchangeable");
}

#[test]
fn test_request_voucher_payload_parity_fixture_f() {
    // Cross-layer parity: matches the SDK fixture in
    // `sdk/src/multisig.test.ts` ("requestVoucherPayload matches Rust
    // fixture F"). If either side's pre-image format drifts, both fail.
    let claim_id = H256::from([0x07u8; 32]);
    let intent_id = H256::from([0x11u8; 32]);
    let voucher_d = [0x22u8; 32];
    let bfpr_d = [0x33u8; 32];
    let digest = request_voucher_payload(&claim_id, &intent_id, &voucher_d, &bfpr_d);
    assert_eq!(
        hex_32(digest),
        TASK_174_FIXTURE_F_HEX,
        "RVCH fixture F digest drifted — regenerate SDK fixture too"
    );
}

/// Fixture F expected hex for `request_voucher_payload`. Generated by
/// `sp_core::hashing::blake2_256(b"RVCH" || claim_id || intent_id ||
///  voucher_digest || bfpr_digest)` with the constants in
/// `test_request_voucher_payload_parity_fixture_f`. The SDK test pins the
/// same hex so any drift in either implementation fails loudly in CI.
const TASK_174_FIXTURE_F_HEX: &str =
    "b3a165c261b9a5b76ec4d22779d0ae2fb56ef0bd8f3da3fcb48a40f1e8b1fdd4";

// ---------------------------------------------------------------------------
// Task #211 — attest_batch_intents unit tests
// ---------------------------------------------------------------------------

/// Build N submitted-but-not-attested intents owned by ALICE. Returns the
/// list of intent_ids in submission order.
fn submit_n_pending(n: u32) -> Vec<IntentId> {
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n {
        let kind = IntentKind::RequestPayout {
            policy_id: H256::from([(0xA0u8.wrapping_add(i as u8)) as u8; 32]),
            oracle_evidence: BoundedVec::try_from(vec![i as u8; 8]).unwrap(),
        };
        let nonce = pallet_intent_settlement::pallet::Nonces::<Test>::get(ALICE);
        let blk: u32 = System::block_number().try_into().unwrap();
        let iid = intent_id_for(ALICE, nonce, &kind, blk);
        assert_ok!(IntentSettlement::submit_intent(
            RuntimeOrigin::signed(ALICE),
            kind,
        ));
        out.push(iid);
    }
    out
}

/// Build a 2-of-3 sig bundle for the ABIN payload over `intent_ids`.
fn abin_sigs_for(intent_ids: &[IntentId]) -> Vec<(CommitteePubkey, CommitteeSig)> {
    let _ = pallet_intent_settlement::attest_batch_intents_payload(intent_ids);
    vec![mock_sig_for(1), mock_sig_for(2)]
}

/// Build N attested-but-not-vouchered intents owned by ALICE. Returns the
/// list of intent_ids in submission order.
fn submit_n_attested(n: u32) -> Vec<IntentId> {
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n {
        let kind = IntentKind::RequestPayout {
            policy_id: H256::from([(0xB0u8.wrapping_add(i as u8)) as u8; 32]),
            oracle_evidence: BoundedVec::try_from(vec![i as u8; 8]).unwrap(),
        };
        let nonce = pallet_intent_settlement::pallet::Nonces::<Test>::get(ALICE);
        let blk: u32 = System::block_number().try_into().unwrap();
        let iid = intent_id_for(ALICE, nonce, &kind, blk);
        assert_ok!(IntentSettlement::submit_intent(
            RuntimeOrigin::signed(ALICE),
            kind,
        ));
        // Attest 2-of-3.
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(1), iid, mock_pubkey_of(&1), [0u8; 64],
        ));
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(2), iid, mock_pubkey_of(&2), [0u8; 64],
        ));
        out.push(iid);
    }
    out
}

/// Build a batch of N RequestVoucherEntry given parallel intent_ids list.
/// Each entry uses a distinct claim_id and a single-intent fairness proof.
fn build_voucher_entries(intent_ids: &[IntentId], amount: u64) -> Vec<RequestVoucherEntry> {
    intent_ids
        .iter()
        .enumerate()
        .map(|(i, iid)| {
            let claim_id = H256::from([(0xC0u8.wrapping_add(i as u8)) as u8; 32]);
            let bfpr = good_fairness_proof(*iid, amount);
            let voucher = good_voucher(claim_id, &bfpr, amount);
            RequestVoucherEntry {
                claim_id,
                intent_id: *iid,
                voucher,
                fairness_proof: bfpr,
            }
        })
        .collect()
}

/// Build the canonical RVBN sig bundle (mock verifier; payload-agnostic
/// since `MockSigVerifier` only checks `sig[0] == pubkey[0]`).
fn rvbn_sigs() -> Vec<(CommitteePubkey, CommitteeSig)> {
    vec![mock_sig_for(1), mock_sig_for(2)]
}

#[test]
fn attest_batch_happy_path_n_5_emits_per_intent_and_batch_events() {
    new_test_ext().execute_with(|| {
        let iids = submit_n_pending(5);
        let sigs = abin_sigs_for(&iids);
        let bv: BoundedVec<IntentId, MaxAttestBatch> =
            BoundedVec::try_from(iids.clone()).unwrap();
        assert_ok!(IntentSettlement::attest_batch_intents(
            RuntimeOrigin::signed(1),
            bv,
            sigs,
        ));
        // All 5 intents are now Attested with the bundle stored.
        for iid in iids.iter() {
            let intent =
                pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
            assert_eq!(intent.status, IntentStatus::Attested);
            let stored =
                pallet_intent_settlement::pallet::AttestationSigs::<Test>::get(iid)
                    .unwrap();
            assert_eq!(stored.len(), 2);
        }
        // Per-intent IntentAttested events still emitted (backward compat).
        let per_intent: Vec<_> = System::events()
            .into_iter()
            .filter_map(|er| match er.event {
                RuntimeEvent::IntentSettlement(
                    pallet_intent_settlement::pallet::Event::IntentAttested { .. }
                ) => Some(()),
                _ => None,
            })
            .collect();
        assert_eq!(per_intent.len(), 5);
        // BatchIntentsAttested fired once.
        let batch_events: Vec<_> = System::events()
            .into_iter()
            .filter_map(|er| match er.event {
                RuntimeEvent::IntentSettlement(
                    pallet_intent_settlement::pallet::Event::BatchIntentsAttested {
                        submitted_count, attested_count, batch_digest, signer_count,
                    }
                ) => Some((submitted_count, attested_count, batch_digest, signer_count)),
                _ => None,
            })
            .collect();
        assert_eq!(batch_events.len(), 1);
        let (sub, att, digest, sc) = &batch_events[0];
        assert_eq!(*sub, 5);
        assert_eq!(*att, 5);
        assert_eq!(*sc, 2);
        let expected =
            pallet_intent_settlement::attest_batch_intents_payload(&iids);
        assert_eq!(*digest, expected);
    });
}

// ---------------------------------------------------------------------------
// Task #210 — submit_batch_intents unit tests
//
// Mirrors the spec-206 PR #27 settle_batch_atomic test layout: happy path,
// scaling to MAX_BATCH (=64 in unit suite, full 256 in bench), atomicity,
// backward-compat with the per-call form, pre-image determinism + parity.
// ---------------------------------------------------------------------------

/// Build a `BuyPolicy` IntentKind with seed-based product/strike/premium.
fn bp_entry(seed: u8, premium: u64) -> SubmitIntentEntry {
    SubmitIntentEntry {
        kind: bp(seed, 1, premium),
    }
}

/// Build a `RequestPayout` IntentKind (no credit/pool side-effect).
fn rp_entry(seed: u8) -> SubmitIntentEntry {
    SubmitIntentEntry {
        kind: IntentKind::RequestPayout {
            policy_id: H256::from([seed; 32]),
            oracle_evidence: BoundedVec::try_from(vec![seed; 8]).unwrap(),
        },
    }
}

#[test]
fn submit_batch_intents_happy_path_n_10() {
    new_test_ext().execute_with(|| {
        let n = 10u32;
        // Top up Alice with enough credit for 10 BuyPolicy premiums.
        pallet_intent_settlement::pallet::Credits::<Test>::insert(
            ALICE,
            10_000_000u64,
        );
        // Bump pool NAV so the per-entry pool-utilization check passes.
        pallet_intent_settlement::pallet::PoolUtilization::<Test>::mutate(|u| {
            u.total_nav_ada = u.total_nav_ada.saturating_add(50_000_000);
        });

        let entries: Vec<SubmitIntentEntry> = (0..n)
            .map(|i| bp_entry(0xC0u8.wrapping_add(i as u8), 1_000))
            .collect();

        let bv: BoundedVec<SubmitIntentEntry, MaxSubmitBatch> =
            BoundedVec::try_from(entries.clone()).unwrap();

        let credits_before =
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE);

        assert_ok!(IntentSettlement::submit_batch_intents(
            RuntimeOrigin::signed(ALICE),
            bv,
        ));

        // All 10 intents stored — Pending. Verified via Nonces (now 10) +
        // PendingBatches index size + BatchIntentsSubmitted event.
        assert_eq!(
            pallet_intent_settlement::pallet::Nonces::<Test>::get(ALICE),
            n as u64
        );
        let pb = pallet_intent_settlement::pallet::PendingBatches::<Test>::get();
        assert_eq!(pb.len() as u32, n);
        // Total premium debited.
        let credits_after =
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE);
        assert_eq!(credits_before - credits_after, 10_000);

        // BatchIntentsSubmitted emitted exactly once with count=10.
        let events: Vec<_> = System::events()
            .into_iter()
            .filter_map(|er| match er.event {
                RuntimeEvent::IntentSettlement(
                    pallet_intent_settlement::pallet::Event::BatchIntentsSubmitted {
                        submitter, count, batch_digest, total_premium_ada,
                    }
                ) => Some((submitter, count, batch_digest, total_premium_ada)),
                _ => None,
            })
            .collect();
        assert_eq!(events.len(), 1);
        let (submitter, count, digest, premium_total) = &events[0];
        assert_eq!(*submitter, ALICE);
        assert_eq!(*count, n);
        assert_eq!(*premium_total, 10_000);
        let expected =
            pallet_intent_settlement::submit_batch_intents_payload(&entries);
        assert_eq!(*digest, expected);
    });
}

#[test]
fn attest_batch_atomic_revert_on_unknown_intent() {
    new_test_ext().execute_with(|| {
        let mut iids = submit_n_pending(3);
        // Inject a bogus intent_id at index 1.
        iids.insert(1, H256::from([0xFFu8; 32]));
        let sigs = abin_sigs_for(&iids);
        let bv: BoundedVec<IntentId, MaxAttestBatch> =
            BoundedVec::try_from(iids.clone()).unwrap();
        assert_noop!(
            IntentSettlement::attest_batch_intents(
                RuntimeOrigin::signed(1),
                bv,
                sigs,
            ),
            pallet_intent_settlement::pallet::Error::<Test>::IntentNotFound,
        );
        // No partial transitions.
        for iid in iids.iter() {
            if iid == &H256::from([0xFFu8; 32]) {
                continue;
            }
            let intent =
                pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
            assert_eq!(
                intent.status,
                IntentStatus::Pending,
                "atomicity broken — partial transition on failed batch"
            );
        }
    });
}

#[test]
fn attest_batch_rejects_duplicate_intent_within_batch() {
    new_test_ext().execute_with(|| {
        let iids = submit_n_pending(3);
        let mut with_dup = iids.clone();
        with_dup.push(iids[0]);
        let sigs = abin_sigs_for(&with_dup);
        let bv: BoundedVec<IntentId, MaxAttestBatch> =
            BoundedVec::try_from(with_dup).unwrap();
        assert_noop!(
            IntentSettlement::attest_batch_intents(
                RuntimeOrigin::signed(1),
                bv,
                sigs,
            ),
            pallet_intent_settlement::pallet::Error::<Test>::DuplicateIntentInBatch,
        );
    });
}

#[test]
fn attest_batch_already_attested_intents_idempotent_skip() {
    // Mixed batch: some intents already-Attested via the legacy single-call,
    // others fresh-Pending. Batch must succeed atomically, transition only
    // the Pending ones, and report attested_count = (count of fresh).
    new_test_ext().execute_with(|| {
        let iids = submit_n_pending(4);
        // Pre-attest the first two via legacy path.
        for iid in iids.iter().take(2) {
            assert_ok!(IntentSettlement::attest_intent(
                RuntimeOrigin::signed(1),
                *iid,
                mock_pubkey_of(&1),
                [0u8; 64],
            ));
            assert_ok!(IntentSettlement::attest_intent(
                RuntimeOrigin::signed(2),
                *iid,
                mock_pubkey_of(&2),
                [0u8; 64],
            ));
            let intent =
                pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
            assert_eq!(intent.status, IntentStatus::Attested);
        }
        // Reset the events log so we only inspect the batch's own events.
        System::reset_events();
        let sigs = abin_sigs_for(&iids);
        let bv: BoundedVec<IntentId, MaxAttestBatch> =
            BoundedVec::try_from(iids.clone()).unwrap();
        assert_ok!(IntentSettlement::attest_batch_intents(
            RuntimeOrigin::signed(1),
            bv,
            sigs,
        ));
        // BatchIntentsAttested: submitted=4, attested=2 (only the freshes).
        let batch_events: Vec<_> = System::events()
            .into_iter()
            .filter_map(|er| match er.event {
                RuntimeEvent::IntentSettlement(
                    pallet_intent_settlement::pallet::Event::BatchIntentsAttested {
                        submitted_count, attested_count, ..
                    }
                ) => Some((submitted_count, attested_count)),
                _ => None,
            })
            .collect();
        assert_eq!(batch_events, vec![(4, 2)]);
        // All 4 are now Attested in storage.
        for iid in iids.iter() {
            let intent =
                pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
            assert_eq!(intent.status, IntentStatus::Attested);
        }
    });
}

#[test]
fn attest_batch_rejects_terminal_status_intents() {
    // If any intent in the batch is in a non-Pending/non-Attested status
    // (e.g. Vouchered, Settled, Expired), the batch atomically rejects.
    new_test_ext().execute_with(|| {
        let iids = submit_n_pending(3);
        // Terminalize the middle intent via the existing TTL pathway:
        // expire_policy_mirror sets it to Expired.
        assert_ok!(IntentSettlement::expire_policy_mirror(
            RuntimeOrigin::signed(1),
            iids[1],
        ));
        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(iids[1]).unwrap();
        assert_eq!(intent.status, IntentStatus::Expired);

        let sigs = abin_sigs_for(&iids);
        let bv: BoundedVec<IntentId, MaxAttestBatch> =
            BoundedVec::try_from(iids.clone()).unwrap();
        assert_noop!(
            IntentSettlement::attest_batch_intents(
                RuntimeOrigin::signed(1),
                bv,
                sigs,
            ),
            pallet_intent_settlement::pallet::Error::<Test>::IntentStatusMismatch,
        );
        // First intent NOT freshly attested (atomic).
        let intent0 =
            pallet_intent_settlement::pallet::Intents::<Test>::get(iids[0]).unwrap();
        assert_eq!(intent0.status, IntentStatus::Pending);
    });
}

#[test]
fn attest_batch_rejects_empty_batch() {
    new_test_ext().execute_with(|| {
        let bv: BoundedVec<IntentId, MaxAttestBatch> = BoundedVec::default();
        let sigs = vec![mock_sig_for(1), mock_sig_for(2)];
        assert_noop!(
            IntentSettlement::attest_batch_intents(
                RuntimeOrigin::signed(1),
                bv,
                sigs,
            ),
            pallet_intent_settlement::pallet::Error::<Test>::EmptyAttestBatch,
        );
    });
}

#[test]
fn attest_batch_rejects_non_committee_caller() {
    new_test_ext().execute_with(|| {
        let iids = submit_n_pending(2);
        let sigs = abin_sigs_for(&iids);
        let bv: BoundedVec<IntentId, MaxAttestBatch> =
            BoundedVec::try_from(iids).unwrap();
        // ALICE (account 100) is NOT a committee member.
        assert_noop!(
            IntentSettlement::attest_batch_intents(
                RuntimeOrigin::signed(ALICE),
                bv,
                sigs,
            ),
            pallet_intent_settlement::pallet::Error::<Test>::NotCommitteeMember,
        );
    });
}

#[test]
fn submit_batch_intents_atomic_revert_on_one_bad_entry() {
    // Inject an entry that exceeds the pool-utilization cap mid-batch. The
    // whole batch must revert — no partial debit, no partial intents.
    new_test_ext().execute_with(|| {
        pallet_intent_settlement::pallet::Credits::<Test>::insert(
            ALICE,
            u64::MAX,
        );
        // cap_bps = 7500, total_nav_ada = 10_000_000 → max coverage 7.5M.
        // Two 1M premiums fit; a 9M third entry blows the cap.
        let entries: Vec<SubmitIntentEntry> = vec![
            bp_entry(0xD0, 1_000_000),
            bp_entry(0xD1, 1_000_000),
            bp_entry(0xD2, 9_000_000), // cap-exceeder
            bp_entry(0xD3, 1_000_000), // would have been fine but never runs
        ];

        let credits_before =
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE);
        let nonce_before =
            pallet_intent_settlement::pallet::Nonces::<Test>::get(ALICE);
        let pb_len_before =
            pallet_intent_settlement::pallet::PendingBatches::<Test>::get().len();

        let bv: BoundedVec<SubmitIntentEntry, MaxSubmitBatch> =
            BoundedVec::try_from(entries).unwrap();
        assert_noop!(
            IntentSettlement::submit_batch_intents(
                RuntimeOrigin::signed(ALICE),
                bv,
            ),
            pallet_intent_settlement::pallet::Error::<Test>::PoolUtilizationExceeded,
        );

        // Atomicity: ZERO mutation. Credits, nonce, PendingBatches index
        // all unchanged from before the failed call.
        assert_eq!(
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE),
            credits_before,
            "atomicity broken — partial credit debit on failed batch"
        );
        assert_eq!(
            pallet_intent_settlement::pallet::Nonces::<Test>::get(ALICE),
            nonce_before
        );
        assert_eq!(
            pallet_intent_settlement::pallet::PendingBatches::<Test>::get().len(),
            pb_len_before
        );
    });
}

#[test]
fn attest_batch_below_threshold_rejected() {
    new_test_ext().execute_with(|| {
        let iids = submit_n_pending(2);
        let bv: BoundedVec<IntentId, MaxAttestBatch> =
            BoundedVec::try_from(iids).unwrap();
        // Only 1 sig — threshold is 2.
        assert_noop!(
            IntentSettlement::attest_batch_intents(
                RuntimeOrigin::signed(1),
                bv,
                vec![mock_sig_for(1)],
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InsufficientSignatures,
        );
    });
}

#[test]
fn submit_batch_intents_rejects_empty_batch() {
    new_test_ext().execute_with(|| {
        let bv: BoundedVec<SubmitIntentEntry, MaxSubmitBatch> = BoundedVec::default();
        assert_noop!(
            IntentSettlement::submit_batch_intents(
                RuntimeOrigin::signed(ALICE),
                bv,
            ),
            pallet_intent_settlement::pallet::Error::<Test>::EmptyIntentBatch,
        );
    });
}

#[test]
fn attest_batch_signature_must_match_batch_digest_not_per_entry() {
    // If a caller signed a per-entry digest (e.g. just the first intent_id)
    // rather than the canonical ABIN payload, the bundle MUST NOT verify
    // against the multi-entry batch's digest. Pure-function assertion.
    let iids = vec![
        H256::from([1u8; 32]),
        H256::from([2u8; 32]),
        H256::from([3u8; 32]),
    ];
    let batch_digest = pallet_intent_settlement::attest_batch_intents_payload(&iids);
    // Compare to single-entry batch digest — must differ.
    let single_digest =
        pallet_intent_settlement::attest_batch_intents_payload(&iids[..1]);
    assert_ne!(batch_digest, single_digest, "batch != single-entry batch");
    // Ordering matters.
    let mut reversed = iids.clone();
    reversed.reverse();
    let reversed_digest =
        pallet_intent_settlement::attest_batch_intents_payload(&reversed);
    assert_ne!(batch_digest, reversed_digest);
}

#[test]
fn attest_batch_scales_within_pending_batches_bound() {
    // 16 entries (cap is MaxPendingBatches=16 in test runtime). Production
    // bound is 256 (MAX_ATTEST_BATCH); see benchmarking.rs for the
    // sublinear weight curve.
    new_test_ext().execute_with(|| {
        const N: u32 = 16;
        let iids = submit_n_pending(N);
        let sigs = abin_sigs_for(&iids);
        let bv: BoundedVec<IntentId, MaxAttestBatch> =
            BoundedVec::try_from(iids.clone()).unwrap();
        assert_ok!(IntentSettlement::attest_batch_intents(
            RuntimeOrigin::signed(1),
            bv,
            sigs,
        ));
        for iid in iids.iter() {
            let intent =
                pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
            assert_eq!(intent.status, IntentStatus::Attested);
        }
    });
}

#[test]
fn submit_batch_intents_request_payout_does_not_touch_credit() {
    // RequestPayout entries don't debit credit — proven separately via
    // `submit_intent_request_payout_doesnt_touch_credit`. Replicate that
    // invariant for the batch path.
    new_test_ext().execute_with(|| {
        let entries: Vec<SubmitIntentEntry> = (0..5)
            .map(|i| rp_entry(0xE0u8.wrapping_add(i)))
            .collect();
        let bv: BoundedVec<SubmitIntentEntry, MaxSubmitBatch> =
            BoundedVec::try_from(entries).unwrap();
        assert_ok!(IntentSettlement::submit_batch_intents(
            RuntimeOrigin::signed(BOB),
            bv,
        ));
        assert_eq!(
            pallet_intent_settlement::pallet::Credits::<Test>::get(BOB),
            0
        );
        assert_eq!(
            pallet_intent_settlement::pallet::Nonces::<Test>::get(BOB),
            5
        );
    });
}

#[test]
fn submit_batch_intents_scales_within_pending_batches_bound() {
    // The test runtime caps MaxPendingBatches at 16, so the largest unit-
    // test batch we can land is 16 entries (every Pending intent occupies
    // an index slot until it terminalizes). Production runtime sets
    // MaxPendingBatches = 10_000 and the bench harness pushes the full
    // MAX_SUBMIT_BATCH = 256 against that — see benchmarking.rs.
    //
    // 16 is sufficient to prove the linear loop is sound on a heterogeneous
    // mix of BuyPolicy + RequestPayout entries.
    new_test_ext().execute_with(|| {
        const N: u32 = 16;
        // Bump NAV so 16 BuyPolicy premiums fit.
        pallet_intent_settlement::pallet::PoolUtilization::<Test>::mutate(|u| {
            u.total_nav_ada = u.total_nav_ada.saturating_add(1_000_000_000);
        });
        pallet_intent_settlement::pallet::Credits::<Test>::insert(
            ALICE,
            1_000_000_000u64,
        );

        let mut entries: Vec<SubmitIntentEntry> = Vec::with_capacity(N as usize);
        for i in 0..N {
            if i % 2 == 0 {
                entries.push(bp_entry(i as u8, 1_000));
            } else {
                entries.push(rp_entry(i as u8));
            }
        }
        let bv: BoundedVec<SubmitIntentEntry, MaxSubmitBatch> =
            BoundedVec::try_from(entries).unwrap();
        assert_ok!(IntentSettlement::submit_batch_intents(
            RuntimeOrigin::signed(ALICE),
            bv,
        ));
        assert_eq!(
            pallet_intent_settlement::pallet::Nonces::<Test>::get(ALICE),
            N as u64
        );
    });
}

#[test]
fn attest_batch_backward_compat_legacy_attest_intent_still_works() {
    // The legacy attest_intent (call_index 1) is unchanged. Single-call
    // accumulation across 2 calls produces the same terminal Attested
    // state as the batch path.
    new_test_ext().execute_with(|| {
        let iid = submit_n_pending(1)[0];
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(1),
            iid,
            mock_pubkey_of(&1),
            [0u8; 64],
        ));
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(2),
            iid,
            mock_pubkey_of(&2),
            [0u8; 64],
        ));
        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
        assert_eq!(intent.status, IntentStatus::Attested);
    });
}

#[test]
fn submit_batch_intents_backward_compat_single_call_still_works() {
    // The existing submit_intent (call_index 0) is untouched. After the
    // batch path lands, single-call submits MUST still work and produce the
    // same terminal state. This is paired with the chain-side bw-compat
    // smoke that runs against the same runtime live.
    new_test_ext().execute_with(|| {
        pallet_intent_settlement::pallet::Credits::<Test>::insert(
            ALICE,
            1_000_000u64,
        );
        let kind = bp(0x77, 1, 500_000);
        let expected_id = intent_id_for(ALICE, 0, &kind, 1);
        assert_ok!(IntentSettlement::submit_intent(
            RuntimeOrigin::signed(ALICE),
            kind,
        ));
        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(expected_id)
                .unwrap();
        assert_eq!(intent.status, IntentStatus::Pending);
    });
}

#[test]
fn attest_batch_payload_deterministic_and_domain_separated() {
    let iids = vec![
        H256::from([1u8; 32]),
        H256::from([2u8; 32]),
    ];
    let a = pallet_intent_settlement::attest_batch_intents_payload(&iids);
    let b = pallet_intent_settlement::attest_batch_intents_payload(&iids);
    assert_eq!(a, b, "deterministic");
    // Domain-separated from STBA. Build a single STBA entry with the same
    // 32-byte content and confirm tags drive the digest apart.
    let stba_entries = vec![SettleBatchEntry {
        claim_id: H256::from([1u8; 32]),
        cardano_tx_hash: [2u8; 32],
        settled_direct: false,
    }];
    let stba = pallet_intent_settlement::settle_batch_atomic_payload(&stba_entries);
    assert_ne!(a, stba, "ABIN != STBA");
}

#[test]
fn attest_batch_payload_parity_fixture_h() {
    // Cross-layer parity: matches the SDK fixture in
    // `sdk/src/multisig.test.ts` ("attestBatchIntentsPayload matches Rust
    // fixture H"). If either side's pre-image format drifts, both fail.
    //
    // Pinned input: 3 intent_ids 0x07*32 / 0x11*32 / 0x22*32.
    let iids = vec![
        H256::from([0x07u8; 32]),
        H256::from([0x11u8; 32]),
        H256::from([0x22u8; 32]),
    ];
    let digest = pallet_intent_settlement::attest_batch_intents_payload(&iids);
    assert_eq!(
        hex_32(digest),
        TASK_211_FIXTURE_H_HEX,
        "ABIN fixture H digest drifted — regenerate SDK fixture too"
    );
}

const TASK_211_FIXTURE_H_HEX: &str =
    "13d4c95e1e392553a6b6462eb0f5a24244007ec2410242b6de8297097a17b613";

// ---------------------------------------------------------------------------
// Task #212 — request_batch_vouchers unit tests
// ---------------------------------------------------------------------------

#[test]
fn request_batch_vouchers_happy_path_n_3() {
    new_test_ext().execute_with(|| {
        let amount = 1_000_000u64;
        let iids = submit_n_attested(3);
        let entries = build_voucher_entries(&iids, amount);
        let bv: BoundedVec<RequestVoucherEntry, MaxVoucherBatch> =
            BoundedVec::try_from(entries.clone()).unwrap();
        let outstanding_before =
            pallet_intent_settlement::pallet::PoolUtilization::<Test>::get()
                .outstanding_coverage_ada;

        // Bump pool NAV so 3 voucher mints fit the cap.
        pallet_intent_settlement::pallet::PoolUtilization::<Test>::mutate(|u| {
            u.total_nav_ada = u.total_nav_ada.saturating_add(amount * 10);
        });

        assert_ok!(IntentSettlement::request_batch_vouchers(
            RuntimeOrigin::signed(1),
            bv,
            rvbn_sigs(),
        ));

        // Each intent now Vouchered, claims + vouchers stored, outstanding
        // coverage incremented by 3 * amount.
        for entry in entries.iter() {
            let intent =
                pallet_intent_settlement::pallet::Intents::<Test>::get(entry.intent_id)
                    .unwrap();
            assert_eq!(intent.status, IntentStatus::Vouchered);
            assert!(
                pallet_intent_settlement::pallet::Vouchers::<Test>::contains_key(
                    entry.claim_id,
                ),
            );
        }
        let outstanding_after =
            pallet_intent_settlement::pallet::PoolUtilization::<Test>::get()
                .outstanding_coverage_ada;
        assert_eq!(outstanding_after - outstanding_before, amount * 3);

        // Per-voucher VoucherIssued events still emitted (bw compat).
        let per_voucher: Vec<_> = System::events()
            .into_iter()
            .filter_map(|er| match er.event {
                RuntimeEvent::IntentSettlement(
                    pallet_intent_settlement::pallet::Event::VoucherIssued { .. }
                ) => Some(()),
                _ => None,
            })
            .collect();
        assert_eq!(per_voucher.len(), 3);

        // BatchVouchersIssued emitted exactly once.
        let batch: Vec<_> = System::events()
            .into_iter()
            .filter_map(|er| match er.event {
                RuntimeEvent::IntentSettlement(
                    pallet_intent_settlement::pallet::Event::BatchVouchersIssued {
                        count, batch_digest, total_amount_ada,
                    }
                ) => Some((count, batch_digest, total_amount_ada)),
                _ => None,
            })
            .collect();
        assert_eq!(batch.len(), 1);
        let (count, _digest, total) = batch[0];
        assert_eq!(count, 3);
        assert_eq!(total, amount * 3);
    });
}

#[test]
fn request_batch_vouchers_atomic_revert_on_invalid_fairness_proof() {
    new_test_ext().execute_with(|| {
        let amount = 1_000_000u64;
        let iids = submit_n_attested(3);
        let mut entries = build_voucher_entries(&iids, amount);
        // Corrupt the second entry's fairness proof: pro_rata_scale_bps > 10_000.
        entries[1].fairness_proof.pro_rata_scale_bps = 99_999;
        let bv: BoundedVec<RequestVoucherEntry, MaxVoucherBatch> =
            BoundedVec::try_from(entries.clone()).unwrap();
        pallet_intent_settlement::pallet::PoolUtilization::<Test>::mutate(|u| {
            u.total_nav_ada = u.total_nav_ada.saturating_add(amount * 10);
        });
        let outstanding_before =
            pallet_intent_settlement::pallet::PoolUtilization::<Test>::get()
                .outstanding_coverage_ada;
        assert_noop!(
            IntentSettlement::request_batch_vouchers(
                RuntimeOrigin::signed(1),
                bv,
                rvbn_sigs(),
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InvalidFairnessProof,
        );
        // No partial mutations.
        for entry in entries.iter() {
            let intent =
                pallet_intent_settlement::pallet::Intents::<Test>::get(entry.intent_id)
                    .unwrap();
            assert_eq!(
                intent.status,
                IntentStatus::Attested,
                "atomicity broken — partial transition on failed batch"
            );
            assert!(
                !pallet_intent_settlement::pallet::Vouchers::<Test>::contains_key(
                    entry.claim_id,
                ),
            );
        }
        let outstanding_after =
            pallet_intent_settlement::pallet::PoolUtilization::<Test>::get()
                .outstanding_coverage_ada;
        assert_eq!(outstanding_before, outstanding_after);
    });
}

#[test]
fn request_batch_vouchers_rejects_duplicate_claim_in_batch() {
    new_test_ext().execute_with(|| {
        let amount = 1_000u64;
        let iids = submit_n_attested(3);
        let mut entries = build_voucher_entries(&iids, amount);
        // Force entries[2].claim_id to collide with entries[0].claim_id.
        entries[2].claim_id = entries[0].claim_id;
        let bv: BoundedVec<RequestVoucherEntry, MaxVoucherBatch> =
            BoundedVec::try_from(entries).unwrap();
        assert_noop!(
            IntentSettlement::request_batch_vouchers(
                RuntimeOrigin::signed(1),
                bv,
                rvbn_sigs(),
            ),
            pallet_intent_settlement::pallet::Error::<Test>::DuplicateClaimInVoucherBatch,
        );
    });
}

#[test]
fn request_batch_vouchers_rejects_pending_intent_in_batch() {
    // An intent that's still Pending (not yet Attested) can't be
    // vouchered. The batch atomically rejects.
    new_test_ext().execute_with(|| {
        let amount = 1_000u64;
        // Two attested + one only-submitted (Pending).
        let iids_attested = submit_n_attested(2);
        let pending_kind = IntentKind::RequestPayout {
            policy_id: H256::from([0xCC; 32]),
            oracle_evidence: BoundedVec::try_from(vec![0u8; 8]).unwrap(),
        };
        let pending_nonce = pallet_intent_settlement::pallet::Nonces::<Test>::get(ALICE);
        let pending_blk: u32 = System::block_number().try_into().unwrap();
        let pending_iid = intent_id_for(ALICE, pending_nonce, &pending_kind, pending_blk);
        assert_ok!(IntentSettlement::submit_intent(
            RuntimeOrigin::signed(ALICE), pending_kind,
        ));
        let mut all_iids = iids_attested.clone();
        all_iids.push(pending_iid);
        let entries = build_voucher_entries(&all_iids, amount);
        let bv: BoundedVec<RequestVoucherEntry, MaxVoucherBatch> =
            BoundedVec::try_from(entries).unwrap();
        assert_noop!(
            IntentSettlement::request_batch_vouchers(
                RuntimeOrigin::signed(1),
                bv,
                rvbn_sigs(),
            ),
            pallet_intent_settlement::pallet::Error::<Test>::IntentStatusMismatch,
        );
    });
}

#[test]
fn request_batch_vouchers_rejects_empty_batch() {
    new_test_ext().execute_with(|| {
        let bv: BoundedVec<RequestVoucherEntry, MaxVoucherBatch> = BoundedVec::default();
        assert_noop!(
            IntentSettlement::request_batch_vouchers(
                RuntimeOrigin::signed(1),
                bv,
                rvbn_sigs(),
            ),
            pallet_intent_settlement::pallet::Error::<Test>::EmptyVoucherBatch,
        );
    });
}

#[test]
fn request_batch_vouchers_rejects_non_committee_caller() {
    new_test_ext().execute_with(|| {
        let amount = 1_000u64;
        let iids = submit_n_attested(1);
        let entries = build_voucher_entries(&iids, amount);
        let bv: BoundedVec<RequestVoucherEntry, MaxVoucherBatch> =
            BoundedVec::try_from(entries).unwrap();
        assert_noop!(
            IntentSettlement::request_batch_vouchers(
                RuntimeOrigin::signed(ALICE), // not committee
                bv,
                rvbn_sigs(),
            ),
            pallet_intent_settlement::pallet::Error::<Test>::NotCommitteeMember,
        );
    });
}

#[test]
fn request_batch_vouchers_below_threshold_rejected() {
    new_test_ext().execute_with(|| {
        let amount = 1_000u64;
        let iids = submit_n_attested(1);
        let entries = build_voucher_entries(&iids, amount);
        let bv: BoundedVec<RequestVoucherEntry, MaxVoucherBatch> =
            BoundedVec::try_from(entries).unwrap();
        assert_noop!(
            IntentSettlement::request_batch_vouchers(
                RuntimeOrigin::signed(1),
                bv,
                vec![mock_sig_for(1)], // only 1 sig, threshold is 2
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InsufficientSignatures,
        );
    });
}

#[test]
fn request_batch_vouchers_signature_must_match_canonical_batch_digest() {
    // The pallet computes voucher_digest + bfpr_digest deterministically
    // before forming the canonical RVBN pre-image. A sig over the legacy
    // single-call RVCH digest (per-entry) must NOT verify against the
    // batch path's RVBN digest. Pure-function assertion.
    let entries = vec![
        (
            H256::from([1u8; 32]),
            H256::from([2u8; 32]),
            [3u8; 32],
            [4u8; 32],
        ),
    ];
    let rvbn = pallet_intent_settlement::request_batch_vouchers_payload(&entries);
    let rvch = pallet_intent_settlement::request_voucher_payload(
        &entries[0].0, &entries[0].1, &entries[0].2, &entries[0].3,
    );
    assert_ne!(rvbn, rvch, "RVBN must domain-separate from RVCH");
}

#[test]
fn request_batch_vouchers_backward_compat_legacy_single_call() {
    // The legacy 5-arg `request_voucher` (call_index 2, with M-of-N from
    // PR #26) is unchanged. Mint via the legacy path and confirm terminal
    // state matches what the batch path produces.
    new_test_ext().execute_with(|| {
        let amount = 100_000u64;
        let iid = submit_n_attested(1)[0];
        let claim_id = H256::from([0xEE; 32]);
        let bfpr = good_fairness_proof(iid, amount);
        let voucher = good_voucher(claim_id, &bfpr, amount);
        pallet_intent_settlement::pallet::PoolUtilization::<Test>::mutate(|u| {
            u.total_nav_ada = u.total_nav_ada.saturating_add(amount * 10);
        });
        assert_ok!(IntentSettlement::request_voucher(
            RuntimeOrigin::signed(1),
            claim_id,
            iid,
            voucher,
            bfpr,
            mock_voucher_sigs(),
        ));
        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
        assert_eq!(intent.status, IntentStatus::Vouchered);
    });
}

#[test]
fn request_batch_vouchers_payload_deterministic_and_domain_separated() {
    let entries = vec![
        (
            H256::from([1u8; 32]),
            H256::from([2u8; 32]),
            [3u8; 32],
            [4u8; 32],
        ),
        (
            H256::from([5u8; 32]),
            H256::from([6u8; 32]),
            [7u8; 32],
            [8u8; 32],
        ),
    ];
    let a = pallet_intent_settlement::request_batch_vouchers_payload(&entries);
    let b = pallet_intent_settlement::request_batch_vouchers_payload(&entries);
    assert_eq!(a, b, "deterministic");
    let mut reversed = entries.clone();
    reversed.reverse();
    let c = pallet_intent_settlement::request_batch_vouchers_payload(&reversed);
    assert_ne!(a, c, "order matters");
}

#[test]
fn request_batch_vouchers_payload_parity_fixture_i() {
    // Cross-layer parity: matches the SDK fixture in
    // `sdk/src/multisig.test.ts` ("requestBatchVouchersPayload matches
    // Rust fixture I"). Pinned input: 2 entries with structured tuple
    // bytes.
    let entries = vec![
        (
            H256::from([0x07u8; 32]),
            H256::from([0x11u8; 32]),
            [0x22u8; 32],
            [0x33u8; 32],
        ),
        (
            H256::from([0x44u8; 32]),
            H256::from([0x55u8; 32]),
            [0x66u8; 32],
            [0x77u8; 32],
        ),
    ];
    let digest = pallet_intent_settlement::request_batch_vouchers_payload(&entries);
    assert_eq!(
        hex_32(digest),
        TASK_212_FIXTURE_I_HEX,
        "RVBN fixture I digest drifted — regenerate SDK fixture too"
    );
}

const TASK_212_FIXTURE_I_HEX: &str =
    "f82d8e395614d905f0a12f78adf5e6562f6493247327bcbac42f5aeba3f34873";

#[test]
fn submit_batch_intents_payload_is_deterministic_and_domain_separated() {
    let entries = vec![
        bp_entry(0x01, 100),
        rp_entry(0x02),
        bp_entry(0x03, 200),
    ];
    let a = pallet_intent_settlement::submit_batch_intents_payload(&entries);
    let b = pallet_intent_settlement::submit_batch_intents_payload(&entries);
    assert_eq!(a, b, "deterministic");

    // Reordering changes the digest.
    let mut reversed = entries.clone();
    reversed.reverse();
    let c = pallet_intent_settlement::submit_batch_intents_payload(&reversed);
    assert_ne!(a, c, "order matters");

    // Domain-separated from STBA. Build a settle batch over 3 entries and
    // compare digests — even with different inner types the tag must guard
    // against any cross-replay.
    let stba_entries = vec![
        SettleBatchEntry {
            claim_id: H256::from([0u8; 32]),
            cardano_tx_hash: [0u8; 32],
            settled_direct: false,
        },
    ];
    let stba = pallet_intent_settlement::settle_batch_atomic_payload(&stba_entries);
    assert_ne!(a, stba, "SBIN != STBA");
}

#[test]
fn submit_batch_intents_payload_parity_fixture_g() {
    // Cross-layer parity: matches the SDK fixture in
    // `sdk/src/multisig.test.ts` ("submitBatchIntentsPayload matches Rust
    // fixture G"). If either side's pre-image format drifts, both fail.
    //
    // Fixture inputs: 3 entries, deterministic — RequestPayout(seed=0x07),
    // RequestPayout(seed=0x11), RequestPayout(seed=0x22) with 4-byte oracle
    // evidence each.
    let entries = vec![
        SubmitIntentEntry {
            kind: IntentKind::RequestPayout {
                policy_id: H256::from([0x07u8; 32]),
                oracle_evidence: BoundedVec::try_from(vec![0u8; 4]).unwrap(),
            },
        },
        SubmitIntentEntry {
            kind: IntentKind::RequestPayout {
                policy_id: H256::from([0x11u8; 32]),
                oracle_evidence: BoundedVec::try_from(vec![0u8; 4]).unwrap(),
            },
        },
        SubmitIntentEntry {
            kind: IntentKind::RequestPayout {
                policy_id: H256::from([0x22u8; 32]),
                oracle_evidence: BoundedVec::try_from(vec![0u8; 4]).unwrap(),
            },
        },
    ];
    let digest = pallet_intent_settlement::submit_batch_intents_payload(&entries);
    assert_eq!(
        hex_32(digest),
        TASK_210_FIXTURE_G_HEX,
        "SBIN fixture G digest drifted — regenerate SDK fixture too"
    );
}

/// Fixture G expected hex for `submit_batch_intents_payload`. Generated by
/// `sp_core::hashing::blake2_256(b"SBIN" || u32_le(N) || N×scale(IntentKind))`
/// with the entries pinned in `submit_batch_intents_payload_parity_fixture_g`.
/// The SDK test pins the same hex so any drift in either implementation
/// fails loudly in CI.
const TASK_210_FIXTURE_G_HEX: &str =
    "a6644ed7143c4460cb5d0b1fab0fd1de6badee4e663b1a6d11d1c223404afb0a";

// ---------------------------------------------------------------------------
// Task #221 — pre-merge regression tests requested in PR #28 security review.
//
// 5 additional regression tests pin the atomic-revert + bound-checking
// guarantees against the live extrinsic so any future refactor that drops
// `checked_add`, `with_storage_layer`, the duplicate-IntentId precondition,
// the `MaxPendingBatches` guard, or the `MaxSubmitBatch` boundary is
// surfaced loudly in CI rather than silently in production.
// ---------------------------------------------------------------------------

/// Task #221 — Test 1: `SubmitBatchPremiumOverflow` regression.
///
/// Construct two `BuyPolicy` entries whose summed `premium_ada` exceeds
/// `u64::MAX`. The pre-flight `checked_add` in `submit_batch_intents` MUST
/// fire, the call MUST atomically revert (no nonce bump, no credit debit,
/// no `PendingBatches` mutation), and the surfaced error MUST be the
/// dedicated `SubmitBatchPremiumOverflow` variant — NOT a generic
/// `InsufficientCredit` (which would mask the overflow as a balance issue
/// and let an attacker probe credit state via crafted overflow attempts).
///
/// Buggy pre-image this test catches: replacing `checked_add` with
/// `saturating_add` would silently pin the running total at `u64::MAX` and
/// then trip `InsufficientCredit` on the per-entry path inside
/// `do_submit_intent`. The test asserts the error variant explicitly so
/// that swap regresses loudly.
#[test]
fn task221_submit_batch_premium_overflow_atomic_revert() {
    new_test_ext().execute_with(|| {
        // Top up Alice with a sane (non-overflow) credit balance so the
        // overflow check is what fires, not InsufficientCredit. We also
        // record the pre-call state so we can assert ZERO mutation.
        pallet_intent_settlement::pallet::Credits::<Test>::insert(
            ALICE,
            1_000u64,
        );
        let credits_before =
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE);
        let nonce_before =
            pallet_intent_settlement::pallet::Nonces::<Test>::get(ALICE);
        let pb_len_before =
            pallet_intent_settlement::pallet::PendingBatches::<Test>::get().len();

        // Two BuyPolicy entries each with premium=u64::MAX. Their sum
        // overflows u64::MAX on the first checked_add.
        let entries: Vec<SubmitIntentEntry> = vec![
            bp_entry(0xE1, u64::MAX),
            bp_entry(0xE2, u64::MAX),
        ];
        let bv: BoundedVec<SubmitIntentEntry, MaxSubmitBatch> =
            BoundedVec::try_from(entries).unwrap();
        assert_noop!(
            IntentSettlement::submit_batch_intents(
                RuntimeOrigin::signed(ALICE),
                bv,
            ),
            pallet_intent_settlement::pallet::Error::<Test>::SubmitBatchPremiumOverflow,
        );

        // Atomicity: nothing moved. assert_noop! already proves storage is
        // pristine via the runtime test harness, but we double-check the
        // user-visible state explicitly so a future refactor that switches
        // away from with_storage_layer can't mask a partial-mutation bug.
        assert_eq!(
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE),
            credits_before,
            "atomicity broken — credit moved on overflow path"
        );
        assert_eq!(
            pallet_intent_settlement::pallet::Nonces::<Test>::get(ALICE),
            nonce_before,
            "atomicity broken — nonce bumped on overflow path"
        );
        assert_eq!(
            pallet_intent_settlement::pallet::PendingBatches::<Test>::get().len(),
            pb_len_before,
            "atomicity broken — PendingBatches mutated on overflow path"
        );
    });
}

/// Task #221 — Test 2: mid-batch `InsufficientCredit` atomic revert.
///
/// Submit a 10-entry batch where Alice's credit balance is sized to cover
/// EXACTLY the first 4 entries' premiums; entry 5 trips
/// `InsufficientCredit` inside `do_submit_intent`. The atomic semantic
/// MUST roll back the first 4 successful debits AND the 4 nonce bumps AND
/// the 4 PendingBatches insertions — nothing committed. This is the
/// most important atomicity assertion in the suite because it exercises
/// the with_storage_layer rollback after a mid-loop failure (vs the
/// `_one_bad_entry` test which trips at entry 3 of 4).
///
/// Buggy pre-image this test catches: stripping the
/// `with_storage_layer` wrapper would let entries 1-4 commit before
/// entry 5's failure rolls the call back. The test asserts the EXACT
/// pre-call state on every observable, so any partial commit fails the
/// suite.
#[test]
fn task221_submit_batch_insufficient_credit_mid_batch_atomic_revert() {
    new_test_ext().execute_with(|| {
        // Bump pool NAV so pool-utilization isn't the failure mode.
        pallet_intent_settlement::pallet::PoolUtilization::<Test>::mutate(|u| {
            u.total_nav_ada = u.total_nav_ada.saturating_add(50_000_000);
        });
        // Credit ALICE with EXACTLY 4 * 1_000 = 4_000 — entry 5's debit
        // tries 5_000 against 0 remaining and fails.
        pallet_intent_settlement::pallet::Credits::<Test>::insert(
            ALICE,
            4_000u64,
        );

        let credits_before =
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE);
        let nonce_before =
            pallet_intent_settlement::pallet::Nonces::<Test>::get(ALICE);
        let pb_len_before =
            pallet_intent_settlement::pallet::PendingBatches::<Test>::get().len();

        let entries: Vec<SubmitIntentEntry> = (0..10u8)
            .map(|i| bp_entry(0xF0u8.wrapping_add(i), 1_000))
            .collect();
        let bv: BoundedVec<SubmitIntentEntry, MaxSubmitBatch> =
            BoundedVec::try_from(entries).unwrap();
        assert_noop!(
            IntentSettlement::submit_batch_intents(
                RuntimeOrigin::signed(ALICE),
                bv,
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InsufficientCredit,
        );

        // Atomicity: every observable identical to pre-call state.
        assert_eq!(
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE),
            credits_before,
            "atomicity broken — partial credit debit committed"
        );
        assert_eq!(
            pallet_intent_settlement::pallet::Nonces::<Test>::get(ALICE),
            nonce_before,
            "atomicity broken — nonce bumped for committed entries"
        );
        assert_eq!(
            pallet_intent_settlement::pallet::PendingBatches::<Test>::get().len(),
            pb_len_before,
            "atomicity broken — partial PendingBatches insertions committed"
        );
        // No BatchIntentsSubmitted event leaked through the failed call.
        let leaked_events: Vec<_> = System::events()
            .into_iter()
            .filter(|er| matches!(
                er.event,
                RuntimeEvent::IntentSettlement(
                    pallet_intent_settlement::pallet::Event::BatchIntentsSubmitted { .. }
                )
            ))
            .collect();
        assert_eq!(
            leaked_events.len(),
            0,
            "BatchIntentsSubmitted leaked through a failed batch — event ordering is wrong"
        );
    });
}

/// Task #221 — Test 3: `DuplicateIntent` collision against pre-existing
/// chain state.
///
/// Submit a single intent (nonce 0) so it lives in `Intents` storage. Then
/// fabricate a batch where one entry's derived `IntentId` collides with
/// the pre-existing one. We achieve the collision by directly inserting a
/// stub `Intent` entry at the SAME `IntentId` that the batch's k-th entry
/// would derive — that's the real-world failure mode (same nonce window
/// retried twice, or a deliberate adversarial nonce-reuse attempt). The
/// whole batch MUST atomically revert.
///
/// Buggy pre-image this test catches: dropping `with_storage_layer` from
/// the per-entry submit path means the entries BEFORE the collision
/// commit. Also catches: stripping the
/// `ensure!(!Intents::<T>::contains_key(intent_id), DuplicateIntent)`
/// guard from `do_submit_intent` would let the new batch silently
/// overwrite the pre-existing intent.
#[test]
fn task221_submit_batch_duplicate_intent_pre_existing_atomic_revert() {
    new_test_ext().execute_with(|| {
        // Top up + bump NAV so credit/cap aren't the issue.
        pallet_intent_settlement::pallet::PoolUtilization::<Test>::mutate(|u| {
            u.total_nav_ada = u.total_nav_ada.saturating_add(50_000_000);
        });
        pallet_intent_settlement::pallet::Credits::<Test>::insert(
            ALICE,
            10_000_000u64,
        );

        // Build the batch's 3rd entry kind UP FRONT, derive its IntentId
        // (ALICE's nonce will be 2 by then, block 1), and pre-insert a
        // stub Intent there.
        let collision_kind = bp(0x77, 1, 1_000);
        let collision_iid = intent_id_for(ALICE, 2, &collision_kind, 1);
        // Insert a stub intent at the colliding ID. Use a RequestPayout
        // kind so it's clearly distinct from the BuyPolicy that would
        // overwrite.
        pallet_intent_settlement::pallet::Intents::<Test>::insert(
            collision_iid,
            Intent {
                submitter: ALICE,
                nonce: 999,
                kind: IntentKind::RequestPayout {
                    policy_id: H256::from([0u8; 32]),
                    oracle_evidence: BoundedVec::try_from(vec![0u8; 4]).unwrap(),
                },
                submitted_block: 1,
                ttl_block: 1_000,
                status: IntentStatus::Pending,
            },
        );

        let credits_before =
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE);
        let nonce_before =
            pallet_intent_settlement::pallet::Nonces::<Test>::get(ALICE);

        // 4-entry batch — entry 3 (0-indexed: index 2) collides.
        let entries: Vec<SubmitIntentEntry> = vec![
            bp_entry(0x70, 1_000),
            bp_entry(0x71, 1_000),
            SubmitIntentEntry { kind: collision_kind },
            bp_entry(0x73, 1_000),
        ];
        let bv: BoundedVec<SubmitIntentEntry, MaxSubmitBatch> =
            BoundedVec::try_from(entries).unwrap();
        assert_noop!(
            IntentSettlement::submit_batch_intents(
                RuntimeOrigin::signed(ALICE),
                bv,
            ),
            pallet_intent_settlement::pallet::Error::<Test>::DuplicateIntent,
        );

        // Atomicity: pre-existing colliding intent is UNCHANGED (status
        // still Pending with its stub fields), credits/nonce identical.
        let preserved =
            pallet_intent_settlement::pallet::Intents::<Test>::get(collision_iid)
                .expect("pre-existing intent must still be in storage");
        assert_eq!(preserved.nonce, 999, "stub intent overwritten — atomicity bug");
        assert_eq!(
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE),
            credits_before,
            "atomicity broken — credit moved despite duplicate-intent revert"
        );
        assert_eq!(
            pallet_intent_settlement::pallet::Nonces::<Test>::get(ALICE),
            nonce_before,
            "atomicity broken — nonce bumped despite duplicate-intent revert"
        );
    });
}

/// Task #221 — Test 4: `PendingBatchesFull` mid-batch atomic revert.
///
/// Fill `PendingBatches` to N-1 (=15 in test runtime where
/// MaxPendingBatches=16), submit a 2-entry batch (the second push would
/// take it to 17 > 16). The batch MUST atomically revert; entry 1 (which
/// would have fit) MUST NOT be silently committed.
///
/// Buggy pre-image this test catches: pre-checking `pb.len() + N <=
/// MaxPendingBatches` BEFORE the loop would be a correct design but
/// stripping it in favour of relying on `try_push` per entry inside
/// `with_storage_layer` is the *current* design. This test pins the
/// per-entry-then-rollback path: if a future PR moves the check to
/// pre-loop AND drops the rollback wrapper, we still want the failure
/// mode to be atomic.
#[test]
fn task221_submit_batch_pending_full_mid_batch_atomic_revert() {
    new_test_ext().execute_with(|| {
        // Bump NAV so pool-cap isn't the failure mode.
        pallet_intent_settlement::pallet::PoolUtilization::<Test>::mutate(|u| {
            u.total_nav_ada = u.total_nav_ada.saturating_add(50_000_000);
        });
        pallet_intent_settlement::pallet::Credits::<Test>::insert(
            ALICE,
            10_000_000u64,
        );
        // Fill PendingBatches to N-1 = 15 by submitting 15 single intents.
        for i in 0..15u8 {
            assert_ok!(IntentSettlement::submit_intent(
                RuntimeOrigin::signed(ALICE),
                bp(0x80u8.wrapping_add(i), 1, 1_000),
            ));
        }
        assert_eq!(
            pallet_intent_settlement::pallet::PendingBatches::<Test>::get().len(),
            15,
            "test setup wrong — PendingBatches should be at 15 before the batch"
        );

        let credits_before =
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE);
        let nonce_before =
            pallet_intent_settlement::pallet::Nonces::<Test>::get(ALICE);

        // 2-entry batch. First entry pushes PendingBatches from 15 -> 16
        // (still fits). Second entry would push 16 -> 17 and trip
        // PendingBatchesFull. The whole batch MUST revert — including the
        // first entry's mutation.
        let entries: Vec<SubmitIntentEntry> = vec![
            bp_entry(0x90, 1_000),
            bp_entry(0x91, 1_000),
        ];
        let bv: BoundedVec<SubmitIntentEntry, MaxSubmitBatch> =
            BoundedVec::try_from(entries).unwrap();
        assert_noop!(
            IntentSettlement::submit_batch_intents(
                RuntimeOrigin::signed(ALICE),
                bv,
            ),
            pallet_intent_settlement::pallet::Error::<Test>::PendingBatchesFull,
        );

        // Atomicity: still at 15, credits + nonce unchanged from pre-batch.
        assert_eq!(
            pallet_intent_settlement::pallet::PendingBatches::<Test>::get().len(),
            15,
            "atomicity broken — PendingBatches partially committed before fill error"
        );
        assert_eq!(
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE),
            credits_before,
            "atomicity broken — credit moved through a failed-fill batch"
        );
        assert_eq!(
            pallet_intent_settlement::pallet::Nonces::<Test>::get(ALICE),
            nonce_before,
            "atomicity broken — nonce bumped for committed entry of failed batch"
        );
    });
}

// ---------------------------------------------------------------------------
// Task #221 — Test 5: full N=256 (MaxSubmitBatch) boundary test.
//
// The main mock runtime caps MaxPendingBatches at 16; landing N=256 needs
// a parallel mock runtime where MaxPendingBatches >= 256 (matching the
// production materios-runtime config of MaxPendingBatches=10_000). We
// encapsulate that runtime in its own sub-module so the rest of the suite
// keeps the tight 16-bound (which exercises the per-block storage budget
// realistically) while this single test pushes the call up to its
// declared MaxSubmitBatch boundary.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod max_submit_batch_boundary {
    use crate as pallet_intent_settlement;
    use crate::pallet::{IsCommitteeMember, VerifyCommitteeSignature};
    use crate::types::*;
    use frame_support::{
        assert_ok, construct_runtime, derive_impl, parameter_types,
        BoundedVec,
    };
    use sp_core::H256;
    use sp_runtime::{traits::IdentityLookup, BuildStorage};

    type Block = frame_system::mocking::MockBlock<Test>;

    construct_runtime! {
        pub enum Test {
            System: frame_system,
            IntentSettlement: pallet_intent_settlement,
        }
    }

    #[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
    impl frame_system::Config for Test {
        type Block = Block;
        type AccountId = u64;
        type Lookup = IdentityLookup<Self::AccountId>;
    }

    parameter_types! {
        pub const MaxCommittee: u32 = 32;
        pub const MaxExpirePerBlock: u32 = 1024;
        pub const DefaultIntentTTL: u32 = 600;
        pub const DefaultClaimTTL: u32 = 28_800;
        /// Production-aligned: 10_000 to comfortably hold a full 256-entry
        /// batch alongside any pre-existing pending intents.
        pub const MaxPendingBatches: u32 = 10_000;
        pub const DefaultMinSignerThreshold: u32 = 2;
        pub const MaxSettleBatch: u32 = 256;
        pub const MaxAttestBatch: u32 = 256;
        /// Pre-existing: this mock was merged on main without MaxVoucherBatch
        /// (introduced after the mock was authored). Adding the missing entry
        /// here unblocks the entire `cargo test -p pallet-intent-settlement`
        /// flow (otherwise ALL tests fail to compile).
        pub const MaxVoucherBatch: u32 = 256;
        /// The boundary we're probing — production MAX_SUBMIT_BATCH = 256.
        pub const MaxSubmitBatch: u32 = 256;
    }

    fn pubkey_of(who: &u64) -> CommitteePubkey {
        let mut out = [0u8; 32];
        out[..8].copy_from_slice(&who.to_le_bytes());
        out
    }
    fn account_of_pubkey(pubkey: &CommitteePubkey) -> Option<u64> {
        let mut lo = [0u8; 8];
        lo.copy_from_slice(&pubkey[..8]);
        let candidate = u64::from_le_bytes(lo);
        if matches!(candidate, 1 | 2 | 3) && pubkey[8..].iter().all(|b| *b == 0) {
            Some(candidate)
        } else {
            None
        }
    }

    pub struct MockCommittee;
    impl IsCommitteeMember<u64> for MockCommittee {
        fn is_member(who: &u64) -> bool {
            matches!(*who, 1 | 2 | 3)
        }
        fn threshold() -> u32 { 2 }
        fn member_count() -> u32 { 3 }
        fn pubkey_of(who: &u64) -> CommitteePubkey { pubkey_of(who) }
        fn account_of_pubkey(pubkey: &CommitteePubkey) -> Option<u64> {
            account_of_pubkey(pubkey)
        }
    }

    pub struct MockSigVerifier;
    impl VerifyCommitteeSignature for MockSigVerifier {
        fn verify(pubkey: &CommitteePubkey, sig: &CommitteeSig, _msg: &[u8]) -> bool {
            sig[0] == pubkey[0]
        }
    }

    impl pallet_intent_settlement::pallet::Config for Test {
        type RuntimeEvent = RuntimeEvent;
        type MaxCommittee = MaxCommittee;
        type MaxExpirePerBlock = MaxExpirePerBlock;
        type DefaultIntentTTL = DefaultIntentTTL;
        type DefaultClaimTTL = DefaultClaimTTL;
        type CommitteeMembership = MockCommittee;
        type MaxPendingBatches = MaxPendingBatches;
        type DefaultMinSignerThreshold = DefaultMinSignerThreshold;
        type SigVerifier = MockSigVerifier;
        type MaxSettleBatch = MaxSettleBatch;
        type MaxAttestBatch = MaxAttestBatch;
        type MaxVoucherBatch = MaxVoucherBatch;
        type MaxSubmitBatch = MaxSubmitBatch;
    }

    const ALICE: u64 = 100;

    fn new_test_ext() -> sp_io::TestExternalities {
        let t = frame_system::GenesisConfig::<Test>::default()
            .build_storage()
            .unwrap();
        let mut ext = sp_io::TestExternalities::new(t);
        ext.execute_with(|| {
            System::set_block_number(1);
            pallet_intent_settlement::pallet::IntentTTL::<Test>::put(600u32);
            pallet_intent_settlement::pallet::ClaimTTL::<Test>::put(28_800u32);
            pallet_intent_settlement::pallet::PoolUtilization::<Test>::put(
                PoolUtilizationParams {
                    target_bps: 5_000,
                    cap_bps: 7_500,
                    // Bump NAV way up so 256 BuyPolicy premiums fit under cap.
                    total_nav_ada: 1_000_000_000_000,
                    outstanding_coverage_ada: 0,
                },
            );
            pallet_intent_settlement::pallet::MinSignerThreshold::<Test>::put(2u32);
        });
        ext
    }

    /// Task #221 — Test 5: full N=256 boundary success.
    ///
    /// Submit a batch with EXACTLY MaxSubmitBatch=256 entries. The call MUST
    /// succeed, all 256 intents MUST be in `Intents`, the `PendingBatches`
    /// index MUST be at 256, the user's nonce MUST advance by 256, and the
    /// `BatchIntentsSubmitted` event MUST report `count == 256`. This pins
    /// the boundary against any future runtime config drift that would
    /// silently let MaxSubmitBatch decrease.
    ///
    /// Weight assertion intentionally NOT made here — the bench-cli wiring
    /// (#190) is still pending so per-block weight is approximated by the
    /// inline `#[pallet::weight(...)]` expression in lib.rs. What we DO
    /// pin here is that the call doesn't panic / overflow / saturate at
    /// the boundary, and that the `count` field of the event matches the
    /// declared MaxSubmitBatch constant — that's the load-bearing invariant
    /// for indexer correlation.
    ///
    /// Buggy pre-image this test catches: lowering MaxSubmitBatch in the
    /// runtime without touching MAX_SUBMIT_BATCH in types.rs would let the
    /// SDK build a 256-entry payload that the runtime then rejects via
    /// BoundedVec::try_from. This test would fail loudly at the BoundedVec
    /// step.
    #[test]
    fn task221_submit_batch_n_256_boundary_success() {
        use crate::types::SubmitIntentEntry;
        use frame_support::assert_ok;
        new_test_ext().execute_with(|| {
            const N: u32 = 256;
            // Top up Alice with enough credit for 256 BuyPolicy premiums of
            // 1_000 each = 256_000 lovelace. Make it 10x for headroom.
            pallet_intent_settlement::pallet::Credits::<Test>::insert(
                ALICE,
                2_560_000u64,
            );

            let entries: Vec<SubmitIntentEntry> = (0..N)
                .map(|i| SubmitIntentEntry {
                    kind: IntentKind::BuyPolicy {
                        product_id: H256::from([(i & 0xFF) as u8; 32]),
                        strike: 1,
                        term_slots: 86_400,
                        premium_ada: 1_000,
                        beneficiary_cardano_addr:
                            BoundedVec::try_from(vec![0xA1u8; 57]).unwrap(),
                    },
                })
                .collect();
            let bv: BoundedVec<SubmitIntentEntry, MaxSubmitBatch> =
                BoundedVec::try_from(entries.clone())
                    .expect("entries.len() must == MaxSubmitBatch == 256");
            assert_eq!(
                bv.len() as u32,
                N,
                "test setup wrong — BoundedVec is not at the N=256 boundary"
            );

            assert_ok!(IntentSettlement::submit_batch_intents(
                RuntimeOrigin::signed(ALICE),
                bv,
            ));

            // Post-conditions: 256 intents stored, nonce advanced by 256,
            // PendingBatches index at 256, BatchIntentsSubmitted event with
            // count == 256.
            assert_eq!(
                pallet_intent_settlement::pallet::Nonces::<Test>::get(ALICE),
                N as u64,
                "nonce did not advance to 256 after a successful 256-entry batch"
            );
            let pb = pallet_intent_settlement::pallet::PendingBatches::<Test>::get();
            assert_eq!(
                pb.len() as u32,
                N,
                "PendingBatches did not capture all 256 intents"
            );
            // Hunt the event with count == 256.
            let count_event = System::events()
                .into_iter()
                .find_map(|er| match er.event {
                    RuntimeEvent::IntentSettlement(
                        pallet_intent_settlement::pallet::Event::BatchIntentsSubmitted {
                            count, ..
                        }
                    ) => Some(count),
                    _ => None,
                });
            assert_eq!(
                count_event,
                Some(N),
                "BatchIntentsSubmitted event missing or wrong count at the N=256 boundary"
            );
        });
    }
}

