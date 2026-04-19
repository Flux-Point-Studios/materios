//! End-to-end integration tests for the Materios happy path.
//!
//! These tests exercise the full loop:
//! receipt-builder -> submit_receipt -> MOTRA fee burn -> query receipt -> verify roots.
//!
//! This module lives in orinq-receipts but tests cross-pallet interaction
//! between `pallet_orinq_receipts`, `pallet_motra`, and `pallet_balances`.
//!
//! NOTE on mock types: AccountId must impl `From<[u8; 32]>` and BlockNumber
//! must satisfy `Into<u32> + From<u32>` because the pallet's `#[pallet::hooks]`
//! impl declares those bounds (find_block_author + validator-rewards era
//! arithmetic). We use `AccountId32` + `u32` block numbers to match.

use frame_support::{
    assert_noop, assert_ok, construct_runtime, derive_impl, parameter_types,
    traits::{ConstBool, ConstU32, ConstU64, Hooks},
};
use sp_core::{crypto::AccountId32, H256};
use sp_runtime::{traits::IdentityLookup, BuildStorage, Perbill};

use crate::weights::WeightInfo as OrinqWeightInfo;

// ---------------------------------------------------------------------------
// Mock runtime with ALL pallets required for the Materios happy path
// ---------------------------------------------------------------------------

type Block = frame_system::mocking::MockBlockU32<Test>;
type MockAccountId = AccountId32;

construct_runtime! {
    pub enum Test {
        System: frame_system,
        Timestamp: pallet_timestamp,
        Aura: pallet_aura,
        Grandpa: pallet_grandpa,
        Balances: pallet_balances,
        Motra: pallet_motra,
        OrinqReceipts: crate,
    }
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
    type AccountId = MockAccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type AccountData = pallet_balances::AccountData<u128>;
}

parameter_types! {
    pub const MinimumPeriod: u64 = 5;
    pub const ExistentialDeposit: u128 = 1;
}

impl pallet_timestamp::Config for Test {
    type Moment = u64;
    type OnTimestampSet = ();
    type MinimumPeriod = MinimumPeriod;
    type WeightInfo = ();
}

impl pallet_aura::Config for Test {
    type AuthorityId = sp_consensus_aura::sr25519::AuthorityId;
    type DisabledValidators = ();
    type MaxAuthorities = ConstU32<32>;
    type AllowMultipleBlocksPerSlot = ConstBool<false>;
    type SlotDuration = pallet_aura::MinimumPeriodTimesTwo<Test>;
}

impl pallet_grandpa::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = ();
    type MaxAuthorities = ConstU32<32>;
    type MaxNominators = ConstU32<0>;
    type MaxSetIdSessionEntries = ConstU64<0>;
    type KeyOwnerProof = sp_core::Void;
    type EquivocationReportSystem = ();
}

impl pallet_balances::Config for Test {
    type MaxLocks = ConstU32<50>;
    type MaxReserves = ConstU32<50>;
    type ReserveIdentifier = [u8; 8];
    type Balance = u128;
    type RuntimeEvent = RuntimeEvent;
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = ();
    type FreezeIdentifier = ();
    type MaxFreezes = ConstU32<0>;
    type RuntimeHoldReason = RuntimeHoldReason;
    type RuntimeFreezeReason = RuntimeFreezeReason;
}

impl pallet_motra::pallet::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = pallet_motra::weights::SubstrateWeight;
}

impl crate::pallet::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = crate::weights::SubstrateWeight;
    type MaxResubmits = ConstU32<64>;
    type MaxCommitteeSize = ConstU32<16>;
}

// ---------------------------------------------------------------------------
// Genesis builder
// ---------------------------------------------------------------------------

/// Construct a deterministic AccountId32 from a single byte seed (for tests).
fn acc(seed: u8) -> MockAccountId {
    AccountId32::new([seed; 32])
}

fn new_integration_ext() -> sp_io::TestExternalities {
    let mut t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();

    // Fund Alice (account 1) with MATRA.
    pallet_balances::GenesisConfig::<Test> {
        balances: vec![
            (acc(1), 10_000_000_000_000_000), // Alice: 10,000 MATRA (12 decimals)
        ],
    }
    .assimilate_storage(&mut t)
    .unwrap();

    // Set MOTRA params — GenesisConfig now has flat (ppm) fields, not a nested
    // MotraParams struct. This fixture drifted from the real pallet when the
    // v5 decimal split landed (see commit f503ec2).
    pallet_motra::GenesisConfig::<Test> {
        min_fee: 1_000,
        congestion_rate: 0,
        target_fullness_ppm: Perbill::from_percent(50).deconstruct(),
        decay_rate_per_block_ppm: 999_000_000, // 99.9% retained
        generation_per_matra_per_block: 1_000,
        max_balance: 1_000_000_000_000_000,
        max_congestion_step: 500,
        length_fee_per_byte: 1_000,
        congestion_smoothing_ppm: Perbill::from_percent(10).deconstruct(),
        _phantom: Default::default(),
    }
    .assimilate_storage(&mut t)
    .unwrap();

    let mut ext = sp_io::TestExternalities::new(t);
    ext.execute_with(|| {
        System::set_block_number(1);
        Timestamp::set_timestamp(1_000);
    });
    ext
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Advance `n` blocks, calling `on_finalize` (which adjusts congestion rate) each time.
fn advance_blocks(n: u64) {
    for _ in 0..n {
        let current = System::block_number();
        Motra::on_finalize(current);
        System::set_block_number(current + 1);
    }
}

/// Helper to submit a receipt with controlled field values.
fn submit_receipt_helper(
    who: MockAccountId,
    receipt_id: H256,
    content_hash: H256,
    base_root_sha256: [u8; 32],
    base_manifest_hash: [u8; 32],
    safety_manifest_hash: [u8; 32],
    monitor_config_hash: [u8; 32],
    attestation_evidence_hash: [u8; 32],
    storage_locator_hash: [u8; 32],
    schema_hash: [u8; 32],
) -> frame_support::dispatch::DispatchResult {
    crate::Pallet::<Test>::submit_receipt(
        RuntimeOrigin::signed(who),
        receipt_id,
        content_hash,
        base_root_sha256,
        None, // zk_root_poseidon
        None, // poseidon_params_hash
        base_manifest_hash,
        safety_manifest_hash,
        monitor_config_hash,
        attestation_evidence_hash,
        storage_locator_hash,
        schema_hash,
    )
}

/// Shorthand: submit a receipt with dummy hashes (varying only receipt_id / content_hash).
fn submit_receipt_quick(
    who: MockAccountId,
    receipt_id: H256,
    content_hash: H256,
) -> frame_support::dispatch::DispatchResult {
    submit_receipt_helper(
        who,
        receipt_id,
        content_hash,
        [0x11; 32],
        [0x22; 32],
        [0x33; 32],
        [0x44; 32],
        [0x55; 32],
        [0x66; 32],
        [0x77; 32],
    )
}

// ============================================================================
// THE "IT'S ALIVE" TEST
//
// Full happy-path: MATRA -> generate MOTRA -> submit receipt -> fee burn -> query
// ============================================================================

#[test]
fn e2e_receipt_submit_with_motra_fee_burn_and_query() {
    new_integration_ext().execute_with(|| {
        let alice = acc(1);

        // ---- Step 1: Verify Alice has MATRA but no MOTRA yet ----
        let matra = pallet_balances::Pallet::<Test>::free_balance(&alice);
        assert!(matra > 0, "Alice should have MATRA: {}", matra);
        assert_eq!(matra, 10_000_000_000_000_000, "Alice should have exactly 10,000 MATRA");

        let motra_before_gen = pallet_motra::MotraBalances::<Test>::get(&alice);
        assert_eq!(motra_before_gen, 0, "Alice should start with 0 MOTRA");

        // ---- Step 2: Advance blocks to generate MOTRA ----
        advance_blocks(100);

        // Claim MOTRA (triggers reconciliation: decay + generation).
        assert_ok!(pallet_motra::Pallet::<Test>::claim_motra(
            RuntimeOrigin::signed(alice.clone())
        ));

        let motra_after_gen = pallet_motra::MotraBalances::<Test>::get(&alice);
        assert!(
            motra_after_gen > 0,
            "Alice should have generated MOTRA after 100 blocks: {}",
            motra_after_gen
        );

        // Sanity-check: generation = MATRA * gen_rate * elapsed / 10^12
        //   = 10_000_000_000_000_000 * 1_000 * 100 / 1_000_000_000_000
        //   = 1_000_000_000 (before decay)
        // With decay applied, the final value is somewhat lower, but should be > 500M.
        assert!(
            motra_after_gen > 500_000_000,
            "Expected substantial MOTRA, got: {}",
            motra_after_gen
        );

        // ---- Step 3: Submit receipt ----
        let receipt_id = H256::from([0xAA; 32]);
        let content_hash = H256::from([0xBB; 32]);
        let base_root = [0x11; 32];
        let manifest = [0x22; 32];
        let safety = [0x33; 32];
        let monitor = [0x44; 32];
        let evidence = [0x55; 32];
        let storage = [0x66; 32];
        let schema = [0x77; 32];

        assert_ok!(crate::Pallet::<Test>::submit_receipt(
            RuntimeOrigin::signed(alice.clone()),
            receipt_id,
            content_hash,
            base_root,
            None, // zk_root_poseidon
            None, // poseidon_params_hash
            manifest,
            safety,
            monitor,
            evidence,
            storage,
            schema,
        ));

        // ---- Step 4: Verify receipt is stored and queryable ----
        let record = crate::Pallet::<Test>::receipts(receipt_id)
            .expect("Receipt should exist after submission");

        assert_eq!(record.content_hash, content_hash.0, "content_hash mismatch");
        assert_eq!(record.base_root_sha256, base_root, "base_root mismatch");
        assert_eq!(record.base_manifest_hash, manifest, "manifest_hash mismatch");
        assert_eq!(record.safety_manifest_hash, safety, "safety_manifest_hash mismatch");
        assert_eq!(record.monitor_config_hash, monitor, "monitor_config_hash mismatch");
        assert_eq!(
            record.attestation_evidence_hash, evidence,
            "evidence_hash mismatch"
        );
        assert_eq!(record.storage_locator_hash, storage, "storage_locator_hash mismatch");
        assert_eq!(record.schema_hash, schema, "schema_hash mismatch");
        assert_eq!(record.submitter, alice.clone(), "submitter mismatch");
        assert!(
            record.created_at_millis > 0,
            "timestamp should be set by pallet_timestamp"
        );
        assert_eq!(
            record.created_at_millis, 1_000,
            "timestamp should match the seeded value"
        );
        assert_eq!(
            record.zk_root_poseidon, None,
            "zk_root_poseidon should be None"
        );
        assert_eq!(
            record.poseidon_params_hash, None,
            "poseidon_params_hash should be None"
        );
        assert_eq!(
            record.availability_cert_hash,
            [0u8; 32],
            "availability_cert_hash should be zeroed initially"
        );

        // ---- Step 5: Verify content_hash reverse index ----
        let ids = crate::Pallet::<Test>::content_index(content_hash);
        assert_eq!(ids.len(), 1, "Should have exactly 1 receipt under this content_hash");
        assert_eq!(ids[0], receipt_id);

        // ---- Step 6: Verify receipt counter ----
        assert_eq!(crate::Pallet::<Test>::receipt_count(), 1);

        // ---- Step 7: Test MOTRA fee burn directly ----
        //
        // NOTE: In a real node, the ChargeMotra SignedExtension calls burn_fee
        // automatically during pre_dispatch. In test, we call submit_receipt
        // directly (bypassing the extension), so the fee is NOT auto-burned.
        // Here we exercise burn_fee explicitly to prove the MOTRA burn path works.
        let motra_before_burn = pallet_motra::MotraBalances::<Test>::get(&alice);
        let burn_amount: u128 = 5_000;

        assert_ok!(pallet_motra::Pallet::<Test>::burn_fee(&alice, burn_amount));

        let motra_after_burn = pallet_motra::MotraBalances::<Test>::get(&alice);
        assert!(
            motra_after_burn < motra_before_burn,
            "MOTRA should decrease after fee burn"
        );
        assert_eq!(
            motra_before_burn - motra_after_burn,
            burn_amount,
            "Exact burn amount should be deducted"
        );

        // ---- Step 8: Verify total_burned metric ----
        assert!(
            pallet_motra::TotalBurned::<Test>::get() >= burn_amount,
            "Total burned should track at least our burn"
        );
    });
}

// ============================================================================
// Multiple receipts sharing the same content_hash
// ============================================================================

#[test]
fn e2e_multiple_receipts_same_content_hash() {
    new_integration_ext().execute_with(|| {
        let alice = acc(1);

        // Generate MOTRA for Alice (needed if fee extension were active).
        advance_blocks(50);
        assert_ok!(pallet_motra::Pallet::<Test>::claim_motra(
            RuntimeOrigin::signed(alice.clone())
        ));

        let content_hash = H256::from([0xCC; 32]);

        // Submit 3 receipts with the same content_hash, different receipt_ids.
        for i in 0u8..3 {
            let receipt_id = H256::from([i; 32]);
            assert_ok!(submit_receipt_quick(alice.clone(), receipt_id, content_hash));
        }

        // All 3 should be indexed under the same content_hash.
        let ids = crate::Pallet::<Test>::content_index(content_hash);
        assert_eq!(ids.len(), 3, "Content index should list all 3 receipt IDs");
        assert_eq!(crate::Pallet::<Test>::receipt_count(), 3);

        // Verify each receipt is independently queryable.
        for i in 0u8..3 {
            let receipt_id = H256::from([i; 32]);
            let record = crate::Pallet::<Test>::receipts(receipt_id)
                .expect("Each receipt should be retrievable");
            assert_eq!(record.submitter, alice.clone());
            assert_eq!(record.content_hash, content_hash.0);
        }
    });
}

// ============================================================================
// MOTRA generation -> fee burn -> regeneration lifecycle
// ============================================================================

#[test]
fn e2e_motra_generation_and_fee_lifecycle() {
    new_integration_ext().execute_with(|| {
        let alice = acc(1);

        // Start: no MOTRA.
        assert_eq!(pallet_motra::MotraBalances::<Test>::get(&alice), 0);

        // Generate MOTRA over 200 blocks.
        advance_blocks(200);
        assert_ok!(pallet_motra::Pallet::<Test>::claim_motra(
            RuntimeOrigin::signed(alice.clone())
        ));
        let generated = pallet_motra::MotraBalances::<Test>::get(&alice);
        assert!(
            generated > 1_000_000,
            "Should have substantial MOTRA: {}",
            generated
        );

        // Burn fees multiple times.
        for _ in 0..10 {
            assert_ok!(pallet_motra::Pallet::<Test>::burn_fee(&alice, 10_000));
        }

        let after_burns = pallet_motra::MotraBalances::<Test>::get(&alice);
        assert_eq!(
            generated - after_burns,
            100_000,
            "10 burns of 10k should equal 100k total"
        );

        // Advance more blocks -- balance should recover via generation.
        advance_blocks(100);
        assert_ok!(pallet_motra::Pallet::<Test>::claim_motra(
            RuntimeOrigin::signed(alice.clone())
        ));
        let recovered = pallet_motra::MotraBalances::<Test>::get(&alice);
        assert!(
            recovered > after_burns,
            "MOTRA should regenerate: {} > {}",
            recovered,
            after_burns
        );
    });
}

// ============================================================================
// Delegation: sponsor pays fees with delegated MOTRA
// ============================================================================

#[test]
fn e2e_delegation_sponsor_pays_fees() {
    new_integration_ext().execute_with(|| {
        let alice = acc(1); // Has MATRA, will delegate generation
        let bob = acc(2); // Sponsor target, no MATRA in this test

        // Alice delegates MOTRA generation to Bob.
        assert_ok!(pallet_motra::Pallet::<Test>::set_delegatee(
            RuntimeOrigin::signed(alice.clone()),
            Some(bob.clone())
        ));

        // Advance blocks so generation accrues.
        advance_blocks(100);
        assert_ok!(pallet_motra::Pallet::<Test>::claim_motra(
            RuntimeOrigin::signed(alice.clone())
        ));

        let alice_motra = pallet_motra::MotraBalances::<Test>::get(&alice);
        let bob_motra = pallet_motra::MotraBalances::<Test>::get(&bob);

        // Bob should have received MOTRA from delegation.
        assert!(
            bob_motra > 0,
            "Bob should have delegated MOTRA: {}",
            bob_motra
        );
        // Alice's own balance should be less (only decay on 0 = 0, no self-generation).
        assert!(
            alice_motra < bob_motra,
            "Alice {} should have less than Bob {}",
            alice_motra,
            bob_motra
        );

        // Bob can pay fees with delegated MOTRA.
        // burn_fee reconciles Bob on entry (applying decay since his last_touched
        // lags the current block). To isolate the burn-only delta from decay,
        // sample bob's balance AFTER reconcile has run.
        let burn_amount = 5_000u128;
        assert_ok!(pallet_motra::Pallet::<Test>::burn_fee(&bob, burn_amount));
        let bob_after = pallet_motra::MotraBalances::<Test>::get(&bob);
        // The exact reduction is (decay_over_elapsed_blocks) + burn_amount.
        // We assert the direction + floor: bob decreased by at least the burn.
        assert!(
            bob_motra > bob_after,
            "Bob's balance must decrease: {} -> {}",
            bob_motra,
            bob_after
        );
        assert!(
            bob_motra - bob_after >= burn_amount,
            "Burn must reduce Bob's balance by at least {}: delta = {}",
            burn_amount,
            bob_motra - bob_after
        );
        // Total-burned counter tracks exactly the burn amount.
        assert_eq!(
            pallet_motra::TotalBurned::<Test>::get(),
            burn_amount,
            "TotalBurned must equal the exact burn amount"
        );
    });
}

// ============================================================================
// Duplicate receipt_id is rejected
// ============================================================================

#[test]
fn e2e_duplicate_receipt_id_is_rejected() {
    new_integration_ext().execute_with(|| {
        let alice = acc(1);
        let receipt_id = H256::from([0xDD; 32]);
        let content_hash_1 = H256::from([0xE1; 32]);
        let content_hash_2 = H256::from([0xE2; 32]);

        // First submission succeeds.
        assert_ok!(submit_receipt_quick(alice.clone(), receipt_id, content_hash_1));

        // Second submission with same receipt_id (even different content_hash) fails.
        assert_noop!(
            submit_receipt_quick(alice.clone(), receipt_id, content_hash_2),
            crate::pallet::Error::<Test>::ReceiptAlreadyExists
        );

        // Counter should still be 1.
        assert_eq!(crate::Pallet::<Test>::receipt_count(), 1);
    });
}

// ============================================================================
// compute_fee returns min_fee with zero congestion
// ============================================================================

#[test]
fn e2e_compute_fee_base_case() {
    new_integration_ext().execute_with(|| {
        // With congestion_rate = 0 and a zero-weight tx of zero encoded length,
        // fee should be exactly min_fee.
        let fee = pallet_motra::Pallet::<Test>::compute_fee(
            frame_support::weights::Weight::from_parts(0, 0),
            0,
        );
        assert_eq!(fee, 1_000, "Zero-weight, zero-length tx should cost min_fee");

        // With non-zero length, length_fee_per_byte contributes.
        let fee_with_len = pallet_motra::Pallet::<Test>::compute_fee(
            frame_support::weights::Weight::from_parts(0, 0),
            100,
        );
        // length_fee_per_byte = 1_000, so 100 bytes -> 100_000 additional.
        assert_eq!(
            fee_with_len,
            1_000 + 100 * 1_000,
            "Length fee should add length_fee_per_byte * len"
        );
    });
}

// ============================================================================
// Full round-trip: generate MOTRA, burn exactly what compute_fee says, verify
// ============================================================================

#[test]
fn e2e_burn_computed_fee_amount() {
    new_integration_ext().execute_with(|| {
        let alice = acc(1);

        // Generate MOTRA.
        advance_blocks(100);
        assert_ok!(pallet_motra::Pallet::<Test>::claim_motra(
            RuntimeOrigin::signed(alice.clone())
        ));

        let motra_before = pallet_motra::MotraBalances::<Test>::get(&alice);

        // Compute what the fee would be for a submit_receipt extrinsic.
        let receipt_weight = <crate::weights::SubstrateWeight as OrinqWeightInfo>::submit_receipt();
        let encoded_len: usize = 500; // approximate encoded extrinsic length
        let fee = pallet_motra::Pallet::<Test>::compute_fee(receipt_weight, encoded_len);

        assert!(fee > 0, "Fee should be positive: {}", fee);
        assert!(
            motra_before > fee,
            "Alice should have enough MOTRA ({}) to pay fee ({})",
            motra_before,
            fee
        );

        // Burn exactly the computed fee.
        assert_ok!(pallet_motra::Pallet::<Test>::burn_fee(&alice, fee));

        let motra_after = pallet_motra::MotraBalances::<Test>::get(&alice);
        assert_eq!(
            motra_before - motra_after,
            fee,
            "Burned amount should equal computed fee"
        );
    });
}

// ============================================================================
// Availability certificate can be attached post-submission
// ============================================================================

#[test]
fn e2e_submit_then_attach_availability_cert() {
    new_integration_ext().execute_with(|| {
        let alice = acc(1);
        let receipt_id = H256::from([0xFA; 32]);
        let content_hash = H256::from([0xFB; 32]);

        // Submit a receipt.
        assert_ok!(submit_receipt_quick(alice.clone(), receipt_id, content_hash));

        // Initially, availability_cert_hash is zeroed.
        let record = crate::Pallet::<Test>::receipts(receipt_id).unwrap();
        assert_eq!(record.availability_cert_hash, [0u8; 32]);

        // Governance (root) attaches a certificate.
        let cert_hash = [0xFF; 32];
        assert_ok!(crate::Pallet::<Test>::set_availability_cert(
            RuntimeOrigin::root(),
            receipt_id,
            cert_hash,
        ));

        // Verify the certificate is stored.
        let updated = crate::Pallet::<Test>::receipts(receipt_id).unwrap();
        assert_eq!(
            updated.availability_cert_hash, cert_hash,
            "Availability cert should be set"
        );
        // All other fields should be unchanged.
        assert_eq!(updated.submitter, alice);
        assert_eq!(updated.content_hash, content_hash.0);
    });
}

// ============================================================================
// Insufficient MOTRA prevents fee burn
// ============================================================================

#[test]
fn e2e_insufficient_motra_prevents_fee_burn() {
    new_integration_ext().execute_with(|| {
        // Use account 99 which has NO MATRA in genesis, so generation is always 0.
        let no_matra_account = acc(99);

        assert_eq!(pallet_motra::MotraBalances::<Test>::get(&no_matra_account), 0);
        assert_eq!(
            pallet_balances::Pallet::<Test>::free_balance(&no_matra_account),
            0,
            "Account 99 should have zero MATRA"
        );

        // Attempting to burn should fail because reconcile generates 0 MOTRA
        // (no MATRA holdings means zero generation).
        //
        // We use `assert_err!` (not `assert_noop!`) because burn_fee calls
        // reconcile() first, which writes to `LastTouched` before the
        // insufficient-balance ensure! fires. That's benign storage churn,
        // not a behavioral regression — what we actually care about is that
        // the call errors with InsufficientMotra.
        frame_support::assert_err!(
            pallet_motra::Pallet::<Test>::burn_fee(&no_matra_account, 1_000),
            pallet_motra::pallet::Error::<Test>::InsufficientMotra
        );
    });
}

// ============================================================================
// Receipt with ZK root (optional Poseidon fields populated)
// ============================================================================

#[test]
fn e2e_receipt_with_zk_root_poseidon() {
    new_integration_ext().execute_with(|| {
        let alice = acc(1);
        let receipt_id = H256::from([0xDE; 32]);
        let content_hash = H256::from([0xAD; 32]);
        let zk_root = [0x99; 32];
        let poseidon_params = [0x88; 32];

        assert_ok!(crate::Pallet::<Test>::submit_receipt(
            RuntimeOrigin::signed(alice.clone()),
            receipt_id,
            content_hash,
            [0x11; 32],       // base_root_sha256
            Some(zk_root),    // zk_root_poseidon
            Some(poseidon_params), // poseidon_params_hash
            [0x22; 32],       // base_manifest_hash
            [0x33; 32],       // safety_manifest_hash
            [0x44; 32],       // monitor_config_hash
            [0x55; 32],       // attestation_evidence_hash
            [0x66; 32],       // storage_locator_hash
            [0x77; 32],       // schema_hash
        ));

        let record = crate::Pallet::<Test>::receipts(receipt_id).unwrap();
        assert_eq!(record.zk_root_poseidon, Some(zk_root));
        assert_eq!(record.poseidon_params_hash, Some(poseidon_params));
    });
}

// ============================================================================
// Total issued / total burned metrics stay consistent
// ============================================================================

#[test]
fn e2e_total_issued_and_burned_metrics() {
    new_integration_ext().execute_with(|| {
        let alice = acc(1);

        let issued_before = pallet_motra::TotalIssued::<Test>::get();
        let burned_before = pallet_motra::TotalBurned::<Test>::get();

        // Generate MOTRA.
        advance_blocks(100);
        assert_ok!(pallet_motra::Pallet::<Test>::claim_motra(
            RuntimeOrigin::signed(alice.clone())
        ));

        let issued_after_gen = pallet_motra::TotalIssued::<Test>::get();
        assert!(
            issued_after_gen > issued_before,
            "Total issued should increase after generation"
        );

        // Burn some.
        let burn_amount = 50_000u128;
        assert_ok!(pallet_motra::Pallet::<Test>::burn_fee(&alice, burn_amount));

        let burned_after = pallet_motra::TotalBurned::<Test>::get();
        assert_eq!(
            burned_after - burned_before,
            burn_amount,
            "Total burned delta should match the burn amount"
        );
    });
}
