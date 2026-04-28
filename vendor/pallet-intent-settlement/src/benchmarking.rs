//! Benchmarks for `pallet_intent_settlement::settle_batch_atomic` (Task #177).
//!
//! These run via `frame-omni-bencher` or a downstream runtime's
//! `cargo run --release --features runtime-benchmarks -- benchmark pallet
//! --pallet pallet_intent_settlement --extrinsic settle_batch_atomic`.
//!
//! The goal is to confirm the cost slope: weight(N=256) / weight(N=1) is
//! sublinear (~10x, NOT ~256x), because the dominant per-call cost — the
//! M-of-N signature verification — is shared across the whole batch.
//!
//! Per `feedback_chain_weight_is_the_real_user_tps_ceiling.md` the chain's
//! existing `settle_claim` consumes ~50M ref_time (largely sig-verify). The
//! batch path expects:
//!   - N=1   : ~55M ref_time   (1.1x baseline; small overhead from STBA hash)
//!   - N=8   : ~70M ref_time   (1.4x baseline)
//!   - N=64  : ~150M ref_time  (3.0x baseline)
//!   - N=256 : ~400M ref_time  (8.0x baseline) — but settling 256 claims
//!
//! That means a 256-batch fits comfortably in one block (block budget
//! ~1.5s ref_time on spec-204 normal class) while a 256-call equivalent
//! via the legacy single-claim path would require 256/2 = 128 blocks.

#![cfg(feature = "runtime-benchmarks")]

use super::*;
use crate::pallet::{Call, Config, IsCommitteeMember};
use frame_benchmarking::v2::*;
use frame_system::RawOrigin;
use sp_std::vec::Vec;

const MAX_BATCH_BENCH: u32 = 256;

/// Build a vouchered claim under a synthetic id for the given index. Uses
/// pallet-internal storage writes directly (we're not measuring the
/// upstream submit/attest/voucher pipeline here — just the settle batch).
fn seed_vouchered_claim<T: Config>(index: u32, amount: u64) -> ClaimId
where
    T::AccountId: parity_scale_codec::Encode,
{
    use crate::pallet::{Claims, Intents};

    // Synthetic claim_id derived from index — guaranteed unique inside the
    // benchmark batch.
    let mut id_bytes = [0u8; 32];
    id_bytes[..4].copy_from_slice(&index.to_be_bytes());
    id_bytes[4..8].copy_from_slice(b"BENC");
    let claim_id = ClaimId::from(id_bytes);
    let intent_id = IntentId::from(id_bytes); // distinct namespace fine for bench

    Claims::<T>::insert(
        claim_id,
        Claim {
            intent_id,
            policy_id: PolicyId::from([0u8; 32]),
            amount_ada: amount,
            issued_block: 1,
            expiry_slot_cardano: 100_000,
            settled: false,
            settled_direct: false,
            cardano_tx_hash: [0u8; 32],
        },
    );

    // Stub intent record so the settle path's status flip is realistic.
    // We rely on the runtime's AccountId being constructible from a seed via
    // `account` helper. Use a dummy submitter account (root-equivalent
    // through bench infra) — the value isn't read in settle_batch_atomic.
    let submitter: T::AccountId = whitelisted_caller();
    let _ = Intents::<T>::insert(
        intent_id,
        Intent {
            submitter,
            nonce: index as u64,
            kind: IntentKind::RequestPayout {
                policy_id: PolicyId::from([0u8; 32]),
                oracle_evidence: Default::default(),
            },
            submitted_block: 1,
            ttl_block: 1_000_000,
            status: IntentStatus::Vouchered,
        },
    );

    claim_id
}

#[benchmarks(
    where
        T::AccountId: parity_scale_codec::Encode,
        BlockNumberFor<T>: Into<u64> + Copy,
)]
mod benchmarks {
    use super::*;

    #[benchmark]
    fn settle_batch_atomic(n: Linear<1, MAX_BATCH_BENCH>) {
        let mut entries: Vec<SettleBatchEntry> = Vec::with_capacity(n as usize);
        for i in 0..n {
            let cid = seed_vouchered_claim::<T>(i, 1_000);
            entries.push(SettleBatchEntry {
                claim_id: cid,
                cardano_tx_hash: [0u8; 32],
                settled_direct: i % 2 == 0,
            });
        }

        // Build a dummy committee bundle. Real signature verification is
        // pluggable via T::SigVerifier; downstream runtimes wire in
        // Sr25519Verifier and this benchmark's weight will reflect that
        // production cost.
        let caller: T::AccountId = whitelisted_caller();
        let caller_pubkey = T::CommitteeMembership::pubkey_of(&caller);
        let signatures: Vec<(CommitteePubkey, CommitteeSig)> =
            sp_std::vec![(caller_pubkey, [0u8; 64])];

        let bv: frame_support::BoundedVec<SettleBatchEntry, T::MaxSettleBatch> =
            frame_support::BoundedVec::try_from(entries)
                .expect("bench n <= MaxSettleBatch");

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), bv, signatures);
    }

    // NOTE: `impl_benchmark_test_suite!` is intentionally OMITTED. Wiring it
    // here pins benchmarks into the pallet's own mock runtime, but our mock
    // uses `u64` AccountId (intentionally — see `tests::mock_pubkey_of`).
    // The benchmark closure computes a payload digest using the AccountId's
    // committee-pubkey derivation, which is fine for `whitelisted_caller`
    // (any 32-byte pubkey works) but doesn't round-trip in the mock's
    // `account_of_pubkey` (which only knows about members 1/2/3). The
    // production weight pass runs in the materios-runtime, which wires
    // `Sr25519Verifier` against real AccountId32 — that's where the
    // canonical weight values come from.

    // ---- Task #211 — attest_batch_intents bench -------------------------

    /// Bench `attest_batch_intents` across `Linear<1, MAX_BATCH>` so the
    /// runtime weight generator produces a sublinear curve matching the
    /// spec-207 cost model:
    ///   N=1   ~55M ref_time   N=64  ~250M ref_time
    ///   N=8   ~75M ref_time   N=256 ~800M ref_time
    /// Versus 256x3 = 768 single `attest_intent` calls at ~50M each =
    /// ~38B ref_time, the batch path is ~50x cheaper at the per-block-budget
    /// level. The bigger structural win is M-of-N collapse: pre-spec-207 a
    /// 3-of-3 committee posted M*N = 768 separate sig-verifies; post-spec-207
    /// it's ONE.
    #[benchmark]
    fn attest_batch_intents(n: Linear<1, MAX_BATCH_BENCH>) {
        use crate::pallet::Intents;
        let mut intent_ids: sp_std::vec::Vec<IntentId> =
            sp_std::vec::Vec::with_capacity(n as usize);
        let submitter: T::AccountId = whitelisted_caller();
        for i in 0..n {
            let mut id_bytes = [0u8; 32];
            id_bytes[..4].copy_from_slice(&i.to_be_bytes());
            id_bytes[4..8].copy_from_slice(b"BABI");
            let iid = IntentId::from(id_bytes);
            Intents::<T>::insert(
                iid,
                Intent {
                    submitter: submitter.clone(),
                    nonce: i as u64,
                    kind: IntentKind::RequestPayout {
                        policy_id: PolicyId::from([0u8; 32]),
                        oracle_evidence: Default::default(),
                    },
                    submitted_block: 1,
                    ttl_block: 1_000_000,
                    status: IntentStatus::Pending,
                },
            );
            intent_ids.push(iid);
        }

        let caller: T::AccountId = whitelisted_caller();
        let caller_pubkey = T::CommitteeMembership::pubkey_of(&caller);
        let signatures: sp_std::vec::Vec<(CommitteePubkey, CommitteeSig)> =
            sp_std::vec![(caller_pubkey, [0u8; 64])];

        let bv: frame_support::BoundedVec<IntentId, T::MaxAttestBatch> =
            frame_support::BoundedVec::try_from(intent_ids)
                .expect("bench n <= MaxAttestBatch");

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), bv, signatures);
    }

    // ---- Task #212 — request_batch_vouchers bench -----------------------

    /// Bench `request_batch_vouchers` across `Linear<1, MAX_BATCH>` so the
    /// runtime weight generator produces a sublinear curve matching the
    /// spec-207 cost model:
    ///   N=1   ~60M ref_time   N=64  ~700M ref_time
    ///   N=8   ~130M ref_time  N=256 ~2.6B ref_time
    /// Versus 256 single `request_voucher` calls at ~100M each = ~25.6B
    /// ref_time, the batch path is ~10x cheaper at the per-block-budget
    /// level.
    #[benchmark]
    fn request_batch_vouchers(n: Linear<1, MAX_BATCH_BENCH>) {
        use crate::pallet::Intents;
        let submitter: T::AccountId = whitelisted_caller();
        let mut entries: sp_std::vec::Vec<RequestVoucherEntry> =
            sp_std::vec::Vec::with_capacity(n as usize);
        for i in 0..n {
            let mut id_bytes = [0u8; 32];
            id_bytes[..4].copy_from_slice(&i.to_be_bytes());
            id_bytes[4..8].copy_from_slice(b"BRBV");
            let intent_id = IntentId::from(id_bytes);
            let mut cid_bytes = id_bytes;
            cid_bytes[8..12].copy_from_slice(b"CLAM");
            let claim_id = ClaimId::from(cid_bytes);
            Intents::<T>::insert(
                intent_id,
                Intent {
                    submitter: submitter.clone(),
                    nonce: i as u64,
                    kind: IntentKind::RequestPayout {
                        policy_id: PolicyId::from([0u8; 32]),
                        oracle_evidence: Default::default(),
                    },
                    submitted_block: 1,
                    ttl_block: 1_000_000,
                    status: IntentStatus::Attested,
                },
            );
            let bfpr = BatchFairnessProof {
                batch_block_range: (1, 1),
                sorted_intent_ids: frame_support::BoundedVec::try_from(
                    sp_std::vec![intent_id],
                ).unwrap(),
                requested_amounts_ada: frame_support::BoundedVec::try_from(
                    sp_std::vec![1_000u64],
                ).unwrap(),
                pool_balance_ada: 1_000_000_000,
                pro_rata_scale_bps: 10_000,
                awarded_amounts_ada: frame_support::BoundedVec::try_from(
                    sp_std::vec![1_000u64],
                ).unwrap(),
            };
            let bfpr_d = compute_fairness_proof_digest(&bfpr);
            let voucher = Voucher {
                claim_id,
                policy_id: PolicyId::from([0u8; 32]),
                beneficiary_cardano_addr: Default::default(),
                amount_ada: 1_000,
                batch_fairness_proof_digest: bfpr_d,
                issued_block: 1,
                expiry_slot_cardano: 100_000,
                committee_sigs: Default::default(),
            };
            entries.push(RequestVoucherEntry {
                claim_id,
                intent_id,
                voucher,
                fairness_proof: bfpr,
            });
        }

        let caller: T::AccountId = whitelisted_caller();
        let caller_pubkey = T::CommitteeMembership::pubkey_of(&caller);
        let signatures: sp_std::vec::Vec<(CommitteePubkey, CommitteeSig)> =
            sp_std::vec![(caller_pubkey, [0u8; 64])];
        let bv: frame_support::BoundedVec<RequestVoucherEntry, T::MaxVoucherBatch> =
            frame_support::BoundedVec::try_from(entries)
                .expect("bench n <= MaxVoucherBatch");

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), bv, signatures);
    }

    // ---- Task #210 — submit_batch_intents bench -------------------------

    /// Bench `submit_batch_intents` across `Linear<1, MAX_BATCH>` so the
    /// runtime weight generator produces a sublinear curve matching the
    /// spec-207 cost model:
    ///   N=1   ~55M ref_time
    ///   N=8   ~70M ref_time
    ///   N=64  ~150M ref_time
    ///   N=256 ~400M ref_time
    /// Versus 256 single `submit_intent` calls at ~500M each = 128B
    /// ref_time, the batch path is ~320x cheaper at the per-block-budget
    /// level. The economic win is even larger because the user pays one
    /// fee instead of N.
    #[benchmark]
    fn submit_batch_intents(n: Linear<1, MAX_BATCH_BENCH>) {
        let caller: T::AccountId = whitelisted_caller();
        let mut entries: sp_std::vec::Vec<SubmitIntentEntry> =
            sp_std::vec::Vec::with_capacity(n as usize);
        for i in 0..n {
            entries.push(SubmitIntentEntry {
                kind: IntentKind::RequestPayout {
                    policy_id: PolicyId::from({
                        let mut b = [0u8; 32];
                        b[..4].copy_from_slice(&i.to_be_bytes());
                        b
                    }),
                    oracle_evidence: Default::default(),
                },
            });
        }
        let bv: frame_support::BoundedVec<SubmitIntentEntry, T::MaxSubmitBatch> =
            frame_support::BoundedVec::try_from(entries)
                .expect("bench n <= MaxSubmitBatch");

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), bv);
    }
}
