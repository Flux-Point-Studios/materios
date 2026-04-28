//! # `pallet_intent_settlement`
//!
//! Materios-side pallet implementing Wave 2 of the Aegis intent-settlement
//! protocol per `docs/spec-v1.md §2`.
//!
//! Responsibilities:
//! - Store and expire user intents (`submit_intent`, `on_initialize` sweep).
//! - Accept committee M-of-N attestations (`attest_intent`).
//! - Issue vouchers (`request_voucher`) bound to a `BatchFairnessProof`.
//! - Mirror Cardano-side settlements (`settle_claim`, `expire_policy_mirror`).
//! - Track per-account ADA credits, consumed at BuyPolicy time and returned on
//!   expiry.
//! - Enforce the Aegis v2 Q1 pool-utilization cap at `submit_intent` time.
//!
//! All cross-layer types and hash pre-images are defined in [`types`].

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;
pub mod types;
pub mod voucher_canonicalize;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod integration;

#[cfg(test)]
mod proptest;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

pub use types::*;

use parity_scale_codec::Encode;

/// Convert an `AccountId` into the 32-byte bag we hash into IntentId. The
/// pallet is generic over AccountId but we require it to be 32-byte
/// encodable (the usual Substrate assumption: `AccountId32`).
pub fn account_to_bytes<A: Encode>(account: &A) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let bytes = account.encode();
    // AccountId32 encodes as 32 raw bytes; u64 (in test runtimes) encodes as 8.
    // We left-pad shorter representations so test-mode hashes are still
    // deterministic and do not collide across runtimes with 32-byte ids.
    let len = bytes.len().min(32);
    buf[..len].copy_from_slice(&bytes[..len]);
    buf
}

/// Issue #7: domain tag for the `credit_deposit` multisig payload.
pub const TAG_CRDP: &[u8; 4] = b"CRDP";
/// Issue #7: domain tag for the `settle_claim` multisig payload.
pub const TAG_STCL: &[u8; 4] = b"STCL";
/// Task #174: domain tag for the `request_voucher` multisig payload. Closes
/// the M-of-N gap on the voucher-mint stage of the intent pipeline so a
/// single committee member can no longer unilaterally mint a voucher with
/// an attestation bundle they posted earlier.
pub const TAG_RVCH: &[u8; 4] = b"RVCH";
/// Task #177: domain tag for the `settle_batch_atomic` multisig payload. The
/// digest is computed once over the FULL ordered batch; one committee
/// signature bundle authorises N settlements. This is the central weight
/// optimisation that lifts user-TPS from ~0.07 to ~10+ by removing the
/// per-claim sig-verify cost.
pub const TAG_STBA: &[u8; 4] = b"STBA";
/// Task #211: domain tag for the `attest_batch_intents` multisig payload.
/// The digest is computed once over the FULL ordered list of intent_ids;
/// one committee signature bundle authorises N attestation transitions
/// (Pending -> Attested). Pre-spec-207 a 3-of-3 committee posted 3*N
/// `attest_intent` extrinsics per batch — at N=256 that's 768 sig-verify
/// rounds per epoch. Post-spec-207 the cost is ONE sig-verify per batch.
/// Domain-separated from STBA / STCL / CRDP / RVCH / SBIN so an ABIN
/// signature can never be replayed against any other call's pre-image.
pub const TAG_ABIN: &[u8; 4] = b"ABIN";
/// Task #212: domain tag for the `request_batch_vouchers` multisig
/// payload. The digest is computed once over the FULL ordered list of
/// (claim_id, intent_id, voucher_digest, bfpr_digest) tuples; one
/// committee signature bundle authorises N voucher mints. Pre-spec-207
/// each voucher mint required its own M-of-N round (per PR #26's RVCH
/// gate); post-spec-207 N mints collapse to one sig-verify. Domain-
/// separated from RVCH / STBA / STCL / CRDP / SBIN / ABIN so a batch-
/// voucher signature can never be replayed against any other pallet
/// pre-image.
pub const TAG_RVBN: &[u8; 4] = b"RVBN";
/// Task #210: domain tag for the `submit_batch_intents` event digest. There
/// is NO M-of-N gate on this extrinsic (it's user-side, not committee-side),
/// but emitting a canonical batch digest in the `BatchIntentsSubmitted`
/// event lets indexers correlate the on-chain landing with the keeper's
/// observed batch. Domain-separates from STBA/RVCH/STCL/CRDP and the
/// upcoming ABIN/RVBN tags so a SBIN digest can never be replayed onto a
/// committee-signed pre-image.
pub const TAG_SBIN: &[u8; 4] = b"SBIN";

/// Canonical digest signed by committee members when authorizing a
/// `credit_deposit(target, amount, cardano_tx_hash)` call (Issue #7).
///
/// `blake2_256(b"CRDP" || target_bytes (32B) || amount_ada (LE u64)
///             || cardano_tx_hash (32B))`
pub fn credit_deposit_payload(
    target_bytes: &[u8; 32],
    amount_ada: u64,
    cardano_tx_hash: &[u8; 32],
) -> [u8; 32] {
    let mut body = alloc::vec::Vec::with_capacity(32 + 8 + 32);
    body.extend_from_slice(target_bytes);
    body.extend_from_slice(&amount_ada.to_le_bytes());
    body.extend_from_slice(cardano_tx_hash);
    crate::types::domain_hash(*TAG_CRDP, &body)
}

/// Canonical digest signed by committee members when authorizing a
/// `settle_claim(claim_id, cardano_tx_hash, settled_direct)` call (Issue #7).
///
/// `blake2_256(b"STCL" || claim_id (32B) || cardano_tx_hash (32B)
///             || settled_direct (1B))`
pub fn settle_claim_payload(
    claim_id: &IntentId,
    cardano_tx_hash: &[u8; 32],
    settled_direct: bool,
) -> [u8; 32] {
    let mut body = alloc::vec::Vec::with_capacity(32 + 32 + 1);
    body.extend_from_slice(claim_id.as_bytes());
    body.extend_from_slice(cardano_tx_hash);
    body.push(if settled_direct { 1u8 } else { 0u8 });
    crate::types::domain_hash(*TAG_STCL, &body)
}

/// Task #174: canonical digest signed by committee members when authorizing
/// a `request_voucher(claim_id, intent_id, voucher, fairness_proof)` call.
///
/// `blake2_256(b"RVCH" || claim_id (32B) || intent_id (32B)
///             || voucher_digest (32B) || bfpr_digest (32B))`
///
/// All four 32-byte inputs are deterministic functions of state visible to
/// every honest operator at the moment of voucher mint:
///   - `claim_id`, `intent_id`: chosen by the keeper, included verbatim in
///     the dispatch.
///   - `voucher_digest`: `compute_voucher_digest(&voucher)`. Pure function of
///     the voucher struct (which the pallet stores as-is).
///   - `bfpr_digest`: `compute_fairness_proof_digest(&fairness_proof)`. Pure
///     function of the fairness-proof struct, and the pallet rejects with
///     `FairnessDigestMismatch` unless `voucher.batch_fairness_proof_digest`
///     matches it — so the two digests cross-check.
///
/// Per `feedback_mofn_hash_determinism.md` no operator-local state (wall
/// clock, Cardano epoch, locally-computed verification level) appears in
/// the pre-image. Replay-across-epoch protection comes from the live
/// committee-membership check in `ensure_threshold_signatures`: rotated-out
/// members can no longer pass `is_member`, so old bundles can't be replayed
/// after a committee rotation.
pub fn request_voucher_payload(
    claim_id: &ClaimId,
    intent_id: &IntentId,
    voucher_digest: &[u8; 32],
    bfpr_digest: &[u8; 32],
) -> [u8; 32] {
    let mut body = alloc::vec::Vec::with_capacity(32 + 32 + 32 + 32);
    body.extend_from_slice(claim_id.as_bytes());
    body.extend_from_slice(intent_id.as_bytes());
    body.extend_from_slice(voucher_digest);
    body.extend_from_slice(bfpr_digest);
    crate::types::domain_hash(*TAG_RVCH, &body)
}

/// Canonical digest signed by committee members when authorizing a
/// `settle_batch_atomic(entries)` call (Task #177).
///
/// Pre-image:
/// `blake2_256(b"STBA"
///   || u32_le(entries.len())
///   || for each entry e: e.claim_id (32B) || e.cardano_tx_hash (32B)
///                        || (e.settled_direct as u8))`
///
/// Note this is a flat byte stream (NOT SCALE-encoded BoundedVec) so the
/// digest is independent of the wire-format quirks called out in
/// `feedback_substrate_interface_boundedvec_wrap.md`. The Aiken / TS keeper
/// mirror reconstructs the same byte stream from raw fields.
///
/// Per `feedback_mofn_hash_determinism.md` rule: only chain-derived inputs
/// (claim_ids, cardano_tx_hashes, settled_direct flags) appear in the
/// pre-image — no operator-local state.
pub fn settle_batch_atomic_payload(
    entries: &[SettleBatchEntry],
) -> [u8; 32] {
    let n = entries.len() as u32;
    let mut body = alloc::vec::Vec::with_capacity(4 + entries.len() * (32 + 32 + 1));
    body.extend_from_slice(&n.to_le_bytes());
    for e in entries.iter() {
        body.extend_from_slice(e.claim_id.as_bytes());
        body.extend_from_slice(&e.cardano_tx_hash);
        body.push(if e.settled_direct { 1u8 } else { 0u8 });
    }
    crate::types::domain_hash(*TAG_STBA, &body)
}

/// Task #211: canonical digest signed by committee members when authorizing
/// an `attest_batch_intents(intent_ids)` call. Pre-image:
///
/// `blake2_256(b"ABIN" || u32_le(N) || N×intent_id (32B each))`
///
/// Flat byte stream — NOT SCALE — so the digest is independent of the
/// substrate-interface BoundedVec wrapping quirk
/// (`feedback_substrate_interface_boundedvec_wrap.md`). The Aiken / TS
/// keeper mirror reconstructs the same stream from raw bytes.
///
/// Per `feedback_mofn_hash_determinism.md`: only chain-derived intent_ids
/// appear in the pre-image (no operator-local state). All committee
/// members independently compute the same digest from the keeper's
/// announced intent_ids list, so threshold can never wedge from divergent
/// pre-images.
pub fn attest_batch_intents_payload(
    intent_ids: &[IntentId],
) -> [u8; 32] {
    let n = intent_ids.len() as u32;
    let mut body = alloc::vec::Vec::with_capacity(4 + intent_ids.len() * 32);
    body.extend_from_slice(&n.to_le_bytes());
    for iid in intent_ids.iter() {
        body.extend_from_slice(iid.as_bytes());
    }
    crate::types::domain_hash(*TAG_ABIN, &body)
}

/// Task #212: canonical digest signed by committee members when
/// authorizing a `request_batch_vouchers(entries)` call. Pre-image:
///
/// `blake2_256(b"RVBN" || u32_le(N)
///             || N x (claim_id (32B) || intent_id (32B)
///                     || voucher_digest (32B) || bfpr_digest (32B)))`
///
/// Each per-entry tuple is identical in shape to the spec-206 single-call
/// `request_voucher_payload` body — the batch path just concatenates N of
/// them after a 4-byte length prefix and re-tags with RVBN. The
/// `voucher_digest` + `bfpr_digest` are computed deterministically by the
/// pallet from each entry's `voucher` + `fairness_proof` (canonical SCALE)
/// before this digest is hashed, so the keeper and committee always see
/// the same pre-image.
///
/// Per `feedback_mofn_hash_determinism.md`: only chain-derived state
/// (claim_ids, intent_ids, deterministic Voucher + BFPR digests) appears
/// in the pre-image — no operator-local fields.
pub fn request_batch_vouchers_payload(
    entries: &[(ClaimId, IntentId, [u8; 32], [u8; 32])],
) -> [u8; 32] {
    let n = entries.len() as u32;
    let mut body = alloc::vec::Vec::with_capacity(4 + entries.len() * (32 + 32 + 32 + 32));
    body.extend_from_slice(&n.to_le_bytes());
    for (claim_id, intent_id, voucher_d, bfpr_d) in entries.iter() {
        body.extend_from_slice(claim_id.as_bytes());
        body.extend_from_slice(intent_id.as_bytes());
        body.extend_from_slice(voucher_d);
        body.extend_from_slice(bfpr_d);
    }
    crate::types::domain_hash(*TAG_RVBN, &body)
}

/// Task #210: canonical batch digest emitted in the `BatchIntentsSubmitted`
/// event. There is NO M-of-N gate on `submit_batch_intents` (it's the
/// user-side stage), so this digest is purely an indexer-facing identity
/// for the batch — it does NOT serve as a sig pre-image. Format:
///
/// `blake2_256(b"SBIN" || u32_le(N) || N×scale(IntentKind))`
///
/// The IntentKind SCALE encoding is identical to what the pallet hashes into
/// IntentId (modulo the per-intent submitter/nonce/block fields), so a
/// keeper that observed the batch off-chain can recompute this digest and
/// correlate with the on-chain `BatchIntentsSubmitted{batch_digest}`. The
/// included N prefix prevents trivial digest collision between two batches
/// that share a kind list of different lengths.
pub fn submit_batch_intents_payload(
    entries: &[SubmitIntentEntry],
) -> [u8; 32] {
    let n = entries.len() as u32;
    let mut body = alloc::vec::Vec::new();
    body.extend_from_slice(&n.to_le_bytes());
    for e in entries.iter() {
        body.extend_from_slice(&e.kind.encode());
    }
    crate::types::domain_hash(*TAG_SBIN, &body)
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use alloc::vec::Vec;
    use frame_support::{pallet_prelude::*, BoundedVec};
    use frame_system::pallet_prelude::*;

    // ---------------------------------------------------------------------
    // Config
    // ---------------------------------------------------------------------

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Upper bound on committee size; `MaxCommittee = 32` per spec §3.1.
        #[pallet::constant]
        type MaxCommittee: Get<u32>;

        /// Max intents expired in a single block (TTL sweep bound).
        #[pallet::constant]
        type MaxExpirePerBlock: Get<u32>;

        /// Default intent TTL in blocks (`600 ≈ 1h` at 6s).
        #[pallet::constant]
        type DefaultIntentTTL: Get<BlockNumber>;

        /// Default claim TTL in blocks (`28_800 ≈ 48h`).
        #[pallet::constant]
        type DefaultClaimTTL: Get<BlockNumber>;

        /// Source of truth for who's on the committee (read-only from this
        /// pallet). We accept an abstract predicate so in tests we can swap it
        /// without wiring the full `pallet_committee_governance`.
        type CommitteeMembership: IsCommitteeMember<Self::AccountId>;

        /// Upper bound on the `PendingBatches` index (intents live in the
        /// index until terminal status). Prevents unbounded growth while also
        /// capping the `get_pending_batches` RPC worst-case. Per spec §2.7
        /// keepers poll in small chunks so 10_000 is ample headroom.
        #[pallet::constant]
        type MaxPendingBatches: Get<u32>;

        /// Genesis default for the `MinSignerThreshold` (number of distinct
        /// committee signatures required to authorize `credit_deposit` and
        /// `settle_claim`). Runtime governance (`set_min_signer_threshold`)
        /// can bump this post-launch without a code upgrade.
        #[pallet::constant]
        type DefaultMinSignerThreshold: Get<u32>;

        /// Signature verifier used by the M-of-N gate on `credit_deposit`
        /// and `settle_claim` (Issue #7). In prod this wires to sr25519; in
        /// tests we substitute a deterministic stub (see `MockSigVerifier`)
        /// so fixtures aren't forced to sign full sr25519 payloads.
        type SigVerifier: VerifyCommitteeSignature;

        /// Task #177: maximum number of claims settled in a single
        /// `settle_batch_atomic` call. The runtime configures this; the
        /// canonical default is `types::MAX_SETTLE_BATCH = 256`. The bound
        /// must fit in the normal-class block budget along with the M-of-N
        /// signature bundle.
        #[pallet::constant]
        type MaxSettleBatch: Get<u32>;

        /// Task #211: maximum number of intents attested in a single
        /// `attest_batch_intents` call. Canonical default is
        /// `types::MAX_ATTEST_BATCH = 256`. Enables collapsing M*N per-epoch
        /// committee extrinsics into ONE batch call.
        #[pallet::constant]
        type MaxAttestBatch: Get<u32>;

        /// Task #212: maximum number of vouchers issued in a single
        /// `request_batch_vouchers` call. Canonical default is
        /// `types::MAX_VOUCHER_BATCH = 256`.
        #[pallet::constant]
        type MaxVoucherBatch: Get<u32>;

        /// Task #210: maximum number of intents submitted in a single
        /// `submit_batch_intents` call. The runtime configures this; the
        /// canonical default is `types::MAX_SUBMIT_BATCH = 256`. Only
        /// constrained by per-block normal-class extrinsic budget plus the
        /// PendingBatches index headroom (so the largest realistic batch
        /// stays well within `MaxPendingBatches`).
        #[pallet::constant]
        type MaxSubmitBatch: Get<u32>;
    }

    /// Abstraction for verifying an `sr25519` signature over a committee
    /// pubkey / payload pair.
    pub trait VerifyCommitteeSignature {
        fn verify(pubkey: &CommitteePubkey, sig: &CommitteeSig, msg: &[u8]) -> bool;
    }

    /// Production verifier: delegates to sr25519 via sp-io crypto host fn.
    pub struct Sr25519Verifier;
    impl VerifyCommitteeSignature for Sr25519Verifier {
        fn verify(pubkey: &CommitteePubkey, sig: &CommitteeSig, msg: &[u8]) -> bool {
            let pk = sp_core::sr25519::Public::from_raw(*pubkey);
            let sg = sp_core::sr25519::Signature::from_raw(*sig);
            sp_io::crypto::sr25519_verify(&sg, msg, &pk)
        }
    }

    /// Abstracts "is this account a member of the current committee?" plus
    /// the bidirectional `AccountId <-> CommitteePubkey` mapping that binds
    /// the caller of `attest_intent` to the pubkey they submit, closing the
    /// attestation-spoofing vector (Issue #4).
    pub trait IsCommitteeMember<AccountId> {
        fn is_member(who: &AccountId) -> bool;
        fn threshold() -> u32;
        fn member_count() -> u32;
        /// Derive the on-chain committee pubkey (`[u8; 32]`) from an
        /// `AccountId`. For `AccountId32` this is the raw 32 bytes of the
        /// account; for test runtimes with `AccountId = u64` we left-pad into
        /// a 32-byte buffer to keep the mapping injective.
        fn pubkey_of(who: &AccountId) -> CommitteePubkey;
        /// Reverse mapping (used to look up the "caller" account when we
        /// only have a pubkey, e.g. a signature in a multisig envelope).
        /// Returns `None` when the pubkey isn't in the current committee.
        fn account_of_pubkey(pubkey: &CommitteePubkey) -> Option<AccountId>;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    // ---------------------------------------------------------------------
    // Storage
    // ---------------------------------------------------------------------

    #[pallet::storage]
    pub type Intents<T: Config> =
        StorageMap<_, Blake2_128Concat, IntentId, Intent<T::AccountId>, OptionQuery>;

    #[pallet::storage]
    pub type Nonces<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, Nonce, ValueQuery>;

    #[pallet::storage]
    pub type Credits<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, AdaLovelace, ValueQuery>;

    #[pallet::storage]
    pub type Claims<T: Config> =
        StorageMap<_, Blake2_128Concat, ClaimId, Claim, OptionQuery>;

    #[pallet::storage]
    pub type Vouchers<T: Config> =
        StorageMap<_, Blake2_128Concat, ClaimId, Voucher, OptionQuery>;

    /// Tracks committee signatures accumulated per intent during the
    /// `Pending -> Attested` transition.
    #[pallet::storage]
    pub type PendingAttestations<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        IntentId,
        BoundedVec<(CommitteePubkey, CommitteeSig), <T as Config>::MaxCommittee>,
        ValueQuery,
    >;

    /// Final attestation bundles (frozen once threshold is reached). Exposed
    /// via the runtime-API for the keeper.
    #[pallet::storage]
    pub type AttestationSigs<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        IntentId,
        BoundedVec<(CommitteePubkey, CommitteeSig), <T as Config>::MaxCommittee>,
        OptionQuery,
    >;

    /// `block -> intents to sweep`. Bounded size guarantees predictable
    /// `on_initialize` weight.
    #[pallet::storage]
    pub type ExpiryQueue<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        BlockNumber,
        BoundedVec<IntentId, ConstU32<MAX_EXPIRE_PER_BLOCK>>,
        ValueQuery,
    >;

    /// Idempotency set for `credit_deposit`. Key = (account, cardano_tx_hash).
    #[pallet::storage]
    pub type ProcessedDeposits<T: Config> =
        StorageMap<_, Blake2_128Concat, (T::AccountId, [u8; 32]), (), OptionQuery>;

    #[pallet::storage]
    pub type LastExportedBlock<T: Config> = StorageValue<_, BlockNumber, ValueQuery>;

    #[pallet::storage]
    pub type IntentTTL<T: Config> = StorageValue<_, BlockNumber, ValueQuery>;

    #[pallet::storage]
    pub type ClaimTTL<T: Config> = StorageValue<_, BlockNumber, ValueQuery>;

    #[pallet::storage]
    pub type PoolUtilization<T: Config> =
        StorageValue<_, PoolUtilizationParams, ValueQuery>;

    /// Index of non-terminal intents (Issue #6). Maintained in lockstep with
    /// the `Intents` map:
    /// - `submit_intent` appends on success
    /// - `settle_claim`, `expire_policy_mirror`, TTL sweep, and the
    ///   `request_voucher` transition (Attested -> Vouchered) remove
    ///
    /// `get_pending_batches` now reads this index and status-filters in-memory
    /// instead of `Intents::<T>::iter()`, replacing the prior O(N) scan with
    /// O(index_len) which is itself bounded by `MaxPendingBatches`.
    #[pallet::storage]
    pub type PendingBatches<T: Config> = StorageValue<
        _,
        BoundedVec<IntentId, <T as Config>::MaxPendingBatches>,
        ValueQuery,
    >;

    /// Task #245: round-robin cursor for the fallback TTL sweep. Each block
    /// `on_initialize` resumes at this offset into `PendingBatches`, scans
    /// up to `FALLBACK_SWEEP_PER_BLOCK` entries, terminalizes any whose
    /// `ttl_block` has passed (Pending/Attested only), and advances the
    /// cursor. Wraps to 0 when it walks off the end. The cursor is a free
    /// integer — wrap-around is safe because `PendingBatches` only shrinks
    /// (terminalized intents get removed) so re-scanning is idempotent.
    ///
    /// Background: `do_submit_intent` enqueues into `ExpiryQueue[ttl_block]`
    /// best-effort with a `MAX_EXPIRE_PER_BLOCK = 256` cap per bucket. Burst
    /// submissions sharing a `ttl_block` (>256 in one block at the same
    /// `IntentTTL`) silently overflowed and were never swept, leaving stale
    /// Pending entries in `PendingBatches` indefinitely. This fallback
    /// guarantees eventual sweep regardless of bucket-cap collisions.
    #[pallet::storage]
    pub type FallbackSweepCursor<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// Task #245: cumulative count of intents terminalized via the
    /// fallback sweep (i.e. NOT via the fast `ExpiryQueue` path). A
    /// non-zero value signals that `MAX_EXPIRE_PER_BLOCK` is being hit
    /// in production — useful indicator for tuning the per-block bucket
    /// cap or the sweep budget.
    #[pallet::storage]
    pub type FallbackSweepCount<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// Governance-tunable minimum number of distinct committee signatures
    /// required to authorize `credit_deposit` or `settle_claim` (Issue #7).
    /// A value of 0 means "not yet initialized — fall back to
    /// `DefaultMinSignerThreshold`"; the effective threshold in-flight is
    /// always `max(stored, 1)`, and further bounded by the committee size.
    #[pallet::storage]
    pub type MinSignerThreshold<T: Config> = StorageValue<_, u32, ValueQuery>;

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        IntentSubmitted {
            intent_id: IntentId,
            submitter: T::AccountId,
            nonce: Nonce,
        },
        IntentAttested {
            intent_id: IntentId,
            attestor_count: u32,
        },
        VoucherIssued {
            claim_id: ClaimId,
            voucher_digest: [u8; 32],
            fairness_proof_digest: [u8; 32],
        },
        ClaimSettled {
            claim_id: ClaimId,
            cardano_tx_hash: [u8; 32],
            settled_direct: bool,
        },
        IntentExpired {
            intent_id: IntentId,
            reason: ExpiryReason,
        },
        CreditRefundRequested {
            intent_id: IntentId,
            submitter: T::AccountId,
            amount_ada: AdaLovelace,
        },
        CreditsCredited {
            account: T::AccountId,
            delta_ada: AdaLovelace,
            source_cardano_tx: [u8; 32],
        },
        PoolUtilizationUpdated {
            total_nav_ada: AdaLovelace,
            outstanding_coverage_ada: AdaLovelace,
        },
        /// Task #177: a `settle_batch_atomic` call landed and settled `count`
        /// claims under one committee-signature verification. `batch_digest`
        /// is the canonical pre-image hash (b"STBA" || ...) so off-chain
        /// observers can correlate the on-chain event with the keeper's
        /// signed batch object. `settled_direct_count` lets indexers split
        /// keeper-batch vs direct-path settlements without iterating the
        /// claims map.
        BatchSettled {
            count: u32,
            batch_digest: [u8; 32],
            settled_direct_count: u32,
        },
        /// Task #211: an `attest_batch_intents` call landed and transitioned
        /// `attested_count` intents from Pending -> Attested under ONE
        /// committee-signature verification. `submitted_count` is the total
        /// number of intent_ids in the call (some may have been attested
        /// already, in which case they're idempotent no-ops and not
        /// counted as freshly attested). `batch_digest` is the canonical
        /// ABIN pre-image hash so indexers can correlate the on-chain
        /// landing with the keeper's signed batch. The legacy per-intent
        /// `IntentAttested` events are STILL emitted for every transitioned
        /// intent, so existing indexer paths keep working unchanged —
        /// `BatchIntentsAttested` is purely additive.
        BatchIntentsAttested {
            submitted_count: u32,
            attested_count: u32,
            batch_digest: [u8; 32],
            signer_count: u32,
        },
        /// Task #212: a `request_batch_vouchers` call landed and minted
        /// `count` vouchers under ONE committee-signature verification.
        /// The legacy per-voucher `VoucherIssued` events are STILL emitted
        /// inside the batch (one per entry) so existing indexer paths keep
        /// working unchanged. `batch_digest` is the canonical RVBN
        /// pre-image hash so off-chain observers can correlate the on-chain
        /// landing with the keeper's signed batch object.
        BatchVouchersIssued {
            count: u32,
            batch_digest: [u8; 32],
            total_amount_ada: AdaLovelace,
        },
        /// Task #210: a `submit_batch_intents` call landed and registered
        /// `count` user intents in one extrinsic. `batch_digest` is the
        /// canonical SBIN pre-image (`blake2_256(b"SBIN" || N || kinds)`)
        /// so off-chain observers can correlate the on-chain landing with
        /// the keeper's observed batch. The individual `IntentSubmitted`
        /// events are STILL emitted for every entry (one per intent), so
        /// downstream indexers tracking single-intent flow keep working
        /// without changes — `BatchIntentsSubmitted` is purely additive.
        BatchIntentsSubmitted {
            submitter: T::AccountId,
            count: u32,
            batch_digest: [u8; 32],
            total_premium_ada: AdaLovelace,
        },
    }

    // ---------------------------------------------------------------------
    // Errors
    // ---------------------------------------------------------------------

    #[pallet::error]
    pub enum Error<T> {
        /// Intent already exists at this id (should be statistically impossible).
        DuplicateIntent,
        /// Account has insufficient ADA credit to cover a `BuyPolicy` premium
        /// or a `RefundCredit` request.
        InsufficientCredit,
        /// Caller is not a current committee member.
        NotCommitteeMember,
        /// Attestation signature did not verify against the IntentId digest.
        BadAttestationSig,
        /// The provided pubkey isn't in the current committee set.
        UnknownCommitteePubkey,
        /// Caller tried to add a duplicate pubkey to the attestation bundle.
        DuplicatePubkey,
        /// The intent is not in the expected status for this extrinsic.
        IntentStatusMismatch,
        /// Intent not found.
        IntentNotFound,
        /// Claim not found.
        ClaimNotFound,
        /// Voucher already exists for this claim.
        DuplicateVoucher,
        /// Fairness-proof invariant violated (sum, scale, ordering).
        InvalidFairnessProof,
        /// Voucher-proof binding: voucher.bfpr_digest doesn't match.
        FairnessDigestMismatch,
        /// Submitted past TTL window.
        TTLElapsed,
        /// Pool utilization would exceed hard cap.
        PoolUtilizationExceeded,
        /// Dwell period for credit refund not yet satisfied.
        DwellNotSatisfied,
        /// Deposit already processed (idempotency guard).
        DepositAlreadyProcessed,
        /// Expire-policy-mirror called on an unknown policy.
        UnknownPolicy,
        /// Committee bundle size exceeds configured MaxCommittee.
        TooManySigs,
        /// Issue #4: `attest_intent` was called with a `pubkey` argument that
        /// does not derive back to the signed origin. Blocks a single caller
        /// from spoofing N attestations via N different pubkeys.
        CallerPubkeyMismatch,
        /// Issue #5: accumulating the batch's fairness-proof amount into
        /// `outstanding_coverage_ada` would overflow `u64`. Rejected rather
        /// than silently wrapping.
        CoverageOverflow,
        /// Issue #6: `PendingBatches` index is at `MaxPendingBatches` capacity.
        /// Caller must wait for pending intents to terminalize before
        /// submitting another. Never hits in steady state — the bound is
        /// sized (10k) for well behind the keeper-poll watermark.
        PendingBatchesFull,
        /// Issue #7: the multisig envelope did not contain enough distinct
        /// valid signatures (threshold check). Carries no details to avoid
        /// leaking which specific signer was missing.
        InsufficientSignatures,
        /// Issue #7: a duplicate pubkey appeared in the multisig signer list.
        /// Treated as a hard reject (not a de-dup) so that replay attacks are
        /// unambiguously surfaced.
        DuplicateSigner,
        /// Issue #7: a signature in the multisig envelope failed sr25519
        /// verification against the canonical payload digest.
        InvalidSignature,
        /// Issue #7: a pubkey in the multisig envelope is not a current
        /// committee member.
        SignerNotCommitteeMember,
        /// Task #177: `settle_batch_atomic` was called with an empty batch.
        /// Trivially-rejecting an empty batch keeps the weight model honest
        /// (we charge ~baseline + N*per-entry; N=0 must not slip through as
        /// "free").
        EmptyBatch,
        /// Task #177: a single batch contained the same `claim_id` twice.
        /// The batch is rejected atomically; no settlements are applied.
        DuplicateClaimInBatch,
        /// Task #177: a claim in the batch was already settled before the
        /// batch landed. Atomic rejection preserves the all-or-nothing
        /// semantic that lets keepers retry the whole batch deterministically.
        BatchClaimAlreadySettled,
        /// Task #211: `attest_batch_intents` was called with an empty
        /// intent_ids vec. Atomically rejected (no fee/state movement) so
        /// the weight model stays honest.
        EmptyAttestBatch,
        /// Task #211: a single batch contained the same `intent_id` twice.
        /// Atomic rejection — pallet must surface the keeper bug rather
        /// than silently dedup.
        DuplicateIntentInBatch,
        /// Task #212: `request_batch_vouchers` was called with an empty
        /// entries vec. Atomically rejected.
        EmptyVoucherBatch,
        /// Task #212: a single batch contained the same `claim_id` twice.
        /// Atomically rejected — pallet must surface the keeper bug.
        DuplicateClaimInVoucherBatch,
        /// Task #210: `submit_batch_intents` was called with an empty entries
        /// vec. Atomically rejected (no fee/credit movement) so the weight
        /// model stays honest (we charge ~baseline + N*per-entry; N=0 must
        /// not slip through as "free").
        EmptyIntentBatch,
        /// Task #210: summing per-entry `BuyPolicy.premium_ada` across the
        /// batch overflows `u64`. Cheaper to reject than to silently wrap,
        /// matching the Issue #5 `CoverageOverflow` precedent on the
        /// voucher-mint stage.
        SubmitBatchPremiumOverflow,
    }

    // ---------------------------------------------------------------------
    // Genesis — seed sensible defaults for IntentTTL/ClaimTTL/PoolUtilization
    // ---------------------------------------------------------------------

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        pub intent_ttl: BlockNumber,
        pub claim_ttl: BlockNumber,
        pub pool_utilization: PoolUtilizationParams,
        /// Issue #7: M-of-N bar for `credit_deposit`/`settle_claim`. Zero
        /// means "use DefaultMinSignerThreshold from Config".
        pub min_signer_threshold: u32,
        #[serde(skip)]
        pub _phantom: core::marker::PhantomData<T>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            let ttl_intent = if self.intent_ttl == 0 {
                T::DefaultIntentTTL::get()
            } else {
                self.intent_ttl
            };
            let ttl_claim = if self.claim_ttl == 0 {
                T::DefaultClaimTTL::get()
            } else {
                self.claim_ttl
            };
            IntentTTL::<T>::put(ttl_intent);
            ClaimTTL::<T>::put(ttl_claim);
            PoolUtilization::<T>::put(self.pool_utilization);
            let mst = if self.min_signer_threshold == 0 {
                T::DefaultMinSignerThreshold::get()
            } else {
                self.min_signer_threshold
            };
            MinSignerThreshold::<T>::put(mst);
        }
    }

    // ---------------------------------------------------------------------
    // Hooks — bounded TTL sweep
    // ---------------------------------------------------------------------

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T>
    where
        BlockNumberFor<T>: Into<u64> + Copy,
    {
        fn on_initialize(n: BlockNumberFor<T>) -> Weight {
            // Convert to u32 block for the expiry key. Saturating-cast avoids
            // panics on tests that burn through block numbers.
            let n_u32: u32 = n.into().try_into().unwrap_or(u32::MAX);
            let mut total = Weight::from_parts(10_000, 0);
            let to_expire = ExpiryQueue::<T>::take(n_u32);
            for intent_id in to_expire {
                total = total.saturating_add(Weight::from_parts(10_000, 0));
                if let Some(mut intent) = Intents::<T>::get(intent_id) {
                    if matches!(
                        intent.status,
                        IntentStatus::Pending | IntentStatus::Attested
                    ) {
                        intent.status = IntentStatus::Expired;
                        // Refund any reserved credit on expiry.
                        if let IntentKind::BuyPolicy { premium_ada, .. } = &intent.kind {
                            Credits::<T>::mutate(&intent.submitter, |c| {
                                *c = c.saturating_add(*premium_ada)
                            });
                        }
                        Intents::<T>::insert(intent_id, intent);
                        // Issue #6: drop from PendingBatches index on TTL
                        // expiry — terminal status.
                        Self::remove_from_pending_batches(intent_id);
                        Self::deposit_event(Event::IntentExpired {
                            intent_id,
                            reason: ExpiryReason::TTL,
                        });
                    }
                }
            }

            // Task #245: fallback sweep. Walks a bounded window of
            // `PendingBatches` and terminalizes any past-TTL Pending/Attested
            // intents missed by `ExpiryQueue` (per-bucket cap overflow).
            //
            // Bounded cost:
            //   - reads:  ≤ FALLBACK_SWEEP_PER_BLOCK + 1 (PendingBatches +
            //             cursor + per-entry Intents::get)
            //   - writes: ≤ FALLBACK_SWEEP_PER_BLOCK + 2 (per-expired
            //             Intents::insert + Credits::mutate + final
            //             PendingBatches::put + cursor put)
            //
            // We mutate `PendingBatches` once at the end (collect IDs to
            // remove first, then a single retain pass), avoiding the
            // O(n²) cost of one mutate per entry. `Intents` writes happen
            // in the loop because they're keyed differently per id.
            let pb = PendingBatches::<T>::get();
            let pb_len = pb.len() as u32;
            if pb_len > 0 {
                let cursor = FallbackSweepCursor::<T>::get() % pb_len;
                let budget = FALLBACK_SWEEP_PER_BLOCK.min(pb_len);
                let mut to_remove: alloc::vec::Vec<IntentId> =
                    alloc::vec::Vec::with_capacity(budget as usize);
                for i in 0..budget {
                    let idx = ((cursor + i) % pb_len) as usize;
                    // Safe: idx < pb_len.
                    let intent_id = pb[idx];
                    total = total.saturating_add(Weight::from_parts(8_000, 0));
                    if let Some(mut intent) = Intents::<T>::get(intent_id) {
                        if matches!(
                            intent.status,
                            IntentStatus::Pending | IntentStatus::Attested
                        ) && intent.ttl_block <= n_u32
                        {
                            intent.status = IntentStatus::Expired;
                            if let IntentKind::BuyPolicy { premium_ada, .. } = &intent.kind {
                                Credits::<T>::mutate(&intent.submitter, |c| {
                                    *c = c.saturating_add(*premium_ada)
                                });
                            }
                            Intents::<T>::insert(intent_id, intent);
                            to_remove.push(intent_id);
                            Self::deposit_event(Event::IntentExpired {
                                intent_id,
                                reason: ExpiryReason::TTLFallback,
                            });
                            total = total.saturating_add(Weight::from_parts(15_000, 0));
                        }
                    }
                }

                if !to_remove.is_empty() {
                    PendingBatches::<T>::mutate(|pb_mut| {
                        pb_mut.retain(|id| !to_remove.contains(id));
                    });
                    FallbackSweepCount::<T>::mutate(|c| {
                        *c = c.saturating_add(to_remove.len() as u64)
                    });
                }

                // Advance the cursor; new pb_len after possible removals.
                let new_pb_len = PendingBatches::<T>::decode_len()
                    .map(|n| n as u32)
                    .unwrap_or(0);
                if new_pb_len == 0 {
                    FallbackSweepCursor::<T>::put(0u32);
                } else {
                    let next = (cursor + budget) % new_pb_len;
                    FallbackSweepCursor::<T>::put(next);
                }
            }

            total
        }
    }

    // ---------------------------------------------------------------------
    // Extrinsics
    // ---------------------------------------------------------------------

    #[pallet::call]
    impl<T: Config> Pallet<T>
    where
        BlockNumberFor<T>: Into<u64> + Copy,
        T::AccountId: Encode,
    {
        /// Submit a new intent. Auto-increments `Nonces[who]`, schedules
        /// expiry, and (for `BuyPolicy`/`RefundCredit`) atomically debits
        /// `Credits[who]` by the premium/refund amount.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(500_000_000, 0))]
        pub fn submit_intent(origin: OriginFor<T>, kind: IntentKind) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::do_submit_intent(who, kind).map(|_| ())
        }

        /// Committee member posts one signature toward the M-of-N bundle for
        /// `intent_id`. First bundle to cross threshold transitions state to
        /// Attested and stores the final `AttestationSigs`. Subsequent calls
        /// are no-ops.
        #[pallet::call_index(1)]
        #[pallet::weight((Weight::from_parts(50_000_000, 0), DispatchClass::Operational, Pays::No))]
        pub fn attest_intent(
            origin: OriginFor<T>,
            intent_id: IntentId,
            pubkey: CommitteePubkey,
            sig: CommitteeSig,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                T::CommitteeMembership::is_member(&who),
                Error::<T>::NotCommitteeMember
            );

            // Issue #4: bind the `pubkey` argument to the signed origin.
            // Previously any committee member could post an attestation
            // "from" any other pubkey, letting one caller spoof N
            // attestations toward threshold. The derivation is runtime-
            // provided (`PubkeyOf`) so `AccountId32` maps to its raw 32-byte
            // public key while test runtimes with `u64` accounts left-pad.
            ensure!(
                T::CommitteeMembership::pubkey_of(&who) == pubkey,
                Error::<T>::CallerPubkeyMismatch
            );

            // If already Attested, make this a no-op (idempotent).
            let mut intent =
                Intents::<T>::get(intent_id).ok_or(Error::<T>::IntentNotFound)?;
            if intent.status != IntentStatus::Pending {
                return Ok(());
            }

            // We don't crypto-verify the ed25519 sig against `intent_id` bytes
            // here at runtime — that's the Cardano validator's job per spec §1.2
            // (Aiken verifies committee sigs). Substrate only enforces that
            // the caller is a committee member and that (pubkey, sig) are
            // well-formed and non-duplicated. That keeps attestation cheap and
            // avoids double-verification (ed25519 is verified at Cardano time).

            // Append to the pending bundle; reject duplicates by pubkey.
            let mut bundle = PendingAttestations::<T>::get(intent_id);
            if bundle.iter().any(|(p, _)| p == &pubkey) {
                return Ok(()); // idempotent on duplicate pubkey
            }
            bundle
                .try_push((pubkey, sig))
                .map_err(|_| Error::<T>::TooManySigs)?;
            PendingAttestations::<T>::insert(intent_id, bundle.clone());

            let threshold = T::CommitteeMembership::threshold();
            if bundle.len() as u32 >= threshold {
                intent.status = IntentStatus::Attested;
                Intents::<T>::insert(intent_id, intent);
                AttestationSigs::<T>::insert(intent_id, bundle.clone());
                PendingAttestations::<T>::remove(intent_id);
                Self::deposit_event(Event::IntentAttested {
                    intent_id,
                    attestor_count: bundle.len() as u32,
                });
            }
            Ok(())
        }

        /// Committee member submits a voucher + fairness proof. The voucher
        /// itself carries the full M-of-N signature bundle; this pallet
        /// checks the fairness-proof invariants and the voucher-to-proof
        /// binding, stores the voucher, and flips the bound intent from
        /// `Attested -> Vouchered`. The Cardano validator re-verifies the
        /// ed25519 signatures.
        ///
        /// Task #174: a `signatures` envelope of M-of-N committee sr25519
        /// signatures over the canonical `request_voucher_payload` digest is
        /// now required. Without this, any single committee member could
        /// unilaterally mint a voucher (bypassing the M-of-N threshold) and
        /// only `settle_claim` would re-check sigs — but by then the audit
        /// story is already broken because the voucher exists. Verification
        /// reuses the same `ensure_threshold_signatures` helper used by
        /// `settle_claim` and `credit_deposit` (caller MUST be one of the
        /// signers, distinct signers, all in the current committee, all sigs
        /// must verify). **Breaking on-chain change**: the previous 4-arg
        /// signature is gone; keepers must upgrade in lockstep with the
        /// runtime spec bump.
        #[pallet::call_index(2)]
        #[pallet::weight((Weight::from_parts(100_000_000, 0), DispatchClass::Operational, Pays::No))]
        pub fn request_voucher(
            origin: OriginFor<T>,
            claim_id: ClaimId,
            intent_id: IntentId,
            voucher: Voucher,
            fairness_proof: BatchFairnessProof,
            signatures: Vec<(CommitteePubkey, CommitteeSig)>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                T::CommitteeMembership::is_member(&who),
                Error::<T>::NotCommitteeMember
            );

            // Check duplicate-voucher first so callers get an unambiguous error
            // when they retry with the same claim_id.
            ensure!(
                !Vouchers::<T>::contains_key(claim_id),
                Error::<T>::DuplicateVoucher
            );
            let mut intent =
                Intents::<T>::get(intent_id).ok_or(Error::<T>::IntentNotFound)?;
            ensure!(
                intent.status == IntentStatus::Attested,
                Error::<T>::IntentStatusMismatch
            );

            Self::validate_fairness_proof(&fairness_proof)?;
            let bfpr_digest = compute_fairness_proof_digest(&fairness_proof);
            ensure!(
                voucher.batch_fairness_proof_digest == bfpr_digest,
                Error::<T>::FairnessDigestMismatch
            );

            // Task #174: M-of-N gate on voucher mint. We compute the canonical
            // pre-image *after* the fairness-proof and digest-binding checks
            // pass, so honest operators all see the same `(voucher_digest,
            // bfpr_digest)` pair the pallet just validated — no operator-local
            // state slips in. The same `ensure_threshold_signatures` routine
            // used by settle_claim/credit_deposit gives us caller-binding,
            // distinct-signer, member-only, and per-sig sr25519 verification.
            let voucher_digest_pre = compute_voucher_digest(&voucher);
            let voucher_payload = request_voucher_payload(
                &claim_id,
                &intent_id,
                &voucher_digest_pre,
                &bfpr_digest,
            );
            Self::ensure_threshold_signatures(&voucher_payload, &who, &signatures)?;

            // Issue #5: pre-check the `outstanding_coverage_ada` increment
            // BEFORE mutating storage (checked_add -> CoverageOverflow) so
            // that a craft-a-batch overflow attempt cannot leave state in a
            // half-updated shape. We only account for this single claim's
            // `voucher.amount_ada`, matching the symmetric `settle_claim`
            // decrement in the same unit — the prior batch-sum semantics
            // drifted the counter for every partial batch (+10*, -1*).
            let pool = PoolUtilization::<T>::get();
            let new_outstanding = pool
                .outstanding_coverage_ada
                .checked_add(voucher.amount_ada)
                .ok_or(Error::<T>::CoverageOverflow)?;

            // Reuse the digest we already computed for the M-of-N pre-image.
            let voucher_digest = voucher_digest_pre;
            let voucher_amount = voucher.amount_ada;

            // Store claim + voucher, flip intent state.
            let claim = Claim {
                intent_id,
                policy_id: voucher.policy_id,
                amount_ada: voucher_amount,
                issued_block: voucher.issued_block,
                expiry_slot_cardano: voucher.expiry_slot_cardano,
                settled: false,
                settled_direct: false,
                cardano_tx_hash: [0u8; 32],
            };
            Claims::<T>::insert(claim_id, claim);
            Vouchers::<T>::insert(claim_id, voucher);
            intent.status = IntentStatus::Vouchered;
            Intents::<T>::insert(intent_id, intent);
            // Issue #6: once Vouchered the intent is out of the keeper's
            // attested-batch window. Drop from the index so get_pending_batches
            // doesn't re-surface it, and the index doesn't grow unboundedly.
            Self::remove_from_pending_batches(intent_id);

            // Issue #5: write the pre-checked value; `outstanding_coverage_ada`
            // is now maintained symmetrically against `settle_claim`.
            PoolUtilization::<T>::mutate(|u| {
                u.outstanding_coverage_ada = new_outstanding;
            });

            Self::deposit_event(Event::VoucherIssued {
                claim_id,
                voucher_digest,
                fairness_proof_digest: bfpr_digest,
            });
            Ok(())
        }

        /// Sugar wrapper around `submit_intent(IntentKind::RefundCredit { .. })`.
        /// Enforces `Credits[who] >= amount`.
        #[pallet::call_index(3)]
        #[pallet::weight(Weight::from_parts(500_000_000, 0))]
        pub fn request_credit_refund(
            origin: OriginFor<T>,
            amount_ada: AdaLovelace,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let credit = Credits::<T>::get(&who);
            ensure!(credit >= amount_ada, Error::<T>::InsufficientCredit);
            let kind = IntentKind::RefundCredit { amount_ada };
            let intent_id = Self::do_submit_intent(who.clone(), kind)?;
            Self::deposit_event(Event::CreditRefundRequested {
                intent_id,
                submitter: who,
                amount_ada,
            });
            Ok(())
        }

        /// Committee mirrors a completed Cardano settlement. Transitions claim
        /// to `settled` and flips the bound intent to `Settled`. `settled_direct`
        /// distinguishes keeper-batch vs direct-path 10-minute fallback.
        #[pallet::call_index(4)]
        #[pallet::weight((Weight::from_parts(50_000_000, 0), DispatchClass::Operational, Pays::No))]
        pub fn settle_claim(
            origin: OriginFor<T>,
            claim_id: ClaimId,
            cardano_tx_hash: [u8; 32],
            settled_direct: bool,
            signatures: Vec<(CommitteePubkey, CommitteeSig)>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                T::CommitteeMembership::is_member(&who),
                Error::<T>::NotCommitteeMember
            );

            // Issue #7: require M-of-N distinct committee signatures over the
            // canonical payload. The origin itself MUST sign (otherwise any
            // member could replay stale signature bundles), so we build the
            // digest including who and verify inclusion.
            let payload = settle_claim_payload(
                &claim_id,
                &cardano_tx_hash,
                settled_direct,
            );
            Self::ensure_threshold_signatures(&payload, &who, &signatures)?;

            let mut claim =
                Claims::<T>::get(claim_id).ok_or(Error::<T>::ClaimNotFound)?;
            if claim.settled {
                return Ok(()); // idempotent
            }
            claim.settled = true;
            claim.settled_direct = settled_direct;
            claim.cardano_tx_hash = cardano_tx_hash;
            let intent_id = claim.intent_id;
            let amount = claim.amount_ada;
            Claims::<T>::insert(claim_id, claim);

            if let Some(mut intent) = Intents::<T>::get(intent_id) {
                intent.status = IntentStatus::Settled;
                Intents::<T>::insert(intent_id, intent);
            }
            // Issue #6: intent is now terminal; drop from index.
            Self::remove_from_pending_batches(intent_id);

            // Decrement outstanding coverage.
            PoolUtilization::<T>::mutate(|u| {
                u.outstanding_coverage_ada =
                    u.outstanding_coverage_ada.saturating_sub(amount);
            });

            Self::deposit_event(Event::ClaimSettled {
                claim_id,
                cardano_tx_hash,
                settled_direct,
            });
            Ok(())
        }

        /// Committee reports that a policy expired on Cardano (Expire redeemer
        /// was executed). Cleans up any bound Materios intent that's still
        /// open.
        #[pallet::call_index(5)]
        #[pallet::weight((Weight::from_parts(30_000_000, 0), DispatchClass::Operational, Pays::No))]
        pub fn expire_policy_mirror(
            origin: OriginFor<T>,
            intent_id: IntentId,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                T::CommitteeMembership::is_member(&who),
                Error::<T>::NotCommitteeMember
            );
            let mut intent =
                Intents::<T>::get(intent_id).ok_or(Error::<T>::UnknownPolicy)?;
            if matches!(
                intent.status,
                IntentStatus::Expired | IntentStatus::Settled
            ) {
                return Ok(());
            }
            intent.status = IntentStatus::Expired;
            Intents::<T>::insert(intent_id, intent);
            // Issue #6: terminal → drop from PendingBatches.
            Self::remove_from_pending_batches(intent_id);
            Self::deposit_event(Event::IntentExpired {
                intent_id,
                reason: ExpiryReason::PolicyExpiredOnCardano,
            });
            Ok(())
        }

        /// Committee registers a confirmed Cardano deposit to the premium
        /// collector script. Idempotent on `(who, cardano_tx_hash)`.
        #[pallet::call_index(6)]
        #[pallet::weight((Weight::from_parts(30_000_000, 0), DispatchClass::Operational, Pays::No))]
        pub fn credit_deposit(
            origin: OriginFor<T>,
            target: T::AccountId,
            amount_ada: AdaLovelace,
            cardano_tx_hash: [u8; 32],
            signatures: Vec<(CommitteePubkey, CommitteeSig)>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                T::CommitteeMembership::is_member(&who),
                Error::<T>::NotCommitteeMember
            );

            // Issue #7: M-of-N gate. Previously any single committee member
            // could unilaterally credit any ADA amount onto any account —
            // trivial pool drain. We now require `MinSignerThreshold`
            // distinct committee signatures over the canonical payload
            // (target, amount, tx_hash) and verify each at runtime.
            let target_bytes = crate::account_to_bytes(&target);
            let payload = credit_deposit_payload(
                &target_bytes,
                amount_ada,
                &cardano_tx_hash,
            );
            Self::ensure_threshold_signatures(&payload, &who, &signatures)?;

            let key = (target.clone(), cardano_tx_hash);
            ensure!(
                !ProcessedDeposits::<T>::contains_key(&key),
                Error::<T>::DepositAlreadyProcessed
            );
            ProcessedDeposits::<T>::insert(&key, ());
            Credits::<T>::mutate(&target, |c| *c = c.saturating_add(amount_ada));

            // Track NAV for pool utilization.
            PoolUtilization::<T>::mutate(|u| {
                u.total_nav_ada = u.total_nav_ada.saturating_add(amount_ada);
            });

            Self::deposit_event(Event::CreditsCredited {
                account: target,
                delta_ada: amount_ada,
                source_cardano_tx: cardano_tx_hash,
            });
            Ok(())
        }

        /// Governance knob — update pool NAV/utilization parameters. Root-only.
        #[pallet::call_index(7)]
        #[pallet::weight((Weight::from_parts(10_000_000, 0), DispatchClass::Operational, Pays::No))]
        pub fn set_pool_utilization(
            origin: OriginFor<T>,
            params: PoolUtilizationParams,
        ) -> DispatchResult {
            ensure_root(origin)?;
            PoolUtilization::<T>::put(params);
            Self::deposit_event(Event::PoolUtilizationUpdated {
                total_nav_ada: params.total_nav_ada,
                outstanding_coverage_ada: params.outstanding_coverage_ada,
            });
            Ok(())
        }

        /// Issue #7: Root-only governance knob to tune the M-of-N floor at
        /// runtime (preprod launches with 2, mainnet bumps to 3 via this
        /// extrinsic). Setting 0 resets to `DefaultMinSignerThreshold`.
        #[pallet::call_index(8)]
        #[pallet::weight((Weight::from_parts(10_000_000, 0), DispatchClass::Operational, Pays::No))]
        pub fn set_min_signer_threshold(
            origin: OriginFor<T>,
            new_threshold: u32,
        ) -> DispatchResult {
            ensure_root(origin)?;
            let v = if new_threshold == 0 {
                T::DefaultMinSignerThreshold::get()
            } else {
                new_threshold
            };
            MinSignerThreshold::<T>::put(v);
            Ok(())
        }

        /// Task #177: settle N already-vouchered claims in a SINGLE extrinsic
        /// under ONE committee-signature verification.
        ///
        /// Cost model:
        /// - One sig-verify pass over the batch digest (the dominant ~weight
        ///   per existing `settle_claim`)
        /// - N * (storage_read(Claims) + storage_write(Claims)
        ///        + storage_read(Intents) + storage_write(Intents)
        ///        + storage_mutate(PoolUtilization)
        ///        + remove_from_pending_batches)
        ///
        /// At N=256 the storage-write cost is comparable to a single
        /// `settle_claim`'s sig-verify cost, so the total weight is roughly
        /// `~1.5–2x weight_of(settle_claim)` — the exact slope is captured
        /// by the runtime-benchmarks recipe (`benchmarking.rs`).
        ///
        /// Atomic semantics: any per-entry failure (claim not found, claim
        /// already settled, duplicate claim_id within the batch) reverts
        /// every storage mutation in this call — no partial settlements.
        ///
        /// Backward compatibility: this extrinsic is purely additive. The
        /// existing 5-stage flow (`submit_intent` + `attest_intent` × M +
        /// `request_voucher` + `settle_claim`) is unchanged. Only the final
        /// `settle_claim` × N step collapses into one batch call.
        ///
        /// Idempotency: callers MUST ensure unique `claim_id`s within a
        /// batch (the pallet rejects duplicates). Across batches, attempting
        /// to settle an already-settled claim is rejected (rather than
        /// silently no-op'd) so the keeper's retry logic stays
        /// deterministic — split the batch and resubmit only the
        /// not-yet-settled subset.
        #[pallet::call_index(9)]
        #[pallet::weight((
            // Base weight ≈ one settle_claim's sig-verify (50M) plus per-entry
            // storage cost (~5M). The benchmarking case overrides this once
            // weights are generated (see benchmarking.rs).
            Weight::from_parts(
                50_000_000u64.saturating_add((entries.len() as u64).saturating_mul(5_000_000)),
                0,
            ),
            DispatchClass::Operational,
            Pays::No,
        ))]
        pub fn settle_batch_atomic(
            origin: OriginFor<T>,
            entries: BoundedVec<SettleBatchEntry, <T as Config>::MaxSettleBatch>,
            signatures: Vec<(CommitteePubkey, CommitteeSig)>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                T::CommitteeMembership::is_member(&who),
                Error::<T>::NotCommitteeMember
            );
            ensure!(!entries.is_empty(), Error::<T>::EmptyBatch);

            // Compute batch digest ONCE over all entries. Single sig-verify
            // pass below — this is where the ~100x throughput unlock lives.
            let payload = settle_batch_atomic_payload(entries.as_slice());
            Self::ensure_threshold_signatures(&payload, &who, &signatures)?;

            // Pass 1: detect duplicate claim_ids INSIDE the batch up-front
            // (cheaper than discovering it mid-loop after we've already
            // mutated state). O(N^2) with N <= 256 — ~32k comparisons worst
            // case, well below sig-verify cost.
            let n = entries.len();
            for i in 0..n {
                for j in (i + 1)..n {
                    ensure!(
                        entries[i].claim_id != entries[j].claim_id,
                        Error::<T>::DuplicateClaimInBatch,
                    );
                }
            }

            // Atomic mutation phase — apply all settlements in a transactional
            // storage layer so any per-entry failure rolls the whole call back.
            // Any error returned from this closure is bubbled up as the
            // extrinsic's DispatchError; on Ok the changes commit.
            let (count, settled_direct_count) =
                frame_support::storage::with_storage_layer::<
                    (u32, u32),
                    sp_runtime::DispatchError,
                    _,
                >(|| {
                    let mut total_amount_unsettled: u64 = 0;
                    let mut direct_count: u32 = 0;

                    for entry in entries.iter() {
                        let mut claim = Claims::<T>::get(entry.claim_id)
                            .ok_or(Error::<T>::ClaimNotFound)?;
                        // Strict reject on already-settled — atomic semantics.
                        ensure!(
                            !claim.settled,
                            Error::<T>::BatchClaimAlreadySettled
                        );
                        claim.settled = true;
                        claim.settled_direct = entry.settled_direct;
                        claim.cardano_tx_hash = entry.cardano_tx_hash;
                        let intent_id = claim.intent_id;
                        let amount = claim.amount_ada;
                        Claims::<T>::insert(entry.claim_id, claim);

                        if let Some(mut intent) = Intents::<T>::get(intent_id) {
                            intent.status = IntentStatus::Settled;
                            Intents::<T>::insert(intent_id, intent);
                        }
                        Self::remove_from_pending_batches(intent_id);

                        if entry.settled_direct {
                            direct_count = direct_count.saturating_add(1);
                        }
                        total_amount_unsettled =
                            total_amount_unsettled.saturating_add(amount);
                    }

                    // Decrement outstanding coverage in ONE mutate call (vs N
                    // separate mutates) — same storage-write economics as
                    // `settle_claim` summed across N calls, but cheaper.
                    PoolUtilization::<T>::mutate(|u| {
                        u.outstanding_coverage_ada = u
                            .outstanding_coverage_ada
                            .saturating_sub(total_amount_unsettled);
                    });

                    Ok((n as u32, direct_count))
                })?;

            Self::deposit_event(Event::BatchSettled {
                count,
                batch_digest: payload,
                settled_direct_count,
            });
            Ok(())
        }

        /// Task #211: attest N intents in ONE extrinsic under ONE M-of-N
        /// signature verification.
        ///
        /// Pre-spec-207 the attest stage ran `attest_intent` once per
        /// (signer, intent) pair: a 3-of-3 committee at N=256 issued 768
        /// chain extrinsics per epoch, each with its own per-call sig-
        /// verify. Post-spec-207 this collapses to a single
        /// `attest_batch_intents(intent_ids, signatures)` call with ONE
        /// sig-verify pass over the whole batch — the largest single-pallet
        /// TPS unlock in the v5.1 plan.
        ///
        /// Per-intent semantics:
        /// - Each intent must currently be `Pending`. If it's `Attested`
        ///   already (raced by another attestation extrinsic), this entry
        ///   is treated as an idempotent no-op (does not contribute to the
        ///   `attested_count` event field) — matches `attest_intent`'s
        ///   prior behaviour. If it's in any other terminal state
        ///   (Vouchered/Settled/Expired), the batch atomically rejects
        ///   with `IntentStatusMismatch`.
        /// - Each intent's `AttestationSigs` storage map is overwritten
        ///   with the call's signature bundle on the Pending -> Attested
        ///   transition. The bundle stored is exactly the `signatures`
        ///   argument truncated to MaxCommittee (the legacy single-call
        ///   `attest_intent` accumulated sigs across calls; the batch path
        ///   posts the full M-of-N envelope in one shot, so the storage
        ///   write is direct).
        ///
        /// Caller binding: same as `settle_batch_atomic`. The caller's
        /// pubkey MUST appear in `signatures` (origin-binding via
        /// `ensure_threshold_signatures`). Subsequent batch calls from the
        /// same committee are idempotent on intents already in Attested
        /// state, so there's no replay-attack window.
        ///
        /// Backward compatibility: the existing per-intent `attest_intent`
        /// (call_index 1) is unchanged. Mixed-mode (some intents attested
        /// via single-call, others via batch) is supported within the same
        /// epoch.
        ///
        /// Atomic semantics: any per-intent failure (intent not found,
        /// terminal status mismatch, duplicate intent_id within the batch)
        /// reverts every storage mutation in this call.
        ///
        /// Cost model:
        /// - Base ~50M ref_time (M-of-N sig-verify pass)
        /// - Plus N * ~3M ref_time (per-intent storage read for `Intents`,
        ///   one storage write each for `Intents` + `AttestationSigs`).
        /// - At N=256 the per-intent cost ~768M dwarfs the sig-verify
        ///   pass — but it's still ~3x cheaper than the legacy 768
        ///   `attest_intent` calls each at ~50M = 38B total.
        #[pallet::call_index(11)]
        #[pallet::weight((
            Weight::from_parts(
                50_000_000u64.saturating_add((intent_ids.len() as u64).saturating_mul(3_000_000)),
                0,
            ),
            DispatchClass::Operational,
            Pays::No,
        ))]
        pub fn attest_batch_intents(
            origin: OriginFor<T>,
            intent_ids: BoundedVec<IntentId, <T as Config>::MaxAttestBatch>,
            signatures: Vec<(CommitteePubkey, CommitteeSig)>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                T::CommitteeMembership::is_member(&who),
                Error::<T>::NotCommitteeMember
            );
            ensure!(!intent_ids.is_empty(), Error::<T>::EmptyAttestBatch);

            // Compute the canonical ABIN digest ONCE over all intent_ids,
            // then verify the M-of-N sig bundle against it ONCE — the
            // throughput unlock.
            let payload = attest_batch_intents_payload(intent_ids.as_slice());
            Self::ensure_threshold_signatures(&payload, &who, &signatures)?;

            // Pass 1: detect duplicate intent_ids inside the batch up-front
            // (cheaper than discovering it mid-loop after we've mutated
            // state). O(N^2) with N <= 256 ~32k comparisons worst case,
            // well below sig-verify cost.
            let n = intent_ids.len();
            for i in 0..n {
                for j in (i + 1)..n {
                    ensure!(
                        intent_ids[i] != intent_ids[j],
                        Error::<T>::DuplicateIntentInBatch,
                    );
                }
            }

            // Truncate the call-level sigs vec into the storage-bound
            // BoundedVec for AttestationSigs. The storage type uses
            // `MaxCommittee` (=32 in prod), and `ensure_threshold_signatures`
            // already proved `signatures.len() >= threshold` — so any
            // overflow here would mean the caller submitted MORE than
            // MaxCommittee sigs, which we treat as an error rather than
            // silently truncate.
            let sigs_bv: BoundedVec<
                (CommitteePubkey, CommitteeSig),
                <T as Config>::MaxCommittee,
            > = BoundedVec::try_from(signatures.clone())
                .map_err(|_| Error::<T>::TooManySigs)?;

            let signer_count = signatures.len() as u32;

            // Atomic mutation phase. Any per-intent failure reverts the
            // whole call — same all-or-nothing semantics as PR #27.
            let attested_count = frame_support::storage::with_storage_layer::<
                u32,
                sp_runtime::DispatchError,
                _,
            >(|| {
                let mut freshly_attested: u32 = 0;
                for iid in intent_ids.iter() {
                    let mut intent =
                        Intents::<T>::get(iid).ok_or(Error::<T>::IntentNotFound)?;
                    match intent.status {
                        IntentStatus::Attested => {
                            // Idempotent — already past the threshold from a
                            // prior batch / single-call. Silently skip.
                            continue;
                        }
                        IntentStatus::Pending => {
                            intent.status = IntentStatus::Attested;
                            Intents::<T>::insert(iid, intent);
                            AttestationSigs::<T>::insert(iid, sigs_bv.clone());
                            // Drop any partial single-call accumulation —
                            // the batch's M-of-N envelope is the canonical
                            // bundle now.
                            PendingAttestations::<T>::remove(iid);
                            Self::deposit_event(Event::IntentAttested {
                                intent_id: *iid,
                                attestor_count: signer_count,
                            });
                            freshly_attested = freshly_attested.saturating_add(1);
                        }
                        _ => {
                            // Vouchered / Settled / Expired / Refunded —
                            // can't be re-attested. Reject the batch
                            // atomically; keeper must split the next batch
                            // and exclude this intent.
                            return Err(Error::<T>::IntentStatusMismatch.into());
                        }
                    }
                }
                Ok(freshly_attested)
            })?;

            Self::deposit_event(Event::BatchIntentsAttested {
                submitted_count: n as u32,
                attested_count,
                batch_digest: payload,
                signer_count,
            });
            Ok(())
        }

        /// Task #212: mint N vouchers in ONE extrinsic under ONE M-of-N
        /// signature verification.
        ///
        /// Pre-spec-207 each voucher mint required its own M-of-N round
        /// (per PR #26's `request_voucher` RVCH gate). At N=256 vouchers
        /// per epoch that's 256 separate sig-verifies. Post-spec-207 those
        /// collapse to one RVBN sig-verify pass over the canonical batch
        /// digest.
        ///
        /// Per-entry semantics (identical to single-call `request_voucher`):
        /// - `intent_id` must be in `Attested` status; transitions to
        ///   `Vouchered`.
        /// - `claim_id` must not already have a Voucher in storage
        ///   (`DuplicateVoucher`).
        /// - `fairness_proof` must satisfy `validate_fairness_proof`
        ///   (`InvalidFairnessProof` on violation).
        /// - `voucher.batch_fairness_proof_digest` must equal the digest
        ///   of `fairness_proof` (`FairnessDigestMismatch`).
        /// - `voucher.amount_ada` adds to `outstanding_coverage_ada`; the
        ///   total batch increment is checked-add-checked at the top so a
        ///   craft-an-overflow attempt cannot leave state half-updated.
        ///
        /// After the per-entry checks pass, the canonical RVBN digest is
        /// computed once over the WHOLE batch's `(claim_id, intent_id,
        /// voucher_digest, bfpr_digest)` tuples and the M-of-N envelope is
        /// verified ONCE against it.
        ///
        /// Backward compatibility: the existing 5-arg `request_voucher`
        /// (call_index 2) is unchanged.
        ///
        /// Atomic semantics: any per-entry failure (intent missing/wrong
        /// status, claim already vouchered, invalid fairness proof, digest
        /// mismatch, duplicate claim_id within batch, coverage overflow)
        /// reverts every storage mutation in this call.
        ///
        /// Cost model:
        /// - Base ~50M ref_time (M-of-N sig-verify + duplicate-claim scan)
        /// - Plus N * ~10M ref_time (per-entry voucher_digest +
        ///   bfpr_digest computation + storage writes for `Claims`,
        ///   `Vouchers`, `Intents`, `PendingBatches` removal,
        ///   `outstanding_coverage_ada` increment).
        /// - At N=256 ~2.6B ref_time. Versus 256 single `request_voucher`
        ///   calls at ~100M each = 25.6B ref_time, the batch path is
        ///   ~10x cheaper.
        #[pallet::call_index(12)]
        #[pallet::weight((
            Weight::from_parts(
                50_000_000u64.saturating_add((entries.len() as u64).saturating_mul(10_000_000)),
                0,
            ),
            DispatchClass::Operational,
            Pays::No,
        ))]
        pub fn request_batch_vouchers(
            origin: OriginFor<T>,
            entries: BoundedVec<RequestVoucherEntry, <T as Config>::MaxVoucherBatch>,
            signatures: Vec<(CommitteePubkey, CommitteeSig)>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                T::CommitteeMembership::is_member(&who),
                Error::<T>::NotCommitteeMember
            );
            ensure!(!entries.is_empty(), Error::<T>::EmptyVoucherBatch);

            // Pass 0: detect duplicate claim_ids inside the batch up-front.
            // O(N^2) at N <= 256 ~32k comparisons, well below sig-verify cost.
            let n = entries.len();
            for i in 0..n {
                for j in (i + 1)..n {
                    ensure!(
                        entries[i].claim_id != entries[j].claim_id,
                        Error::<T>::DuplicateClaimInVoucherBatch,
                    );
                }
            }

            // Pass 1: per-entry digest computation + per-entry digest
            // binding check. We do this BEFORE the M-of-N sig-verify so
            // honest operators all see the same `(voucher_digest,
            // bfpr_digest)` pair the pallet just validated — no operator-
            // local state slips into the canonical pre-image (per
            // `feedback_mofn_hash_determinism.md`).
            let mut tuples: alloc::vec::Vec<(ClaimId, IntentId, [u8; 32], [u8; 32])> =
                alloc::vec::Vec::with_capacity(n);
            for entry in entries.iter() {
                Self::validate_fairness_proof(&entry.fairness_proof)?;
                let bfpr_digest =
                    compute_fairness_proof_digest(&entry.fairness_proof);
                ensure!(
                    entry.voucher.batch_fairness_proof_digest == bfpr_digest,
                    Error::<T>::FairnessDigestMismatch
                );
                let voucher_digest = compute_voucher_digest(&entry.voucher);
                tuples.push((
                    entry.claim_id,
                    entry.intent_id,
                    voucher_digest,
                    bfpr_digest,
                ));
            }

            // ONE sig-verify pass over the whole batch — the throughput
            // unlock. Domain-tagged with RVBN so a per-entry RVCH
            // signature can never replay onto the batch path.
            let payload = request_batch_vouchers_payload(&tuples);
            Self::ensure_threshold_signatures(&payload, &who, &signatures)?;

            // Atomic mutation phase. Each per-entry mutation mirrors the
            // single-call `request_voucher` body (issue #5 ordering
            // preserved: pre-check coverage overflow on the WHOLE batch
            // sum before mutating, mirror that per-entry as we walk).
            let (count, total_amount_unsettled) = frame_support::storage::with_storage_layer::<
                (u32, u64),
                sp_runtime::DispatchError,
                _,
            >(|| {
                let mut running_total: u64 = 0;
                for (idx, entry) in entries.iter().enumerate() {
                    // Duplicate-voucher check (per single-call semantics).
                    ensure!(
                        !Vouchers::<T>::contains_key(entry.claim_id),
                        Error::<T>::DuplicateVoucher
                    );
                    let mut intent = Intents::<T>::get(entry.intent_id)
                        .ok_or(Error::<T>::IntentNotFound)?;
                    ensure!(
                        intent.status == IntentStatus::Attested,
                        Error::<T>::IntentStatusMismatch
                    );

                    // Coverage overflow check — same checked-add as
                    // request_voucher (issue #5).
                    let pool = PoolUtilization::<T>::get();
                    let new_outstanding = pool
                        .outstanding_coverage_ada
                        .checked_add(entry.voucher.amount_ada)
                        .ok_or(Error::<T>::CoverageOverflow)?;

                    let voucher_amount = entry.voucher.amount_ada;
                    let claim = Claim {
                        intent_id: entry.intent_id,
                        policy_id: entry.voucher.policy_id,
                        amount_ada: voucher_amount,
                        issued_block: entry.voucher.issued_block,
                        expiry_slot_cardano: entry.voucher.expiry_slot_cardano,
                        settled: false,
                        settled_direct: false,
                        cardano_tx_hash: [0u8; 32],
                    };
                    Claims::<T>::insert(entry.claim_id, claim);
                    Vouchers::<T>::insert(entry.claim_id, entry.voucher.clone());
                    intent.status = IntentStatus::Vouchered;
                    Intents::<T>::insert(entry.intent_id, intent);
                    Self::remove_from_pending_batches(entry.intent_id);

                    PoolUtilization::<T>::mutate(|u| {
                        u.outstanding_coverage_ada = new_outstanding;
                    });

                    // Per-voucher event still emitted for indexer
                    // back-compat — same shape as single-call. The
                    // `voucher_digest` + `fairness_proof_digest` were
                    // computed in pass 1 and stashed in `tuples`.
                    let (_cid, _iid, vd, bd) = tuples[idx];
                    Self::deposit_event(Event::VoucherIssued {
                        claim_id: entry.claim_id,
                        voucher_digest: vd,
                        fairness_proof_digest: bd,
                    });

                    running_total = running_total.saturating_add(voucher_amount);
                }
                Ok((n as u32, running_total))
            })?;

            Self::deposit_event(Event::BatchVouchersIssued {
                count,
                batch_digest: payload,
                total_amount_ada: total_amount_unsettled,
            });
            Ok(())
        }

        /// Task #210: register N user intents in ONE extrinsic.
        ///
        /// User-side burst submission. Pre-spec-207 each intent required its
        /// own `submit_intent` extrinsic — at 256 intents that's 256
        /// signatures, 256 fee debits, and 256 round trips through the
        /// mempool. Post-spec-207 a single `submit_batch_intents(entries)`
        /// debits the user's fee once, takes ONE pre-image of the batch (for
        /// indexer correlation, NOT for sig-verify — the user origin is the
        /// only authority needed here), and runs the same per-intent state
        /// transitions inside a single transactional storage layer.
        ///
        /// Atomic semantics: the entire batch reverts on the FIRST per-entry
        /// failure (insufficient credit, pool-utilization cap, duplicate
        /// intent collision, or PendingBatches index overflow). No partial
        /// debit, no partial intents stored. Callers can retry the batch
        /// deterministically after fixing whichever entry tripped the
        /// rejection.
        ///
        /// Idempotency: the existing single-call `submit_intent` enforces
        /// `DuplicateIntent` via the IntentId pre-image (which already
        /// includes the user's nonce). Inside the batch each entry consumes
        /// nonce+i, so two identical entries in the same batch produce
        /// different IntentIds and BOTH commit (they're not duplicates from
        /// the chain's perspective). Two identical batches submitted twice
        /// (same nonce starting point) hit `DuplicateIntent` on the second
        /// call's first entry and atomically revert — the legacy guarantee.
        ///
        /// Backward compatibility: the existing 1-arg `submit_intent` is
        /// unchanged. Callers can mix single and batch in the same block.
        ///
        /// Cost model:
        /// - Base ~50M ref_time (signature verify + envelope decode)
        /// - Plus N*~5M ref_time (per-entry pool-utilization check +
        ///   IntentId derivation + storage writes for `Intents`, `Nonces`,
        ///   `PendingBatches`, `ExpiryQueue`)
        /// - Plus the standard `submit_intent` per-call weight (500M from
        ///   the legacy single-call) but consumed ONCE per batch, not per
        ///   entry — that's the throughput unlock.
        #[pallet::call_index(10)]
        #[pallet::weight({
            // Base weight ~50M (single-call submit_intent's amortised cost)
            // plus per-entry storage cost ~5M. Tuned to match the sublinear
            // pattern proven in PR #27 (settle_batch_atomic) — actual numbers
            // are pinned by the runtime-benchmarks recipe in benchmarking.rs.
            //
            // Task #221 (PR #28 pre-merge security review): proof_size is no
            // longer 0. Per-entry proof footprint ~5KB worst case (one
            // `Intents::insert` value + one `Nonces::mutate` + one
            // `PendingBatches::try_push` + one `ExpiryQueue::insert` + the
            // SCALE-encoded `IntentKind` itself, dominated by BuyPolicy's
            // 114-byte beneficiary_cardano_addr). Plus a 16KB base for the
            // M-of-N free zone, header reads, and pool-utilization fetch.
            // The bench-cli wiring (#190) is still pending so this remains
            // a hand-tuned upper bound — the runtime-benchmarks pass will
            // replace this whole expression with the generated WeightInfo
            // entry when #190 lands. Until then, this estimate keeps the
            // per-block normal-class budget honest at N=256
            // (~16KB + 256*5KB ~1.3MB proof_size, well under the 5MB limit
            // documented in types.rs::MAX_SUBMIT_BATCH).
            const BASE_PROOF_SIZE: u64 = 16_384;
            const PER_ENTRY_PROOF_SIZE: u64 = 5_120;
            let n = entries.len() as u64;
            Weight::from_parts(
                50_000_000u64.saturating_add(n.saturating_mul(5_000_000)),
                BASE_PROOF_SIZE.saturating_add(n.saturating_mul(PER_ENTRY_PROOF_SIZE)),
            )
        })]
        pub fn submit_batch_intents(
            origin: OriginFor<T>,
            entries: BoundedVec<SubmitIntentEntry, <T as Config>::MaxSubmitBatch>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(!entries.is_empty(), Error::<T>::EmptyIntentBatch);

            // Compute the canonical SBIN digest BEFORE consuming entries —
            // this is purely for indexer correlation (no sig-verify), so
            // it's safe to do up-front. Costs O(sum of SCALE-encoded kinds)
            // which is dominated by the BoundedVec encoding the user already
            // paid to land.
            let batch_digest = submit_batch_intents_payload(entries.as_slice());

            // Pre-flight: sum BuyPolicy premiums across the batch. Reject
            // overflow before mutating storage so a craft-an-overflow
            // attempt cannot leave state half-updated. The per-entry credit
            // and pool-utilization checks STILL run inside `do_submit_intent`
            // (we don't pre-check them here — letting the per-entry path run
            // keeps semantics identical to a sequence of single-call
            // `submit_intent`s, just collapsed into one origin/fee).
            let mut total_premium_ada: AdaLovelace = 0;
            for entry in entries.iter() {
                if let IntentKind::BuyPolicy { premium_ada, .. } = &entry.kind {
                    total_premium_ada = total_premium_ada
                        .checked_add(*premium_ada)
                        .ok_or(Error::<T>::SubmitBatchPremiumOverflow)?;
                }
            }

            // Atomic mutation phase. Any per-entry error from
            // `do_submit_intent` (insufficient credit, pool-cap exceeded,
            // duplicate intent, pending-batches full) bubbles up and rolls
            // back EVERY mutation in this call — including any entries that
            // already debited credits. This matches the all-or-nothing
            // semantics PR #27 established for `settle_batch_atomic`.
            let count = entries.len() as u32;
            frame_support::storage::with_storage_layer::<
                (),
                sp_runtime::DispatchError,
                _,
            >(|| {
                for entry in entries.into_iter() {
                    Self::do_submit_intent(who.clone(), entry.kind)?;
                }
                Ok(())
            })?;

            Self::deposit_event(Event::BatchIntentsSubmitted {
                submitter: who,
                count,
                batch_digest,
                total_premium_ada,
            });
            Ok(())
        }
    }

    // ---------------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------------

    impl<T: Config> Pallet<T>
    where
        BlockNumberFor<T>: Into<u64> + Copy,
        T::AccountId: Encode,
    {
        pub fn do_submit_intent(
            who: T::AccountId,
            kind: IntentKind,
        ) -> Result<IntentId, DispatchError> {
            // Pool utilization cap (Aegis v2 Q1) — only evaluated for BuyPolicy.
            if let IntentKind::BuyPolicy { premium_ada, .. } = &kind {
                // Debit credits FIRST so refund on expiry is well-defined.
                let c = Credits::<T>::get(&who);
                ensure!(c >= *premium_ada, Error::<T>::InsufficientCredit);
                let u = PoolUtilization::<T>::get();
                let nav = u.total_nav_ada.max(1); // avoid div/0 on empty pool
                let proposed = u.outstanding_coverage_ada.saturating_add(*premium_ada);
                let new_bps = ((proposed as u128).saturating_mul(10_000)
                    / nav as u128) as u32;
                ensure!(
                    new_bps <= u.cap_bps,
                    Error::<T>::PoolUtilizationExceeded
                );
                Credits::<T>::insert(&who, c - *premium_ada);
            }
            if let IntentKind::RefundCredit { amount_ada } = &kind {
                let c = Credits::<T>::get(&who);
                ensure!(c >= *amount_ada, Error::<T>::InsufficientCredit);
                Credits::<T>::insert(&who, c - *amount_ada);
            }

            let nonce = Nonces::<T>::get(&who);
            let now_u32: u32 = <frame_system::Pallet<T>>::block_number()
                .into()
                .try_into()
                .unwrap_or(u32::MAX);
            let ttl = IntentTTL::<T>::get();
            let ttl_block = now_u32.saturating_add(if ttl == 0 {
                T::DefaultIntentTTL::get()
            } else {
                ttl
            });

            let submitter_bytes = crate::account_to_bytes(&who);
            let intent_id = compute_intent_id(&submitter_bytes, nonce, &kind, now_u32);

            ensure!(
                !Intents::<T>::contains_key(intent_id),
                Error::<T>::DuplicateIntent
            );

            // Issue #6: maintain a bounded index alongside Intents so
            // get_pending_batches can avoid the O(N) Intents::iter() scan.
            // Check the capacity BEFORE any storage mutation so the TX is a
            // no-op on bound-exceeded.
            let mut pb = PendingBatches::<T>::get();
            pb.try_push(intent_id)
                .map_err(|_| Error::<T>::PendingBatchesFull)?;

            let intent = Intent {
                submitter: who.clone(),
                nonce,
                kind,
                submitted_block: now_u32,
                ttl_block,
                status: IntentStatus::Pending,
            };
            Intents::<T>::insert(intent_id, intent);
            Nonces::<T>::insert(&who, nonce.saturating_add(1));
            PendingBatches::<T>::put(pb);

            let mut queue = ExpiryQueue::<T>::get(ttl_block);
            let _ = queue.try_push(intent_id); // best-effort; if full, GC runs next block
            ExpiryQueue::<T>::insert(ttl_block, queue);

            Self::deposit_event(Event::IntentSubmitted {
                intent_id,
                submitter: who,
                nonce,
            });
            Ok(intent_id)
        }

        fn validate_fairness_proof(p: &BatchFairnessProof) -> DispatchResult {
            // pro_rata <= 10000
            ensure!(p.pro_rata_scale_bps <= 10_000, Error::<T>::InvalidFairnessProof);
            // parallel-vec invariant
            let n = p.sorted_intent_ids.len();
            ensure!(
                p.requested_amounts_ada.len() == n && p.awarded_amounts_ada.len() == n,
                Error::<T>::InvalidFairnessProof
            );
            // sorted_intent_ids strictly ascending
            for w in p.sorted_intent_ids.windows(2) {
                ensure!(
                    w[0].as_bytes() < w[1].as_bytes(),
                    Error::<T>::InvalidFairnessProof
                );
            }
            // per-entry awarded = requested * scale / 10000
            // sum awarded <= pool_balance_ada
            let mut sum_awarded: u128 = 0;
            for i in 0..n {
                let req = p.requested_amounts_ada[i] as u128;
                let award = p.awarded_amounts_ada[i] as u128;
                let expected = req.saturating_mul(p.pro_rata_scale_bps as u128) / 10_000u128;
                ensure!(award == expected, Error::<T>::InvalidFairnessProof);
                sum_awarded = sum_awarded.saturating_add(award);
            }
            ensure!(
                sum_awarded <= p.pool_balance_ada as u128,
                Error::<T>::InvalidFairnessProof
            );
            // batch_block_range must be inclusive + non-decreasing
            ensure!(
                p.batch_block_range.0 <= p.batch_block_range.1,
                Error::<T>::InvalidFairnessProof
            );
            Ok(())
        }

        /// Runtime-API helper: return up to `max_count` attested-but-not-
        /// vouchered intents with `submitted_block >= since_block`.
        ///
        /// Issue #6: this previously scanned the entire `Intents` map which
        /// was O(N_total) per keeper poll. We now iterate the
        /// `PendingBatches` index (bounded by `MaxPendingBatches`) and
        /// in-memory filter by status. Terminal transitions (settle, expire,
        /// voucher) remove their id from the index, so the iteration cost
        /// tracks real work, not historical churn.
        pub fn get_pending_batches(
            since_block: BlockNumber,
            max_count: u32,
        ) -> Vec<BatchPayload<T::AccountId>> {
            let mut out = Vec::new();
            let pb = PendingBatches::<T>::get();
            for intent_id in pb.iter() {
                let intent = match Intents::<T>::get(intent_id) {
                    Some(i) => i,
                    None => continue, // stale index entry, harmless
                };
                if intent.submitted_block < since_block {
                    continue;
                }
                if intent.status != IntentStatus::Attested {
                    continue;
                }
                let sigs = AttestationSigs::<T>::get(intent_id).unwrap_or_default();
                let sigs_static: BoundedVec<
                    (CommitteePubkey, CommitteeSig),
                    ConstU32<MAX_COMMITTEE>,
                > = BoundedVec::truncate_from(sigs.into_inner());
                out.push(BatchPayload {
                    intent,
                    intent_id: *intent_id,
                    attestation_sigs: sigs_static,
                });
                if out.len() as u32 >= max_count {
                    break;
                }
            }
            out
        }

        /// Issue #6: remove `intent_id` from the `PendingBatches` index. No-op
        /// if the id isn't present (idempotent on already-terminalized intents).
        pub(crate) fn remove_from_pending_batches(intent_id: IntentId) {
            PendingBatches::<T>::mutate(|pb| {
                if let Some(pos) = pb.iter().position(|id| id == &intent_id) {
                    pb.remove(pos);
                }
            });
        }

        /// Issue #7: verify that `signatures` contains at least the effective
        /// `MinSignerThreshold` distinct, valid sr25519 signatures over
        /// `payload`, each produced by a current committee member. The caller
        /// (`who`) itself MUST appear as one of the signers — this binds the
        /// on-chain origin to the multisig bundle so a stale bundle can't be
        /// replayed by a non-signing member.
        ///
        /// Task #174: visibility lifted to `pub` so the sibling
        /// `settle_batch_atomic` extrinsic (#177) and any future M-of-N call
        /// in the pallet share one verification routine. The function is
        /// intentionally NOT hoisted into a separate `sig_verify.rs` module
        /// because it depends on `T::CommitteeMembership`, `T::SigVerifier`,
        /// and the pallet-internal `MinSignerThreshold` storage — extracting
        /// it would only move the call surface, not the dependency graph,
        /// while creating a merge-conflict footprint for #177.
        pub fn ensure_threshold_signatures(
            payload: &[u8; 32],
            who: &T::AccountId,
            signatures: &[(CommitteePubkey, CommitteeSig)],
        ) -> DispatchResult {
            let effective_threshold = {
                let stored = MinSignerThreshold::<T>::get();
                let base = if stored == 0 {
                    T::DefaultMinSignerThreshold::get()
                } else {
                    stored
                };
                base.max(1)
            };

            // Short-circuit: must have at least `threshold` entries.
            ensure!(
                signatures.len() as u32 >= effective_threshold,
                Error::<T>::InsufficientSignatures
            );

            // Origin-binding: the caller's own pubkey must be one of the signers.
            let caller_pubkey = T::CommitteeMembership::pubkey_of(who);

            let mut seen: alloc::vec::Vec<CommitteePubkey> =
                alloc::vec::Vec::with_capacity(signatures.len());
            let mut caller_present = false;
            for (pubkey, sig) in signatures.iter() {
                // Duplicate-signer check (Issue #7: prevent "2-of-2 by one
                // caller pasting the same sig twice").
                ensure!(!seen.contains(pubkey), Error::<T>::DuplicateSigner);
                // Every signer must be a current committee member.
                let account = T::CommitteeMembership::account_of_pubkey(pubkey)
                    .ok_or(Error::<T>::SignerNotCommitteeMember)?;
                ensure!(
                    T::CommitteeMembership::is_member(&account),
                    Error::<T>::SignerNotCommitteeMember
                );
                // sr25519 verify via T::SigVerifier (pluggable so tests can
                // swap in a deterministic stub — see `MockSigVerifier` in
                // tests.rs). Signatures in prod are sr25519 per spec §3.1.
                if !T::SigVerifier::verify(pubkey, sig, payload) {
                    return Err(Error::<T>::InvalidSignature.into());
                }
                if pubkey == &caller_pubkey {
                    caller_present = true;
                }
                seen.push(*pubkey);
            }
            ensure!(caller_present, Error::<T>::InsufficientSignatures);

            // Effective count of distinct signers must meet the threshold.
            ensure!(
                seen.len() as u32 >= effective_threshold,
                Error::<T>::InsufficientSignatures
            );
            Ok(())
        }

        /// Runtime-API: full voucher for a claim id.
        pub fn get_voucher(claim_id: ClaimId) -> Option<Voucher> {
            Vouchers::<T>::get(claim_id)
        }

        /// Test helper: number of pending intents (any status). Not in public API.
        #[cfg(test)]
        pub fn intent_count() -> u32 {
            Intents::<T>::iter().count() as u32
        }
    }
}

// Re-export for downstream / Aiken-parity SDK.
pub use crate::types::{
    compute_committee_set_digest, compute_fairness_proof_digest, compute_intent_id,
    compute_voucher_digest, domain_hash, RequestVoucherEntry, SettleBatchEntry,
    SubmitIntentEntry,
};
