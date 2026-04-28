//! Shared type definitions for `pallet_intent_settlement`.
//!
//! The canonical hash pre-images and byte layouts here are authoritative per
//! `docs/spec-v1.md §1`. The Aiken validator mirror (Team B) must treat these
//! SCALE-encoded bytes as opaque and reproduce the exact same Blake2b-256
//! domain-tagged hashes.

use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::{pallet_prelude::*, BoundedVec};
use scale_info::TypeInfo;
use sp_core::H256;
use sp_runtime::RuntimeDebug;

pub use parity_scale_codec as codec;

// ---------------------------------------------------------------------------
// Primitive aliases — see spec §1.3
// ---------------------------------------------------------------------------

pub type IntentId = H256;
pub type PolicyId = H256;
pub type ClaimId = H256;
pub type BlockNumber = u32;
pub type Nonce = u64;
pub type AdaLovelace = u64;
pub type SlotNumber = u64;
pub type CommitteePubkey = [u8; 32];
pub type CommitteeSig = [u8; 64];

// ---------------------------------------------------------------------------
// Bounded constants (spec §1.4, §1.6, §1.7)
// ---------------------------------------------------------------------------

/// Max length of a bech32 Cardano address (mainnet bech32 is up to 103 bytes
/// stringified; 114 gives headroom for future address schemes).
pub const MAX_CARDANO_ADDR: u32 = 114;

/// Max bytes of opaque oracle evidence attached to a `RequestPayout` intent.
pub const MAX_ORACLE_EVIDENCE: u32 = 512;

/// Max claims per batch fairness proof / per voucher.
pub const MAX_BATCH: u32 = 256;

/// Task #177: max claims settled in a single `settle_batch_atomic` call.
/// Sized so a full batch + a committee signature bundle fit comfortably
/// within a single block's normal-class extrinsic budget. 256 entries =
/// 256 * 65B = ~16KB raw payload, well below the 5MB proof_size limit.
pub const MAX_SETTLE_BATCH: u32 = 256;

/// Task #211: max intents attested in a single `attest_batch_intents` call.
/// Mirrors MAX_SETTLE_BATCH. The attest stage is the per-epoch hot path;
/// pre-spec-207 a 3-of-3 committee posted 3*N attest_intent extrinsics per
/// batch — at N=256 that's 768 sig-verify rounds per epoch. Post-spec-207
/// it collapses to ONE M-of-N sig verify per attest_batch_intents call —
/// the largest single-pallet TPS unlock in the v5.1 plan.
pub const MAX_ATTEST_BATCH: u32 = 256;

/// Task #212: max vouchers issued in a single `request_batch_vouchers`
/// call. Each entry holds a `Voucher` + `BatchFairnessProof`, both of
/// which cap their internal slices at MAX_BATCH=256.
pub const MAX_VOUCHER_BATCH: u32 = 256;

/// Task #210: max intents submitted in a single `submit_batch_intents` call.
/// Mirror MAX_SETTLE_BATCH so the user-side burst stage matches the
/// committee-settle stage. Sized for the largest realistic intent
/// (BuyPolicy with 114B beneficiary addr + 8B premium ~200B SCALE encoded);
/// 256 * 200B ~50KB worst-case extrinsic payload, well below the 5MB
/// proof_size limit.
pub const MAX_SUBMIT_BATCH: u32 = 256;

/// Max committee signatures per voucher (spec §3.1 uses `MaxCommittee=32`).
pub const MAX_COMMITTEE: u32 = 32;

/// Max intents that may expire in a single block (TTL sweep bound).
pub const MAX_EXPIRE_PER_BLOCK: u32 = 256;

/// Task #245: max entries the fallback `PendingBatches` sweep visits per
/// block. Independent of `MAX_EXPIRE_PER_BLOCK` so the fast path
/// (`ExpiryQueue::take`) can stay at 256 while the slow rescue path stays
/// cheap (one storage read per inspected entry, ≤ this many writes for
/// terminalized intents). Sized so a full `MaxPendingBatches=10_000` index
/// is fully traversed in ≤ 157 blocks (~16 min at 6s).
pub const FALLBACK_SWEEP_PER_BLOCK: u32 = 64;

// ---------------------------------------------------------------------------
// Domain tags (spec §1.1)
// ---------------------------------------------------------------------------

pub const TAG_INTT: &[u8; 4] = b"INTT";
pub const TAG_POLY: &[u8; 4] = b"POLY";
pub const TAG_CLAM: &[u8; 4] = b"CLAM";
pub const TAG_VCHR: &[u8; 4] = b"VCHR";
pub const TAG_BFPR: &[u8; 4] = b"BFPR";
pub const TAG_CMTT: &[u8; 4] = b"CMTT";

/// Domain-tagged Blake2b-256 hash.
///
/// ```text
/// out = blake2_256(tag || body)
/// ```
pub fn domain_hash(tag: [u8; 4], body: &[u8]) -> [u8; 32] {
    let mut buf = sp_std::vec::Vec::with_capacity(4 + body.len());
    buf.extend_from_slice(&tag);
    buf.extend_from_slice(body);
    sp_core::hashing::blake2_256(&buf)
}

// ---------------------------------------------------------------------------
// Intent
// ---------------------------------------------------------------------------

#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, PartialEq, Eq)]
pub enum IntentKind {
    /// User wants to open a new policy with paid premium.
    BuyPolicy {
        product_id: H256,
        strike: u64,
        term_slots: u32,
        premium_ada: AdaLovelace,
        beneficiary_cardano_addr: BoundedVec<u8, ConstU32<MAX_CARDANO_ADDR>>,
    },
    /// User wants to request a payout on an existing policy.
    RequestPayout {
        policy_id: PolicyId,
        oracle_evidence: BoundedVec<u8, ConstU32<MAX_ORACLE_EVIDENCE>>,
    },
    /// User wants their pre-funded credit back.
    RefundCredit { amount_ada: AdaLovelace },
}

#[derive(
    Clone, Copy, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, PartialEq, Eq,
)]
pub enum IntentStatus {
    Pending = 0,
    Attested = 1,
    Vouchered = 2,
    Settled = 3,
    Expired = 4,
    Refunded = 5,
}

#[derive(
    Clone, Copy, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, PartialEq, Eq,
)]
pub enum ExpiryReason {
    /// Expired due to `ttl_block` elapsing.
    TTL = 0,
    /// Expired via keeper-reported Cardano-side `Expire` redeemer mirror.
    PolicyExpiredOnCardano = 1,
    /// Task #245: TTL elapsed but the intent was not in `ExpiryQueue` at
    /// sweep time (the per-block bucket was full at submit time and the
    /// id was silently dropped). Picked up by the fallback `PendingBatches`
    /// scan. Functionally identical to `TTL`, distinct variant so indexers
    /// can monitor for capacity-overflow incidents.
    TTLFallback = 2,
}

/// The on-chain intent record. `submitter/nonce/kind/submitted_block` are
/// hashed into the IntentId; `ttl_block/status` evolve with state.
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, PartialEq, Eq)]
pub struct Intent<AccountId> {
    pub submitter: AccountId,
    pub nonce: Nonce,
    pub kind: IntentKind,
    pub submitted_block: BlockNumber,
    pub ttl_block: BlockNumber,
    pub status: IntentStatus,
}

// ---------------------------------------------------------------------------
// Claim / Voucher / Fairness Proof
// ---------------------------------------------------------------------------

#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, PartialEq, Eq)]
pub struct Claim {
    pub intent_id: IntentId,
    pub policy_id: PolicyId,
    pub amount_ada: AdaLovelace,
    pub issued_block: BlockNumber,
    pub expiry_slot_cardano: SlotNumber,
    pub settled: bool,
    pub settled_direct: bool,
    pub cardano_tx_hash: [u8; 32],
}

#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, PartialEq, Eq)]
pub struct BatchFairnessProof {
    pub batch_block_range: (BlockNumber, BlockNumber),
    pub sorted_intent_ids: BoundedVec<IntentId, ConstU32<MAX_BATCH>>,
    pub requested_amounts_ada: BoundedVec<AdaLovelace, ConstU32<MAX_BATCH>>,
    pub pool_balance_ada: AdaLovelace,
    pub pro_rata_scale_bps: u32,
    pub awarded_amounts_ada: BoundedVec<AdaLovelace, ConstU32<MAX_BATCH>>,
}

#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, PartialEq, Eq)]
pub struct Voucher {
    pub claim_id: ClaimId,
    pub policy_id: PolicyId,
    pub beneficiary_cardano_addr: BoundedVec<u8, ConstU32<MAX_CARDANO_ADDR>>,
    pub amount_ada: AdaLovelace,
    pub batch_fairness_proof_digest: [u8; 32],
    pub issued_block: BlockNumber,
    pub expiry_slot_cardano: SlotNumber,
    pub committee_sigs:
        BoundedVec<(CommitteePubkey, CommitteeSig), ConstU32<MAX_COMMITTEE>>,
}

// ---------------------------------------------------------------------------
// Pool Utilization (Aegis v2 decision Q1)
// ---------------------------------------------------------------------------

/// Public commitment: hard cap on outstanding coverage vs pool NAV.
/// Defaults per spec v2 decisions: target 5000 bps (50%), cap 7500 bps (75%).
#[derive(
    Clone, Copy, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, PartialEq, Eq,
    serde::Serialize, serde::Deserialize,
)]
pub struct PoolUtilizationParams {
    pub target_bps: u32,
    pub cap_bps: u32,
    pub total_nav_ada: AdaLovelace,
    pub outstanding_coverage_ada: AdaLovelace,
}

impl Default for PoolUtilizationParams {
    fn default() -> Self {
        Self {
            target_bps: 5000,
            cap_bps: 7500,
            total_nav_ada: 0,
            outstanding_coverage_ada: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Runtime-API payloads
// ---------------------------------------------------------------------------

/// Keeper-facing payload. Returned from the runtime-API; the committee-sig
/// bundle uses a static `ConstU32<32>` bound so the API type is runtime-agnostic
/// (the pallet's internal storage uses `T::MaxCommittee` which is `= 32` on
/// Materios per spec §3.1).
#[derive(Clone, Encode, Decode, TypeInfo, RuntimeDebug, PartialEq, Eq)]
pub struct BatchPayload<AccountId> {
    pub intent: Intent<AccountId>,
    pub intent_id: IntentId,
    pub attestation_sigs:
        BoundedVec<(CommitteePubkey, CommitteeSig), ConstU32<MAX_COMMITTEE>>,
}

// ---------------------------------------------------------------------------
// Canonical pre-image helpers
// ---------------------------------------------------------------------------

/// Canonical IntentId pre-image:
/// `blake2_256(b"INTT" || submitter (32B) || nonce (LE u64) || scale(kind) || submitted_block (LE u32))`
pub fn compute_intent_id(
    submitter_bytes: &[u8; 32],
    nonce: Nonce,
    kind: &IntentKind,
    submitted_block: BlockNumber,
) -> IntentId {
    let mut body = sp_std::vec::Vec::new();
    body.extend_from_slice(submitter_bytes);
    body.extend_from_slice(&nonce.to_le_bytes());
    body.extend_from_slice(&kind.encode());
    body.extend_from_slice(&submitted_block.to_le_bytes());
    H256::from(domain_hash(*TAG_INTT, &body))
}

/// Canonical BatchFairnessProof digest:
/// `blake2_256(b"BFPR" || scale(proof))`
pub fn compute_fairness_proof_digest(proof: &BatchFairnessProof) -> [u8; 32] {
    domain_hash(*TAG_BFPR, &proof.encode())
}

/// Canonical Voucher digest (the object committee members ed25519-sign):
///
/// `blake2_256(b"VCHR" || claim_id || policy_id || beneficiary_bytes
///            || amount (LE u64) || bfpr_digest || issued_block (LE u32)
///            || expiry_slot (LE u64))`
///
/// NOTE: SCALE-encodes `beneficiary_cardano_addr` via its compact-length
/// prefix + raw bytes so an Aiken mirror can reconstruct with
/// `cbor.serialise` on an equivalent `ByteArray`.
pub fn compute_voucher_digest(v: &Voucher) -> [u8; 32] {
    let mut body = sp_std::vec::Vec::new();
    body.extend_from_slice(v.claim_id.as_bytes());
    body.extend_from_slice(v.policy_id.as_bytes());
    // encode bech32 address as scale bytes (length-prefixed) so both sides agree
    body.extend_from_slice(&v.beneficiary_cardano_addr.encode());
    body.extend_from_slice(&v.amount_ada.to_le_bytes());
    body.extend_from_slice(&v.batch_fairness_proof_digest);
    body.extend_from_slice(&v.issued_block.to_le_bytes());
    body.extend_from_slice(&v.expiry_slot_cardano.to_le_bytes());
    domain_hash(*TAG_VCHR, &body)
}

/// Canonical committee-set digest (for Cardano mirror ext field).
/// `blake2_256(b"CMTT" || scale_vec(pubkeys) || threshold (LE u32))`
pub fn compute_committee_set_digest(pubkeys: &[CommitteePubkey], threshold: u32) -> [u8; 32] {
    let mut body = sp_std::vec::Vec::new();
    body.extend_from_slice(&pubkeys.to_vec().encode());
    body.extend_from_slice(&threshold.to_le_bytes());
    domain_hash(*TAG_CMTT, &body)
}

// ---------------------------------------------------------------------------
// Task #177: SettleBatchEntry — single entry in a `settle_batch_atomic` call
// ---------------------------------------------------------------------------

/// One claim's worth of settlement data inside a `settle_batch_atomic` batch.
///
/// All three fields are chain-derivable — see `feedback_mofn_hash_determinism`
/// for why no operator-local state appears here.
#[derive(
    Clone, Copy, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, PartialEq, Eq,
)]
pub struct SettleBatchEntry {
    pub claim_id: ClaimId,
    pub cardano_tx_hash: [u8; 32],
    pub settled_direct: bool,
}

// ---------------------------------------------------------------------------
// Task #212: RequestVoucherEntry — single entry in a `request_batch_vouchers`
// call. Same per-claim payload as the spec-206 single-call `request_voucher`
// (PR #26), packaged so a committee can mint N vouchers under ONE M-of-N
// signature bundle.
// ---------------------------------------------------------------------------

/// One voucher's worth of mint data inside a `request_batch_vouchers`
/// batch. The pallet validates each entry's fairness-proof + digest binding
/// + issues the voucher, all under ONE batch sig-verify pass — pre-spec-207
/// each voucher mint required its own M-of-N round.
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, PartialEq, Eq)]
pub struct RequestVoucherEntry {
    pub claim_id: ClaimId,
    pub intent_id: IntentId,
    pub voucher: Voucher,
    pub fairness_proof: BatchFairnessProof,
}

// ---------------------------------------------------------------------------
// Task #210: SubmitIntentEntry — single entry in a `submit_batch_intents` call
// ---------------------------------------------------------------------------

/// One user intent inside a `submit_batch_intents` batch. Carries the same
/// payload as a single `submit_intent(kind)` call, minus the user origin —
/// the batch's signed origin is the submitter for every entry. Pre-spec-207
/// a 256-intent burst required 256 extrinsics; post-spec-207 it's one
/// extrinsic with a single fee-payer + a single all-or-nothing semantic
/// (atomic via `with_storage_layer` so no partial debit on a mid-batch
/// rejection).
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, PartialEq, Eq)]
pub struct SubmitIntentEntry {
    pub kind: IntentKind,
}
