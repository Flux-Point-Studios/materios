use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_core::H256;

pub type ReceiptId = H256;
pub type ContentHash = H256;

// SCALE-canonical availability certificate. Every field has fixed encoded
// width (no `Compact<u32>` length prefixes), so `cert.encode()` is exactly
// 202 bytes and the byte layout is identical to the symmetric Python
// encoder. Bumping any pinned constant below is a schema change.

/// Domain separator: ASCII `"materios-availability-cert-v1"` (29 bytes)
/// right-padded to 32 bytes. The fixed-width slot avoids SCALE length-prefix
/// representational ambiguity.
pub const CERT_DOMAIN_BYTES: &[u8; 32] = b"materios-availability-cert-v1\x00\x00\x00";

/// Compile-time guarantee that `CERT_DOMAIN_BYTES` is 32 bytes.
const _: () = assert!(CERT_DOMAIN_BYTES.len() == 32);

/// Reserved for future epoch-aware cert format.
pub const CERT_EPOCH_PLACEHOLDER: u32 = 0;

/// Retention window in days. `u32::MAX` is reserved as a "retain forever"
/// sentinel.
pub const CERT_RETENTION_DAYS: u32 = 365;

/// Attestation level. `2 = HASH_VERIFIED` in the daemon-side enum.
pub const CERT_ATTESTATION_LEVEL: u8 = 2;

/// Cert schema version. `0` is reserved as a migration sentinel.
pub const CERT_SCHEMA_VERSION: u8 = 1;

/// SCALE-canonical availability certificate. Encoded length is exactly
/// 202 bytes and must match the symmetric Python encoder in
/// `operator-kit/daemon/cert_builder.py`.
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Debug, PartialEq, Eq)]
pub struct Cert {
    /// Domain separator — `CERT_DOMAIN_BYTES`. 32 raw bytes, no length prefix.
    pub domain: [u8; 32],
    /// Chain genesis block hash. Runtime sources from
    /// `frame_system::Pallet::<T>::block_hash(0)`; daemon RPC mirrors via
    /// `chain_getBlockHash[0]`. Must agree.
    pub chain_id: [u8; 32],
    /// Receipt id (H256.0).
    pub receipt_id: [u8; 32],
    /// Content hash from `ReceiptRecord.content_hash`.
    pub content_hash: [u8; 32],
    /// Canonical chunk-Merkle root from `ReceiptRecord.base_root_sha256`.
    pub base_root: [u8; 32],
    /// Storage locator from `ReceiptRecord.storage_locator_hash`.
    pub storage_locator: [u8; 32],
    /// Pinned epoch placeholder (`CERT_EPOCH_PLACEHOLDER`).
    pub epoch: u32,
    /// Pinned retention window (`CERT_RETENTION_DAYS`).
    pub retention_days: u32,
    /// Pinned attestation level (`CERT_ATTESTATION_LEVEL`).
    pub attestation_level: u8,
    /// Pinned cert schema version (`CERT_SCHEMA_VERSION`).
    pub schema_version: u8,
}

#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Debug, PartialEq, Eq)]
pub struct ReceiptRecord<AccountId> {
    pub schema_hash: [u8; 32],
    pub content_hash: [u8; 32],
    pub base_root_sha256: [u8; 32],
    pub zk_root_poseidon: Option<[u8; 32]>,
    pub poseidon_params_hash: Option<[u8; 32]>,
    pub base_manifest_hash: [u8; 32],
    pub safety_manifest_hash: [u8; 32],
    pub monitor_config_hash: [u8; 32],
    pub attestation_evidence_hash: [u8; 32],
    pub storage_locator_hash: [u8; 32],
    pub availability_cert_hash: [u8; 32],
    pub created_at_millis: u64,
    pub submitter: AccountId,
}

/// Player anti-cheat signature data, stored separately from ReceiptRecord.
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Debug, PartialEq, Eq)]
pub struct PlayerSigRecord {
    pub player_pubkey: [u8; 32],
    pub player_sig: [u8; 64],
    pub sig_type: u8,
}

/// Lightweight anchor record for SDK-submitted content. Cert daemon does
/// not process anchors.
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Debug, PartialEq, Eq)]
pub struct AnchorRecord<AccountId> {
    pub content_hash: [u8; 32],
    pub root_hash: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub created_at_millis: u64,
    pub submitter: AccountId,
}

/// Reason for slashing an attestor's bond. The variant is recorded in the
/// `Slashed` event so indexers can classify each slash.
#[derive(Clone, Copy, Encode, Decode, TypeInfo, MaxEncodedLen, Debug, PartialEq, Eq)]
pub enum SlashReason {
    /// The attestor produced an invalid signature for an availability
    /// certificate (cryptographic failure or forged material).
    InvalidSignature,
    /// The attestor was unreachable / did not attest during a window in
    /// which they were expected to.
    Unavailability,
    /// Double-signing: the attestor signed two conflicting certificates
    /// for the same receipt.
    DoubleSign,
    /// Generic governance-authored slash — reason encoded off-chain.
    Governance,
}
