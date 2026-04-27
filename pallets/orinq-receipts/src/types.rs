use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_core::H256;

pub type ReceiptId = H256;
pub type ContentHash = H256;

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

/// Player anti-cheat signature data, stored separately from ReceiptRecord
/// to maintain backward compatibility with v1 receipt storage encoding.
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Debug, PartialEq, Eq)]
pub struct PlayerSigRecord {
    pub player_pubkey: [u8; 32],
    pub player_sig: [u8; 64],
    pub sig_type: u8,
}

/// Lightweight anchor record for SDK-submitted content (PoI traces, checkpoints).
/// Separate from ReceiptRecord — cert daemon does not process anchors.
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Debug, PartialEq, Eq)]
pub struct AnchorRecord<AccountId> {
    pub content_hash: [u8; 32],
    pub root_hash: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub created_at_millis: u64,
    pub submitter: AccountId,
}

/// Reason for slashing an attestor's bond.
///
/// Enumerates the misbehaviours governance / the runtime can cite when
/// invoking `slash_attestor`. The variant is recorded in the `Slashed`
/// event so indexers / dashboards can classify each slash.
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
