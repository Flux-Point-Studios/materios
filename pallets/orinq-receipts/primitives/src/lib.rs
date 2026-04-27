#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use parity_scale_codec::{Codec, Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_core::H256;

/// Receipt record re-exported for RPC consumers.
///
/// This is intentionally a standalone copy so that the primitives crate does not
/// depend on the pallet crate (which would create a circular dependency through
/// the runtime).
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
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

/// Status of a receipt on-chain. Used by `get_receipt_status` runtime API.
///
/// - `Pending`: receipt exists but has no availability certificate yet.
/// - `Certified`: receipt exists and has a non-zero availability certificate hash.
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub enum ReceiptStatus {
    /// Receipt exists on-chain but has not yet received an availability certificate.
    Pending,
    /// Receipt exists and has been certified (availability_cert_hash is non-zero).
    Certified,
}

sp_api::decl_runtime_apis! {
    /// Runtime API for querying orinq-receipts state.
    ///
    /// These methods are callable via RPC without submitting a transaction,
    /// making them ideal for read-only queries from SDKs and frontends.
    pub trait OrinqReceiptsApi<AccountId> where AccountId: Codec {
        /// Look up a single receipt by its unique ID.
        fn get_receipt(id: H256) -> Option<ReceiptRecord<AccountId>>;

        /// Return all receipt IDs that share the given content hash.
        fn get_receipts_by_content(content_hash: H256) -> Vec<H256>;

        /// Total number of receipts ever submitted.
        fn receipt_count() -> u64;

        /// Check whether a receipt with the given ID exists on-chain.
        ///
        /// This is a lightweight check that avoids deserializing the full
        /// receipt record. Useful for pre-flight validation before submission.
        fn receipt_exists(receipt_id: H256) -> bool;

        /// Get the status of a receipt: `None` if it does not exist,
        /// `Some(Pending)` if it exists without a certificate, or
        /// `Some(Certified)` if an availability certificate has been attached.
        fn get_receipt_status(receipt_id: H256) -> Option<ReceiptStatus>;
    }
}
