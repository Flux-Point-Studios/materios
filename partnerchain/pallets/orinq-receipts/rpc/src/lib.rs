use std::sync::Arc;

use jsonrpsee::{
    core::RpcResult,
    proc_macros::rpc,
};
use parity_scale_codec::Codec;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::H256;
use sp_runtime::traits::Block as BlockT;

pub use orinq_receipts_primitives::{
    OrinqReceiptsApi as OrinqReceiptsRuntimeApi, ReceiptRecord, ReceiptStatus,
};

// ---------------------------------------------------------------------------
// RPC trait
// ---------------------------------------------------------------------------

#[rpc(server, namespace = "orinq")]
pub trait OrinqReceiptsApi<AccountId> {
    /// Fetch a single receipt by ID.
    #[method(name = "getReceipt")]
    fn get_receipt(&self, receipt_id: H256) -> RpcResult<Option<ReceiptRecord<AccountId>>>;

    /// Return all receipt IDs sharing a content hash.
    #[method(name = "getReceiptsByContent")]
    fn get_receipts_by_content(&self, content_hash: H256) -> RpcResult<Vec<H256>>;

    /// Total number of receipts ever submitted.
    #[method(name = "getReceiptCount")]
    fn get_receipt_count(&self) -> RpcResult<u64>;

    /// Check whether a receipt with the given ID exists on-chain.
    ///
    /// This is a lightweight existence check that avoids deserializing
    /// the full receipt record. Returns `true` if the receipt exists.
    /// Useful for pre-flight validation before submission to avoid
    /// wasting MOTRA fees on a transaction that will fail with
    /// `ReceiptAlreadyExists`.
    #[method(name = "receiptExists")]
    fn receipt_exists(&self, receipt_id: H256) -> RpcResult<bool>;

    /// Get the status of a receipt on-chain.
    ///
    /// Returns `null` if the receipt does not exist, `"Pending"` if the
    /// receipt exists but has no availability certificate, or `"Certified"`
    /// if an availability certificate has been attached.
    #[method(name = "getReceiptStatus")]
    fn get_receipt_status(&self, receipt_id: H256) -> RpcResult<Option<ReceiptStatus>>;
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/// Concrete RPC handler backed by a substrate client.
pub struct OrinqReceipts<C, Block> {
    client: Arc<C>,
    _marker: std::marker::PhantomData<Block>,
}

impl<C, Block> OrinqReceipts<C, Block> {
    pub fn new(client: Arc<C>) -> Self {
        Self {
            client,
            _marker: Default::default(),
        }
    }
}

impl<C, Block, AccountId> OrinqReceiptsApiServer<AccountId> for OrinqReceipts<C, Block>
where
    Block: BlockT,
    C: Send + Sync + 'static,
    C: ProvideRuntimeApi<Block>,
    C: HeaderBackend<Block>,
    C::Api: OrinqReceiptsRuntimeApi<Block, AccountId>,
    AccountId: Codec + Send + Sync + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    fn get_receipt(&self, receipt_id: H256) -> RpcResult<Option<ReceiptRecord<AccountId>>> {
        let api = self.client.runtime_api();
        let best = self.client.info().best_hash;
        api.get_receipt(best, receipt_id)
            .map_err(|e| jsonrpsee::types::ErrorObjectOwned::owned(
                9000,
                "Runtime API error",
                Some(e.to_string()),
            ))
    }

    fn get_receipts_by_content(&self, content_hash: H256) -> RpcResult<Vec<H256>> {
        let api = self.client.runtime_api();
        let best = self.client.info().best_hash;
        api.get_receipts_by_content(best, content_hash)
            .map_err(|e| jsonrpsee::types::ErrorObjectOwned::owned(
                9001,
                "Runtime API error",
                Some(e.to_string()),
            ))
    }

    fn get_receipt_count(&self) -> RpcResult<u64> {
        let api = self.client.runtime_api();
        let best = self.client.info().best_hash;
        api.receipt_count(best)
            .map_err(|e| jsonrpsee::types::ErrorObjectOwned::owned(
                9002,
                "Runtime API error",
                Some(e.to_string()),
            ))
    }

    fn receipt_exists(&self, receipt_id: H256) -> RpcResult<bool> {
        let api = self.client.runtime_api();
        let best = self.client.info().best_hash;
        api.receipt_exists(best, receipt_id)
            .map_err(|e| jsonrpsee::types::ErrorObjectOwned::owned(
                9003,
                "Runtime API error",
                Some(e.to_string()),
            ))
    }

    fn get_receipt_status(&self, receipt_id: H256) -> RpcResult<Option<ReceiptStatus>> {
        let api = self.client.runtime_api();
        let best = self.client.info().best_hash;
        api.get_receipt_status(best, receipt_id)
            .map_err(|e| jsonrpsee::types::ErrorObjectOwned::owned(
                9004,
                "Runtime API error",
                Some(e.to_string()),
            ))
    }
}
