//! A collection of node-specific RPC methods.
//!
//! Merges Substrate system RPC with orinq-receipts + MOTRA RPCs.
//!
//! NOTE: `pallet_transaction_payment_rpc` was removed at spec 202 (HIGH #1
//! follow-up to PR #9, 2026-04-21). The pallet it depended on was deleted
//! from the runtime because it was never wired into `SignedExtra` —
//! `ChargeMotra` is the sole tx-fee path. Wallets / explorers should
//! query `MotraApi::estimate_fee` for MOTRA-denominated fee quotes.

use std::sync::Arc;

use jsonrpsee::RpcModule;
use materios_runtime::{opaque::Block, AccountId, Nonce};
use sc_transaction_pool_api::TransactionPool;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::{Error as BlockchainError, HeaderBackend, HeaderMetadata};


/// Full client dependencies.
pub struct FullDeps<C, P> {
    /// The client instance to use.
    pub client: Arc<C>,
    /// Transaction pool instance.
    pub pool: Arc<P>,
}

/// Instantiate all full RPC extensions.
pub fn create_full<C, P>(
    deps: FullDeps<C, P>,
) -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>>
where
    C: ProvideRuntimeApi<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = BlockchainError>
        + Send
        + Sync
        + 'static,
    C::Api: substrate_frame_rpc_system::AccountNonceApi<Block, AccountId, Nonce>,
    C::Api: orinq_receipts_primitives::OrinqReceiptsApi<Block, AccountId>,
    C::Api: motra_primitives::MotraApi<Block>,
    C::Api: sp_block_builder::BlockBuilder<Block>,
    P: TransactionPool + Send + Sync + 'static,
{
    use motra_rpc::MotraRpcApiServer;
    use orinq_receipts_rpc::{OrinqReceipts, OrinqReceiptsApiServer};
    use substrate_frame_rpc_system::{System, SystemApiServer};

    let mut module = RpcModule::new(());
    let FullDeps { client, pool } = deps;

    // Substrate built-ins
    module.merge(System::new(client.clone(), pool).into_rpc())?;

    // Orinq receipts
    module.merge(OrinqReceipts::new(client.clone()).into_rpc())?;

    // MOTRA capacity token
    module.merge(motra_rpc::MotraRpc::new(client).into_rpc())?;

    Ok(module)
}
