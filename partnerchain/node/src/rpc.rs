//! A collection of node-specific RPC methods.
//!
//! Merges Substrate system + transaction-payment RPCs with the orinq-receipts RPC.

use std::sync::Arc;

use jsonrpsee::RpcModule;
use materios_runtime::{opaque::Block, AccountId, Balance, Nonce};
use sc_transaction_pool_api::TransactionPool;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::{Error as BlockchainError, HeaderBackend, HeaderMetadata};
use sp_runtime::traits::Block as BlockT;

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
    C::Api: pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>,
    C::Api: orinq_receipts_primitives::OrinqReceiptsApi<Block, AccountId>,
    C::Api: motra_primitives::MotraApi<Block>,
    C::Api: sp_block_builder::BlockBuilder<Block>,
    P: TransactionPool + Send + Sync + 'static,
{
    use motra_rpc::MotraRpcApiServer;
    use orinq_receipts_rpc::{OrinqReceipts, OrinqReceiptsApiServer};
    use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApiServer};
    use substrate_frame_rpc_system::{System, SystemApiServer};

    let mut module = RpcModule::new(());
    let FullDeps { client, pool } = deps;

    // Substrate built-ins
    module.merge(System::new(client.clone(), pool).into_rpc())?;
    module.merge(TransactionPayment::new(client.clone()).into_rpc())?;

    // Orinq receipts
    module.merge(OrinqReceipts::new(client.clone()).into_rpc())?;

    // MOTRA capacity token
    module.merge(motra_rpc::MotraRpc::new(client).into_rpc())?;

    Ok(module)
}
