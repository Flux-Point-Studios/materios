//! Node-specific RPC methods: Substrate system + orinq-receipts + MOTRA.

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

    module.merge(System::new(client.clone(), pool).into_rpc())?;
    module.merge(OrinqReceipts::new(client.clone()).into_rpc())?;
    module.merge(motra_rpc::MotraRpc::new(client).into_rpc())?;

    Ok(module)
}
