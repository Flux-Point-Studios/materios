use std::sync::Arc;

use jsonrpsee::{
    core::RpcResult,
    proc_macros::rpc,
};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::crypto::AccountId32;
use sp_runtime::traits::Block as BlockT;

pub use motra_primitives::{MotraApi as MotraRuntimeApi, MotraParams};

// ---------------------------------------------------------------------------
// RPC trait
// ---------------------------------------------------------------------------

#[rpc(server, namespace = "motra")]
pub trait MotraRpcApi {
    /// Get the MOTRA balance for an account.
    #[method(name = "getBalance")]
    fn get_balance(&self, account: AccountId32) -> RpcResult<u128>;

    /// Get current MOTRA system parameters.
    #[method(name = "getParams")]
    fn get_params(&self) -> RpcResult<MotraParams>;

    /// Estimate the MOTRA fee for a transaction with the given weight (ref_time).
    #[method(name = "estimateFee")]
    fn estimate_fee(&self, weight_ref_time: u64) -> RpcResult<u128>;

    /// Get total MOTRA ever issued.
    #[method(name = "totalIssued")]
    fn total_issued(&self) -> RpcResult<u128>;

    /// Get total MOTRA burned as fees (cumulative).
    #[method(name = "totalBurned")]
    fn total_burned(&self) -> RpcResult<u128>;

    /// Get count of transactions that failed due to insufficient MOTRA.
    #[method(name = "insufficientFailures")]
    fn insufficient_failures(&self) -> RpcResult<u64>;
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

pub struct MotraRpc<C, Block> {
    client: Arc<C>,
    _marker: std::marker::PhantomData<Block>,
}

impl<C, Block> MotraRpc<C, Block> {
    pub fn new(client: Arc<C>) -> Self {
        Self {
            client,
            _marker: Default::default(),
        }
    }
}

fn api_err(e: impl std::fmt::Display) -> jsonrpsee::types::ErrorObjectOwned {
    jsonrpsee::types::ErrorObjectOwned::owned(
        9100,
        "MOTRA runtime API error",
        Some(e.to_string()),
    )
}

impl<C, Block> MotraRpcApiServer for MotraRpc<C, Block>
where
    Block: BlockT,
    C: Send + Sync + 'static,
    C: ProvideRuntimeApi<Block>,
    C: HeaderBackend<Block>,
    C::Api: MotraRuntimeApi<Block>,
{
    fn get_balance(&self, account: AccountId32) -> RpcResult<u128> {
        let api = self.client.runtime_api();
        let best = self.client.info().best_hash;
        api.motra_balance(best, account).map_err(api_err)
    }

    fn get_params(&self) -> RpcResult<MotraParams> {
        let api = self.client.runtime_api();
        let best = self.client.info().best_hash;
        api.motra_params(best).map_err(api_err)
    }

    fn estimate_fee(&self, weight_ref_time: u64) -> RpcResult<u128> {
        let api = self.client.runtime_api();
        let best = self.client.info().best_hash;
        api.estimate_fee(best, weight_ref_time).map_err(api_err)
    }

    fn total_issued(&self) -> RpcResult<u128> {
        let api = self.client.runtime_api();
        let best = self.client.info().best_hash;
        api.total_motra_issued(best).map_err(api_err)
    }

    fn total_burned(&self) -> RpcResult<u128> {
        let api = self.client.runtime_api();
        let best = self.client.info().best_hash;
        api.total_motra_burned(best).map_err(api_err)
    }

    fn insufficient_failures(&self) -> RpcResult<u64> {
        let api = self.client.runtime_api();
        let best = self.client.info().best_hash;
        api.insufficient_motra_failures(best).map_err(api_err)
    }
}
