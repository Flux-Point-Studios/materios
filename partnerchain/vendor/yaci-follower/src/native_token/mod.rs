use crate::db_model::{self, Block};
use crate::metrics::McFollowerMetrics;
use crate::observed_async_trait;
use crate::{DataSourceError, Result};
use derive_new::new;
use itertools::Itertools;
use sidechain_domain::*;
use sp_native_token_management::{MainChainScripts, NativeTokenManagementDataSource};
use sqlx::PgPool;
use std::sync::{Arc, Mutex};

#[derive(new)]
pub struct NativeTokenManagementDataSourceImpl {
	pub pool: PgPool,
	pub metrics_opt: Option<McFollowerMetrics>,
	security_parameter: u32,
	cache_size: u16,
	#[new(default)]
	cache: Arc<Mutex<Cache>>,
}

observed_async_trait!(
impl NativeTokenManagementDataSource for NativeTokenManagementDataSourceImpl {
	async fn get_total_native_token_transfer(
		&self,
		after_block: Option<McBlockHash>,
		to_block: McBlockHash,
		scripts: MainChainScripts,
	) -> std::result::Result<NativeTokenAmount, Box<dyn std::error::Error + Send + Sync>> {
		if let Some(after_block) = after_block {
			if after_block == to_block {
				Ok(NativeTokenAmount(0))
			} else if let Some(amount) = self.get_from_cache(&after_block, &to_block, &scripts) {
				Ok(amount)
			} else {
				let block_to_amount = self
					.get_data_to_cache(&after_block, &to_block, &scripts)
					.await?;
				let amount = block_to_amount
					.iter()
					.skip(1) // the first element is the 'after_block' which is not included in the sum
					.take_while_inclusive(|(block_hash, _)| *block_hash != to_block)
					.map(|(_, amount)| amount)
					.sum();
				if let Ok(mut cache) = self.cache.lock() {
					cache.update(block_to_amount, scripts)
				}
				Ok(NativeTokenAmount(amount))
			}
		} else {
			let amount = self
				.query_transfers_from_genesis(&to_block, &scripts)
				.await?;
			Ok(amount)
		}
	}
});

impl NativeTokenManagementDataSourceImpl {
	pub fn new_from_env(
		pool: PgPool,
		metrics_opt: Option<McFollowerMetrics>,
	) -> std::result::Result<Self, &'static str> {
		let security_parameter: u32 = std::env::var("CARDANO_SECURITY_PARAMETER")
			.ok()
			.and_then(|s| s.parse().ok())
			.ok_or("Couldn't read env variable CARDANO_SECURITY_PARAMETER as u32")?;
		Ok(Self { pool, metrics_opt, security_parameter, cache_size: 1000, cache: Default::default() })
	}

	fn get_from_cache(
		&self,
		after_block: &McBlockHash,
		to_block: &McBlockHash,
		scripts: &MainChainScripts,
	) -> Option<NativeTokenAmount> {
		let cache = self.cache.lock().ok()?;
		if cache.scripts.as_ref() == Some(scripts) {
			cache.get_sum_in_range(after_block, to_block).map(NativeTokenAmount)
		} else {
			None
		}
	}

	// invariant: to_block is always a stable block
	async fn get_data_to_cache(
		&self,
		from_block: &McBlockHash,
		to_block: &McBlockHash,
		scripts: &MainChainScripts,
	) -> Result<Vec<(McBlockHash, u128)>> {
		let (from_block_no, to_block_no, latest_block) = futures::try_join!(
			get_from_block_no(from_block, &self.pool),
			get_to_block_no(to_block, &self.pool),
			get_latest_block(&self.pool),
		)?;
		let latest_stable_block = latest_block.block_no.saturating_sub(self.security_parameter);

		let cache_to_block_no = std::cmp::min(
			latest_stable_block,
			std::cmp::max(to_block_no, from_block_no.saturating_add(self.cache_size.into())),
		);
		let transfers = self.query_db(from_block_no, cache_to_block_no, scripts).await?;
		Ok(transfers.iter().map(|t| (McBlockHash(t.block_hash), t.amount)).collect())
	}

	async fn query_db(
		&self,
		from_block: u32,
		to_block: u32,
		scripts: &MainChainScripts,
	) -> Result<Vec<db_model::BlockTokenAmount>> {
		let address = scripts.illiquid_supply_validator_address.to_string();
		Ok(db_model::get_native_token_transfers(
			&self.pool,
			from_block,
			to_block,
			&scripts.native_token_policy_id.0,
			&scripts.native_token_asset_name.0,
			&address,
		)
		.await?)
	}

	async fn query_transfers_from_genesis(
		&self,
		to_block: &McBlockHash,
		scripts: &MainChainScripts,
	) -> Result<NativeTokenAmount> {
		let to_block = get_to_block_no(to_block, &self.pool).await?;
		let address = scripts.illiquid_supply_validator_address.to_string();
		Ok(NativeTokenAmount(
			db_model::get_total_native_tokens_transfered(
				&self.pool,
				to_block,
				&scripts.native_token_policy_id.0,
				&scripts.native_token_asset_name.0,
				&address,
			)
			.await?,
		))
	}
}

async fn get_from_block_no(from_block: &McBlockHash, pool: &PgPool) -> Result<u32> {
	Ok(db_model::get_block_by_hash(pool, from_block.clone())
		.await?
		.ok_or(DataSourceError::ExpectedDataNotFound(format!(
			"Lower bound block {from_block} not found when querying for native token transfers"
		)))?
		.block_no)
}

async fn get_to_block_no(to_block: &McBlockHash, pool: &PgPool) -> Result<u32> {
	Ok(db_model::get_block_by_hash(pool, to_block.clone())
		.await?
		.ok_or(DataSourceError::ExpectedDataNotFound(format!(
			"Upper bound block {to_block} not found when querying for native token transfers"
		)))?
		.block_no)
}

async fn get_latest_block(pool: &PgPool) -> Result<Block> {
	db_model::get_latest_block_info(pool).await?.ok_or(DataSourceError::ExpectedDataNotFound(
		"The latest block not found when querying for native token transfers".to_string(),
	))
}

#[derive(Default)]
pub(crate) struct Cache {
	block_hash_to_amount: Vec<(McBlockHash, u128)>,
	pub(crate) scripts: Option<MainChainScripts>,
}

impl Cache {
	fn get_sum_in_range(&self, after: &McBlockHash, to: &McBlockHash) -> Option<u128> {
		let after_idx = self.block_hash_to_amount.iter().position(|(block, _)| block == after)?;
		let to_idx = self.block_hash_to_amount.iter().position(|(block, _)| block == to)?;
		let after_to = self.block_hash_to_amount.get((after_idx + 1)..=to_idx)?;
		Some(after_to.iter().map(|(_, amount)| amount).sum())
	}

	pub fn update(
		&mut self,
		block_hash_to_amount: Vec<(McBlockHash, u128)>,
		scripts: MainChainScripts,
	) {
		self.block_hash_to_amount = block_hash_to_amount;
		self.scripts = Some(scripts);
	}
}
