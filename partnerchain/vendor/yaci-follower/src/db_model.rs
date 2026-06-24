//! Row types and queries against the yaci-store 3.0.0-beta3 Postgres schema.
//!
//! Differences from the cardano-db-sync schema that this module bridges:
//! - hashes (`block.hash`, `address_utxo.tx_hash`, `datum.hash`) are lowercase
//!   hex `varchar`, not `bytea`.
//! - datum CBOR (`address_utxo.inline_datum`, `datum.datum`) is hex `text`, not
//!   a JSONB `value`. Decoded via [`crate::db_datum::DbDatum`].
//! - block time (`block.block_time`) is a unix-seconds `bigint`, not a timestamp.
//! - stake is keyed on `epoch_stake.active_epoch` (== db-sync `epoch_no`), NOT
//!   the raw `epoch` column (which is `active_epoch - 2`). Filtering `epoch` is
//!   the #1 footgun and is off by two Cardano epochs.

use crate::db_datum::DbDatum;
use crate::SqlxError;
use cardano_serialization_lib::PlutusData;
use chrono::{DateTime, NaiveDateTime};
#[cfg(any(all(feature = "candidate-source", not(feature = "mithril-stake")), feature = "native-token"))]
use num_traits::ToPrimitive;
use sidechain_domain::*;
use sqlx::{Pool, Postgres};
use std::str::FromStr;

/// Parses a lowercase-hex hash string from yaci-store into a fixed 32-byte array.
pub(crate) fn parse_hash32(hex_hash: &str) -> Result<[u8; 32], String> {
	let bytes = hex::decode(hex_hash).map_err(|e| format!("invalid hex hash: {e}"))?;
	bytes
		.try_into()
		.map_err(|v: Vec<u8>| format!("expected 32-byte hash, got {} bytes", v.len()))
}

/// Parses a lowercase-hex pool-id / key-hash string into a fixed 28-byte array.
/// Used by the yaci `epoch_stake` stake path; the `mithril-stake` path decodes
/// the pool hash from bech32 instead (see [`crate::mithril_stake`]).
#[cfg(any(all(feature = "candidate-source", not(feature = "mithril-stake")), test))]
pub(crate) fn parse_hash28(hex_hash: &str) -> Result<[u8; 28], String> {
	let bytes = hex::decode(hex_hash).map_err(|e| format!("invalid hex hash: {e}"))?;
	bytes
		.try_into()
		.map_err(|v: Vec<u8>| format!("expected 28-byte hash, got {} bytes", v.len()))
}

/// Converts a yaci `block_time` (unix seconds, `bigint`) into a `NaiveDateTime`.
pub(crate) fn block_time_to_naive(unix_seconds: i64) -> Result<NaiveDateTime, String> {
	DateTime::from_timestamp(unix_seconds, 0)
		.map(|dt| dt.naive_utc())
		.ok_or_else(|| format!("block_time out of range: {unix_seconds}"))
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Block {
	pub block_no: u32,
	pub hash: [u8; 32],
	pub epoch_no: u32,
	pub slot_no: u64,
	pub time: NaiveDateTime,
}

#[cfg(feature = "block-source")]
impl From<Block> for MainchainBlock {
	fn from(b: Block) -> Self {
		MainchainBlock {
			number: McBlockNumber(b.block_no),
			hash: McBlockHash(b.hash),
			epoch: McEpochNumber(b.epoch_no),
			slot: McSlotNumber(b.slot_no),
			timestamp: b.time.and_utc().timestamp().try_into().expect("i64 timestamp is valid u64"),
		}
	}
}

/// Raw row as read from the yaci `block` table (hex hash, unix-seconds time).
#[derive(Debug, Clone, sqlx::FromRow)]
struct BlockRow {
	number: i64,
	hash: String,
	epoch: i32,
	slot: i64,
	block_time: i64,
}

impl TryFrom<BlockRow> for Block {
	type Error = sqlx::Error;
	fn try_from(r: BlockRow) -> Result<Self, Self::Error> {
		Ok(Block {
			block_no: r.number.try_into().map_err(decode_err)?,
			hash: parse_hash32(&r.hash).map_err(decode_err)?,
			epoch_no: r.epoch.try_into().map_err(decode_err)?,
			slot_no: r.slot.try_into().map_err(decode_err)?,
			time: block_time_to_naive(r.block_time).map_err(decode_err)?,
		})
	}
}

fn decode_err<E: std::fmt::Display>(e: E) -> sqlx::Error {
	sqlx::Error::Decode(e.to_string().into())
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct StakePoolEntry {
	pub pool_hash: [u8; 28],
	pub stake: u64,
}

#[cfg(all(feature = "candidate-source", not(feature = "mithril-stake")))]
#[derive(Debug, Clone, sqlx::FromRow)]
struct StakePoolRow {
	pool_id: String,
	stake: sqlx::types::BigDecimal,
}

#[cfg(all(feature = "candidate-source", not(feature = "mithril-stake")))]
impl TryFrom<StakePoolRow> for StakePoolEntry {
	type Error = sqlx::Error;
	fn try_from(r: StakePoolRow) -> Result<Self, Self::Error> {
		Ok(StakePoolEntry {
			pool_hash: parse_hash28(&r.pool_id).map_err(decode_err)?,
			stake: r.stake.to_u64().ok_or_else(|| decode_err("stake is always u64"))?,
		})
	}
}

#[derive(Debug, Clone)]
pub(crate) struct MainchainTxOutput {
	pub utxo_id: UtxoId,
	pub tx_block_no: u32,
	pub tx_slot_no: u64,
	pub tx_epoch_no: u32,
	pub tx_index_in_block: u32,
	pub datum: Option<PlutusData>,
	pub tx_inputs: Vec<UtxoId>,
}

/// Raw UTxO row from `address_utxo` joined to `block` and `transaction`.
/// `inline_datum` is hex CBOR text; `tx_inputs` is the set of inputs that
/// funded the producing transaction, as `txhash#index` strings.
#[derive(Debug, Clone, sqlx::FromRow)]
struct MainchainTxOutputRow {
	tx_hash: String,
	output_index: i16,
	tx_block_no: i64,
	tx_slot_no: i64,
	tx_epoch_no: i32,
	tx_index_in_block: i32,
	inline_datum: Option<String>,
	tx_inputs: Vec<String>,
}

impl TryFrom<MainchainTxOutputRow> for MainchainTxOutput {
	type Error = sqlx::Error;
	fn try_from(r: MainchainTxOutputRow) -> Result<Self, Self::Error> {
		let datum = match r.inline_datum {
			Some(hex_cbor) => Some(DbDatum::from_hex_cbor(&hex_cbor).map_err(sqlx::Error::Decode)?.0),
			None => None,
		};
		let tx_inputs: Result<Vec<UtxoId>, _> =
			r.tx_inputs.into_iter().filter(|s| !s.is_empty()).map(|i| UtxoId::from_str(&i)).collect();
		let tx_inputs = tx_inputs.map_err(decode_err)?;
		Ok(MainchainTxOutput {
			utxo_id: UtxoId {
				tx_hash: McTxHash(parse_hash32(&r.tx_hash).map_err(decode_err)?),
				index: UtxoIndex(r.output_index.try_into().map_err(decode_err)?),
			},
			tx_block_no: r.tx_block_no.try_into().map_err(decode_err)?,
			tx_slot_no: r.tx_slot_no.try_into().map_err(decode_err)?,
			tx_epoch_no: r.tx_epoch_no.try_into().map_err(decode_err)?,
			tx_index_in_block: r.tx_index_in_block.try_into().map_err(decode_err)?,
			datum,
			tx_inputs,
		})
	}
}

#[derive(Debug, Clone)]
pub(crate) struct TokenTxOutput {
	pub datum: Option<PlutusData>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct TokenTxOutputRow {
	inline_datum: Option<String>,
}

impl TryFrom<TokenTxOutputRow> for TokenTxOutput {
	type Error = sqlx::Error;
	fn try_from(r: TokenTxOutputRow) -> Result<Self, Self::Error> {
		let datum = match r.inline_datum {
			Some(hex_cbor) => Some(DbDatum::from_hex_cbor(&hex_cbor).map_err(sqlx::Error::Decode)?.0),
			None => None,
		};
		Ok(TokenTxOutput { datum })
	}
}

// ----------------------------------------------------------------------------
// Queries
// ----------------------------------------------------------------------------

#[cfg(any(feature = "block-source", feature = "native-token"))]
pub(crate) async fn get_latest_block_info(
	pool: &Pool<Postgres>,
) -> Result<Option<Block>, SqlxError> {
	let row = sqlx::query_as::<_, BlockRow>(
		"SELECT number, hash, epoch, slot, block_time
		 FROM block
		 WHERE number IS NOT NULL
		 ORDER BY number DESC
		 LIMIT 1",
	)
	.fetch_optional(pool)
	.await?;
	Ok(row.map(Block::try_from).transpose()?)
}

#[cfg(feature = "block-source")]
pub(crate) async fn get_blocks_by_numbers(
	pool: &Pool<Postgres>,
	from: u32,
	to: u32,
) -> Result<Vec<Block>, SqlxError> {
	let rows = sqlx::query_as::<_, BlockRow>(
		"SELECT number, hash, epoch, slot, block_time
		 FROM block
		 WHERE number >= $1 AND number <= $2
		 ORDER BY number ASC",
	)
	.bind(from as i64)
	.bind(to as i64)
	.fetch_all(pool)
	.await?;
	Ok(rows.into_iter().map(Block::try_from).collect::<Result<_, _>>()?)
}

#[cfg(feature = "block-source")]
pub(crate) async fn get_highest_block(
	pool: &Pool<Postgres>,
	max_block_number: u32,
	min_time: NaiveDateTime,
	max_time: NaiveDateTime,
) -> Result<Option<Block>, SqlxError> {
	let min_ts = min_time.and_utc().timestamp();
	let max_ts = max_time.and_utc().timestamp();
	let row = sqlx::query_as::<_, BlockRow>(
		"SELECT number, hash, epoch, slot, block_time
		 FROM block
		 WHERE number <= $1 AND block_time >= $2 AND block_time <= $3
		 ORDER BY number DESC
		 LIMIT 1",
	)
	.bind(max_block_number as i64)
	.bind(min_ts)
	.bind(max_ts)
	.fetch_optional(pool)
	.await?;
	Ok(row.map(Block::try_from).transpose()?)
}

#[cfg(any(feature = "block-source", feature = "native-token"))]
pub(crate) async fn get_block_by_hash(
	pool: &Pool<Postgres>,
	hash: McBlockHash,
) -> Result<Option<Block>, SqlxError> {
	let row = sqlx::query_as::<_, BlockRow>(
		"SELECT number, hash, epoch, slot, block_time FROM block WHERE hash = $1",
	)
	.bind(hex::encode(hash.0))
	.fetch_optional(pool)
	.await?;
	Ok(row.map(Block::try_from).transpose()?)
}

#[cfg(feature = "candidate-source")]
pub(crate) async fn get_latest_block_for_epoch(
	pool: &Pool<Postgres>,
	epoch: u32,
) -> Result<Option<Block>, SqlxError> {
	let row = sqlx::query_as::<_, BlockRow>(
		"SELECT number, hash, epoch, slot, block_time
		 FROM block
		 WHERE epoch <= $1 AND slot IS NOT NULL AND number IS NOT NULL
		 ORDER BY slot DESC
		 LIMIT 1",
	)
	.bind(epoch as i32)
	.fetch_optional(pool)
	.await?;
	Ok(row.map(Block::try_from).transpose()?)
}

/// Latest stable epoch: one less than the epoch of the highest stable block
/// (HSB), where HSB = tip block number minus the security parameter. Mirrors
/// db-sync's `get_latest_stable_epoch`.
#[cfg(feature = "candidate-source")]
pub(crate) async fn get_latest_stable_epoch(
	pool: &Pool<Postgres>,
	security_parameter: u32,
) -> Result<Option<u32>, SqlxError> {
	let row: Option<(i32,)> = sqlx::query_as(
		"SELECT stable_block.epoch - 1 AS epoch_no
		 FROM block
		 INNER JOIN block AS stable_block ON block.number - $1 = stable_block.number
		 WHERE block.number IS NOT NULL
		 ORDER BY block.number DESC
		 LIMIT 1",
	)
	.bind(security_parameter as i64)
	.fetch_optional(pool)
	.await?;
	Ok(row.map(|(e,)| e as u32))
}

/// Stake distribution for an epoch. CRITICAL: filters on `active_epoch`, which
/// equals db-sync's `epoch_no` (active_epoch = epoch + 2). The pool id is the
/// raw 28-byte pool hash as lowercase hex.
///
/// TRUSTLESS UPGRADE SEAM (#370): with `mithril-stake` enabled, the body reads a
/// Mithril-certified per-pool stake distribution instead of this yaci query —
/// Mithril certifies exactly this `(pool_hash, stake)` Ariadne snapshot, the one
/// follower input otherwise only as trustworthy as the local yaci-store. yaci
/// stake is byte-identical to db-sync (and to Mithril, proven per-pool); Mithril
/// removes the trust-in-the-local-DB assumption and lets the deployment drop the
/// heaviest yaci module (`adapot`/`epoch_stake`). The default path keeps the
/// yaci query so the seam is opt-in.
#[cfg(all(feature = "candidate-source", not(feature = "mithril-stake")))]
pub(crate) async fn get_stake_distribution(
	pool: &Pool<Postgres>,
	active_epoch: u32,
) -> Result<Vec<StakePoolEntry>, SqlxError> {
	let rows = sqlx::query_as::<_, StakePoolRow>(
		"SELECT pool_id, SUM(amount) AS stake
		 FROM epoch_stake
		 WHERE active_epoch = $1 AND pool_id IS NOT NULL
		 GROUP BY pool_id",
	)
	.bind(active_epoch as i32)
	.fetch_all(pool)
	.await?;
	Ok(rows.into_iter().map(StakePoolEntry::try_from).collect::<Result<_, _>>()?)
}

/// Mithril-stake variant of the seam. The yaci Postgres `pool` is intentionally
/// unused — the whole point is to stop trusting the local DB for stake. The
/// per-epoch fetch + certificate verification + cache lives in
/// [`crate::mithril_stake`]; the blocking `mithril-client` invocation runs on a
/// blocking thread so the async runtime is not stalled.
#[cfg(all(feature = "candidate-source", feature = "mithril-stake"))]
pub(crate) async fn get_stake_distribution(
	_pool: &Pool<Postgres>,
	active_epoch: u32,
) -> Result<Vec<StakePoolEntry>, SqlxError> {
	use std::sync::OnceLock;
	static CACHE: OnceLock<crate::mithril_stake::MithrilStakeCache> = OnceLock::new();
	let cache = CACHE.get_or_init(crate::mithril_stake::MithrilStakeCache::default);

	if let Some(cached) = cache.get(active_epoch) {
		return Ok(cached);
	}

	let result = tokio::task::spawn_blocking(move || {
		let config = crate::mithril_stake::MithrilConfig::from_env()?;
		let scratch = crate::mithril_stake::MithrilStakeCache::default();
		crate::mithril_stake::get_stake_distribution_mithril(&config, &scratch, active_epoch)
	})
	.await
	.map_err(|e| sqlx::Error::Decode(format!("mithril stake task join: {e}").into()))?
	.map_err(|e| sqlx::Error::Decode(format!("mithril stake: {e}").into()))?;

	cache.put(active_epoch, result.clone());
	Ok(result)
}

/// Epoch nonce, read from yaci `epoch_nonce.nonce` (hex `varchar`). Proven
/// byte-identical to db-sync `epoch_param.nonce` across 28/28 epochs.
#[cfg(feature = "candidate-source")]
pub(crate) async fn get_epoch_nonce(
	pool: &Pool<Postgres>,
	epoch: u32,
) -> Result<Option<Vec<u8>>, SqlxError> {
	let row: Option<(String,)> =
		sqlx::query_as("SELECT nonce FROM epoch_nonce WHERE epoch = $1")
			.bind(epoch as i32)
			.fetch_optional(pool)
			.await?;
	match row {
		Some((nonce_hex,)) => {
			let bytes = hex::decode(&nonce_hex).map_err(|e| sqlx::Error::Decode(e.to_string().into()))?;
			Ok(Some(bytes))
		},
		None => Ok(None),
	}
}

/// Latest UTxO at the given asset's policy, produced in an epoch `<= epoch`.
/// Mirrors db-sync's `get_token_utxo_for_epoch`; yaci carries the policy id in
/// the `address_utxo.amounts` JSONB array.
#[cfg(feature = "candidate-source")]
pub(crate) async fn get_token_utxo_for_epoch(
	pool: &Pool<Postgres>,
	policy_id: &[u8],
	epoch: u32,
) -> Result<Option<TokenTxOutput>, SqlxError> {
	let policy_hex = hex::encode(policy_id);
	let row = sqlx::query_as::<_, TokenTxOutputRow>(
		"SELECT au.inline_datum
		 FROM address_utxo au
		 WHERE au.amounts @> $1::jsonb
		   AND au.epoch <= $2
		 ORDER BY au.block DESC, au.output_index DESC
		 LIMIT 1",
	)
	.bind(format!("[{{\"policy_id\":\"{policy_hex}\"}}]"))
	.bind(epoch as i32)
	.fetch_optional(pool)
	.await?;
	Ok(row.map(TokenTxOutput::try_from).transpose()?)
}

/// Unspent UTxOs at `address`, created on or before `block`, and either never
/// spent or spent strictly after `block`. yaci tracks creation in
/// `address_utxo` and spends in `tx_input` (keyed by the consumed output's
/// `tx_hash`/`output_index`). The producing transaction's inputs come from
/// `transaction.inputs` (JSONB array of `{tx_hash, output_index}`).
#[cfg(feature = "candidate-source")]
pub(crate) async fn get_utxos_for_address(
	pool: &Pool<Postgres>,
	address: &str,
	block: u32,
) -> Result<Vec<MainchainTxOutput>, SqlxError> {
	let rows = sqlx::query_as::<_, MainchainTxOutputRow>(
		"SELECT
		     au.tx_hash,
		     au.output_index,
		     au.block               AS tx_block_no,
		     au.slot                AS tx_slot_no,
		     au.epoch               AS tx_epoch_no,
		     t.tx_index             AS tx_index_in_block,
		     au.inline_datum,
		     COALESCE(
		       (SELECT array_agg(concat_ws('#', inp->>'tx_hash', inp->>'output_index'))
		        FROM jsonb_array_elements(t.inputs) AS inp),
		       ARRAY[]::text[]
		     ) AS tx_inputs
		 FROM address_utxo au
		 INNER JOIN transaction t ON t.tx_hash = au.tx_hash
		 LEFT JOIN tx_input spent
		     ON spent.tx_hash = au.tx_hash AND spent.output_index = au.output_index
		 WHERE au.owner_addr = $1
		   AND au.block <= $2
		   AND (spent.tx_hash IS NULL OR spent.spent_at_block > $3)",
	)
	.bind(address)
	.bind(block as i64)
	.bind(block as i64)
	.fetch_all(pool)
	.await?;
	Ok(rows.into_iter().map(MainchainTxOutput::try_from).collect::<Result<_, _>>()?)
}

/// Sum of all native-token transfers to the illiquid-supply address from
/// genesis to `to_block` inclusive. Mirrors db-sync's
/// `get_total_native_tokens_transfered`, reading per-asset quantities from the
/// `address_utxo.amounts` JSONB.
#[cfg(feature = "native-token")]
pub(crate) async fn get_total_native_tokens_transfered(
	pool: &Pool<Postgres>,
	to_block: u32,
	policy_id: &[u8],
	asset_name: &[u8],
	illiquid_supply_address: &str,
) -> Result<u128, SqlxError> {
	let unit = format!("{}{}", hex::encode(policy_id), hex::encode(asset_name));
	let row: (sqlx::types::BigDecimal,) = sqlx::query_as(
		"SELECT COALESCE(SUM((amt->>'quantity')::numeric), 0)
		 FROM address_utxo au,
		      jsonb_array_elements(au.amounts) AS amt
		 WHERE au.owner_addr = $1
		   AND amt->>'unit' = $2
		   AND au.block <= $3",
	)
	.bind(illiquid_supply_address)
	.bind(unit)
	.bind(to_block as i64)
	.fetch_one(pool)
	.await?;
	Ok(row.0.to_u128().unwrap_or(0))
}

/// Per-block sums of native-token transfers to the illiquid-supply address in
/// `[from_block, to_block]`. Mirrors db-sync's `get_native_token_transfers`.
#[cfg(feature = "native-token")]
pub(crate) async fn get_native_token_transfers(
	pool: &Pool<Postgres>,
	from_block: u32,
	to_block: u32,
	policy_id: &[u8],
	asset_name: &[u8],
	illiquid_supply_address: &str,
) -> Result<Vec<BlockTokenAmount>, SqlxError> {
	let unit = format!("{}{}", hex::encode(policy_id), hex::encode(asset_name));
	let rows = sqlx::query_as::<_, BlockTokenAmountRow>(
		"SELECT b.hash AS block_hash,
		        COALESCE(SUM((amt->>'quantity')::numeric), 0) AS amount
		 FROM block b
		 LEFT JOIN address_utxo au
		        ON au.block = b.number AND au.owner_addr = $1
		 LEFT JOIN LATERAL jsonb_array_elements(au.amounts) AS amt
		        ON amt->>'unit' = $2
		 WHERE b.number >= $3 AND b.number <= $4
		 GROUP BY b.number, b.hash
		 ORDER BY b.number ASC",
	)
	.bind(illiquid_supply_address)
	.bind(unit)
	.bind(from_block as i64)
	.bind(to_block as i64)
	.fetch_all(pool)
	.await?;
	Ok(rows.into_iter().map(BlockTokenAmount::try_from).collect::<Result<_, _>>()?)
}

#[cfg(feature = "native-token")]
#[derive(Debug, Clone)]
pub(crate) struct BlockTokenAmount {
	pub block_hash: [u8; 32],
	pub amount: u128,
}

#[cfg(feature = "native-token")]
#[derive(Debug, Clone, sqlx::FromRow)]
struct BlockTokenAmountRow {
	block_hash: String,
	amount: sqlx::types::BigDecimal,
}

#[cfg(feature = "native-token")]
impl TryFrom<BlockTokenAmountRow> for BlockTokenAmount {
	type Error = sqlx::Error;
	fn try_from(r: BlockTokenAmountRow) -> Result<Self, Self::Error> {
		Ok(BlockTokenAmount {
			block_hash: parse_hash32(&r.block_hash).map_err(decode_err)?,
			amount: r.amount.to_u128().ok_or_else(|| decode_err("amount is always u128"))?,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_64_char_hex_into_32_bytes() {
		let hash = "67d682b519036ae9e5d9b0e624ba3cddc4426bebebc56ba96f1287897c7f051c";
		let bytes = parse_hash32(hash).expect("valid 64-char hex");
		assert_eq!(bytes.len(), 32);
		assert_eq!(bytes[0], 0x67);
		assert_eq!(bytes[31], 0x1c);
	}

	#[test]
	fn rejects_wrong_length_hash() {
		assert!(parse_hash32("dead").is_err());
	}

	#[test]
	fn rejects_non_hex_hash() {
		assert!(parse_hash32(&"z".repeat(64)).is_err());
	}

	#[test]
	fn parses_56_char_hex_pool_id_into_28_bytes() {
		let pool = "0312ea8e3de121da6ee1195f3f6f6dbc294940e8691d7791598c09aa";
		let bytes = parse_hash28(pool).expect("valid 56-char hex");
		assert_eq!(bytes.len(), 28);
		assert_eq!(bytes[0], 0x03);
		assert_eq!(bytes[27], 0xaa);
	}

	#[test]
	fn block_time_unix_seconds_converts_to_utc_naive() {
		// 1_596_491_091 = 2020-08-03T20:24:51Z (Cardano Shelley-era timestamp).
		let dt = block_time_to_naive(1_596_491_091).expect("in range");
		assert_eq!(dt.and_utc().timestamp(), 1_596_491_091);
	}
}
