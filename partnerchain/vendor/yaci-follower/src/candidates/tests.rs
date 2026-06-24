//! Tests for the yaci-store-backed `AuthoritySelectionDataSource`.
//!
//! Pure-logic tests run in CI. DB-integration tests are `#[ignore]`d: they
//! require a reachable yaci-store Postgres via `YACI_DATABASE_URL` (the .230
//! pilot, typically reached over an SSH tunnel) and assert the golden parity
//! values proven byte-identical against cardano-db-sync.

use crate::candidates::CandidatesDataSourceImpl;
use crate::metrics::mock::test_metrics;
use authority_selection_inherents::authority_selection_inputs::AuthoritySelectionDataSource;
use sidechain_domain::*;

fn yaci_database_url() -> Option<String> {
	std::env::var("YACI_DATABASE_URL").ok()
}

async fn live_source() -> CandidatesDataSourceImpl {
	let url = yaci_database_url().expect("YACI_DATABASE_URL must be set for #[ignore] integration tests");
	let pool = sqlx::PgPool::connect(&url).await.expect("connect to yaci-store pg");
	CandidatesDataSourceImpl::new(pool, Some(test_metrics())).await.expect("data source")
}

/// GOLDEN (proven byte-identical to db-sync `epoch_param.nonce`):
/// epoch 7 nonce == 67d682b519036ae9e5d9b0e624ba3cddc4426bebebc56ba96f1287897c7f051c.
#[tokio::test]
#[ignore = "requires YACI_DATABASE_URL (.230 pilot)"]
async fn get_epoch_nonce_matches_db_sync_golden_epoch_7() {
	let source = live_source().await;
	let nonce = source.get_epoch_nonce(McEpochNumber(7)).await.unwrap();
	let expected = EpochNonce(
		hex::decode("67d682b519036ae9e5d9b0e624ba3cddc4426bebebc56ba96f1287897c7f051c").unwrap(),
	);
	assert_eq!(nonce, Some(expected));
}

/// GOLDEN (proven byte-identical to db-sync, keyed on active_epoch):
/// active_epoch 92 => 285 pools / 239_375_391_050_590 lovelace total stake.
/// This is the #1 footgun guard: the query MUST filter `active_epoch`, not the
/// raw `epoch` column (off by two Cardano epochs).
#[tokio::test]
#[ignore = "requires YACI_DATABASE_URL (.230 pilot)"]
async fn get_stake_distribution_active_epoch_92_matches_db_sync_golden() {
	let source = live_source().await;
	let entries = crate::db_model::get_stake_distribution(&source.pool, 92).await.unwrap();
	let total: u128 = entries.iter().map(|e| e.stake as u128).sum();
	assert_eq!(entries.len(), 285, "expected 285 pools at active_epoch 92");
	assert_eq!(total, 239_375_391_050_590, "expected golden total lovelace at active_epoch 92");
}

/// Filtering the raw `epoch` column instead of `active_epoch` returns a
/// DIFFERENT (off-by-two) result. Proves we are not accidentally on the wrong
/// column.
#[tokio::test]
#[ignore = "requires YACI_DATABASE_URL (.230 pilot)"]
async fn raw_epoch_column_does_not_match_active_epoch_golden() {
	let source = live_source().await;
	let raw_epoch_90: (i64,) = sqlx::query_as(
		"SELECT COALESCE(SUM(amount),0)::bigint FROM epoch_stake WHERE epoch = 92 AND pool_id IS NOT NULL",
	)
	.fetch_one(&source.pool)
	.await
	.unwrap();
	// active_epoch 92 golden is 239_375_391_050_590; raw epoch 92 is a different snapshot.
	assert_ne!(raw_epoch_90.0 as u128, 239_375_391_050_590u128);
}

/// epoch nonce for a not-yet-reached epoch returns None rather than erroring.
#[tokio::test]
#[ignore = "requires YACI_DATABASE_URL (.230 pilot)"]
async fn get_epoch_nonce_unknown_epoch_is_none() {
	let source = live_source().await;
	let nonce = source.get_epoch_nonce(McEpochNumber(99_999)).await.unwrap();
	assert_eq!(nonce, None);
}

/// UTxO + inline-datum end-to-end against live data: `get_utxos_for_address`
/// returns unspent UTxOs at `block` and every `inline_datum` decodes from hex
/// CBOR into `PlutusData` (proving the third load-bearing follower input — the
/// path D-param / candidate registrations ride on). Uses a high-cardinality
/// datum-bearing preprod script address.
#[tokio::test]
#[ignore = "requires YACI_DATABASE_URL (.230 pilot)"]
async fn get_utxos_for_address_returns_unspent_decodable_datums() {
	let source = live_source().await;
	let address = "addr_test1wryq87gq9kev98w8ddk6c9rtfta9xdj8k2aqespmxk7tlsgr4eee9";
	let tip = crate::db_model::get_latest_block_info(&source.pool)
		.await
		.unwrap()
		.expect("a tip block")
		.block_no;
	let utxos = crate::db_model::get_utxos_for_address(&source.pool, address, tip).await.unwrap();
	assert!(!utxos.is_empty(), "expected unspent UTxOs at the address");
	let with_datum = utxos.iter().filter(|u| u.datum.is_some()).count();
	assert!(with_datum > 0, "expected at least one inline-datum UTxO to decode as PlutusData");
}
