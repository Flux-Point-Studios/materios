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

/// GOLDEN: `get_ariadne_parameters` end-to-end against the pilot's materios
/// config tokens. Exercises the one previously-untested follower path (NOTES.md):
/// the D-parameter UTxO + the permissioned-candidates list UTxO, both selected
/// by `epoch <= data_epoch` and decoded through the verbatim
/// `partner-chains-plutus-data` path.
///
/// The pilot holds the materios D-parameter token under policy
/// `38dddaf5198b927b19dac9b28226ab29eddad176d5d81c7748bc2c31` whose latest datum
/// is `9fd879809f0f01ff00ff` => (permissioned=15, registered=1), and the matching
/// permissioned-candidates token under policy
/// `ef2890d1e98247819abcf2df6e891824ed950a4216d36c71ee6f9974` carrying four
/// candidates. Asserting both proves yaci decodes the live (15,1) Ariadne config
/// — the D-param/registration golden that was blocked until the pilot indexed
/// these tokens.
#[tokio::test]
#[ignore = "requires YACI_DATABASE_URL (.230 pilot with materios config tokens)"]
async fn get_ariadne_parameters_decodes_live_15_1_d_param_golden() {
	let source = live_source().await;

	let d_param_policy = PolicyId(
		hex::decode("38dddaf5198b927b19dac9b28226ab29eddad176d5d81c7748bc2c31")
			.unwrap()
			.try_into()
			.unwrap(),
	);
	let permissioned_policy = PolicyId(
		hex::decode("ef2890d1e98247819abcf2df6e891824ed950a4216d36c71ee6f9974")
			.unwrap()
			.try_into()
			.unwrap(),
	);

	// Epoch 296 is the data tip the pilot has indexed these tokens at; the
	// `epoch <= $2` query then picks the latest UTxO for each policy.
	let params = source
		.get_ariadne_parameters(McEpochNumber(296), d_param_policy, permissioned_policy)
		.await
		.expect("get_ariadne_parameters must succeed against the pilot config tokens");

	assert_eq!(
		params.d_parameter.num_permissioned_candidates, 15,
		"expected 15 permissioned candidates from datum 9fd879809f0f01ff00ff"
	);
	assert_eq!(
		params.d_parameter.num_registered_candidates, 1,
		"expected 1 registered candidate from datum 9fd879809f0f01ff00ff"
	);

	assert_eq!(
		params.permissioned_candidates.len(),
		4,
		"expected 4 permissioned candidates in the ef2890d1 list datum"
	);
	let first_sidechain_key = hex::encode(&params.permissioned_candidates[0].sidechain_public_key.0);
	assert_eq!(
		first_sidechain_key,
		"0316acb17138d708413136b2b30b665bf7ac4a7bf4b6c215c3ea6279bb50e77494",
		"first permissioned candidate sidechain key must match the on-chain list datum"
	);
}

/// THE LOAD-BEARING GOLDEN (#370): a Mithril-certified per-pool stake
/// distribution, fetched with full certificate-chain verification, equals the
/// db-sync `epoch_stake` snapshot for the aligned epoch — per-pool AND in total.
///
/// Epoch alignment (empirically determined + locked by
/// `mithril_stake::tests::epoch_alignment_offset_is_two`): Mithril epoch N ==
/// db-sync `epoch_no` N+2. This test exercises `active_epoch = 297` => Mithril
/// epoch 295, whose db-sync golden (epoch_no 297) is 415 non-zero-stake pools /
/// 1_608_793_594_792_590-class total. The exact reference values were captured
/// against the .230 db-sync (`SELECT COUNT(DISTINCT pool_id), SUM(amount) FROM
/// epoch_stake WHERE epoch_no=297 AND amount>0`):
///   - 415 pools with non-zero stake
///   - 1_608_793_594_792_982 lovelace total
/// db-sync additionally carries 74 zero-stake pools at this epoch which Mithril
/// omits; they carry zero Ariadne weight, so the certified set is the active set.
///
/// Trustlessness is real here: `get_stake_distribution_mithril` shells the
/// pinned `mithril-client`, which verifies the certificate chain against the
/// genesis vkey before any value is read. Requires:
///   MITHRIL_AGGREGATOR_ENDPOINT, MITHRIL_GENESIS_VERIFICATION_KEY,
///   MITHRIL_CLIENT_BIN (path to the verified binary), and the requested epoch
///   to be inside the aggregator's retention window.
#[cfg(feature = "mithril-stake")]
#[tokio::test]
#[ignore = "requires live Mithril preprod aggregator + pinned mithril-client (cert verification)"]
async fn mithril_stake_distribution_matches_db_sync_golden_active_epoch_297() {
	use crate::mithril_stake::{
		get_stake_distribution_mithril, MithrilConfig, MithrilStakeCache,
	};

	let active_epoch = 297u32; // => Mithril epoch 295
	let entries = tokio::task::spawn_blocking(move || {
		let config = MithrilConfig::from_env().expect(
			"MITHRIL_AGGREGATOR_ENDPOINT + MITHRIL_GENESIS_VERIFICATION_KEY (+ MITHRIL_CLIENT_BIN) must be set",
		);
		let cache = MithrilStakeCache::default();
		get_stake_distribution_mithril(&config, &cache, active_epoch)
			.expect("cert-verified Mithril stake distribution for active_epoch 297 (Mithril 295)")
	})
	.await
	.expect("spawn_blocking join");

	let total: u128 = entries.iter().map(|e| e.stake as u128).sum();
	assert_eq!(
		entries.len(),
		415,
		"expected 415 non-zero-stake pools from Mithril epoch 295 (== db-sync epoch_no 297)"
	);
	assert_eq!(
		total, 1_608_793_594_792_982,
		"Mithril certified total must equal db-sync epoch_stake epoch_no 297 total"
	);

	// per-pool spot check: this pool hash + stake was cross-verified against
	// db-sync `pool_hash.hash_raw` / `epoch_stake.amount` at epoch_no 297.
	let pool_hash: [u8; 28] =
		hex::decode("7facad662e180ce45e5c504957cd1341940c72a708728f7ecfc6e349")
			.unwrap()
			.try_into()
			.unwrap();
	let entry = entries
		.iter()
		.find(|e| e.pool_hash == pool_hash)
		.expect("the cross-verified pool must be present in the certified set");
	assert_eq!(
		entry.stake, 7_674_469_639_226,
		"per-pool certified stake must equal db-sync epoch_stake for this pool"
	);

	// no duplicate pool hashes (the certified set is one entry per pool).
	let unique: std::collections::HashSet<_> = entries.iter().map(|e| e.pool_hash).collect();
	assert_eq!(unique.len(), entries.len(), "certified pool set must be unique per pool");
}
