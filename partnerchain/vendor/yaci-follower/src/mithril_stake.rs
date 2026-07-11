//! Mithril-certified per-pool stake distribution — the trustless drop-in for the
//! yaci `epoch_stake` query behind the `mithril-stake` feature (#370, Tier-2 of
//! LEAN-DEPLOYMENT.md).
//!
//! Mithril GA certifies exactly the `(pool_hash, stake)` Ariadne snapshot, so the
//! follower no longer trusts the local yaci-store `adapot`/`epoch_stake` (the
//! heaviest, most-RAM-hungry yaci module — a reward replay). The certificate
//! chain is verified in-process by the `mithril-client` binary against the
//! release-network genesis verification key before any value is read.
//!
//! ## Epoch alignment (the #445-style footgun — empirically locked)
//!
//! Mithril labels its stake distribution by the epoch in which the snapshot is
//! *taken*; that stake becomes *active* two Cardano epochs later. db-sync's
//! `epoch_stake.epoch_no` (== yaci `active_epoch`) is the *active* epoch. So:
//!
//! ```text
//! mithril_epoch = active_epoch - 2
//! ```
//!
//! Proven byte-identical on two independent preprod epoch pairs (per-pool and
//! total, modulo db-sync's zero-stake pools which carry zero Ariadne weight):
//! Mithril 294 == db-sync epoch_no 296 (412 pools / 1606572572988498 lovelace),
//! Mithril 295 == db-sync epoch_no 297 (415 pools / 1608793594792982 lovelace).
//! [`MITHRIL_TO_ACTIVE_EPOCH_OFFSET`] locks the offset; a dedicated test fails if
//! anyone changes it.

use crate::db_model::StakePoolEntry;
use std::collections::HashMap;
use std::sync::Mutex;

/// `active_epoch = mithril_epoch + 2`. See module docs for the empirical proof.
pub(crate) const MITHRIL_TO_ACTIVE_EPOCH_OFFSET: u32 = 2;

/// The Mithril epoch whose certified stake distribution becomes *active* in
/// `active_epoch`. Returns `None` for the two genesis epochs that have no
/// two-epochs-earlier Mithril snapshot.
pub(crate) fn mithril_epoch_for_active_epoch(active_epoch: u32) -> Option<u32> {
	active_epoch.checked_sub(MITHRIL_TO_ACTIVE_EPOCH_OFFSET)
}

/// bech32 character set (BIP-173); index = 5-bit value.
const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Decodes a Cardano bech32 pool id (`pool1…`) into its 28-byte pool hash — the
/// same `[u8;28]` db-sync stores in `pool_hash.hash_raw`. We only need the data
/// part regrouped 5→8 bits (the HRP is always `pool` and the checksum is dropped
/// after the certificate chain has already attested the payload), so this is a
/// dependency-free decode rather than pulling a new bech32 crate version into
/// the pinned partner-chains workspace.
pub(crate) fn pool_bech32_to_hash28(pool_id: &str) -> Result<[u8; 28], String> {
	let lower = pool_id.to_ascii_lowercase();
	let sep = lower.rfind('1').ok_or_else(|| format!("no bech32 separator in {pool_id}"))?;
	let (hrp, data_with_sep) = lower.split_at(sep);
	if hrp != "pool" {
		return Err(format!("expected 'pool' hrp, got '{hrp}'"));
	}
	let data_chars = &data_with_sep[1..];
	if data_chars.len() < 6 {
		return Err(format!("bech32 payload too short in {pool_id}"));
	}
	// drop the 6-char checksum.
	let payload = &data_chars[..data_chars.len() - 6];
	let mut values = Vec::with_capacity(payload.len());
	for c in payload.bytes() {
		let v = BECH32_CHARSET
			.iter()
			.position(|&x| x == c)
			.ok_or_else(|| format!("invalid bech32 char '{}' in {pool_id}", c as char))?;
		values.push(v as u8);
	}
	let bytes = convert_bits_5_to_8(&values)?;
	bytes
		.try_into()
		.map_err(|v: Vec<u8>| format!("expected 28-byte pool hash, got {} bytes", v.len()))
}

/// Regroups 5-bit bech32 values into 8-bit bytes, rejecting non-zero padding
/// (the canonical bech32 constraint).
fn convert_bits_5_to_8(values: &[u8]) -> Result<Vec<u8>, String> {
	let mut acc: u32 = 0;
	let mut bits: u32 = 0;
	let mut out = Vec::new();
	for &v in values {
		acc = (acc << 5) | (v as u32);
		bits += 5;
		while bits >= 8 {
			bits -= 8;
			out.push(((acc >> bits) & 0xff) as u8);
		}
	}
	if bits >= 5 || ((acc << (8 - bits)) & 0xff) != 0 {
		return Err("non-zero bech32 padding".to_string());
	}
	Ok(out)
}

/// The verified `mithril-client` JSON output for a `cardano-stake-distribution`:
/// `stake_distribution` maps bech32 pool id -> active stake in lovelace.
#[derive(serde::Deserialize)]
struct VerifiedStakeDistribution {
	epoch: u32,
	stake_distribution: HashMap<String, u64>,
}

/// Parses the cert-verified `mithril-client` JSON into the follower's
/// `Vec<StakePoolEntry>` — identical shape to the yaci `epoch_stake` path.
/// Asserts the file's epoch matches what we requested (guards a stale/cached file).
pub(crate) fn parse_verified_stake_distribution(
	json: &str,
	expected_mithril_epoch: u32,
) -> Result<Vec<StakePoolEntry>, String> {
	let parsed: VerifiedStakeDistribution =
		serde_json::from_str(json).map_err(|e| format!("invalid mithril SD json: {e}"))?;
	if parsed.epoch != expected_mithril_epoch {
		return Err(format!(
			"mithril SD epoch mismatch: file is {}, requested {}",
			parsed.epoch, expected_mithril_epoch
		));
	}
	parsed
		.stake_distribution
		.into_iter()
		.map(|(pool_id, stake)| {
			Ok(StakePoolEntry { pool_hash: pool_bech32_to_hash28(&pool_id)?, stake })
		})
		.collect()
}

/// Per-epoch cache: a Mithril stake distribution is fixed once the certificate
/// is signed, so we fetch + verify each `active_epoch` at most once per process.
#[derive(Default)]
pub(crate) struct MithrilStakeCache {
	by_active_epoch: Mutex<HashMap<u32, Vec<StakePoolEntry>>>,
}

impl MithrilStakeCache {
	pub(crate) fn get(&self, active_epoch: u32) -> Option<Vec<StakePoolEntry>> {
		self.by_active_epoch.lock().expect("mithril cache mutex").get(&active_epoch).cloned()
	}

	pub(crate) fn put(&self, active_epoch: u32, entries: Vec<StakePoolEntry>) {
		self.by_active_epoch.lock().expect("mithril cache mutex").insert(active_epoch, entries);
	}
}

/// Configuration for the Mithril stake source, read from the environment.
/// `MITHRIL_AGGREGATOR_ENDPOINT` + `MITHRIL_GENESIS_VERIFICATION_KEY` are
/// mandatory (no default network — the operator must pin preprod vs mainnet);
/// `MITHRIL_CLIENT_BIN` defaults to `mithril-client` on `PATH`.
pub(crate) struct MithrilConfig {
	pub aggregator_endpoint: String,
	pub genesis_verification_key: String,
	pub client_bin: String,
}

impl MithrilConfig {
	pub(crate) fn from_env() -> Result<Self, String> {
		let aggregator_endpoint = std::env::var("MITHRIL_AGGREGATOR_ENDPOINT")
			.map_err(|_| "MITHRIL_AGGREGATOR_ENDPOINT must be set for the mithril-stake feature".to_string())?;
		let genesis_verification_key = std::env::var("MITHRIL_GENESIS_VERIFICATION_KEY").map_err(|_| {
			"MITHRIL_GENESIS_VERIFICATION_KEY must be set for the mithril-stake feature".to_string()
		})?;
		let client_bin = std::env::var("MITHRIL_CLIENT_BIN").unwrap_or_else(|_| "mithril-client".to_string());
		Ok(Self { aggregator_endpoint, genesis_verification_key, client_bin })
	}
}

/// Shells `mithril-client cardano-stake-distribution download <mithril_epoch>`,
/// which fetches the artifact AND verifies the certificate chain against the
/// genesis vkey in-process, then returns the verified JSON. Trustlessness lives
/// here: a download that fails certificate verification exits non-zero and we
/// propagate the error rather than reading unverified stake.
fn download_verified_stake_distribution(
	config: &MithrilConfig,
	mithril_epoch: u32,
) -> Result<String, String> {
	let dir = std::env::temp_dir().join(format!("mithril-sd-{mithril_epoch}"));
	std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {dir:?}: {e}"))?;
	// The cert-verified stake distribution lands here; keep it owner-only so a
	// world-readable, predictable temp path can't leak or be pre-created by
	// another local user under the same shared temp dir.
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
			.map_err(|e| format!("chmod 0700 {dir:?}: {e}"))?;
	}

	let output = std::process::Command::new(&config.client_bin)
		.args([
			"cardano-stake-distribution",
			"download",
			&mithril_epoch.to_string(),
			"--download-dir",
		])
		.arg(&dir)
		.arg("--json")
		.env("AGGREGATOR_ENDPOINT", &config.aggregator_endpoint)
		.env("GENESIS_VERIFICATION_KEY", &config.genesis_verification_key)
		.output()
		.map_err(|e| format!("spawn {}: {e}", config.client_bin))?;

	if !output.status.success() {
		return Err(format!(
			"mithril-client failed (status {}): {}",
			output.status,
			String::from_utf8_lossy(&output.stderr)
		));
	}

	let path = dir.join(format!("cardano_stake_distribution-{mithril_epoch}.json"));
	std::fs::read_to_string(&path).map_err(|e| format!("read verified SD {path:?}: {e}"))
}

/// Fetches the Mithril-certified stake distribution for the given `active_epoch`
/// (mapping to `active_epoch - 2` on the Mithril side), parses it into
/// `Vec<StakePoolEntry>`, and caches it. This is the body of the
/// `get_stake_distribution` seam when `mithril-stake` is enabled.
pub(crate) fn get_stake_distribution_mithril(
	config: &MithrilConfig,
	cache: &MithrilStakeCache,
	active_epoch: u32,
) -> Result<Vec<StakePoolEntry>, String> {
	if let Some(cached) = cache.get(active_epoch) {
		return Ok(cached);
	}
	let mithril_epoch = mithril_epoch_for_active_epoch(active_epoch)
		.ok_or_else(|| format!("no Mithril stake distribution for active_epoch {active_epoch} (pre-genesis)"))?;
	let json = download_verified_stake_distribution(config, mithril_epoch)?;
	let entries = parse_verified_stake_distribution(&json, mithril_epoch)?;
	cache.put(active_epoch, entries.clone());
	Ok(entries)
}

#[cfg(test)]
mod tests {
	use super::*;

	/// LOCKS the #445-style epoch alignment: Mithril epoch N == db-sync
	/// `epoch_no` N+2 (== yaci `active_epoch` N+2). Proven byte-identical on
	/// preprod (Mithril 294/295 == db-sync 296/297). If anyone changes the
	/// offset, this fails — and the live golden would silently read the wrong
	/// epoch's stake.
	#[test]
	fn epoch_alignment_offset_is_two() {
		assert_eq!(MITHRIL_TO_ACTIVE_EPOCH_OFFSET, 2);
		assert_eq!(mithril_epoch_for_active_epoch(297), Some(295));
		assert_eq!(mithril_epoch_for_active_epoch(296), Some(294));
		assert_eq!(mithril_epoch_for_active_epoch(1), None);
		assert_eq!(mithril_epoch_for_active_epoch(0), None);
	}

	/// LOCKS the bech32 pool-id decode against a known preprod pool whose
	/// 28-byte hash was cross-checked against db-sync `pool_hash.hash_raw`.
	#[test]
	fn bech32_pool_id_decodes_to_db_sync_hash_raw() {
		let hash = pool_bech32_to_hash28("pool107k26e3wrqxwghju2py40ngngx2qcu48ppeg7lk0cm35jl2aenx")
			.expect("valid pool bech32");
		assert_eq!(
			hex::encode(hash),
			"7facad662e180ce45e5c504957cd1341940c72a708728f7ecfc6e349"
		);
	}

	#[test]
	fn bech32_rejects_wrong_hrp() {
		assert!(pool_bech32_to_hash28("addr1xyz000000000000").is_err());
	}

	#[test]
	fn bech32_rejects_invalid_char() {
		// 'b' is not in the bech32 charset.
		assert!(pool_bech32_to_hash28("pool1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").is_err());
	}

	/// Parses a verified-format SD blob into `StakePoolEntry` and checks the
	/// epoch guard + per-pool decode + total.
	#[test]
	fn parses_verified_stake_distribution_blob() {
		let json = r#"{
			"epoch": 295,
			"hash": "deadbeef",
			"certificate_hash": "cafe",
			"stake_distribution": {
				"pool107k26e3wrqxwghju2py40ngngx2qcu48ppeg7lk0cm35jl2aenx": 7674469639226
			},
			"created_at": "2026-06-20T00:00:00Z"
		}"#;
		let entries = parse_verified_stake_distribution(json, 295).expect("parse");
		assert_eq!(entries.len(), 1);
		assert_eq!(
			hex::encode(entries[0].pool_hash),
			"7facad662e180ce45e5c504957cd1341940c72a708728f7ecfc6e349"
		);
		assert_eq!(entries[0].stake, 7674469639226);
	}

	/// The epoch guard rejects a file for the wrong epoch (stale/cached download).
	#[test]
	fn parse_rejects_epoch_mismatch() {
		let json = r#"{"epoch": 294, "hash":"x","certificate_hash":"y","stake_distribution":{},"created_at":"z"}"#;
		assert!(parse_verified_stake_distribution(json, 295).is_err());
	}

	/// Round-trips through the cache: first put, then get returns the same.
	#[test]
	fn cache_round_trips_per_active_epoch() {
		let cache = MithrilStakeCache::default();
		assert!(cache.get(297).is_none());
		let entries = vec![StakePoolEntry { pool_hash: [7u8; 28], stake: 42 }];
		cache.put(297, entries.clone());
		assert_eq!(cache.get(297), Some(entries));
		assert!(cache.get(296).is_none());
	}
}
