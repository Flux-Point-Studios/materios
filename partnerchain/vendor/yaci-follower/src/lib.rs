//! Provides implementations of the Materios main-chain-follower Data Sources
//! that read from a yaci-store 3.0.0-beta3 Postgres database instead of
//! cardano-db-sync. The public surface (the four `*DataSource` trait impls)
//! is identical to `db-sync-follower`; only the SQL and Postgres column types
//! differ. See NOTES.md for the proven-byte-identical mapping.
use cardano_serialization_lib::PlutusData;

pub mod data_sources;
mod db_datum;
mod db_model;
pub mod metrics;

#[cfg(feature = "block-source")]
pub mod block;
#[cfg(feature = "candidate-source")]
pub mod candidates;
#[cfg(feature = "mc-hash")]
pub mod mc_hash;
#[cfg(feature = "mithril-stake")]
pub(crate) mod mithril_stake;
#[cfg(feature = "native-token")]
pub mod native_token;
#[cfg(feature = "sidechain-rpc")]
pub mod sidechain_rpc;

#[derive(Debug)]
pub struct SqlxError(sqlx::Error);

impl From<sqlx::Error> for SqlxError {
	fn from(value: sqlx::Error) -> Self {
		SqlxError(value)
	}
}

impl From<SqlxError> for DataSourceError {
	fn from(e: SqlxError) -> Self {
		DataSourceError::InternalDataSourceError(e.0.to_string())
	}
}

impl From<SqlxError> for Box<dyn std::error::Error + Send + Sync> {
	fn from(e: SqlxError) -> Self {
		e.0.into()
	}
}

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum DataSourceError {
	#[error("Bad request: `{0}`.")]
	BadRequest(String),
	#[error("Internal error of data source: `{0}`.")]
	InternalDataSourceError(String),
	#[error("Could not decode {datum:?} to {to:?}, this means that there is an error in Plutus scripts or chain-follower is obsolete.")]
	DatumDecodeError { datum: PlutusData, to: String },
	#[error("'{0}' not found. Possible causes: main chain follower configuration error, yaci-store not synced fully, or data not set on the main chain.")]
	ExpectedDataNotFound(String),
	#[error("Invalid data. {0} Possible cause it an error in Plutus scripts or chain-follower is obsolete.")]
	InvalidData(String),
}

pub type Result<T> = std::result::Result<T, DataSourceError>;
