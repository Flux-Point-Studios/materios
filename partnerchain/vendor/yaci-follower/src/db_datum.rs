use cardano_serialization_lib::PlutusData;
use sqlx::database::HasValueRef;
use sqlx::error::BoxDynError;
use sqlx::{Decode, Postgres};

/// Wraps PlutusData to provide sqlx::Decode and sqlx::Type implementations.
///
/// yaci-store stores datum CBOR as a hex-encoded TEXT column (`datum.datum`,
/// `address_utxo.inline_datum`), unlike cardano-db-sync which stores it as a
/// JSONB `datum.value`. We therefore hex-decode the text and feed the raw CBOR
/// bytes straight into `PlutusData::from_bytes` — the same `PlutusData` the
/// existing `partner-chains-plutus-data` decoders (`DParamDatum`,
/// `RegisterValidatorDatum`) consume verbatim.
#[derive(Debug, Clone, PartialEq)]
pub struct DbDatum(pub PlutusData);

impl DbDatum {
	/// Decodes a hex-encoded CBOR datum string into a `PlutusData`.
	pub fn from_hex_cbor(hex_cbor: &str) -> Result<Self, BoxDynError> {
		let bytes = hex::decode(hex_cbor)?;
		let datum = PlutusData::from_bytes(bytes)
			.map_err(|e| format!("Failed to decode datum CBOR: {e}"))?;
		Ok(DbDatum(datum))
	}
}

impl sqlx::Type<Postgres> for DbDatum {
	fn type_info() -> <Postgres as sqlx::Database>::TypeInfo {
		<String as sqlx::Type<Postgres>>::type_info()
	}
}

impl<'r> sqlx::Decode<'r, Postgres> for DbDatum
where
	String: Decode<'r, Postgres>,
{
	fn decode(value: <Postgres as HasValueRef<'r>>::ValueRef) -> Result<Self, BoxDynError> {
		let hex_cbor: String = <String as Decode<Postgres>>::decode(value)?;
		DbDatum::from_hex_cbor(&hex_cbor)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use partner_chains_plutus_data::d_param::{d_parameter_to_plutus_data, DParamDatum};
	use sidechain_domain::DParameter;

	/// Golden: a legacy D-parameter datum is a definite-length CBOR array of two
	/// unsigned ints `[1, 2]` => `0x82 0x01 0x02`. yaci-store delivers this as the
	/// lowercase hex TEXT "820102". It must decode through the verbatim
	/// `partner-chains-plutus-data` path to `DParameter { permissioned: 1,
	/// registered: 2 }`.
	#[test]
	fn decodes_golden_legacy_d_param_cbor_hex() {
		let db_datum = DbDatum::from_hex_cbor("820102").expect("golden CBOR must decode");
		let d_param: DParameter =
			DParamDatum::try_from(db_datum.0).expect("must parse as D-param").into();
		assert_eq!(
			d_param,
			DParameter { num_permissioned_candidates: 1, num_registered_candidates: 2 }
		);
	}

	/// Round-trips a v0 D-parameter datum: encode via the upstream
	/// `d_parameter_to_plutus_data`, serialize to CBOR, hex it the way yaci-store
	/// stores it, then decode back. Proves the hex->CBOR->PlutusData seam is
	/// byte-exact against the library's own canonical encoding.
	#[test]
	fn round_trips_v0_d_param_through_yaci_hex_text() {
		let original = DParameter { num_permissioned_candidates: 17, num_registered_candidates: 42 };
		let plutus = d_parameter_to_plutus_data(&original);
		let yaci_hex_text = hex::encode(plutus.to_bytes());

		let decoded = DbDatum::from_hex_cbor(&yaci_hex_text).expect("must decode");
		let round_tripped: DParameter =
			DParamDatum::try_from(decoded.0).expect("must parse as D-param").into();
		assert_eq!(round_tripped, original);
	}

	/// A malformed hex string must surface as an error, not a panic.
	#[test]
	fn rejects_non_hex_input() {
		assert!(DbDatum::from_hex_cbor("not-hex-zz").is_err());
	}
}
