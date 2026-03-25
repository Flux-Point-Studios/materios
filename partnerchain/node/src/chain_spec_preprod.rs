//! Chain specification for Materios Partner Chain on Cardano Preprod.
//!
//! This is the "real" chain spec (vs the --dev spec) that connects to
//! Cardano preprod via the Partner Chains toolkit.

use materios_runtime::{
    AccountId, Balance, RuntimeGenesisConfig, WASM_BINARY,
    SessionKeys,
};
use sc_service::ChainType;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
use sp_core::{sr25519, Pair, Public};
use sp_runtime::traits::{IdentifyAccount, Verify};

/// Specialized `ChainSpec` for preprod.
pub type ChainSpec = sc_service::GenericChainSpec;

/// Helper to generate a crypto pair from seed.
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{}", seed), None)
        .expect("static values are valid; qed")
        .public()
}

type AccountPublic = <materios_runtime::Signature as Verify>::Signer;

pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
    AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
    AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

/// Helper to build an authority key set (Aura + Grandpa) from a seed.
pub fn authority_keys_from_seed(s: &str) -> (AuraId, GrandpaId) {
    (
        get_from_seed::<AuraId>(s),
        get_from_seed::<GrandpaId>(s),
    )
}

/// Preprod chain spec.
///
/// Key differences from dev:
/// - ChainType::Live (not Development)
/// - No single-authority shortcut
/// - Requires real key generation via wizards
/// - Connects to Cardano preprod via db-sync + ogmios
/// - D-parameter starts fully permissioned (only registered candidates)
/// - Governance initialized at genesis UTXO
pub fn preprod_config() -> Result<ChainSpec, String> {
    Ok(ChainSpec::builder(
        WASM_BINARY.ok_or("WASM binary not available")?,
        None,
    )
    .with_name("Materios Preprod")
    .with_id("materios_preprod")
    .with_chain_type(ChainType::Live)
    .with_protocol_id("materios-preprod")
    .with_genesis_config_patch(serde_json::json!({
        "balances": {
            "balances": []
        },
        "sudo": {
            "key": null
        },
        "motra": {
            "minFee": 1_000_000,
            "congestionRate": 0,
            "targetFullnessPpm": 500_000_000,
            "decayRatePerBlockPpm": 999_900_000,
            "generationPerMatraPerBlock": 100,
            "maxBalance": 1_000_000_000_000_000u128,
            "maxCongestionStep": 1_000_000,
            "lengthFeePerByte": 1_000,
            "congestionSmoothingPpm": 100_000_000
        }
    }))
    .build())
}

/// Staging chain spec — for internal testing before preprod.
/// Similar to preprod but with pre-funded test accounts.
pub fn staging_config() -> Result<ChainSpec, String> {
    let alice = get_account_id_from_seed::<sr25519::Public>("Alice");
    let bob = get_account_id_from_seed::<sr25519::Public>("Bob");

    Ok(ChainSpec::builder(
        WASM_BINARY.ok_or("WASM binary not available")?,
        None,
    )
    .with_name("Materios Staging")
    .with_id("materios_staging")
    .with_chain_type(ChainType::Live)
    .with_protocol_id("materios-staging")
    .with_genesis_config_patch(serde_json::json!({
        "balances": {
            "balances": [
                [alice, 1_000_000_000_000_000_000u128],
                [bob, 1_000_000_000_000_000_000u128],
            ]
        },
        "sudo": {
            "key": alice
        },
        "aura": {
            "authorities": [
                get_from_seed::<AuraId>("Alice"),
                get_from_seed::<AuraId>("Bob"),
            ]
        },
        "grandpa": {
            "authorities": [
                (get_from_seed::<GrandpaId>("Alice"), 1u64),
                (get_from_seed::<GrandpaId>("Bob"), 1u64),
            ]
        },
        "motra": {
            "minFee": 1_000_000,
            "congestionRate": 0,
            "targetFullnessPpm": 500_000_000,
            "decayRatePerBlockPpm": 999_900_000,
            "generationPerMatraPerBlock": 100,
            "maxBalance": 1_000_000_000_000_000u128,
            "maxCongestionStep": 1_000_000,
            "lengthFeePerByte": 1_000,
            "congestionSmoothingPpm": 100_000_000
        }
    }))
    .build())
}
