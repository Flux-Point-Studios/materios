use materios_runtime::{
    SessionKeys, AccountId, Balance, RuntimeGenesisConfig, Signature, WASM_BINARY,
};
use sc_service::ChainType;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
use sp_core::{sr25519, Pair, Public};
use sp_runtime::traits::{IdentifyAccount, Verify};

/// Specialized `ChainSpec` for the Materios network.
pub type ChainSpec = sc_service::GenericChainSpec;

/// Helper to generate a crypto pair from seed.
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{}", seed), None)
        .expect("static values are valid; qed")
        .public()
}

type AccountPublic = <Signature as Verify>::Signer;

/// Helper to derive an account ID from seed.
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

/// Number of sidechain slots per epoch.
/// In permissioned-only mode (D=1.0) with 6s blocks, 60 slots = ~6 min epochs.
const SLOTS_PER_EPOCH: u32 = 60;

/// Development chain spec with a single validator (Alice).
pub fn development_config() -> Result<ChainSpec, String> {
    Ok(ChainSpec::builder(
        WASM_BINARY.ok_or_else(|| "Development WASM binary not available".to_string())?,
        None,
    )
    .with_name("Materios Development")
    .with_id("materios_dev")
    .with_chain_type(ChainType::Development)
    .with_genesis_config_patch(testnet_genesis(
        // Initial authorities
        vec![authority_keys_from_seed("Alice")],
        // Sudo account
        get_account_id_from_seed::<sr25519::Public>("Alice"),
        // Pre-funded accounts
        vec![
            get_account_id_from_seed::<sr25519::Public>("Alice"),
            get_account_id_from_seed::<sr25519::Public>("Bob"),
            get_account_id_from_seed::<sr25519::Public>("Charlie"),
            get_account_id_from_seed::<sr25519::Public>("Dave"),
            get_account_id_from_seed::<sr25519::Public>("Eve"),
            get_account_id_from_seed::<sr25519::Public>("Ferdie"),
            get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
            get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
        ],
        true,
    ))
    .build())
}

/// Local testnet with Alice and Bob as validators.
pub fn local_testnet_config() -> Result<ChainSpec, String> {
    Ok(ChainSpec::builder(
        WASM_BINARY.ok_or_else(|| "Local testnet WASM binary not available".to_string())?,
        None,
    )
    .with_name("Materios Local Testnet")
    .with_id("materios_local")
    .with_chain_type(ChainType::Local)
    .with_genesis_config_patch(testnet_genesis(
        // Initial authorities
        vec![
            authority_keys_from_seed("Alice"),
            authority_keys_from_seed("Bob"),
        ],
        // Sudo account
        get_account_id_from_seed::<sr25519::Public>("Alice"),
        // Pre-funded accounts
        vec![
            get_account_id_from_seed::<sr25519::Public>("Alice"),
            get_account_id_from_seed::<sr25519::Public>("Bob"),
            get_account_id_from_seed::<sr25519::Public>("Charlie"),
            get_account_id_from_seed::<sr25519::Public>("Dave"),
            get_account_id_from_seed::<sr25519::Public>("Eve"),
            get_account_id_from_seed::<sr25519::Public>("Ferdie"),
            get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
            get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
        ],
        true,
    ))
    .build())
}

const ENDOWMENT: Balance = 1_000_000_000_000_000_000;

/// Build a genesis config JSON patch.
///
/// Includes configuration for the 6 IOG partner-chain pallets:
///   1. pallet_sidechain        -- sidechain params (genesis_utxo, slots_per_epoch)
///   2. pallet_partner_chains_session (Session) -- initial validator set
///   3. pallet_session_validator_management (SessionCommitteeManagement) -- committee + scripts
///   4. pallet_session (PalletSession) -- substrate session stub (default)
///   5. pallet_block_rewards (BlockRewards) -- no genesis storage needed
///   6. pallet_native_token_management -- native token bridge scripts (placeholder)
///
/// Running in permissioned-only mode (D=1.0): Cardano mainchain follower not required.
/// The `genesis_utxo` and `main_chain_scripts` fields use placeholder/default values
/// that will be replaced when the Cardano bridge is activated.
fn testnet_genesis(
    initial_authorities: Vec<(AuraId, GrandpaId)>,
    root_key: AccountId,
    endowed_accounts: Vec<AccountId>,
    _enable_println: bool,
) -> serde_json::Value {
    // Build the initial_validators list for Session pallet.
    // In permissioned-only mode, the cross-chain key is derived from the Aura
    // key bytes (placeholder; real ECDSA cross-chain keys come later).
    // Format: [(AccountId, SessionKeys), ...]
    // For the JSON genesis patch, the Session pallet expects the validator account
    // to be derived from the cross-chain public key.  In permissioned mode we use
    // the Aura sr25519 key as the validator account ID.
    let session_initial_validators: Vec<serde_json::Value> = initial_authorities
        .iter()
        .map(|(aura, grandpa)| {
            // The session keys structure matches the runtime's SessionKeys { aura, grandpa }
            serde_json::json!([
                // Validator account ID (derived from aura key in dev/test)
                aura,
                {
                    "aura": aura,
                    "grandpa": grandpa,
                }
            ])
        })
        .collect();

    // For SessionCommitteeManagement, initial_authorities maps
    // (AuthorityId, AuthorityKeys) pairs.  In permissioned-only mode the
    // AuthorityId (cross-chain public key) is unused, so we pass an empty list.
    // The committee will be bootstrapped from the Session pallet's initial set.

    serde_json::json!({
        "balances": {
            "balances": endowed_accounts
                .iter()
                .map(|k| (k.clone(), ENDOWMENT))
                .collect::<Vec<_>>(),
        },
        "aura": {
            // Left empty; validators are now managed by the Session pallet.
            "authorities": [],
        },
        "grandpa": {
            // Left empty; validators are now managed by the Session pallet.
            "authorities": [],
        },
        "sudo": {
            "key": Some(root_key),
        },
        // -- IOG partner-chain pallets --
        // 1. Sidechain pallet: epoch/slot configuration.
        //    genesis_utxo is a placeholder (all zeros) for permissioned-only mode.
        "sidechain": {
            "genesisUtxo": "0x0000000000000000000000000000000000000000000000000000000000000000#0",
            "slotsPerEpoch": SLOTS_PER_EPOCH,
        },
        // 2. Session pallet (pallet_partner_chains_session): initial validator set.
        "session": {
            "initialValidators": session_initial_validators,
        },
        // 3. SessionCommitteeManagement (pallet_session_validator_management):
        //    In permissioned-only mode we start with an empty authority list here.
        //    The committee is bootstrapped from the Session pallet's initial validators.
        //    main_chain_scripts use placeholder values (not needed until D < 1.0).
        "sessionCommitteeManagement": {
            "initialAuthorities": [],
            "mainChainScripts": {
                "committeeCandidateAddress": "",
                "dParameterPolicyId": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "permissionedCandidatesPolicyId": "0x0000000000000000000000000000000000000000000000000000000000000000",
            },
        },
        // 4. PalletSession (substrate session stub): default, no config needed.
        "palletSession": {},
        // 5. NativeTokenManagement: placeholder scripts for permissioned-only mode.
        "nativeTokenManagement": {
            "mainChainScripts": {
                "nativeTokenPolicyId": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "illiquidSupplyAddress": "",
            },
        },
        // Note: BlockRewards has no genesis config.
    })
}
