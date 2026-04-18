//! Chain specification for Materios Preprod — clean genesis, no overrides.

use materios_runtime::WASM_BINARY;
use sc_service::ChainType;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
use sp_core::crypto::AccountId32;

/// Specialized `ChainSpec` for preprod.
pub type ChainSpec = sc_service::GenericChainSpec;

/// Create an AccountId32 from raw 32-byte hex.
fn account(hex: [u8; 32]) -> AccountId32 {
    AccountId32::from(hex)
}

/// Number of sidechain slots per epoch for preprod.
/// With 6s blocks, 600 slots = ~1 hour epochs.
const PREPROD_SLOTS_PER_EPOCH: u32 = 600;

/// Preprod chain spec — Gemtek + Node-2 + Node-3 + MacBook as initial 4-validator authority set.
/// Sudo is a 2-of-3 multisig. All fixes baked in from genesis.
///
/// Now includes IOG partner-chain pallet genesis configuration for permissioned-only
/// mode (D=1.0).  Cardano mainchain follower placeholders will be replaced when the
/// bridge is activated.
pub fn preprod_config() -> Result<ChainSpec, String> {
    // -- Accounts --
    let alice_faucet = account([
        0xd4, 0x35, 0x93, 0xc7, 0x15, 0xfd, 0xd3, 0x1c,
        0x61, 0x14, 0x1a, 0xbd, 0x04, 0xa9, 0x9f, 0xd6,
        0x82, 0x2c, 0x85, 0x58, 0x85, 0x4c, 0xcd, 0xe3,
        0x9a, 0x56, 0x84, 0xe7, 0xa5, 0x6d, 0xa2, 0x7d,
    ]);
    let keyholder_1 = account([
        0x56, 0x78, 0xcd, 0x42, 0x1e, 0xd8, 0x24, 0xdd,
        0x2f, 0x88, 0x60, 0xb5, 0x4d, 0xa0, 0xe4, 0x4b,
        0x41, 0xac, 0xfd, 0x64, 0x6f, 0xd8, 0x13, 0x64,
        0x47, 0x22, 0xef, 0xd6, 0x5a, 0xa6, 0x5b, 0x5b,
    ]);
    let keyholder_2 = account([
        0x44, 0xd1, 0xc0, 0x84, 0xf7, 0xa1, 0x7e, 0x2b,
        0xeb, 0x08, 0x0c, 0xd5, 0x1c, 0x85, 0xbc, 0x2e,
        0x21, 0x4c, 0xfc, 0xe1, 0x91, 0x4b, 0x0a, 0xd3,
        0x84, 0xbb, 0x4e, 0xed, 0x99, 0xe7, 0x97, 0x76,
    ]);
    let keyholder_3 = account([
        0xea, 0x7e, 0xa0, 0x2e, 0xce, 0x50, 0x45, 0x39,
        0x78, 0x98, 0x1b, 0x20, 0xbe, 0xf4, 0xec, 0x39,
        0x18, 0x13, 0x49, 0x12, 0x29, 0x96, 0x53, 0x4d,
        0x8a, 0xce, 0xb0, 0x1d, 0xa2, 0x2f, 0x44, 0x00,
    ]);
    // 2-of-3 multisig of keyholders [Nate, K2, K3] with threshold=2.
    // VERIFIED by substrate-interface and by the chain itself (prior v3 attempt
    // emitted NewMultisig with this exact address when Nate called as_multi).
    //
    //   Nate (5E25rtEBkk8UXbAGPWsiwi82pmUtdmrFSCv7wQekSnSVpiZf)
    //   K2   (5DcwRUB9FBS7PQdTdkFtvj4ssc2FPVpxgumZsWjLMmhvzrTa)
    //   K3   (5HNAgGdHwaJQyCuZVQEHavQLb25XT3aYXcDBCGLe9hbpFiP2)
    //
    // Derivation: blake2_256("modlpy/utilisuba" ++ SCALE(sorted_pubkeys) ++ SCALE(u16 threshold))
    // Result:    0x2989e974ed4960137c9d16234524a7f5178d1a680483453dcd3f3209e63af692
    // SS58 (42): 5D1AnhuDNuvHbRzMeLGt235BMMcNSaB4wAad6us55xLGxUfM
    //
    // The previous v3 attempts carried an incorrect address (0x7fdedf68...) that
    // didn't derive from any known signatories — it was a typo that made sudo
    // unreachable. THIS time the bytes are the genuine multi_account_id.
    let multisig_sudo = account([
        0x29, 0x89, 0xe9, 0x74, 0xed, 0x49, 0x60, 0x13,
        0x7c, 0x9d, 0x16, 0x23, 0x45, 0x24, 0xa7, 0xf5,
        0x17, 0x8d, 0x1a, 0x68, 0x04, 0x83, 0x45, 0x3d,
        0xcd, 0x3f, 0x32, 0x09, 0xe6, 0x3a, 0xf6, 0x92,
    ]); // 5D1AnhuDNuvHbRzMeLGt235BMMcNSaB4wAad6us55xLGxUfM (2-of-3 multisig of Nate+K2+K3)
    let macbook_account = account([
        0x20, 0xcd, 0xba, 0x0a, 0x5d, 0x36, 0x8c, 0x5e,
        0xb0, 0xee, 0x11, 0x9d, 0x25, 0xf4, 0x40, 0xf8,
        0xc2, 0x61, 0xeb, 0xd5, 0x0f, 0x23, 0x63, 0xda,
        0xe4, 0xeb, 0x3e, 0xd6, 0x07, 0xf6, 0x4c, 0x08,
    ]);
    let gemtek_account = account([
        0x7e, 0x27, 0xbb, 0x13, 0xfd, 0x6f, 0xb6, 0x2c,
        0xc0, 0xe7, 0xc5, 0x99, 0x16, 0x95, 0x2c, 0x8c,
        0x21, 0x49, 0x60, 0x90, 0x42, 0x08, 0x29, 0x5a,
        0x0d, 0x70, 0xc4, 0xc4, 0x8e, 0x2a, 0x9a, 0x29,
    ]);
    let node2_account = account([
        0x8e, 0xd4, 0x46, 0xc7, 0x11, 0x4f, 0xbe, 0xb7,
        0x51, 0x86, 0x6e, 0x67, 0x52, 0xde, 0xdf, 0x36,
        0xfb, 0xa9, 0xb3, 0xd2, 0x83, 0x2a, 0x9f, 0xc5,
        0x0a, 0x00, 0x5e, 0x00, 0xed, 0x0a, 0xb1, 0x24,
    ]);
    let node3_account = account([
        0x92, 0x5f, 0xe8, 0x60, 0x5f, 0xe3, 0x2a, 0x53,
        0xa7, 0xb3, 0x91, 0x49, 0x8f, 0xc1, 0xb0, 0xab,
        0x91, 0xd3, 0xaf, 0x73, 0x19, 0x60, 0x7b, 0xd7,
        0x0b, 0x85, 0x0b, 0x4f, 0x5f, 0xa9, 0xd2, 0x55,
    ]);

    // -- Authority keys --
    let macbook_aura = AuraId::from(sp_core::sr25519::Public::from_raw([
        0x20, 0xcd, 0xba, 0x0a, 0x5d, 0x36, 0x8c, 0x5e,
        0xb0, 0xee, 0x11, 0x9d, 0x25, 0xf4, 0x40, 0xf8,
        0xc2, 0x61, 0xeb, 0xd5, 0x0f, 0x23, 0x63, 0xda,
        0xe4, 0xeb, 0x3e, 0xd6, 0x07, 0xf6, 0x4c, 0x08,
    ]));
    let macbook_grandpa = GrandpaId::from(sp_core::ed25519::Public::from_raw([
        0xc0, 0x5b, 0x56, 0xda, 0xb7, 0xa8, 0x70, 0x18,
        0x71, 0xa8, 0xbe, 0x75, 0xae, 0xd6, 0xe2, 0xad,
        0x8c, 0x5e, 0xb5, 0xff, 0x93, 0x5d, 0xdd, 0x2b,
        0x00, 0xee, 0xca, 0x72, 0x99, 0xaf, 0x35, 0xb1,
    ]));
    let gemtek_aura = AuraId::from(sp_core::sr25519::Public::from_raw([
        0x7e, 0x27, 0xbb, 0x13, 0xfd, 0x6f, 0xb6, 0x2c,
        0xc0, 0xe7, 0xc5, 0x99, 0x16, 0x95, 0x2c, 0x8c,
        0x21, 0x49, 0x60, 0x90, 0x42, 0x08, 0x29, 0x5a,
        0x0d, 0x70, 0xc4, 0xc4, 0x8e, 0x2a, 0x9a, 0x29,
    ]));
    let gemtek_grandpa = GrandpaId::from(sp_core::ed25519::Public::from_raw([
        0x6c, 0x48, 0x4a, 0x9d, 0x5a, 0x8d, 0x01, 0x82,
        0xe0, 0xf3, 0xbf, 0x9d, 0x8f, 0xfc, 0x4c, 0xa7,
        0x07, 0x0f, 0xd0, 0x8d, 0xa4, 0x73, 0x29, 0xaf,
        0xca, 0x79, 0xf4, 0xb3, 0xdf, 0x6a, 0xaa, 0x7e,
    ]));
    let node2_aura = AuraId::from(sp_core::sr25519::Public::from_raw([
        0x8e, 0xd4, 0x46, 0xc7, 0x11, 0x4f, 0xbe, 0xb7,
        0x51, 0x86, 0x6e, 0x67, 0x52, 0xde, 0xdf, 0x36,
        0xfb, 0xa9, 0xb3, 0xd2, 0x83, 0x2a, 0x9f, 0xc5,
        0x0a, 0x00, 0x5e, 0x00, 0xed, 0x0a, 0xb1, 0x24,
    ]));
    let node2_grandpa = GrandpaId::from(sp_core::ed25519::Public::from_raw([
        0x4d, 0xc9, 0xc8, 0xf9, 0xbd, 0x37, 0xdf, 0x2b,
        0xb9, 0x22, 0x34, 0x58, 0xc8, 0x97, 0xb0, 0x00,
        0xfe, 0x43, 0x62, 0x95, 0x8d, 0xa6, 0xee, 0xb6,
        0x41, 0x3b, 0x93, 0xdc, 0xfb, 0xab, 0xe2, 0xba,
    ]));
    let node3_aura = AuraId::from(sp_core::sr25519::Public::from_raw([
        0x92, 0x5f, 0xe8, 0x60, 0x5f, 0xe3, 0x2a, 0x53,
        0xa7, 0xb3, 0x91, 0x49, 0x8f, 0xc1, 0xb0, 0xab,
        0x91, 0xd3, 0xaf, 0x73, 0x19, 0x60, 0x7b, 0xd7,
        0x0b, 0x85, 0x0b, 0x4f, 0x5f, 0xa9, 0xd2, 0x55,
    ]));
    let node3_grandpa = GrandpaId::from(sp_core::ed25519::Public::from_raw([
        0x75, 0x0d, 0x4b, 0xa2, 0xa8, 0x31, 0xa3, 0x0d,
        0x41, 0x90, 0x09, 0xf2, 0xd8, 0xbc, 0x1e, 0xf1,
        0xe6, 0xfc, 0x6f, 0x67, 0x3c, 0x7a, 0x2b, 0x5b,
        0x50, 0x0a, 0x2b, 0x7f, 0x2a, 0x68, 0x45, 0x8e,
    ]));

    Ok(ChainSpec::builder(
        WASM_BINARY.ok_or("WASM binary not available")?,
        None,
    )
    .with_name("Materios Preprod v5")
    .with_id("materios_preprod_v5")
    .with_chain_type(ChainType::Live)
    .with_protocol_id("materios-preprod-v5")
    .with_properties({
        // Token metadata — required so explorers / wallets display correct units.
        // MATRA = 6 decimals (matches cMATRA on Cardano; constrained by u64).
        // MOTRA = 15 decimals (Midnight DUST parity; separate pallet storage).
        let mut props = serde_json::Map::new();
        props.insert("tokenDecimals".to_string(), serde_json::json!(6));
        props.insert("tokenSymbol".to_string(), serde_json::json!("MATRA"));
        props.insert("ss58Format".to_string(), serde_json::json!(42));
        props
    })
    .with_genesis_config_patch(serde_json::json!({
        "balances": {
            "balances": [
                // Faucet signer (//Alice) — 10M MATRA for drips
                [alice_faucet, 10_000_000_000_000u128],
                // Multisig sudo account — 1,000 MATRA for governance ops
                [multisig_sudo, 1_000_000_000u128],
                // 3 multisig keyholders — 100 MATRA each for governance TXs
                [keyholder_1, 100_000_000u128],
                [keyholder_2, 100_000_000u128],
                [keyholder_3, 100_000_000u128],
                // 4 validator accounts — 100 MATRA each for MOTRA generation
                [macbook_account, 100_000_000u128],
                [gemtek_account, 100_000_000u128],
                [node2_account, 100_000_000u128],
                [node3_account, 100_000_000u128],
            ]
        },
        "sudo": {
            "key": multisig_sudo
        },
        // Initial Aura/Grandpa authorities (bootstrap set).
        // Session pallet takes over authority management after first epoch.
        "aura": {
            "authorities": [macbook_aura, gemtek_aura, node2_aura, node3_aura],
        },
        "grandpa": {
            "authorities": [[macbook_grandpa, 1], [gemtek_grandpa, 1], [node2_grandpa, 1], [node3_grandpa, 1]],
        },
        "motra": {
            // v5 decimals: MATRA=6, MOTRA=15. These must mirror MotraParams::default() in
            // pallets/motra/src/types.rs (genesis build ignores the Rust Default and applies
            // the chain-spec values directly).
            "minFee": 1_000_000_000u128,
            "congestionRate": 0,
            "targetFullnessPpm": 500_000_000,
            "decayRatePerBlockPpm": 999_900_000,
            "generationPerMatraPerBlock": 100_000u128,
            "maxBalance": 1_000_000_000_000_000_000u128,
            "maxCongestionStep": 1_000_000_000u128,
            "lengthFeePerByte": 1_000_000u128,
            "congestionSmoothingPpm": 100_000_000
        },
        // -- IOG partner-chain pallets (permissioned-only mode, D=1.0) --
        // Serialization rules learned the hard way:
        //  * pallet-level keys are camelCase (sessionCommitteeManagement, mainChainScripts)
        //    because the runtime's aggregate GenesisConfig uses rename_all="camelCase"
        //  * INNER sub-struct fields (MainChainScripts) are snake_case because that
        //    struct has plain serde derive with no rename_all. Using camelCase there
        //    is silently dropped as "unknown field" and leaves Default (all zeros).
        // Real deployed contract values from project_cardano_preprod_contracts.md.
        "sidechain": {
            "genesisUtxo": "0bacdb7e50ba61a1f9e28007a4f9543fa0e8e31ce10027b2f1dda8ab3438d388#0",
            "slotsPerEpoch": PREPROD_SLOTS_PER_EPOCH,
        },
        "session": {
            "initialValidators": [
                [macbook_aura, { "aura": macbook_aura, "grandpa": macbook_grandpa }],
                [gemtek_aura,  { "aura": gemtek_aura,  "grandpa": gemtek_grandpa  }],
                [node2_aura,   { "aura": node2_aura,   "grandpa": node2_grandpa   }],
                [node3_aura,   { "aura": node3_aura,   "grandpa": node3_grandpa   }],
            ],
        },
        "sessionCommitteeManagement": {
            "initialAuthorities": [],
            "mainChainScripts": {
                // MainchainAddress serializes as hex of UTF-8 bytes of the bech32 string
                // (the follower queries db-sync for the literal address string).
                // Hex below = "addr_test1wzr6en3y43437qps5wscegufxw0euspmy0c3976mjm95j0cwuvezm"
                "committee_candidate_address": "0x616464725f7465737431777a7236656e337934333433377170733577736365677566787730657573706d793063333937366d6a6d39356a3063777576657a6d",
                "d_parameter_policy_id": "0x7f57bb675447c65ba0d68270a6b9b93aecc8dfdacaa3aa8cd081f9f3",
                "permissioned_candidates_policy_id": "0x70cd1c6fbbbd7b1e855f589abd842f433ec0d7b46c7a9e437194e931",
            },
        },
        "palletSession": {},
        // nativeTokenManagement left to runtime defaults — no native token is
        // minted to it yet on Cardano preprod, so the zero policy id + empty
        // validator address are intentional. Set via sudo when a token is
        // deployed. (Providing wrong field names here would fail build-spec
        // deserialization; the expected snake_case fields are
        // native_token_policy_id, native_token_asset_name, and
        // illiquid_supply_validator_address.)
    }))
    .build())
}
