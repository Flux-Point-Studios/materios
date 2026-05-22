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

/// Preprod chain spec: 4-validator authority set (Gemtek, Node-2, Node-3,
/// MacBook), 2-of-3 multisig sudo, governance-tuned constants baked into
/// genesis so chain-resets inherit them (compile-time defaults override
/// runtime storage on reset).
///
/// AttestationThreshold + initial CommitteeMembers are NOT yet exposed in
/// `pallet-orinq-receipts` GenesisConfig; restore those via post-genesis
/// multisig sudo until that surface lands.
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
    //   Nate (5E25rtEBkk8UXbAGPWsiwi82pmUtdmrFSCv7wQekSnSVpiZf)
    //   K2   (5DcwRUB9FBS7PQdTdkFtvj4ssc2FPVpxgumZsWjLMmhvzrTa)
    //   K3   (5HNAgGdHwaJQyCuZVQEHavQLb25XT3aYXcDBCGLe9hbpFiP2)
    // Derivation:
    //   blake2_256("modlpy/utilisuba" ++ SCALE(sorted_pubkeys) ++ SCALE(u16 threshold))
    //   = 0x2989e974ed4960137c9d16234524a7f5178d1a680483453dcd3f3209e63af692
    //   = SS58 (42) 5D1AnhuDNuvHbRzMeLGt235BMMcNSaB4wAad6us55xLGxUfM
    let multisig_sudo = account([
        0x29, 0x89, 0xe9, 0x74, 0xed, 0x49, 0x60, 0x13,
        0x7c, 0x9d, 0x16, 0x23, 0x45, 0x24, 0xa7, 0xf5,
        0x17, 0x8d, 0x1a, 0x68, 0x04, 0x83, 0x45, 0x3d,
        0xcd, 0x3f, 0x32, 0x09, 0xe6, 0x3a, 0xf6, 0x92,
    ]);
    // MacBook AURA pubkey (block-author key); SS58 (42)
    // 5CoiW8b5wm45shiSagjxyFgpz7DS8pZiESQRVUcxJU1W687J.
    let macbook_account = account([
        0x20, 0xcd, 0xba, 0x0a, 0x5d, 0x36, 0x8c, 0x5e,
        0xb0, 0xee, 0x11, 0x9d, 0x25, 0xf4, 0x40, 0xf8,
        0xc2, 0x61, 0xeb, 0xd5, 0x0f, 0x23, 0x63, 0xda,
        0xe4, 0xeb, 0x3e, 0xd6, 0x07, 0xf6, 0x4c, 0x08,
    ]);
    // MacBook CERT-DAEMON account, distinct from the aura key (separate
    // mnemonic so validator/attestor responsibilities can rotate
    // independently); SS58 (42) 5GgCBrKDwMCWckd8P7CNLxy2ARmPHRVE4yjXuTP1vfwNtYzX.
    // Needs `BondRequirement + buffer` MATRA at genesis so the daemon can
    // auto-bond + join_committee on first run.
    let macbook_cert_daemon = account([
        0xcc, 0x01, 0xe4, 0x88, 0x13, 0x48, 0x01, 0x4c,
        0xc4, 0x14, 0xcd, 0x33, 0xc9, 0xa3, 0x97, 0xd5,
        0xd6, 0xed, 0xb1, 0x1c, 0x6c, 0x9d, 0x92, 0x9e,
        0x37, 0xb6, 0xaf, 0x76, 0x08, 0x93, 0x2f, 0x71,
    ]);
    // SECURITY: the previous Gemtek key 0x7e27bb13... must never be
    // reintroduced — its mnemonic got anchored to Cardano mainnet. Current
    // SS58 = 5Dd7WuLMyb71NT1Bea6oEZH8Je3MkQzamHVeU4tmQbtPWq2v.
    let gemtek_account = account([
        0x44, 0xf3, 0xba, 0xfb, 0xc3, 0x93, 0xf2, 0x4f,
        0xcf, 0xab, 0xbf, 0x57, 0xd4, 0xca, 0x73, 0xa6,
        0xa6, 0xb5, 0xdf, 0x35, 0x8c, 0xda, 0xa9, 0x48,
        0x0a, 0x51, 0x7a, 0x97, 0xf1, 0x89, 0x96, 0x4b,
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
        0x44, 0xf3, 0xba, 0xfb, 0xc3, 0x93, 0xf2, 0x4f,
        0xcf, 0xab, 0xbf, 0x57, 0xd4, 0xca, 0x73, 0xa6,
        0xa6, 0xb5, 0xdf, 0x35, 0x8c, 0xda, 0xa9, 0x48,
        0x0a, 0x51, 0x7a, 0x97, 0xf1, 0x89, 0x96, 0x4b,
    ]));
    let gemtek_grandpa = GrandpaId::from(sp_core::ed25519::Public::from_raw([
        0x45, 0x58, 0x85, 0x34, 0x22, 0x16, 0x49, 0x39,
        0xec, 0xa6, 0x90, 0xf2, 0x1f, 0x76, 0xa6, 0x14,
        0xf7, 0x95, 0x73, 0x52, 0xe0, 0x1a, 0x44, 0x8a,
        0x49, 0x86, 0xca, 0x3d, 0x55, 0xd9, 0x8f, 0x23,
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
    .with_name("Materios Preprod v6")
    .with_id("materios_preprod_v6")
    .with_chain_type(ChainType::Live)
    .with_protocol_id("materios-preprod-v6")
    .with_properties({
        // MATRA = 6 decimals (matches cMATRA on Cardano); MOTRA = 15
        // decimals (Midnight DUST parity, separate pallet storage).
        let mut props = serde_json::Map::new();
        props.insert("tokenDecimals".to_string(), serde_json::json!(6));
        props.insert("tokenSymbol".to_string(), serde_json::json!("MATRA"));
        props.insert("ss58Format".to_string(), serde_json::json!(42));
        props
    })
    .with_genesis_config_patch(serde_json::json!({
        "balances": {
            "balances": [
                // //Alice faucet — 10M MATRA for drips + rescues.
                [alice_faucet, 10_000_000_000_000u128],
                // 2-of-3 multisig sudo — 1k MATRA for governance ops +
                // multisig deposits.
                [multisig_sudo, 1_000_000_000u128],
                // 3 keyholders — 1k MATRA each so MOTRA accrues fast enough
                // to dispatch the first multisig sudo without a //Alice
                // MOTRA-bootstrap.
                [keyholder_1, 1_000_000_000u128],
                [keyholder_2, 1_000_000_000u128],
                [keyholder_3, 1_000_000_000u128],
                // 4 cert-daemon accounts — `BondRequirement` (1k MATRA) +
                // 100 buffer for fees + above-ED. Linux nodes reuse the aura
                // key; MacBook uses a separate mnemonic.
                [gemtek_account, 1_100_000_000u128],
                [node2_account, 1_100_000_000u128],
                [node3_account, 1_100_000_000u128],
                [macbook_cert_daemon, 1_100_000_000u128],
                // MacBook AURA account — 100 MATRA (block-author key only).
                [macbook_account, 100_000_000u128],
            ]
        },
        "sudo": {
            "key": multisig_sudo
        },
        "aura": {
            "authorities": [macbook_aura, gemtek_aura, node2_aura, node3_aura],
        },
        "grandpa": {
            "authorities": [[macbook_grandpa, 1], [gemtek_grandpa, 1], [node2_grandpa, 1], [node3_grandpa, 1]],
        },
        "motra": {
            // MUST mirror `MotraParams::default()` in pallets/motra/src/types.rs
            // — genesis build ignores Rust Default and applies these directly.
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
        // OrinqReceipts: every value baked in here is a governance-tuned
        // constant that compile-time defaults would otherwise override at
        // chain reset. INNER fields use snake_case (the pallet's GenesisConfig
        // has plain serde derive with no rename_all); the OUTER pallet key
        // is camelCase per the runtime aggregate GenesisConfig's
        // rename_all="camelCase".
        //
        // NOT YET EXPOSED at genesis: attestation_threshold + initial
        // committee members — restore via post-genesis multisig sudo.
        "orinqReceipts": {
            // 1 MATRA per signer (default 10 would 99.3% over-pay).
            "attestation_reward_per_signer": 1_000_000u128,
            // 50K MATRA cap per era.
            "era_cap_base": 50_000_000_000u128,
            // Matches the 64-cap committee size (default 16 under-allocates).
            "era_cap_baseline_attestor_count": 32u32,
            // Pinned explicit so a future chain-spec change can't silently
            // drop it to 0 and open a committee-dilution attack.
            "bond_requirement": 1_000_000_000u128,
            "receipt_submission_fee": 1_000_000u128,
            "receipt_submission_fee_floor": 100_000u128,
            // ~24h at 6s blocks.
            "receipt_expiry_blocks": 14_400u32
        },
        // IOG partner-chain pallets (permissioned-only mode, D=1.0).
        //
        // Serialization rules:
        //  - pallet-level keys are camelCase (runtime aggregate GenesisConfig
        //    has rename_all="camelCase")
        //  - INNER sub-struct fields (MainChainScripts) are snake_case
        //    because that struct has plain serde derive. Using camelCase
        //    there is SILENTLY dropped as "unknown field" and leaves
        //    Default (all zeros).
        "sidechain": {
            "genesisUtxo": "13313ea0119e0c4330f64f1809159064a371a1bbf2050b1fe13d5492280dca50#0",
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
                // MainchainAddress serializes as hex of UTF-8 bytes of the
                // bech32 string (the follower queries db-sync for the literal
                // address). Hex below =
                // "addr_test1wrld9uhaepas48twjy3qevncsyrhjdqnkz2wzu4yzjc2qhq24f4v4".
                "committee_candidate_address": "0x616464725f746573743177726c643975686165706173343874776a79337165766e63737972686a64716e6b7a32777a7534797a6a6332716871323466347634",
                "d_parameter_policy_id": "0x38dddaf5198b927b19dac9b28226ab29eddad176d5d81c7748bc2c31",
                "permissioned_candidates_policy_id": "0xef2890d1e98247819abcf2df6e891824ed950a4216d36c71ee6f9974",
            },
        },
        "palletSession": {},
        // nativeTokenManagement left to runtime defaults until a token is
        // deployed. Expected snake_case fields if set later:
        // native_token_policy_id, native_token_asset_name,
        // illiquid_supply_validator_address.
    }))
    .build())
}
