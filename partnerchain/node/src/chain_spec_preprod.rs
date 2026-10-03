//! Chain specification for Materios Preprod — clean genesis, no overrides.

use crate::chain_spec::Authority;
use materios_runtime::{
    opaque::SessionKeys, CrossChainPublic, Multisig, TESTNET_TIMELOCK_DELAYS, WASM_BINARY,
};
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
    let mut keyholders = [
        keyholder_1.clone(),
        keyholder_2.clone(),
        keyholder_3.clone(),
    ];
    keyholders.sort();
    let keyholders_3_of_3 = Multisig::multi_account_id(&keyholders, 3);
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
    // Cross-chain keys: each authority's sidechain key in the Cardano
    // permissioned candidates datum, so the genesis committee names the same
    // validators Cardano's draw does.
    let macbook_cross_chain = CrossChainPublic::from(sp_core::ecdsa::Public::from_raw([
        0x02, 0xec, 0x64, 0x82, 0x23, 0x00, 0x71, 0x35,
        0x85, 0xd9, 0xb0, 0xc3, 0xeb, 0x14, 0x56, 0xbb,
        0x99, 0xc3, 0xcc, 0x42, 0xd7, 0x9f, 0x4a, 0xb8,
        0xe5, 0x35, 0x38, 0xe5, 0x0c, 0x9b, 0xed, 0x0a,
        0x61,
    ]));
    let gemtek_cross_chain = CrossChainPublic::from(sp_core::ecdsa::Public::from_raw([
        0x03, 0x47, 0x7f, 0xc2, 0xa5, 0xb7, 0xb2, 0x87,
        0xed, 0x89, 0xec, 0x47, 0x55, 0x6e, 0x00, 0x02,
        0xaa, 0x0d, 0x7c, 0xf8, 0x8b, 0x1f, 0xbd, 0x6f,
        0xbe, 0x17, 0x22, 0xeb, 0x1e, 0xf7, 0x87, 0x35,
        0x99,
    ]));
    let node2_cross_chain = CrossChainPublic::from(sp_core::ecdsa::Public::from_raw([
        0x03, 0x4f, 0x29, 0x3c, 0x28, 0x1c, 0x59, 0xb8,
        0x20, 0x0e, 0xa3, 0x16, 0xd1, 0xc8, 0xd7, 0x15,
        0x4c, 0x1b, 0x06, 0xa9, 0xed, 0x26, 0x03, 0x25,
        0x10, 0x49, 0xb9, 0xfd, 0xa6, 0x3f, 0x2e, 0xd6,
        0xce,
    ]));
    let node3_cross_chain = CrossChainPublic::from(sp_core::ecdsa::Public::from_raw([
        0x03, 0xf2, 0xc1, 0xc5, 0x0d, 0x62, 0xf0, 0x23,
        0xc6, 0x37, 0xaf, 0xe7, 0x99, 0x96, 0x84, 0x31,
        0x57, 0xc6, 0x91, 0x4e, 0x92, 0x96, 0x05, 0xcd,
        0xe3, 0xc5, 0x3d, 0xe4, 0x7a, 0x68, 0x96, 0xfc,
        0x0e,
    ]));
    let authority =
        |cross_chain, aura, grandpa| -> Authority { (cross_chain, SessionKeys { aura, grandpa }) };
    let authorities = vec![
        authority(macbook_cross_chain, macbook_aura, macbook_grandpa),
        authority(gemtek_cross_chain, gemtek_aura, gemtek_grandpa),
        authority(node2_cross_chain, node2_aura, node2_grandpa),
        authority(node3_cross_chain, node3_aura, node3_grandpa),
    ];

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
        // Short delays so ceremonies can be rehearsed. The guardian is the
        // keyholders' 3-of-3 multisig: an account apart from the 2-of-3 sudo
        // key, held by the same keyholders, which rehearses vetoes and
        // co-signs but cannot answer a stolen sudo key. A mainnet guardian
        // is held by other keyholders.
        "rootTimelock": {
            "delays": TESTNET_TIMELOCK_DELAYS,
            "guardian": keyholders_3_of_3,
        },
        "aura": {
            "authorities": [],
        },
        "grandpa": {
            "authorities": [],
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
        // OrinqReceipts: governance-tuned values. A FRAME pallet's genesis
        // config is camelCase with deny_unknown_fields, so a snake_case key
        // makes the whole genesis fail to build.
        //
        // NOT YET EXPOSED at genesis: attestation_threshold + initial
        // committee members — restore via post-genesis multisig sudo.
        "orinqReceipts": {
            // 1 MATRA per signer.
            "attestationRewardPerSigner": 1_000_000u128,
            // 50K MATRA cap per era.
            "eraCapBase": 50_000_000_000u128,
            // Matches the 64-cap committee size.
            "eraCapBaselineAttestorCount": 32u32,
            "bondRequirement": 1_000_000_000u128,
            "receiptSubmissionFee": 1_000_000u128,
            "receiptSubmissionFeeFloor": 100_000u128,
            // ~24h at 6s blocks.
            "receiptExpiryBlocks": 14_400u32
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
        "sessionCommitteeManagement": {
            "initialAuthorities": authorities,
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

#[cfg(test)]
mod tests {
    use super::{preprod_config, Authority, ChainSpec, CrossChainPublic, GrandpaId, SessionKeys};
    use crate::chain_spec::{
        authority_keys_from_seed,
        tests::{
            cardano, genesis_header, inherent_data, peers_check, play, propose,
            seated_after_first_rotation, seated_at_genesis, seated_now, start,
            stored_attestor_rewards, Seated,
        },
    };
    use materios_runtime::{
        Block, Header, OrinqReceipts, RuntimeCall, RuntimeOrigin, SessionCommitteeManagement,
    };
    use pallet_orinq_receipts::types::PinnedMember;
    use pallet_session_validator_management::Call;
    use sp_core::{Decode, Encode};
    use sp_inherents::InherentData;
    use sp_runtime::{traits::Block as _, BuildStorage};

    /// The permissioned candidates on Cardano preprod: each authority's
    /// cross-chain, aura and grandpa keys, in the order genesis seats them
    /// (MacBook, Gemtek, Node-2, Node-3).
    const CARDANO_CANDIDATES: [(&str, &str, &str); 4] = [
        (
            "02ec64822300713585d9b0c3eb1456bb99c3cc42d79f4ab8e53538e50c9bed0a61",
            "20cdba0a5d368c5eb0ee119d25f440f8c261ebd50f2363dae4eb3ed607f64c08",
            "c05b56dab7a8701871a8be75aed6e2ad8c5eb5ff935ddd2b00eeca7299af35b1",
        ),
        (
            "03477fc2a5b7b287ed89ec47556e0002aa0d7cf88b1fbd6fbe1722eb1ef7873599",
            "44f3bafbc393f24fcfabbf57d4ca73a6a6b5df358cdaa9480a517a97f189964b",
            "4558853422164939eca690f21f76a614f7957352e01a448a4986ca3d55d98f23",
        ),
        (
            "034f293c281c59b8200ea316d1c8d7154c1b06a9ed2603251049b9fda63f2ed6ce",
            "8ed446c7114fbeb751866e6752dedf36fba9b3d2832a9fc50a005e00ed0ab124",
            "4dc9c8f9bd37df2bb9223458c897b000fe4362958da6eeb6413b93dcfbabe2ba",
        ),
        (
            "03f2c1c50d62f023c637afe79996843157c6914e929605cde3c53de47a6896fc0e",
            "925fe8605fe32a53a7b391498fc1b0ab91d3af7319607bd70b850b4f5fa9d255",
            "750d4ba2a831a30d419009f2d8bc1ef1e6fc6f673c7a2b5b500a2b7f2a68458e",
        ),
    ];

    fn cardano_candidates() -> Vec<Authority> {
        let bytes = |hex: &str| sp_core::bytes::from_hex(hex).unwrap();
        CARDANO_CANDIDATES
            .iter()
            .map(|(cross_chain, aura, grandpa)| {
                (
                    CrossChainPublic::try_from(&bytes(cross_chain)[..]).unwrap(),
                    SessionKeys {
                        aura: TryFrom::try_from(&bytes(aura)[..]).unwrap(),
                        grandpa: TryFrom::try_from(&bytes(grandpa)[..]).unwrap(),
                    },
                )
            })
            .collect()
    }

    /// `authorities` in the order Ariadne seats them.
    fn in_seating_order(mut authorities: Vec<Authority>) -> Vec<Authority> {
        authorities.sort_by(|a, b| a.0.cmp(&b.0));
        authorities
    }

    /// `spec` with `edit` applied to its genesis patch.
    fn patched(spec: &ChainSpec, edit: impl FnOnce(&mut serde_json::Value)) -> ChainSpec {
        let mut json: serde_json::Value =
            serde_json::from_str(&spec.as_json(false).unwrap()).unwrap();
        edit(&mut json["genesis"]["runtimeGenesis"]["patch"]);
        ChainSpec::from_json_bytes(json.to_string().into_bytes()).unwrap()
    }

    /// The preprod spec with `committee` as its genesis committee, and the
    /// four authorities also seeded into Aura if `aura`, and into GRANDPA if
    /// `grandpa`.
    fn preprod_seating(committee: Vec<Authority>, aura: bool, grandpa: bool) -> ChainSpec {
        let authorities = cardano_candidates();
        patched(&preprod_config().unwrap(), |patch| {
            patch["sessionCommitteeManagement"]["initialAuthorities"] =
                serde_json::json!(committee);
            if aura {
                patch["aura"] = serde_json::json!({
                    "authorities": authorities.iter().map(|(_, keys)| &keys.aura).collect::<Vec<_>>(),
                });
            }
            if grandpa {
                patch["grandpa"] = serde_json::json!({
                    "authorities": authorities.iter().map(|(_, keys)| (&keys.grandpa, 1)).collect::<Vec<_>>(),
                });
            }
        })
    }

    /// The first slot of sidechain epoch `epoch`.
    fn epoch_start(epoch: u64) -> u64 {
        epoch * u64::from(super::PREPROD_SLOTS_PER_EPOCH)
    }

    /// The four authorities and Charlie, so a draw seats five, with a quorum
    /// of four live authors.
    fn the_four_and_charlie() -> Vec<Authority> {
        let mut listed = cardano_candidates();
        listed.push(authority_keys_from_seed("Charlie"));
        listed
    }

    /// Gemtek, Node-2 and Node-3 author epoch 1000's last three blocks while
    /// Cardano lists `the_four_and_charlie`. Returns the last. MacBook's
    /// first block would be the next, the first of epoch 1001, which rotates
    /// the committee and proposes the next one: a draw of five that only
    /// MacBook's own block brings to a quorum of live authors.
    fn three_authors_before_the_rotation() -> Result<Header, String> {
        let listed = cardano(&the_four_and_charlie());
        let mut parent = genesis_header();
        for slot in epoch_start(1_001) - 3..epoch_start(1_001) {
            parent = play(&parent, slot, &listed)?;
        }
        Ok(parent)
    }

    fn macbook_authors_first_at_the_rotation() -> Result<Header, String> {
        let parent = three_authors_before_the_rotation()?;
        play(
            &parent,
            epoch_start(1_001),
            &cardano(&the_four_and_charlie()),
        )
    }

    /// Cardano's permissioned list for each sidechain epoch from 1000 to
    /// 1009, while FPS ramps a core onto it every other epoch from 1002,
    /// then swaps the second one out for another at 1007.
    fn ramped_then_swapped() -> Vec<(u64, Vec<Authority>)> {
        let cores = cardano_candidates();
        let [p5, p6, p7, p8] = ["Charlie", "Dave", "Eve", "Ferdie"].map(authority_keys_from_seed);
        (1_000..=1_009)
            .map(|epoch| {
                let added = match epoch {
                    ..=1_001 => vec![],
                    1_002..=1_003 => vec![&p5],
                    1_004..=1_005 => vec![&p5, &p6],
                    1_006 => vec![&p5, &p6, &p7],
                    _ => vec![&p5, &p7, &p8],
                };
                (epoch, cores.iter().chain(added).cloned().collect())
            })
            .collect()
    }

    /// Plays block 1 at epoch 1000's last slot, then the first 15 slots of
    /// each epoch from 1001 to 1009, every slot's author online, while
    /// Cardano lists `ramped_then_swapped`. Returns each GRANDPA set a block
    /// scheduled.
    fn play_the_ramp() -> Result<Vec<Vec<GrandpaId>>, String> {
        let mut parent = genesis_header();
        let mut scheduled = Vec::new();
        for (epoch, listed) in ramped_then_swapped() {
            let listed = cardano(&listed);
            let slots = match epoch {
                1_000 => epoch_start(1_001) - 1..epoch_start(1_001),
                _ => epoch_start(epoch)..epoch_start(epoch) + 15,
            };
            for slot in slots {
                parent = play(&parent, slot, &listed)?;
                if let Some(change) = sc_consensus_grandpa::find_scheduled_change::<Block>(&parent)
                {
                    scheduled.push(
                        change
                            .next_authorities
                            .into_iter()
                            .map(|(key, _)| key)
                            .collect(),
                    );
                }
            }
        }
        Ok(scheduled)
    }

    /// `block` with its committee inherent seating `committee` instead.
    fn seating(block: &Block, committee: Vec<Authority>) -> Block {
        let (header, mut inherents) = block.clone().deconstruct();
        let set = inherents
            .iter_mut()
            .find_map(|inherent| match &mut inherent.function {
                RuntimeCall::SessionCommitteeManagement(Call::set { validators, .. }) => {
                    Some(validators)
                }
                _ => None,
            })
            .expect("the block carries a committee inherent");
        *set = committee.try_into().unwrap();
        Block::new(header, inherents)
    }

    /// Whether a peer that runs `code`, the runtime a spec carries, in the
    /// node's WASM executor accepts `block`'s inherents, checked with `data`
    /// on `state` as the parent's. What the check writes is thrown away.
    fn compiled_peers_accept(
        state: &mut sp_io::TestExternalities,
        code: &[u8],
        block: &Block,
        data: &InherentData,
    ) -> bool {
        use sp_core::traits::{
            CallContext, CodeExecutor, Externalities, RuntimeCode, WrappedRuntimeCode,
        };
        let fetcher = WrappedRuntimeCode(code.into());
        let runtime_code = RuntimeCode {
            code_fetcher: &fetcher,
            heap_pages: None,
            hash: sp_core::blake2_256(code).to_vec(),
        };
        let mut ext = state.ext();
        ext.storage_start_transaction();
        let (checked, _) = sc_executor::WasmExecutor::<sp_io::SubstrateHostFunctions>::builder()
            .build()
            .call(
                &mut ext,
                &runtime_code,
                "BlockBuilder_check_inherents",
                &(block, data).encode(),
                CallContext::Offchain,
            );
        ext.storage_rollback_transaction().unwrap();
        sp_inherents::CheckInherentsResult::decode(&mut &checked.expect("the runtime runs")[..])
            .unwrap()
            .ok()
    }

    fn next_committee() -> Option<Vec<Authority>> {
        SessionCommitteeManagement::next_committee_storage().map(|next| next.committee.to_vec())
    }

    /// Root's levers on committee selection, each as Root arms it: every
    /// gate flag alone, all four together, and a pinned committee. The
    /// break-glass holders are the genesis authorities.
    fn levers() -> Vec<(&'static str, Box<dyn Fn()>)> {
        let root = RuntimeOrigin::root;
        let arm_break_glass = move || {
            let holders = cardano_candidates()
                .iter()
                .map(|(_, keys)| keys.aura.encode().try_into().unwrap())
                .collect();
            OrinqReceipts::set_break_glass_aura_keys(root(), holders).unwrap();
            OrinqReceipts::set_break_glass_floor_enabled(root(), true).unwrap();
        };
        vec![
            ("no lever", Box::new(|| ())),
            (
                "the slack invariant",
                Box::new(move || OrinqReceipts::set_slack_invariant_enabled(root(), true).unwrap()),
            ),
            (
                "the contribution window",
                Box::new(move || {
                    OrinqReceipts::set_contribution_window_enabled(root(), true).unwrap()
                }),
            ),
            (
                "core eviction",
                Box::new(move || OrinqReceipts::set_core_eviction_enabled(root(), true).unwrap()),
            ),
            ("the break-glass floor", Box::new(arm_break_glass)),
            (
                "every flag",
                Box::new(move || {
                    OrinqReceipts::set_slack_invariant_enabled(root(), true).unwrap();
                    OrinqReceipts::set_contribution_window_enabled(root(), true).unwrap();
                    OrinqReceipts::set_core_eviction_enabled(root(), true).unwrap();
                    arm_break_glass();
                }),
            ),
            (
                "a pinned committee",
                Box::new(move || {
                    let members = cardano_candidates()
                        .iter()
                        .map(|(cross_chain, keys)| PinnedMember {
                            cross_chain: cross_chain.encode().try_into().unwrap(),
                            aura: keys.aura.encode().try_into().unwrap(),
                            grandpa: keys.grandpa.encode().try_into().unwrap(),
                        })
                        .collect();
                    OrinqReceipts::set_pinned_committee(root(), members, u64::MAX).unwrap()
                }),
            ),
        ]
    }

    #[test]
    fn a_fresh_preprod_chain_keeps_its_authorities_through_the_first_rotation() {
        let spec = preprod_config().unwrap();
        let authorities = cardano_candidates();
        assert_eq!(
            seated_after_first_rotation(&spec, &authorities),
            Seated::by(&authorities)
        );
        assert_eq!(seated_at_genesis(&spec), Seated::by(&authorities));
    }

    /// Genesis refuses, with its reason, a committee the chain cannot run
    /// from. Without one, block 1 proposes an empty committee and the first
    /// rotation schedules an empty GRANDPA set, which the node's block import
    /// refuses; a key listed twice votes twice; and Aura and GRANDPA are
    /// seated from the committee alone.
    #[test]
    fn genesis_refuses_a_committee_the_chain_cannot_run_from() {
        let four = cardano_candidates;
        let edited = |edit: fn(&mut Vec<Authority>)| {
            let mut committee = four();
            edit(&mut committee);
            preprod_seating(committee, false, false)
        };
        let oversized = in_seating_order(
            (0..=materios_runtime::MAX_VALIDATORS)
                .map(|seat| authority_keys_from_seed(&format!("Seat{seat}")))
                .collect(),
        );
        let mut not_refused = Vec::new();
        for (case, spec, reason) in [
            (
                "Aura and GRANDPA seeded without a committee",
                preprod_seating(Vec::new(), true, true),
                "the genesis committee is empty",
            ),
            (
                "no committee",
                preprod_seating(Vec::new(), false, false),
                "the genesis committee is empty",
            ),
            (
                "Aura seeded too",
                preprod_seating(four(), true, false),
                "leave aura and grandpa empty",
            ),
            (
                "GRANDPA seeded too",
                preprod_seating(four(), false, true),
                "leave aura and grandpa empty",
            ),
            (
                "more seats than MaxValidators",
                preprod_seating(oversized, false, false),
                "more seats than MaxValidators",
            ),
            (
                "an authority listed twice",
                edited(|committee| committee[3] = committee[0].clone()),
                "ascending cross-chain-key order",
            ),
            (
                "two authorities out of order",
                edited(|committee| committee.swap(0, 1)),
                "ascending cross-chain-key order",
            ),
            (
                "two authorities sharing an Aura key",
                edited(|committee| committee[1].1.aura = committee[0].1.aura.clone()),
                "share an Aura or GRANDPA key",
            ),
            (
                "two authorities sharing a GRANDPA key",
                edited(|committee| committee[1].1.grandpa = committee[0].1.grandpa.clone()),
                "share an Aura or GRANDPA key",
            ),
        ] {
            match spec.build_storage() {
                Err(error) if error.contains(reason) => {}
                built => not_refused.push(format!(
                    "{case}: {:?}",
                    built
                        .map(|_| ())
                        .map_err(|error| error.lines().next().map(str::to_owned))
                )),
            }
        }
        assert!(not_refused.is_empty(), "{not_refused:#?}");
        assert!(preprod_seating(four(), false, false)
            .build_storage()
            .is_ok());
    }

    #[test]
    fn peers_accept_a_rotation_block_whose_author_makes_the_quorum_with_its_first_block() {
        start(&preprod_config().unwrap()).execute_with(|| {
            macbook_authors_first_at_the_rotation()
                .unwrap_or_else(|rejection| panic!("{rejection}"));
            assert_eq!(
                next_committee(),
                Some(in_seating_order(the_four_and_charlie()))
            );
        });
    }

    /// The check still bites: MacBook's rotation block re-proposing the
    /// genesis committee, where the draw seats Charlie too, is rejected.
    #[test]
    fn peers_reject_a_rotation_block_that_keeps_the_committee_the_draw_replaces() {
        start(&preprod_config().unwrap()).execute_with(|| {
            let parent = three_authors_before_the_rotation()
                .unwrap_or_else(|rejection| panic!("{rejection}"));
            let (block, data) = propose(
                &parent,
                epoch_start(1_001),
                &cardano(&the_four_and_charlie()),
            );
            let kept = seating(&block, cardano_candidates());
            assert_eq!(
                peers_check(&kept, &data),
                Err("/ariadne: The validators in the block do not match the calculated \
                     validators. Input data hash \
                     (0xa466c3bc80bfa4daa489a7f3a3c662edd5c5d687d3d7758d3572db7b1d285e4a) is valid."
                    .to_string())
            );
        });
    }

    /// Peers run the runtime the spec carries, compiled, not the native one
    /// the harness plays. While their Ariadne data is absent, that code
    /// accepts an honest block 1, which re-seats the genesis committee, and
    /// refuses the same block seating outsiders.
    #[test]
    fn the_compiled_runtime_refuses_a_first_block_seating_outsiders_while_peers_have_no_ariadne_data(
    ) {
        let storage = preprod_config().unwrap().build_storage().unwrap();
        let code = storage.top[sp_core::storage::well_known_keys::CODE].clone();
        let mut state = sp_io::TestExternalities::new(storage);
        let slot = epoch_start(1_001) - 1;
        let (honest, _) = state
            .execute_with(|| propose(&genesis_header(), slot, &cardano(&cardano_candidates())));
        let outsiders = ["Mallory1", "Mallory2"]
            .map(authority_keys_from_seed)
            .to_vec();
        let injected = seating(&honest, in_seating_order(outsiders));
        let without_ariadne = inherent_data(slot, None);
        let mut accepts =
            |block: &Block| compiled_peers_accept(&mut state, &code, block, &without_ariadne);
        assert!(accepts(&honest));
        assert!(!accepts(&injected));
    }

    #[test]
    fn peers_accept_every_block_while_the_slack_invariant_is_armed_and_cardano_ramps_then_swaps_a_core(
    ) {
        start(&preprod_config().unwrap()).execute_with(|| {
            OrinqReceipts::set_slack_invariant_enabled(RuntimeOrigin::root(), true).unwrap();
            play_the_ramp().unwrap_or_else(|rejection| panic!("{rejection}"));
            let (_, swapped) = ramped_then_swapped().pop().unwrap();
            assert_eq!(seated_now(), Seated::by(&in_seating_order(swapped)));
        });
    }

    #[test]
    fn peers_accept_every_block_under_each_lever_on_committee_selection() {
        let genesis = preprod_config().unwrap().build_storage().unwrap();
        let mut rejected = Vec::new();
        for (lever, arm) in levers() {
            sp_io::TestExternalities::new(genesis.clone()).execute_with(|| {
                arm();
                if let Err(rejection) = macbook_authors_first_at_the_rotation() {
                    rejected.push(format!(
                        "{lever}, MacBook first at the rotation: {rejection}"
                    ));
                }
            });
            sp_io::TestExternalities::new(genesis.clone()).execute_with(|| {
                arm();
                match play_the_ramp() {
                    Ok(scheduled) => assert!(
                        scheduled.iter().all(|set| !set.is_empty()),
                        "{lever}: {scheduled:?}"
                    ),
                    Err(rejection) => rejected.push(format!("{lever}, the ramp: {rejection}")),
                }
            });
        }
        assert!(rejected.is_empty(), "{rejected:#?}");
    }

    #[test]
    fn preprod_genesis_stores_its_tuned_attestor_rewards() {
        let storage = super::preprod_config().unwrap().build_storage().unwrap();
        assert_eq!(
            stored_attestor_rewards(storage),
            (1_000_000, 50_000_000_000, 32)
        );
    }
}
