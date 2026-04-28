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
/// v6 reset 2026-04-28: GRANDPA finality wedge recovery. Same 4 founding
/// validators (NOT 6 — SuNewbie/Hetzner onboard post-launch via standard
/// upsert-permissioned-candidates once v6 is stable). Spec-208 runtime
/// preserved (no new runtime build for genesis). Real Cardano follower from
/// genesis (no mock mode toggle anywhere in chain-spec; USE_MAIN_CHAIN_FOLLOWER_MOCK
/// is a runtime env var only and is left unset / forced false in start scripts).
/// Initial Cardano D-parameter set to (8, 0) post-genesis to dodge stock
/// Ariadne with-replacement-sampling shrink bug; bumped to (8, 2) only after
/// spec-209 ceremony (TTL + finality circuit breaker + without-replacement
/// sampling fix) lands.
///
/// 2026-04-28 governance bake-in (lesson from v5 → v6 reset): every governance-
/// tuned constant set via post-genesis sudo on v5 (block 70941 multisig batch:
/// AttestationRewardPerSigner=1M, EraCapBaselineAttestorCount=32, plus
/// AttestationThreshold=3 via setCommittee) was wiped at v6 reset because chain-
/// spec defaults baked in at compile time override runtime storage. Every cert
/// then overpaid ~99.3% MATRA per cert (~430 instead of ~3) until the same
/// multisig batch was re-fired post-v6. Permanent fix: every governance-tuned
/// value now lives in this file's `orinqReceipts` genesis patch so the next
/// reset (or fresh bootstrap, e.g. mainnet) inherits them. Founders are now
/// pre-endowed with `BondRequirement + dust + fee_buffer` to avoid the bond-
/// starvation loop that required //Alice rescue transfers post-v6 reset. See
/// `feedback_chain_reset_committee_bond_starvation.md` for the gory recovery
/// details.
///
/// NOTE: AttestationThreshold + initial CommitteeMembers are NOT yet exposed
/// in pallet-orinq-receipts GenesisConfig (only attestation_reward_per_signer,
/// era_cap_baseline_attestor_count, bond_requirement, etc. are settable at
/// genesis). A follow-up PR extends GenesisConfig to expose initial_committee_
/// members + initial_attestation_threshold so they can be baked in here too.
/// Until then, restore those two via post-genesis multisig sudo per
/// `reference_multisig_sudo.md`.
///
/// Now includes IOG partner-chain pallet genesis configuration for permissioned-only
/// mode. Cardano mainchain follower placeholders will be replaced when the
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
    // MacBook AURA pubkey — the block-author key, used in `aura.authorities` and
    // `session.initialValidators`. Derived from the MacBook validator's keystore
    // (separate Sr25519 key from the cert-daemon key below). SS58 prefix-42:
    // 5CoiW8b5wm45shiSagjxyFgpz7DS8pZiESQRVUcxJU1W687J.
    let macbook_account = account([
        0x20, 0xcd, 0xba, 0x0a, 0x5d, 0x36, 0x8c, 0x5e,
        0xb0, 0xee, 0x11, 0x9d, 0x25, 0xf4, 0x40, 0xf8,
        0xc2, 0x61, 0xeb, 0xd5, 0x0f, 0x23, 0x63, 0xda,
        0xe4, 0xeb, 0x3e, 0xd6, 0x07, 0xf6, 0x4c, 0x08,
    ]);
    // MacBook CERT-DAEMON account — distinct from the aura key on MacBook
    // (Linux validators reuse the aura key for cert-daemon by design; MacBook
    // uses a separate mnemonic so the validator/attestor responsibilities can
    // be rotated independently). SS58 prefix-42:
    // 5GgCBrKDwMCWckd8P7CNLxy2ARmPHRVE4yjXuTP1vfwNtYzX.
    // This account needs `BondRequirement + buffer` MATRA at genesis so the
    // daemon can auto-bond + join_committee on first run, instead of looping
    // forever on "Insufficient free MATRA" until an out-of-band //Alice transfer
    // (the recovery dance we had to do post-v6 reset, 2026-04-28).
    let macbook_cert_daemon = account([
        0xcc, 0x01, 0xe4, 0x88, 0x13, 0x48, 0x01, 0x4c,
        0xc4, 0x14, 0xcd, 0x33, 0xc9, 0xa3, 0x97, 0xd5,
        0xd6, 0xed, 0xb1, 0x1c, 0x6c, 0x9d, 0x92, 0x9e,
        0x37, 0xb6, 0xaf, 0x76, 0x08, 0x93, 0x2f, 0x71,
    ]);
    // Gemtek rotated keys (post-v3-mnemonic-leak, 2026-04-17). SS58 =
    // 5Dd7WuLMyb71NT1Bea6oEZH8Je3MkQzamHVeU4tmQbtPWq2v. Old pre-rotation key
    // 0x7e27bb13... must never be reintroduced — it corresponds to a mnemonic
    // that got anchored to Cardano mainnet.
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
                // Faucet signer (//Alice) — 10M MATRA for drips + ongoing rescues.
                [alice_faucet, 10_000_000_000_000u128],
                // Multisig sudo account (2-of-3 keyholder pseudo) — 1,000 MATRA
                // for governance ops + multisig deposits (DepositBase=1000+factor).
                [multisig_sudo, 1_000_000_000u128],
                // 3 multisig keyholders — 1,000 MATRA each. Bumped from 100 to 1,000
                // 2026-04-28 so MOTRA can accumulate fast enough at fresh-chain
                // genesis to dispatch the first multisig sudo without needing a
                // //Alice MOTRA-bootstrap dance per `reference_multisig_sudo.md`.
                [keyholder_1, 1_000_000_000u128],
                [keyholder_2, 1_000_000_000u128],
                [keyholder_3, 1_000_000_000u128],
                // 4 cert-daemon / attestor accounts — 1,100 MATRA each
                // (`BondRequirement` 1,000 + 100 buffer for fees + above-ED).
                // For Linux nodes (Gemtek/Node-2/Node-3), the cert-daemon reuses
                // the aura key, so the same account holds bond + authors blocks.
                // For MacBook, the cert-daemon uses a separate mnemonic — see
                // `macbook_cert_daemon` constant above.
                //
                // Pre-endowing avoids the bond-starvation wedge we hit post-v6
                // reset (2026-04-28) where founders had only 100M base each
                // (1/10 of BondRequirement) and looped forever on "Insufficient
                // free MATRA" until rescued by //Alice. Per
                // `feedback_chain_reset_committee_bond_starvation.md`.
                [gemtek_account, 1_100_000_000u128],
                [node2_account, 1_100_000_000u128],
                [node3_account, 1_100_000_000u128],
                [macbook_cert_daemon, 1_100_000_000u128],
                // MacBook AURA account — 100 MATRA (block-author key only;
                // doesn't bond, doesn't pay fees, just needs to exist + above-ED).
                [macbook_account, 100_000_000u128],
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
        // -- OrinqReceipts genesis (v5.1 tokenomics tune-down baked in) --
        // Every value here matches the post-2026-04-24 v5 tune-down that was
        // deployed via 2-of-3 multisig sudo (`OrinqReceipts.set_attestation_*`
        // + setEraCapBaselineAttestorCount) and got wiped at the v6 reset
        // 2026-04-28. Baking them into chain-spec genesis means future resets
        // (or fresh bootstraps) inherit the intended preprod economics by
        // default, no post-genesis dispatch needed.
        //
        // INNER FIELDS use snake_case because pallet-orinq-receipts
        // GenesisConfig has plain serde derive with no rename_all (verified
        // 2026-04-28 in pallets/orinq-receipts/src/lib.rs:550-573). The OUTER
        // pallet key ("orinqReceipts") is camelCase per the runtime aggregate
        // GenesisConfig's rename_all="camelCase" (see comment on
        // `sessionCommitteeManagement` below for the same pattern).
        //
        // NOT YET EXPOSED IN GENESIS: attestation_threshold + initial committee
        // members. These still need a post-genesis multisig sudo dispatch (one
        // call to `OrinqReceipts.setCommittee(<4 founder cert-daemon SS58s>, 3)`)
        // until pallet-orinq-receipts GenesisConfig is extended. Tracked as a
        // follow-up task.
        "orinqReceipts": {
            // 1 MATRA (6 decimals) per signer — matches v5.1 tokenomics target.
            // Without this, default is 10 MATRA → ~99.3% over-payment per cert.
            "attestation_reward_per_signer": 1_000_000u128,
            // 50K MATRA cap per era — default value, made explicit.
            "era_cap_base": 50_000_000_000u128,
            // 32 attestor baseline for cap auto-scaling — matches v5.1 setting
            // (default is 16, which under-allocates for our 64-cap committee).
            "era_cap_baseline_attestor_count": 32u32,
            // 1,000 MATRA bond requirement — default value, made explicit so a
            // future chain-spec change can't silently drop it to 0 and open a
            // committee-dilution attack.
            "bond_requirement": 1_000_000_000u128,
            // Per-receipt submission fee 1 MATRA, floor 0.1 MATRA (defaults).
            "receipt_submission_fee": 1_000_000u128,
            "receipt_submission_fee_floor": 100_000u128,
            // ~24 hours expiry at 6s blocks (default).
            "receipt_expiry_blocks": 14_400u32
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
            // v6 reset 2026-04-28: fresh genesis UTXO consumed by
            // `partner-chains-node smart-contracts governance init` against the
            // operator payment.skey on Cardano preprod. Source UTXO selected
            // for being the smallest clean (no datum, no native assets) entry
            // at addr_test1vp5q4y7afh45sulup233v78tqtzhykr309flljdx2jc277qw5eapd.
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
                // v6 partner-chain script identifiers — emitted by
                // `partner-chains-node smart-contracts get-scripts` against the
                // v6 genesis UTXO 13313ea0...#0 (Cardano preprod tx
                // 0x8afee608cbf6ef633c4d8aac47b72cbd6eeec1e498eca9ba374313eb651f43fc).
                // MainchainAddress serializes as hex of UTF-8 bytes of the bech32 string
                // (the follower queries db-sync for the literal address string).
                // Hex below = "addr_test1wrld9uhaepas48twjy3qevncsyrhjdqnkz2wzu4yzjc2qhq24f4v4"
                "committee_candidate_address": "0x616464725f746573743177726c643975686165706173343874776a79337165766e63737972686a64716e6b7a32777a7534797a6a6332716871323466347634",
                "d_parameter_policy_id": "0x38dddaf5198b927b19dac9b28226ab29eddad176d5d81c7748bc2c31",
                "permissioned_candidates_policy_id": "0xef2890d1e98247819abcf2df6e891824ed950a4216d36c71ee6f9974",
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
