use materios_runtime::{
    opaque::SessionKeys, AccountId, Balance, Block, CrossChainPublic, Runtime,
    SessionCommitteeManagement, Signature, TESTNET_TIMELOCK_DELAYS, WASM_BINARY,
};
use sc_service::ChainType;
use sp_consensus_aura::{runtime_decl_for_aura_api::AuraApi, sr25519::AuthorityId as AuraId};
use sp_consensus_grandpa::{runtime_decl_for_grandpa_api::GrandpaApi, AuthorityId as GrandpaId};
use sp_core::{ecdsa, sr25519, Pair, Public};
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

/// A genesis authority: the cross-chain key that names it in the committee,
/// and the session keys it authors and votes with.
///
/// A chain spec seats its authorities only through
/// `sessionCommitteeManagement.initialAuthorities`: the session pallet's
/// genesis initialises Aura and GRANDPA from that committee. The committee
/// also outlasts genesis. While Cardano's draw fails the live-quorum floor,
/// as it does at block 1 unless one author alone is a quorum, block 1
/// proposes this committee again.
///
/// The runtime's genesis builder refuses a committee that is empty, whose
/// first rotation would schedule an empty GRANDPA set and halt the chain;
/// `aura` or `grandpa` authorities set beside it; more seats than
/// `MaxValidators`; an authority listed twice or out of ascending
/// cross-chain-key order, Ariadne's order when every candidate gets a seat;
/// and an Aura or GRANDPA key two authorities share.
pub type Authority = (CrossChainPublic, SessionKeys);

/// The authority a development seed derives.
pub fn authority_keys_from_seed(s: &str) -> Authority {
    (
        get_from_seed::<ecdsa::Public>(s).into(),
        SessionKeys {
            aura: get_from_seed::<AuraId>(s),
            grandpa: get_from_seed::<GrandpaId>(s),
        },
    )
}

/// Who a chain seats: its committee, the keys Aura takes authors from, and
/// the keys GRANDPA votes with.
#[derive(Debug, PartialEq)]
pub struct Seated {
    pub committee: Vec<Authority>,
    pub aura: Vec<AuraId>,
    pub grandpa: Vec<GrandpaId>,
}

impl Seated {
    /// A committee of `authorities`, each authoring and voting with its own
    /// session keys.
    pub fn by(authorities: &[Authority]) -> Self {
        Seated {
            committee: authorities.to_vec(),
            aura: authorities
                .iter()
                .map(|(_, keys)| keys.aura.clone())
                .collect(),
            grandpa: authorities
                .iter()
                .map(|(_, keys)| keys.grandpa.clone())
                .collect(),
        }
    }
}

/// Who the chain state in scope seats.
pub fn seated_now() -> Seated {
    Seated {
        committee: SessionCommitteeManagement::current_committee_storage()
            .committee
            .to_vec(),
        aura: <Runtime as AuraApi<Block, AuraId>>::authorities(),
        grandpa: <Runtime as GrandpaApi<Block>>::grandpa_authorities()
            .into_iter()
            .map(|(key, _)| key)
            .collect(),
    }
}

/// Refuses `spec` when a chain started from its genesis does not keep its
/// authorities through the first committee rotation. A fresh chain's first
/// Cardano draw fails the live-quorum floor, so that rotation seats the
/// genesis `SessionCommitteeManagement.CurrentCommittee`: an empty one
/// schedules an empty GRANDPA set, which no node imports, and any other one
/// hands authoring or finality to keys that did not hold it. The runtime's
/// genesis builder refuses both, but a raw spec's genesis never runs it.
///
/// Preprod v6 is the one exception: it started with no genesis committee
/// before the live-quorum floor existed, so its first rotation seated
/// Cardano's draw.
pub fn check_genesis_committee(spec: &dyn sc_service::ChainSpec) -> Result<(), String> {
    let seated = sp_io::TestExternalities::new(spec.build_storage()?).execute_with(seated_now);
    let committee = Seated::by(&seated.committee);
    let refusal = if seated.committee.is_empty() {
        "its genesis SessionCommitteeManagement.CurrentCommittee is empty: a fresh chain's first \
         committee rotation seats it and schedules an empty GRANDPA set, which no node imports, \
         so the chain halts there"
    } else if seated.aura != committee.aura {
        "its genesis Aura.Authorities are not its genesis \
         SessionCommitteeManagement.CurrentCommittee's aura keys, in the committee's order: a \
         fresh chain's first committee rotation seats the committee, and hands authoring to keys \
         that did not author before it"
    } else if seated.grandpa != committee.grandpa {
        "its genesis Grandpa.Authorities are not its genesis \
         SessionCommitteeManagement.CurrentCommittee's grandpa keys, in the committee's order: a \
         fresh chain's first committee rotation seats the committee, and hands finality to keys \
         that did not finalize before it"
    } else {
        return Ok(());
    };
    let executor = crate::chain_identity::Executor::builder().build();
    let genesis = crate::chain_identity::genesis(spec, &executor)?.hash;
    if genesis == crate::chain_spec_preprod::PREPROD_V6_GENESIS {
        return Ok(());
    }
    Err(format!(
        "refusing chain spec {}: {refusal} (genesis {genesis:?})",
        spec.id()
    ))
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

const ENDOWMENT: Balance = 1_000_000_000_000; // 1M MATRA (6 decimals)

/// Build a genesis config JSON patch.
///
/// Includes configuration for the 6 IOG partner-chain pallets:
///   1. pallet_sidechain        -- sidechain params (genesis_utxo, slots_per_epoch)
///   2. pallet_partner_chains_session (Session) -- seats the genesis committee
///   3. pallet_session_validator_management (SessionCommitteeManagement) -- committee + scripts
///   4. pallet_session (PalletSession) -- substrate session stub (default)
///   5. pallet_block_rewards (BlockRewards) -- no genesis storage needed
///   6. pallet_native_token_management -- native token bridge scripts (placeholder)
///
/// Running in permissioned-only mode (D=1.0): Cardano mainchain follower not required.
/// The `genesis_utxo` and `main_chain_scripts` fields use placeholder/default values
/// that will be replaced when the Cardano bridge is activated.
fn testnet_genesis(
    initial_authorities: Vec<Authority>,
    root_key: AccountId,
    endowed_accounts: Vec<AccountId>,
    _enable_println: bool,
) -> serde_json::Value {
    serde_json::json!({
        "balances": {
            "balances": endowed_accounts
                .iter()
                .map(|k| (k.clone(), ENDOWMENT))
                .collect::<Vec<_>>(),
        },
        "aura": {
            "authorities": [],
        },
        "grandpa": {
            "authorities": [],
        },
        "sudo": {
            "key": Some(root_key),
        },
        // Root behind short delays, with Bob able to veto.
        "rootTimelock": {
            "delays": TESTNET_TIMELOCK_DELAYS,
            "guardian": Some(get_account_id_from_seed::<sr25519::Public>("Bob")),
        },
        // -- IOG partner-chain pallets --
        // 1. Sidechain pallet: epoch/slot configuration.
        //    genesis_utxo is a placeholder (all zeros) for permissioned-only mode.
        "sidechain": {
            "genesisUtxo": "0x0000000000000000000000000000000000000000000000000000000000000000#0",
            "slotsPerEpoch": SLOTS_PER_EPOCH,
        },
        // 3. SessionCommitteeManagement (pallet_session_validator_management):
        //    the genesis committee, which the Session pallet (2) seats.
        //    main_chain_scripts use placeholder values (not needed until D < 1.0).
        "sessionCommitteeManagement": {
            "initialAuthorities": initial_authorities,
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
        // The attestor reward and era cap have no runtime default.
        "orinqReceipts": {
            "attestationRewardPerSigner": 1_000_000u128,
            "eraCapBase": 50_000_000_000u128,
            "eraCapBaselineAttestorCount": 32u32,
        },
        // Note: BlockRewards has no genesis config.
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{authority_keys_from_seed, seated_now, Authority, ChainSpec, GrandpaId, Seated};
    use authority_selection_inherents::authority_selection_inputs::AuthoritySelectionInputs;
    use materios_runtime::{Block, Header, Runtime, Sidechain, UncheckedExtrinsic, SLOT_DURATION};
    use sidechain_domain::{
        byte_string::SizedByteString, AuraPublicKey, DParameter, EpochNonce, GrandpaPublicKey,
        PermissionedCandidateData, SidechainPublicKey,
    };
    use sp_api::runtime_decl_for_core::Core;
    use sp_block_builder::runtime_decl_for_block_builder::BlockBuilder;
    use sp_consensus_aura::{Slot, AURA_ENGINE_ID};
    use sp_core::{Decode, Encode};
    use sp_inherents::InherentData;
    use sp_runtime::{
        traits::{Block as _, Header as _},
        BuildStorage, Digest, DigestItem, Storage,
    };

    /// A chain started from `spec`. The runtime's genesis builder builds its
    /// state from the spec's own code, as `build-spec` and a starting node do.
    pub(crate) fn start(spec: &ChainSpec) -> sp_io::TestExternalities {
        sp_io::TestExternalities::new(spec.build_storage().expect("the genesis builds"))
    }

    pub(crate) fn seated_at_genesis(spec: &ChainSpec) -> Seated {
        start(spec).execute_with(seated_now)
    }

    /// Cardano's committee selection inputs: `candidates` as the permissioned
    /// candidates, one seat each, and no registered seats.
    pub(crate) fn cardano(candidates: &[Authority]) -> AuthoritySelectionInputs {
        AuthoritySelectionInputs {
            d_parameter: DParameter {
                num_permissioned_candidates: candidates.len() as u16,
                num_registered_candidates: 0,
            },
            permissioned_candidates: candidates
                .iter()
                .map(|(cross_chain, keys)| PermissionedCandidateData {
                    sidechain_public_key: SidechainPublicKey(cross_chain.encode()),
                    aura_public_key: AuraPublicKey(keys.aura.encode()),
                    grandpa_public_key: GrandpaPublicKey(keys.grandpa.encode()),
                })
                .collect(),
            registered_candidates: Vec::new(),
            epoch_nonce: EpochNonce(vec![7; 32]),
        }
    }

    pub(crate) fn genesis_header() -> Header {
        Header::new(
            0,
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
        )
    }

    /// A node's inherent data for the block at `slot`, with `ariadne` as what
    /// its Ariadne inherent data provider gave it.
    pub(crate) fn inherent_data(
        slot: u64,
        ariadne: Option<&AuthoritySelectionInputs>,
    ) -> InherentData {
        let mut data = InherentData::new();
        data.put_data(sp_timestamp::INHERENT_IDENTIFIER, &(slot * SLOT_DURATION))
            .unwrap();
        if let Some(inputs) = ariadne {
            data.put_data(sp_session_validator_management::INHERENT_IDENTIFIER, inputs)
                .unwrap();
        }
        data.put_data(
            sp_block_rewards::INHERENT_IDENTIFIER,
            &SizedByteString([0; 32]),
        )
        .unwrap();
        data
    }

    /// The block the slot's author proposes after `parent` while Cardano's
    /// selection inputs are `cardano`, and the inherent data it was made
    /// from. Nothing it wrote is kept.
    pub(crate) fn propose(
        parent: &Header,
        slot: u64,
        cardano: &AuthoritySelectionInputs,
    ) -> (Block, InherentData) {
        let digest = Digest {
            logs: vec![DigestItem::PreRuntime(
                AURA_ENGINE_ID,
                Slot::from(slot).encode(),
            )],
        };
        let pre = Header::new(
            parent.number + 1,
            Default::default(),
            Default::default(),
            parent.hash(),
            digest,
        );
        let data = inherent_data(slot, Some(cardano));
        let (header, inherents) = discarded(|| run(&pre, None, &data));
        (Block::new(header, inherents), data)
    }

    /// Checks `block`'s inherents as every peer does before importing it:
    /// with `check_inherents` at its parent, as the node's Aura import queue
    /// calls it, throwing away what the check wrote. `Err` says why the
    /// peers reject it.
    pub(crate) fn peers_check(block: &Block, data: &InherentData) -> Result<(), String> {
        let checked = discarded(|| {
            <Runtime as BlockBuilder<Block>>::check_inherents(block.clone(), data.clone())
        });
        if checked.ok() {
            return Ok(());
        }
        Err(checked
            .into_errors()
            .map(|(id, error)| {
                let reason = if id == sp_session_validator_management::INHERENT_IDENTIFIER {
                    sp_session_validator_management::InherentError::decode(&mut &error[..])
                        .map(|error| error.to_string())
                        .unwrap_or_else(|_| sp_core::bytes::to_hex(&error, false))
                } else {
                    sp_core::bytes::to_hex(&error, false)
                };
                format!("{}: {reason}", String::from_utf8_lossy(&id))
            })
            .collect::<Vec<_>>()
            .join("; "))
    }

    /// Plays the block after `parent` at `slot` as the network does, while
    /// Cardano's selection inputs are `cardano`: the slot's author proposes
    /// it, and peers import it only if their check passes. Returns the
    /// imported header, or why the peers rejected the block.
    pub(crate) fn play(
        parent: &Header,
        slot: u64,
        cardano: &AuthoritySelectionInputs,
    ) -> Result<Header, String> {
        let (block, data) = propose(parent, slot, cardano);
        peers_check(&block, &data).map_err(|rejection| {
            format!(
                "peers reject block #{} at slot {slot}: {rejection}",
                block.header().number
            )
        })?;
        let (proposed, inherents) = block.deconstruct();
        let (imported, _) = run(&proposed, Some(inherents), &data);
        assert_eq!(imported, proposed, "peers import the block they checked");
        Ok(imported)
    }

    /// Runs the block `header` opens: initialises it, applies `inherents`,
    /// or those the runtime makes from `data` if none are given, and
    /// finalises it.
    fn run(
        header: &Header,
        inherents: Option<Vec<UncheckedExtrinsic>>,
        data: &InherentData,
    ) -> (Header, Vec<UncheckedExtrinsic>) {
        <Runtime as Core<Block>>::initialize_block(header);
        let inherents = inherents
            .unwrap_or_else(|| <Runtime as BlockBuilder<Block>>::inherent_extrinsics(data.clone()));
        for inherent in &inherents {
            <Runtime as BlockBuilder<Block>>::apply_extrinsic(inherent.clone())
                .expect("the inherent is valid")
                .expect("the inherent dispatches");
        }
        (
            <Runtime as BlockBuilder<Block>>::finalize_block(),
            inherents,
        )
    }

    /// `f`'s result, with every storage write it made rolled back.
    fn discarded<R>(f: impl FnOnce() -> R) -> R {
        sp_io::storage::start_transaction();
        let result = f();
        sp_io::storage::rollback_transaction();
        result
    }

    /// Who a chain started from `spec` seats after its first committee
    /// rotation, while Cardano lists `candidates`. Block 1 proposes the next
    /// committee, and block 2, the first of the next epoch, rotates to it.
    /// GRANDPA's set is the one block 2's header schedules, read as the
    /// node's block import reads it.
    pub(crate) fn seated_after_first_rotation(
        spec: &ChainSpec,
        candidates: &[Authority],
    ) -> Seated {
        start(spec).execute_with(|| {
            let cardano = cardano(candidates);
            let epoch_length = u64::from(Sidechain::slots_per_epoch().0);
            let block_1 = play(&genesis_header(), 1_000 * epoch_length + 1, &cardano)
                .unwrap_or_else(|rejection| panic!("{rejection}"));
            let block_2 = play(&block_1, 1_001 * epoch_length, &cardano)
                .unwrap_or_else(|rejection| panic!("{rejection}"));
            let scheduled = sc_consensus_grandpa::find_scheduled_change::<Block>(&block_2)
                .expect("block 2 rotates the committee and schedules a GRANDPA set");
            Seated {
                grandpa: scheduled
                    .next_authorities
                    .into_iter()
                    .map(|(key, _)| key)
                    .collect(),
                ..seated_now()
            }
        })
    }

    /// The genesis committee `spec` declares, as its genesis patch lists it.
    fn declared_committee(spec: &ChainSpec) -> Vec<Authority> {
        let json: serde_json::Value = serde_json::from_str(&spec.as_json(false).unwrap()).unwrap();
        serde_json::from_value(
            json["genesis"]["runtimeGenesis"]["patch"]["sessionCommitteeManagement"]
                ["initialAuthorities"]
                .clone(),
        )
        .unwrap()
    }

    /// Every builder declares a genesis committee, and genesis seats exactly
    /// that committee, each authority once, ascending by cross-chain key.
    #[test]
    fn every_builder_seats_the_committee_it_declares_each_authority_once_in_ascending_cross_chain_key_order(
    ) {
        for (name, spec) in [
            ("development", super::development_config()),
            ("local", super::local_testnet_config()),
            ("preprod", crate::chain_spec_preprod::preprod_config()),
        ] {
            let spec = spec.unwrap();
            let declared = declared_committee(&spec);
            assert!(!declared.is_empty(), "{name} declares no genesis committee");
            let committee = seated_at_genesis(&spec).committee;
            assert_eq!(committee, declared, "{name}");
            assert!(
                committee.windows(2).all(|pair| pair[0].0 < pair[1].0),
                "{name}: {:?}",
                committee
                    .iter()
                    .map(|(cross_chain, _)| cross_chain)
                    .collect::<Vec<_>>()
            );
        }
    }

    /// Every builder starts settlement at its current storage version with
    /// both legacy cutovers at block zero, which that version reads as
    /// closed: no upgrade migrates it, and the legacy settle and expire calls
    /// never run. Its attestors bond the minimum settlement bond.
    #[test]
    fn every_builder_starts_settlement_at_its_current_version_with_the_attestor_bond_as_its_minimum(
    ) {
        use pallet_intent_settlement::{
            PolicyExpireCutoverBlock, SettlementStorageVersion, StcaCutoverBlock,
        };
        for (name, spec) in [
            ("development", super::development_config()),
            ("local", super::local_testnet_config()),
            ("preprod", crate::chain_spec_preprod::preprod_config()),
        ] {
            start(&spec.unwrap()).execute_with(|| {
                assert_eq!(SettlementStorageVersion::<Runtime>::get(), 4, "{name}");
                for (cutover, stored) in [
                    (
                        StcaCutoverBlock::<Runtime>::get(),
                        StcaCutoverBlock::<Runtime>::exists(),
                    ),
                    (
                        PolicyExpireCutoverBlock::<Runtime>::get(),
                        PolicyExpireCutoverBlock::<Runtime>::exists(),
                    ),
                ] {
                    assert_eq!((cutover, stored), (0, true), "{name}");
                }
                assert_eq!(
                    pallet_orinq_receipts::BondRequirement::<Runtime>::get(),
                    materios_runtime::IntentSettlementMinSettlementBond::get(),
                    "{name}"
                );
            });
        }
    }

    /// Every spec carries this runtime's code, so a genesis hash is only as
    /// reproducible as that code. The code names its source files in panic
    /// messages, by remapped paths only: the repository as /materios, the
    /// Cargo home as /cargo-home and the toolchain as /rust-toolchain, never
    /// where the machine that built it keeps them.
    #[test]
    fn the_runtime_code_names_no_directory_of_the_machine_that_built_it() {
        let code = materios_runtime::WASM_BINARY_BLOATY.expect("the runtime is built");
        let names = |path: &str| {
            code.windows(path.len())
                .any(|bytes| bytes == path.as_bytes())
        };
        let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap()
            .display()
            .to_string();
        let cargo_home = std::env::var("CARGO_HOME")
            .unwrap_or_else(|_| format!("{}/.cargo", std::env::var("HOME").unwrap()));
        let sysroot = std::process::Command::new("rustc")
            .args(["--print", "sysroot"])
            .output()
            .expect("rustc runs");
        let sysroot = String::from_utf8(sysroot.stdout).unwrap().trim().to_owned();
        for directory in [repository, cargo_home, sysroot] {
            assert!(!names(&directory), "the runtime names {directory}");
        }
        for remapped in [
            "/materios/partnerchain/runtime/src/",
            "/cargo-home/registry/src/",
            "/cargo-home/git/checkouts/",
            "/rust-toolchain/lib/rustlib/src/rust/library/",
        ] {
            assert!(names(remapped), "the runtime never names {remapped}");
        }
    }

    #[test]
    fn fresh_development_and_local_chains_keep_their_authorities_through_the_first_rotation() {
        for (spec, seeds) in [
            (super::development_config(), &["Alice"][..]),
            (super::local_testnet_config(), &["Alice", "Bob"][..]),
        ] {
            let spec = spec.unwrap();
            let authorities: Vec<_> = seeds
                .iter()
                .copied()
                .map(authority_keys_from_seed)
                .collect();
            assert_eq!(
                seated_at_genesis(&spec),
                Seated::by(&authorities),
                "{seeds:?}"
            );
            assert_eq!(
                seated_after_first_rotation(&spec, &authorities),
                Seated::by(&authorities),
                "{seeds:?}"
            );
        }
    }

    /// Block 1's draw fails the live-quorum floor, so the first rotation
    /// seats the genesis committee rather than candidates that have never
    /// authored a block.
    #[test]
    fn a_fresh_chain_keeps_its_genesis_committee_over_cardano_candidates_that_have_not_authored() {
        let genesis = ["Alice", "Bob"].map(authority_keys_from_seed);
        let cardano = ["Charlie", "Dave", "Eve"].map(authority_keys_from_seed);
        assert_eq!(
            seated_after_first_rotation(&super::local_testnet_config().unwrap(), &cardano),
            Seated::by(&genesis)
        );
    }

    /// (reward per signer, era cap base, era cap baseline) as genesis stored
    /// them, read back through the runtime's own getters.
    pub(crate) fn stored_attestor_rewards(storage: Storage) -> (u128, u128, u32) {
        sp_io::TestExternalities::new(storage).execute_with(|| {
            (
                materios_runtime::OrinqReceipts::attestation_reward_per_signer(),
                materios_runtime::OrinqReceipts::era_cap_base(),
                materios_runtime::OrinqReceipts::era_cap_baseline_attestor_count(),
            )
        })
    }

    #[test]
    fn development_genesis_sets_attestor_rewards_explicitly() {
        let storage = super::development_config()
            .unwrap()
            .build_storage()
            .unwrap();
        assert_eq!(
            stored_attestor_rewards(storage),
            (1_000_000, 50_000_000_000, 32)
        );
    }

    #[test]
    fn local_testnet_genesis_sets_attestor_rewards_explicitly() {
        let storage = super::local_testnet_config()
            .unwrap()
            .build_storage()
            .unwrap();
        assert_eq!(
            stored_attestor_rewards(storage),
            (1_000_000, 50_000_000_000, 32)
        );
    }

    /// The key of the storage value `pallet` keeps as `item`.
    fn storage_key(pallet: &str, item: &str) -> Vec<u8> {
        [
            sp_core::twox_128(pallet.as_bytes()),
            sp_core::twox_128(item.as_bytes()),
        ]
        .concat()
    }

    /// `spec` as `build-spec --raw` writes it, with `writes` stored over its
    /// genesis.
    fn raw(spec: &ChainSpec, writes: &[(Vec<u8>, Vec<u8>)]) -> serde_json::Value {
        let mut json: serde_json::Value =
            serde_json::from_str(&spec.as_json(true).unwrap()).unwrap();
        for (key, value) in writes {
            json["genesis"]["raw"]["top"][sp_core::bytes::to_hex(key, false).as_str()] =
                sp_core::bytes::to_hex(value, false).into();
        }
        json
    }

    /// Loads `json` as the node loads the chain spec file `--chain` names.
    fn load_file(name: &str, json: &serde_json::Value) -> Result<ChainSpec, String> {
        let path = std::env::temp_dir().join(format!(
            "materios-node-test-{}-{name}.json",
            std::process::id()
        ));
        std::fs::write(&path, json.to_string()).unwrap();
        let cli = <crate::cli::Cli as clap::Parser>::parse_from(["materios-node"]);
        // A spec loaded from a file reads its genesis from the file when used.
        let loaded = sc_cli::SubstrateCli::load_spec(&cli, path.to_str().unwrap())
            .and_then(|spec| spec.as_json(true));
        std::fs::remove_file(&path).unwrap();
        ChainSpec::from_json_bytes(loaded?.into_bytes())
    }

    /// Cardano candidates that have never authored a block, so a fresh
    /// chain's first draw over them fails the live-quorum floor.
    fn unproven_candidates() -> [Authority; 3] {
        ["Charlie", "Dave", "Eve"].map(authority_keys_from_seed)
    }

    /// A raw spec carries its genesis past the runtime's genesis builder, which
    /// refuses an empty committee. The chain it starts schedules an empty
    /// GRANDPA set at its first rotation, which no node imports, so the node
    /// refuses the spec when it loads it.
    #[test]
    fn the_node_refuses_a_raw_genesis_whose_committee_is_empty() {
        let json = raw(
            &super::local_testnet_config().unwrap(),
            &[(
                storage_key("SessionCommitteeManagement", "CurrentCommittee"),
                (0u64, Vec::<Authority>::new()).encode(),
            )],
        );
        let halting = ChainSpec::from_json_bytes(json.to_string().into_bytes()).unwrap();
        assert_eq!(
            seated_after_first_rotation(&halting, &unproven_candidates()).grandpa,
            Vec::<GrandpaId>::new()
        );
        let refused = load_file("empty-committee", &json)
            .err()
            .expect("the node refuses it");
        assert!(
            refused.contains(
                "chain spec materios_local: its genesis SessionCommitteeManagement.CurrentCommittee is empty"
            ),
            "{refused}"
        );
    }

    /// Genesis authors with keys other than its committee's hand authoring
    /// to the committee at the first rotation, whoever holds its keys.
    #[test]
    fn the_node_refuses_a_raw_genesis_whose_aura_authorities_are_not_its_committee() {
        let [alice, _, charlie] = ["Alice", "Bob", "Charlie"].map(authority_keys_from_seed);
        let json = raw(
            &super::local_testnet_config().unwrap(),
            &[(
                storage_key("Aura", "Authorities"),
                vec![alice.1.aura, charlie.1.aura].encode(),
            )],
        );
        let refused = load_file("aura-not-committee", &json)
            .err()
            .expect("the node refuses it");
        assert!(
            refused.contains(
                "chain spec materios_local: its genesis Aura.Authorities are not its genesis \
                 SessionCommitteeManagement.CurrentCommittee's aura keys"
            ),
            "{refused}"
        );
    }

    /// Genesis voters other than its committee's hand finality to the
    /// committee at the first rotation, whoever holds its keys.
    #[test]
    fn the_node_refuses_a_raw_genesis_whose_grandpa_authorities_are_not_its_committee() {
        let alice = authority_keys_from_seed("Alice");
        let json = raw(
            &super::local_testnet_config().unwrap(),
            &[(
                storage_key("Grandpa", "Authorities"),
                vec![(alice.1.grandpa, 1u64)].encode(),
            )],
        );
        let refused = load_file("grandpa-not-committee", &json)
            .err()
            .expect("the node refuses it");
        assert!(
            refused.contains(
                "chain spec materios_local: its genesis Grandpa.Authorities are not its genesis \
                 SessionCommitteeManagement.CurrentCommittee's grandpa keys"
            ),
            "{refused}"
        );
    }

    /// Each builder's spec, as `build-spec` writes it, and its raw form, as
    /// `build-spec --raw` writes it from that file, loads with the committee
    /// it seats.
    #[test]
    fn the_node_loads_every_builder_spec_and_its_build_spec_raw_form() {
        for (name, spec) in [
            ("development", super::development_config()),
            ("local", super::local_testnet_config()),
            ("preprod", crate::chain_spec_preprod::preprod_config()),
        ] {
            let spec = spec.unwrap();
            let plain: serde_json::Value =
                serde_json::from_str(&spec.as_json(false).unwrap()).unwrap();
            let loaded = load_file(&format!("{name}-plain"), &plain).unwrap();
            let raw: serde_json::Value =
                serde_json::from_str(&loaded.as_json(true).unwrap()).unwrap();
            let loaded = load_file(&format!("{name}-raw"), &raw).unwrap();
            assert_eq!(
                seated_at_genesis(&loaded),
                Seated::by(&declared_committee(&spec)),
                "{name}"
            );
        }
    }

    /// Preprod v6 started with no genesis committee, before the live-quorum
    /// floor, and its first rotation seated Cardano's draw. The node loads
    /// that genesis, and refuses the same genesis with any byte changed.
    #[test]
    fn the_node_loads_the_preprod_v6_genesis_and_refuses_any_other_without_a_committee() {
        use std::io::Read;
        let mut text = String::new();
        flate2::read::GzDecoder::new(
            std::fs::File::open(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tools/launch-preflight/fixtures/preprod-v6-raw.json.gz"
            ))
            .unwrap(),
        )
        .read_to_string(&mut text)
        .unwrap();
        let v6: serde_json::Value = serde_json::from_str(&text).unwrap();
        load_file("preprod-v6", &v6).unwrap();

        let mut other = v6;
        other["genesis"]["raw"]["top"][sp_core::bytes::to_hex(
            sp_core::storage::well_known_keys::HEAP_PAGES,
            false,
        )
        .as_str()] = sp_core::bytes::to_hex(&64u64.encode(), false).into();
        let refused = load_file("preprod-v6-changed", &other)
            .err()
            .expect("the node refuses it");
        assert!(
            refused.contains(
                "chain spec materios_preprod_v6: its genesis SessionCommitteeManagement.CurrentCommittee is empty"
            ),
            "{refused}"
        );
    }
}
