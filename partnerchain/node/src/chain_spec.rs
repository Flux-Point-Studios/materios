use materios_runtime::{
    opaque::SessionKeys, AccountId, Balance, CrossChainPublic, Signature, TESTNET_TIMELOCK_DELAYS,
    WASM_BINARY,
};
use sc_service::ChainType;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
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
/// genesis initialises Aura and GRANDPA from that committee, and panics with
/// "Authorities are already initialized!" if `aura` or `grandpa` is set too.
/// The committee also outlasts genesis. While Cardano's draw fails the
/// live-quorum floor, as it does at block 1 unless one author alone is a
/// quorum, block 1 proposes this committee again, so a spec without one
/// schedules an empty GRANDPA set at its first rotation and halts.
///
/// List each authority once, in ascending cross-chain-key order, which is
/// the order Ariadne seats a committee in. A duplicate carries double weight
/// in GRANDPA, and any other order is re-seated by the first draw.
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
    use super::{authority_keys_from_seed, AuraId, Authority, ChainSpec, GrandpaId};
    use authority_selection_inherents::authority_selection_inputs::AuthoritySelectionInputs;
    use materios_runtime::{
        Block, Header, Runtime, SessionCommitteeManagement, Sidechain, UncheckedExtrinsic,
        SLOT_DURATION,
    };
    use sidechain_domain::{
        byte_string::SizedByteString, AuraPublicKey, DParameter, EpochNonce, GrandpaPublicKey,
        PermissionedCandidateData, SidechainPublicKey,
    };
    use sp_api::runtime_decl_for_core::Core;
    use sp_block_builder::runtime_decl_for_block_builder::BlockBuilder;
    use sp_consensus_aura::{runtime_decl_for_aura_api::AuraApi, Slot, AURA_ENGINE_ID};
    use sp_consensus_grandpa::runtime_decl_for_grandpa_api::GrandpaApi;
    use sp_core::{Decode, Encode};
    use sp_inherents::InherentData;
    use sp_runtime::{
        traits::{Block as _, Header as _},
        BuildStorage, Digest, DigestItem, Storage,
    };

    /// Who a chain seats: its committee, the keys Aura takes authors from,
    /// and the keys GRANDPA votes with.
    #[derive(Debug, PartialEq)]
    pub(crate) struct Seated {
        pub(crate) committee: Vec<Authority>,
        pub(crate) aura: Vec<AuraId>,
        pub(crate) grandpa: Vec<GrandpaId>,
    }

    impl Seated {
        /// A committee of `authorities`, each authoring and voting with its
        /// own session keys.
        pub(crate) fn by(authorities: &[Authority]) -> Self {
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

    /// A chain started from `spec`. The runtime's genesis builder builds its
    /// state from the spec's own code, as `build-spec` and a starting node do.
    pub(crate) fn start(spec: &ChainSpec) -> sp_io::TestExternalities {
        sp_io::TestExternalities::new(spec.build_storage().expect("the genesis builds"))
    }

    pub(crate) fn seated_now() -> Seated {
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
        let mut data = InherentData::new();
        data.put_data(sp_timestamp::INHERENT_IDENTIFIER, &(slot * SLOT_DURATION))
            .unwrap();
        data.put_data(
            sp_session_validator_management::INHERENT_IDENTIFIER,
            cardano,
        )
        .unwrap();
        data.put_data(
            sp_block_rewards::INHERENT_IDENTIFIER,
            &SizedByteString([0; 32]),
        )
        .unwrap();
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

    /// Every builder's genesis committee names each authority once, in the
    /// order Ariadne seats a committee: ascending by cross-chain key.
    #[test]
    fn every_builder_seats_each_authority_once_in_ascending_cross_chain_key_order() {
        for (name, spec) in [
            ("development", super::development_config()),
            ("local", super::local_testnet_config()),
            ("preprod", crate::chain_spec_preprod::preprod_config()),
        ] {
            let committee = seated_at_genesis(&spec.unwrap()).committee;
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
}
