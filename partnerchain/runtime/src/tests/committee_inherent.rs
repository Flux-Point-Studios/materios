//! The committee inherent as the network plays it. The slot's author makes
//! each block from its own inherent data; every peer checks the block with
//! `check_inherents` at the parent, as the node's Aura import queue does, and
//! imports it only if that passes.

use crate::*;
use authority_selection_inherents::authority_selection_inputs::AuthoritySelectionInputs;
use frame_support::inherent::ProvideInherent;
use pallet_session_validator_management::Call as CommitteeCall;
use parity_scale_codec::{Decode, Encode};
use sidechain_domain::{
    byte_string::SizedByteString, AuraPublicKey, DParameter, EpochNonce, GrandpaPublicKey,
    PermissionedCandidateData, SidechainPublicKey,
};
use sp_api::runtime_decl_for_core::Core;
use sp_block_builder::runtime_decl_for_block_builder::BlockBuilder;
use sp_consensus_aura::{Slot, AURA_ENGINE_ID};
use sp_consensus_grandpa::{ConsensusLog, GRANDPA_ENGINE_ID};
use sp_core::{ecdsa, ed25519, sr25519, Pair};
use sp_inherents::InherentData;
use sp_runtime::{
    traits::{Block as _, Header as _},
    transaction_validity::{InvalidTransaction, TransactionValidityError},
    BuildStorage, Digest, DigestItem,
};

const SLOTS_PER_EPOCH: u64 = 10;

type Authority = (CrossChainPublic, SessionKeys);

fn authority(seed: &str) -> Authority {
    let uri = format!("//{seed}");
    let cross_chain = ecdsa::Pair::from_string(&uri, None).unwrap().public();
    let aura = sr25519::Pair::from_string(&uri, None).unwrap().public();
    let grandpa = ed25519::Pair::from_string(&uri, None).unwrap().public();
    (cross_chain.into(), (aura, grandpa).into())
}

fn authorities(seeds: &[&str]) -> Vec<Authority> {
    seeds.iter().copied().map(authority).collect()
}

/// `authorities` in the order Ariadne seats them.
fn in_seating_order(mut authorities: Vec<Authority>) -> Vec<Authority> {
    authorities.sort_by(|a, b| a.0.cmp(&b.0));
    authorities
}

/// The four FPS cores, seated at genesis in Ariadne's order.
fn cores() -> Vec<Authority> {
    in_seating_order(authorities(&["Core1", "Core2", "Core3", "Core4"]))
}

fn outsiders() -> Vec<Authority> {
    authorities(&["Mallory1", "Mallory2"])
}

/// A chain whose genesis seats `committee`.
fn chain(committee: &[Authority]) -> sp_io::TestExternalities {
    RuntimeGenesisConfig {
        sidechain: pallet_sidechain::GenesisConfig {
            genesis_utxo: Default::default(),
            slots_per_epoch: sidechain_slots::SlotsPerEpoch(SLOTS_PER_EPOCH as u32),
            ..Default::default()
        },
        session_committee_management: pallet_session_validator_management::GenesisConfig {
            initial_authorities: committee.to_vec(),
            main_chain_scripts: Default::default(),
        },
        ..Default::default()
    }
    .build_storage()
    .expect("the genesis builds")
    .into()
}

/// Cardano's committee selection inputs: `candidates` as the permissioned
/// candidates, one seat each, and no registered seats.
fn cardano(candidates: &[Authority]) -> AuthoritySelectionInputs {
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

/// A node's inherent data for the block at `slot`, with `ariadne` as what its
/// Ariadne inherent data provider gave it.
fn inherent_data(slot: u64, ariadne: Option<&AuthoritySelectionInputs>) -> InherentData {
    let mut data = InherentData::new();
    data.put_data(
        <pallet_timestamp::Pallet<Runtime> as ProvideInherent>::INHERENT_IDENTIFIER,
        &(slot * SLOT_DURATION),
    )
    .unwrap();
    data.put_data(
        sp_block_rewards::INHERENT_IDENTIFIER,
        &SizedByteString([0; 32]),
    )
    .unwrap();
    if let Some(inputs) = ariadne {
        data.put_data(sp_session_validator_management::INHERENT_IDENTIFIER, inputs)
            .unwrap();
    }
    data
}

fn genesis_header() -> Header {
    Header::new(
        0,
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
    )
}

/// `f`'s result, with every storage write it made rolled back.
fn discarded<R>(f: impl FnOnce() -> R) -> R {
    sp_io::storage::start_transaction();
    let result = f();
    sp_io::storage::rollback_transaction();
    result
}

/// Initialises the block `header` opens, applies `inherents` and finalises it.
fn run(header: &Header, inherents: &[UncheckedExtrinsic]) -> Header {
    <Runtime as Core<Block>>::initialize_block(header);
    for inherent in inherents {
        <Runtime as BlockBuilder<Block>>::apply_extrinsic(inherent.clone())
            .expect("the inherent is valid")
            .expect("the inherent dispatches");
    }
    <Runtime as BlockBuilder<Block>>::finalize_block()
}

/// The block the author of `slot` makes after `parent` from `data`, with
/// `edit` applied to the inherents the runtime made. Nothing it wrote is kept.
fn propose_edited(
    parent: &Header,
    slot: u64,
    data: &InherentData,
    edit: impl FnOnce(&mut Vec<UncheckedExtrinsic>),
) -> Block {
    let pre = Header::new(
        parent.number + 1,
        Default::default(),
        Default::default(),
        parent.hash(),
        Digest {
            logs: vec![DigestItem::PreRuntime(
                AURA_ENGINE_ID,
                Slot::from(slot).encode(),
            )],
        },
    );
    discarded(|| {
        <Runtime as Core<Block>>::initialize_block(&pre);
        let mut inherents = <Runtime as BlockBuilder<Block>>::inherent_extrinsics(data.clone());
        edit(&mut inherents);
        for inherent in &inherents {
            <Runtime as BlockBuilder<Block>>::apply_extrinsic(inherent.clone())
                .expect("the inherent is valid")
                .expect("the inherent dispatches");
        }
        Block::new(
            <Runtime as BlockBuilder<Block>>::finalize_block(),
            inherents,
        )
    })
}

fn propose(parent: &Header, slot: u64, data: &InherentData) -> Block {
    propose_edited(parent, slot, data, |_| ())
}

/// A modified author's block: the runtime's own inherents for `data` without
/// the committee inherent, plus `set(validators)` for the next unset epoch.
fn propose_injected(
    parent: &Header,
    slot: u64,
    data: &InherentData,
    validators: Vec<Authority>,
) -> Block {
    propose_edited(parent, slot, data, |inherents| {
        inherents.retain(|x| !matches!(x.function, RuntimeCall::SessionCommitteeManagement(_)));
        inherents.push(UncheckedExtrinsic::new_unsigned(
            RuntimeCall::SessionCommitteeManagement(CommitteeCall::set {
                validators: validators.try_into().unwrap(),
                for_epoch_number: SessionCommitteeManagement::get_next_unset_epoch_number(),
                selection_inputs_hash: SizedByteString([0xee; 32]),
            }),
        ));
    })
}

/// Checks `block`'s inherents as a peer whose inherent data is `data` does
/// before importing it, throwing away what the check wrote. `Err` says why
/// the peer rejects it.
fn peers_check(block: &Block, data: &InherentData) -> Result<(), String> {
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

/// Imports `block` after a peer whose inherent data is `data` checked it.
fn import(block: Block, data: &InherentData) -> Result<Header, String> {
    peers_check(&block, data).map_err(|rejection| {
        format!("peers reject block #{}: {rejection}", block.header().number)
    })?;
    let (proposed, inherents) = block.deconstruct();
    let imported = run(&proposed, &inherents);
    assert_eq!(imported, proposed, "peers import the block they checked");
    Ok(imported)
}

/// The block after `parent` at `slot`, made and checked from the same `data`.
fn play(parent: &Header, slot: u64, data: &InherentData) -> Result<Header, String> {
    import(propose(parent, slot, data), data)
}

/// The GRANDPA set `header` schedules, if it schedules one.
fn scheduled_grandpa_set(header: &Header) -> Option<Vec<GrandpaId>> {
    header.digest().logs().iter().find_map(|log| match log {
        DigestItem::Consensus(id, data) if *id == GRANDPA_ENGINE_ID => {
            match ConsensusLog::<BlockNumber>::decode(&mut &data[..]).ok()? {
                ConsensusLog::ScheduledChange(change) | ConsensusLog::ForcedChange(_, change) => {
                    Some(
                        change
                            .next_authorities
                            .into_iter()
                            .map(|(key, _)| key)
                            .collect(),
                    )
                }
                _ => None,
            }
        }
        _ => None,
    })
}

fn current_committee() -> Vec<Authority> {
    SessionCommitteeManagement::current_committee_storage()
        .committee
        .to_vec()
}

fn next_committee() -> Option<Vec<Authority>> {
    SessionCommitteeManagement::next_committee_storage().map(|next| next.committee.to_vec())
}

fn aura_authorities() -> Vec<AuraId> {
    pallet_aura::Authorities::<Runtime>::get().to_vec()
}

fn epoch_start(epoch: u64) -> u64 {
    epoch * SLOTS_PER_EPOCH
}

/// Every lever Root has armed on live preprod: the slack invariant, core
/// eviction, and the break-glass floor with the cores as its holders.
fn arm_live_levers() {
    let root = RuntimeOrigin::root;
    OrinqReceipts::set_slack_invariant_enabled(root(), true).unwrap();
    OrinqReceipts::set_core_eviction_enabled(root(), true).unwrap();
    let holders = cores()
        .iter()
        .map(|(_, keys)| keys.aura.encode().try_into().unwrap())
        .collect();
    OrinqReceipts::set_break_glass_aura_keys(root(), holders).unwrap();
    OrinqReceipts::set_break_glass_floor_enabled(root(), true).unwrap();
}

/// The slot of the first block a test plays inside an Ariadne-None window.
const IN_THE_WINDOW: u64 = 1_000 * SLOTS_PER_EPOCH + 5;

/// The chain after each core authors one of the first blocks of epoch 1000,
/// with no Ariadne data at any node: the committee for 1001 is still unset.
fn into_an_ariadne_none_window() -> Header {
    let mut parent = genesis_header();
    for slot in epoch_start(1_000)..IN_THE_WINDOW {
        parent = play(&parent, slot, &inherent_data(slot, None)).unwrap();
    }
    assert_eq!(next_committee(), None);
    parent
}

#[test]
fn peers_without_ariadne_data_refuse_a_block_that_seats_outsiders() {
    chain(&cores()).execute_with(|| {
        let parent = into_an_ariadne_none_window();
        let slot = IN_THE_WINDOW;
        let data = inherent_data(slot, None);
        let injected = propose_injected(&parent, slot, &data, outsiders());
        assert_eq!(
            peers_check(&injected, &data),
            Err(
                "/ariadne: The validators in the block do not match the calculated validators"
                    .to_string()
            )
        );
    });
}

#[test]
fn peers_without_ariadne_data_refuse_a_block_that_seats_an_empty_committee() {
    chain(&cores()).execute_with(|| {
        let parent = into_an_ariadne_none_window();
        let slot = IN_THE_WINDOW;
        let data = inherent_data(slot, None);
        let injected = propose_injected(&parent, slot, &data, Vec::new());
        assert_eq!(
            peers_check(&injected, &data),
            Err(
                "/ariadne: The validators in the block do not match the calculated validators"
                    .to_string()
            )
        );
    });
}

/// Block 1 has no parent whose reference its own must stay at or ahead of,
/// so its author may cite any stable block the peers accept, one that leaves
/// their Ariadne data empty included, at any time and not only inside a
/// window.
#[test]
fn peers_without_ariadne_data_refuse_a_first_block_that_seats_outsiders_or_no_one() {
    chain(&cores()).execute_with(|| {
        let slot = epoch_start(1_000);
        let data = inherent_data(slot, None);
        for committee in [outsiders(), Vec::new()] {
            let injected = propose_injected(&genesis_header(), slot, &data, committee.clone());
            assert_eq!(
                peers_check(&injected, &data),
                Err(
                    "/ariadne: The validators in the block do not match the calculated validators"
                        .to_string()
                ),
                "{committee:?}"
            );
        }
    });
}

/// The first block after a runtime upgrade. The peers' check initialises the
/// block, which runs the upgrade's migrations in the check's discarded state;
/// the import runs them again for good. Peers accept the block, and the
/// import records the upgrade.
#[test]
fn peers_accept_the_first_block_after_a_runtime_upgrade_and_its_import_records_the_upgrade() {
    chain(&cores()).execute_with(|| {
        let version = <Runtime as Core<Block>>::version();
        frame_system::LastRuntimeUpgrade::<Runtime>::put(frame_system::LastRuntimeUpgradeInfo {
            spec_version: (version.spec_version - 1).into(),
            spec_name: version.spec_name.clone(),
        });
        let recorded = || {
            frame_system::LastRuntimeUpgrade::<Runtime>::get()
                .is_some_and(|last| !last.was_upgraded(&version))
        };
        let slot = epoch_start(1_000);
        let data = inherent_data(slot, Some(&cardano(&cores())));
        let block = propose(&genesis_header(), slot, &data);
        assert!(!recorded());
        import(block, &data).unwrap_or_else(|rejection| panic!("{rejection}"));
        assert!(recorded());
    });
}

/// After an honest block stores the next committee, a second committee
/// inherent cannot replace it: not one the peers can check, and not even one
/// that re-seats the committee in force, which their check lets through.
#[test]
fn a_second_committee_inherent_cannot_overwrite_the_stored_next_committee() {
    chain(&cores()).execute_with(|| {
        let listed = cardano(&cores());
        let mut parent = genesis_header();
        for slot in epoch_start(1_000)..epoch_start(1_000) + 2 {
            parent = play(&parent, slot, &inherent_data(slot, Some(&listed))).unwrap();
        }
        assert_eq!(next_committee(), Some(cores()));

        let slot = epoch_start(1_000) + 2;
        let without_ariadne = inherent_data(slot, None);
        let injected = propose_edited(&parent, slot, &without_ariadne, |_| ());
        let overwrite = |validators: Vec<Authority>| {
            let mut block = injected.clone();
            block.extrinsics.push(UncheckedExtrinsic::new_unsigned(
                RuntimeCall::SessionCommitteeManagement(CommitteeCall::set {
                    validators: validators.try_into().unwrap(),
                    for_epoch_number: sidechain_domain::ScEpochNumber(
                        SessionCommitteeManagement::current_committee_storage()
                            .epoch
                            .0
                            + 1,
                    ),
                    selection_inputs_hash: SizedByteString([0xee; 32]),
                }),
            ));
            block
        };

        assert!(peers_check(&overwrite(outsiders()), &without_ariadne).is_err());

        let reseat = overwrite(cores());
        assert_eq!(peers_check(&reseat, &without_ariadne), Ok(()));
        let (header, extrinsics) = reseat.deconstruct();
        discarded(|| {
            <Runtime as Core<Block>>::initialize_block(&header);
            let (set, others) = extrinsics.split_last().unwrap();
            for extrinsic in others {
                <Runtime as BlockBuilder<Block>>::apply_extrinsic(extrinsic.clone())
                    .unwrap()
                    .unwrap();
            }
            assert_eq!(
                <Runtime as BlockBuilder<Block>>::apply_extrinsic(set.clone()),
                Err(TransactionValidityError::Invalid(
                    InvalidTransaction::BadMandatory
                ))
            );
        });
        assert_eq!(next_committee(), Some(cores()));
    });
}

/// Cardano's permissioned list for each sidechain epoch from 1000 to 1009,
/// while FPS ramps a core onto it every other epoch from 1002, then swaps
/// the second one out for another at 1007.
fn ramped_then_swapped() -> Vec<(u64, Vec<Authority>)> {
    let [p5, p6, p7, p8] = ["Core5", "Core6", "Core7", "Core8"].map(authority);
    (1_000..=1_009)
        .map(|epoch| {
            let added = match epoch {
                ..=1_001 => vec![],
                1_002..=1_003 => vec![&p5],
                1_004..=1_005 => vec![&p5, &p6],
                1_006 => vec![&p5, &p6, &p7],
                _ => vec![&p5, &p7, &p8],
            };
            (epoch, cores().iter().chain(added).cloned().collect())
        })
        .collect()
}

#[test]
fn peers_accept_every_block_while_the_slack_invariant_is_armed_and_cardano_ramps_then_swaps_a_core()
{
    chain(&cores()).execute_with(|| {
        OrinqReceipts::set_slack_invariant_enabled(RuntimeOrigin::root(), true).unwrap();
        let mut parent = genesis_header();
        for (epoch, listed) in ramped_then_swapped() {
            let listed = cardano(&listed);
            for slot in epoch_start(epoch)..epoch_start(epoch + 1) {
                parent = play(&parent, slot, &inherent_data(slot, Some(&listed)))
                    .unwrap_or_else(|rejection| panic!("epoch {epoch}, slot {slot}: {rejection}"));
            }
        }
        let (_, swapped) = ramped_then_swapped().pop().unwrap();
        assert_eq!(current_committee(), in_seating_order(swapped));
    });
}

/// Cardano as one node's Ariadne inherent data provider sees it.
struct Follower {
    /// Sidechain slots per Cardano epoch.
    mc_epoch_slots: u64,
    /// How many slots before Cardano's own epoch boundary the node's
    /// main-chain epoch configuration places it.
    early_slots: u64,
    /// How many slots the stable block a header references trails its slot.
    stability_slots: u64,
}

impl Follower {
    /// The node's Ariadne data for the block at `slot`, read on the parent's
    /// state as the node reads it: `None` while the Cardano epoch it would
    /// draw the next unset committee from is past the epoch of the stable
    /// block the header references. It depends on the parent's state, the
    /// slot and the referenced block, never on the node's follower tip.
    fn ariadne(
        &self,
        slot: u64,
        listed: &AuthoritySelectionInputs,
    ) -> Option<AuthoritySelectionInputs> {
        let next_unset = SessionCommitteeManagement::get_next_unset_epoch_number().0;
        let for_epoch = if next_unset == 1 {
            slot / SLOTS_PER_EPOCH
        } else {
            next_unset
        };
        let for_mc_epoch = (epoch_start(for_epoch) + self.early_slots) / self.mc_epoch_slots;
        let reference_mc_epoch = slot.saturating_sub(self.stability_slots) / self.mc_epoch_slots;
        (for_mc_epoch <= reference_mc_epoch).then(|| listed.clone())
    }
}

/// Live preprod's shape, scaled down: a node configured a fifth of a Cardano
/// epoch early, and the stable block a tenth of an epoch behind the slot.
const EARLY: Follower = Follower {
    mc_epoch_slots: 50,
    early_slots: 10,
    stability_slots: 5,
};

/// A node whose main-chain epoch configuration matches Cardano's.
const ON_TIME: Follower = Follower {
    mc_epoch_slots: 50,
    early_slots: 0,
    stability_slots: 5,
};

#[test]
fn an_honest_chain_produces_and_rotates_through_ariadne_none_windows_with_live_levers_armed() {
    const LAG_SLOTS: u64 = 7;
    let listed = cardano(&cores());
    let mut author = chain(&cores());
    let mut lagging = chain(&cores());
    author.execute_with(arm_live_levers);
    lagging.execute_with(arm_live_levers);

    // Four Cardano epochs, ending two sidechain epochs past the last
    // window, after the committee has caught up.
    let first = epoch_start(1_000);
    let last = first + 4 * EARLY.mc_epoch_slots + 2 * SLOTS_PER_EPOCH;
    let mut tip = genesis_header();
    let mut unchecked = std::collections::VecDeque::new();
    let mut lagging_tip = genesis_header();
    let (mut none_blocks, mut rotations) = (0, 0);
    // A peer whose follower trails by LAG_SLOTS cannot check a block until
    // it holds the stable block the header references; then it checks the
    // block on its own copy of the parent's state.
    let mut lagging_peer_checks = |made_at: u64, block: Block| {
        lagging.execute_with(|| {
            let data = inherent_data(made_at, EARLY.ariadne(made_at, &listed).as_ref());
            lagging_tip = import(block, &data)
                .unwrap_or_else(|rejection| panic!("lagging peer, slot {made_at}: {rejection}"));
        });
    };
    for slot in first..last {
        author.execute_with(|| {
            let ariadne = EARLY.ariadne(slot, &listed);
            none_blocks += usize::from(ariadne.is_none());
            let data = inherent_data(slot, ariadne.as_ref());
            let block = propose(&tip, slot, &data);
            tip = import(block.clone(), &data)
                .unwrap_or_else(|rejection| panic!("slot {slot}: {rejection}"));
            if let Some(set) = scheduled_grandpa_set(&tip) {
                assert!(
                    !set.is_empty(),
                    "slot {slot} schedules an empty GRANDPA set"
                );
                rotations += 1;
            }
            unchecked.push_back((slot, block));
        });
        while unchecked
            .front()
            .is_some_and(|(made_at, _)| made_at + LAG_SLOTS <= slot)
        {
            let (made_at, block) = unchecked.pop_front().unwrap();
            lagging_peer_checks(made_at, block);
        }
    }
    for (made_at, block) in unchecked {
        lagging_peer_checks(made_at, block);
    }

    assert_eq!(
        lagging_tip, tip,
        "the lagging peer reaches the author's tip"
    );
    author.execute_with(|| {
        assert!(
            none_blocks > 50,
            "only {none_blocks} blocks in Ariadne-None windows"
        );
        assert!(rotations > 10, "only {rotations} rotations");
        assert_eq!(
            SessionCommitteeManagement::current_committee_storage()
                .epoch
                .0,
            (last - 1) / SLOTS_PER_EPOCH,
            "the committee caught up with the epoch after the last window"
        );
        assert_eq!(current_committee(), cores());
        assert_eq!(
            aura_authorities(),
            cores()
                .into_iter()
                .map(|(_, keys)| keys.aura)
                .collect::<Vec<_>>()
        );
    });
}

/// A node whose main-chain epoch configuration is on time draws a committee
/// while a node configured early has no Ariadne data. The early node accepts
/// the draw when it re-seats the committee in force, so honest nodes
/// configured differently keep one chain while the committee is unchanged.
#[test]
fn a_peer_without_ariadne_data_follows_an_author_whose_draw_keeps_the_committee() {
    let listed = cardano(&cores());
    let mut on_time = chain(&cores());
    let mut early = chain(&cores());
    on_time.execute_with(arm_live_levers);
    early.execute_with(arm_live_levers);

    let first = epoch_start(1_000);
    let mut tip = genesis_header();
    let mut divergent = 0;
    for slot in first..first + 3 * ON_TIME.mc_epoch_slots {
        let (block, author_has_data) = on_time.execute_with(|| {
            let ariadne = ON_TIME.ariadne(slot, &listed);
            let data = inherent_data(slot, ariadne.as_ref());
            let block = propose(&tip, slot, &data);
            tip = import(block.clone(), &data).unwrap();
            (block, ariadne.is_some())
        });
        early.execute_with(|| {
            let ariadne = EARLY.ariadne(slot, &listed);
            let carries_set = block.extrinsics.iter().any(|x| {
                matches!(
                    x.function,
                    RuntimeCall::SessionCommitteeManagement(CommitteeCall::set { .. })
                )
            });
            divergent += usize::from(author_has_data && ariadne.is_none() && carries_set);
            import(block, &inherent_data(slot, ariadne.as_ref()))
                .unwrap_or_else(|rejection| panic!("early peer, slot {slot}: {rejection}"));
        });
    }
    assert!(
        divergent > 0,
        "no block drew a committee the early peer could not recompute"
    );
}

/// The limit of that: a draw that changes the committee is refused by a
/// peer without Ariadne data, which cannot tell it from an injected one.
#[test]
fn a_peer_without_ariadne_data_refuses_a_draw_that_changes_the_committee() {
    chain(&cores()).execute_with(|| {
        let parent = into_an_ariadne_none_window();
        let slot = IN_THE_WINDOW;
        let grown: Vec<_> = cores().into_iter().chain([authority("Core5")]).collect();
        let drawn = propose(&parent, slot, &inherent_data(slot, Some(&cardano(&grown))));
        assert!(drawn.extrinsics.iter().any(|x| matches!(
            x.function,
            RuntimeCall::SessionCommitteeManagement(CommitteeCall::set { .. })
        )));
        assert_eq!(
            peers_check(&drawn, &inherent_data(slot, None)),
            Err(
                "/ariadne: The validators in the block do not match the calculated validators"
                    .to_string()
            )
        );
    });
}
