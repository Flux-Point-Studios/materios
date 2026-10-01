//! The committee inherent as the network plays it. The slot's author makes
//! each block from its own inherent data; every peer checks the block with
//! `check_inherents` at the parent, as the node's Aura import queue does, and
//! imports it only if that passes.

use crate::*;
use authority_selection_inherents::authority_selection_inputs::AuthoritySelectionInputs;
use frame_support::inherent::ProvideInherent;
use parity_scale_codec::{Decode, Encode};
use sidechain_domain::{
    byte_string::SizedByteString, AuraPublicKey, DParameter, EpochNonce, GrandpaPublicKey,
    PermissionedCandidateData, SidechainPublicKey,
};
use sp_api::runtime_decl_for_core::Core;
use sp_block_builder::runtime_decl_for_block_builder::BlockBuilder;
use sp_consensus_aura::{Slot, AURA_ENGINE_ID};
use sp_core::{ecdsa, ed25519, sr25519, Pair};
use sp_inherents::InherentData;
use sp_runtime::{
    traits::{Block as _, Header as _},
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


fn current_committee() -> Vec<Authority> {
    SessionCommitteeManagement::current_committee_storage()
        .committee
        .to_vec()
}


fn epoch_start(epoch: u64) -> u64 {
    epoch * SLOTS_PER_EPOCH
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
