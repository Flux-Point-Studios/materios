#[cfg(feature = "std")]
use crate::authority_selection_inputs::AuthoritySelectionDataSource;
use crate::authority_selection_inputs::AuthoritySelectionInputs;
use parity_scale_codec::{Decode, Encode};
use sidechain_domain::mainchain_epoch::MainchainEpochConfig;
#[cfg(feature = "std")]
use {
	crate::authority_selection_inputs::AuthoritySelectionInputsCreationError,
	sidechain_domain::mainchain_epoch::MainchainEpochDerivation,
	sidechain_domain::*,
	sidechain_slots::ScSlotConfig,
	sp_api::ProvideRuntimeApi,
	sp_consensus_slots::Slot,
	sp_inherents::{InherentData, InherentIdentifier},
	sp_runtime::traits::Block as BlockT,
	sp_session_validator_management::{
		InherentError, MainChainScripts, SessionValidatorManagementApi, INHERENT_IDENTIFIER,
	},
};

/// The type of the inherent.
pub type InherentType = AuthoritySelectionInputs;

#[derive(Clone, Debug, Encode, Decode)]
pub struct AriadneInherentDataProvider {
	pub data: Option<AuthoritySelectionInputs>,
}

#[cfg(feature = "std")]
impl AriadneInherentDataProvider {
	pub async fn from_mc_data(
		candidate_data_source: &(dyn AuthoritySelectionDataSource + Send + Sync),
		for_epoch: McEpochNumber,
		scripts: MainChainScripts,
	) -> Result<Self, InherentProviderCreationError> {
		Ok(Self {
			data: Some(
				AuthoritySelectionInputs::from_mc_data(candidate_data_source, for_epoch, scripts)
					.await?,
			),
		})
	}

	/// [materios-patch: relaxed-until] The committees of sessions before
	/// `relaxed_until` are drawn under the preprod relaxation their chain drew
	/// them under, so that its blocks still verify: from the data stored up to
	/// the Cardano epoch the session starts in, given once the stable reference
	/// block is in that epoch. Later committees are drawn under upstream's rule.
	pub async fn new<Block, SessionKeys, CrossChainPublic, T>(
		client: &T,
		sc_slot_config: &ScSlotConfig,
		mc_epoch_config: &MainchainEpochConfig,
		parent_hash: <Block as BlockT>::Hash,
		slot: Slot,
		candidate_data_source: &(dyn AuthoritySelectionDataSource + Send + Sync),
		mc_reference_epoch: McEpochNumber,
		relaxed_until: ScEpochNumber,
	) -> Result<Self, InherentProviderCreationError>
	where
		SessionKeys: Decode,
		CrossChainPublic: Decode + Encode,
		Block: BlockT,
		T: ProvideRuntimeApi<Block> + Send + Sync,
		T::Api: SessionValidatorManagementApi<
			Block,
			SessionKeys,
			CrossChainPublic,
			AuthoritySelectionInputs,
			ScEpochNumber,
		>,
	{
		let for_sc_epoch = sc_epoch_for_next_ariadne_cidp(client, sc_slot_config, parent_hash, slot)?;
		let for_mc_epoch = sc_epoch_to_mc_epoch(for_sc_epoch, sc_slot_config, mc_epoch_config)?;
		let relaxed = for_sc_epoch < relaxed_until;
		// A follower serves the data stored up to an epoch for the epoch two after it.
		let usage_epoch =
			if relaxed { McEpochNumber(for_mc_epoch.0 + 2) } else { for_mc_epoch };

		let data_epoch = candidate_data_source.data_epoch(usage_epoch).await?;
		// We could accept mc_reference at last slot of data_epoch, but calculations are much easier like that.
		// Additionally, in current implementation, the inequality below is always true, thus there is no need to make it more accurate.
		let scripts = client.runtime_api().get_main_chain_scripts(parent_hash)?;
		if data_epoch < mc_reference_epoch || (relaxed && data_epoch == mc_reference_epoch) {
			Ok(AriadneInherentDataProvider::from_mc_data(
				candidate_data_source,
				usage_epoch,
				scripts,
			)
			.await?)
		} else {
			Ok(AriadneInherentDataProvider { data: None })
		}
	}
}

#[cfg(feature = "std")]
#[derive(Debug, thiserror::Error)]
pub enum InherentProviderCreationError {
	#[error("Slot represents a timestamp bigger than of u64::MAX")]
	SlotTooBig,
	#[error("Couldn't convert timestamp to main chain epoch: {0}")]
	McEpochDerivationError(#[from] sidechain_domain::mainchain_epoch::EpochDerivationError),
	#[error("Runtime API call failed: {0}")]
	ApiError(#[from] sp_api::ApiError),
	#[error("Failed to create authority selection inputs: {0}")]
	InputsCreationError(#[from] AuthoritySelectionInputsCreationError),
	#[error("Data source call failed: {0}")]
	DataSourceError(#[from] Box<dyn std::error::Error + Send + Sync>),
}

#[cfg(feature = "std")]
fn sc_epoch_for_next_ariadne_cidp<Block, SessionKeys, CrossChainPublic, T>(
	client: &T,
	sc_slot_config: &ScSlotConfig,
	parent_hash: <Block as BlockT>::Hash,
	slot: Slot,
) -> Result<ScEpochNumber, InherentProviderCreationError>
where
	Block: BlockT,
	SessionKeys: Decode,
	CrossChainPublic: Decode + Encode,
	T: ProvideRuntimeApi<Block> + Send + Sync,
	T::Api: SessionValidatorManagementApi<
		Block,
		SessionKeys,
		CrossChainPublic,
		AuthoritySelectionInputs,
		ScEpochNumber,
	>,
{
	let next_unset_epoch = client.runtime_api().get_next_unset_epoch_number(parent_hash)?;

	// A special case for the genesis committee (current epoch 0, next unset epoch 1).
	// The genesis committee epoch is initialized with 0, so in the very first block we need to provide
	// the epoch number based on the current slot number
	if next_unset_epoch == ScEpochNumber(1) {
		Ok(sc_slot_config.epoch_number(slot))
	} else {
		Ok(next_unset_epoch)
	}
}

#[cfg(feature = "std")]
fn sc_epoch_to_mc_epoch(
	sc_epoch: ScEpochNumber,
	sc_slot_config: &ScSlotConfig,
	epoch_config: &MainchainEpochConfig,
) -> Result<McEpochNumber, InherentProviderCreationError> {
	let timestamp = sc_slot_config
		.epoch_start_time(sc_epoch)
		.ok_or(InherentProviderCreationError::SlotTooBig)?;

	epoch_config
		.timestamp_to_mainchain_epoch(timestamp)
		.map_err(InherentProviderCreationError::McEpochDerivationError)
}

#[cfg(feature = "std")]
#[async_trait::async_trait]
impl sp_inherents::InherentDataProvider for AriadneInherentDataProvider {
	async fn provide_inherent_data(
		&self,
		inherent_data: &mut InherentData,
	) -> Result<(), sp_inherents::Error> {
		match &self.data {
			None => Ok(()),
			Some(data) => inherent_data.put_data(INHERENT_IDENTIFIER, data),
		}
	}

	async fn try_handle_error(
		&self,
		identifier: &InherentIdentifier,
		error: &[u8],
	) -> Option<Result<(), sp_inherents::Error>> {
		// Dont' process modules from other inherents
		if *identifier != INHERENT_IDENTIFIER {
			return None;
		}

		let mut error = error;
		Some(Err(sp_inherents::Error::Application(Box::from(
			<InherentError as parity_scale_codec::Decode>::decode(&mut error).ok()?,
		))))
	}
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct CommitteeConfig {
	pub min_size: u16,
	pub max_size: u16,
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::ariadne_inherent_data_provider::AriadneInherentDataProvider;
	use crate::authority_selection_inputs::AriadneParameters;
	use crate::mock::MockAuthoritySelectionDataSource;
	use crate::runtime_api_mock::*;
	use sidechain_domain::mainchain_epoch::*;
	use sidechain_slots::*;
	use sp_core::offchain::Timestamp;
	use sp_core::H256;
	use SlotDuration;

	#[tokio::test]
	async fn return_empty_ariadne_cidp_if_runtime_requests_too_new_epoch() {
		// This is the epoch number that is too new
		let next_unset_epoch_number = ScEpochNumber(42);
		let client = TestApi { next_unset_epoch_number };
		let sc_slot_config = ScSlotConfig {
			slots_per_epoch: SlotsPerEpoch(10),
			slot_duration: SlotDuration::from_millis(1000),
		};
		let epoch_config = MainchainEpochConfig {
			first_epoch_timestamp_millis: Timestamp::from_unix_millis(0),
			first_epoch_number: 0,
			epoch_duration_millis: Duration::from_millis(
				u64::from(sc_slot_config.slots_per_epoch.0)
					* sc_slot_config.slot_duration.as_millis()
					* 10,
			),
			first_slot_number: 0,
		};
		let mc_reference_epoch = McEpochNumber(1);
		let empty_ariadne_idp = AriadneInherentDataProvider::new(
			&client,
			&sc_slot_config,
			&epoch_config,
			H256::zero(),
			// This is the slot that will be used to calculate current_epoch_number
			Slot::from(400u64),
			&MockAuthoritySelectionDataSource::default(),
			mc_reference_epoch,
			UPSTREAM,
		)
		.await;

		assert!(empty_ariadne_idp.is_ok());
		assert!(empty_ariadne_idp.unwrap().data.is_none());
	}

	/// Cardano data as an upstream follower serves it: for the epoch two
	/// before the one it is used in. Its epoch nonce names the epoch whose
	/// data it is.
	struct Follower;

	fn stored_for(epoch: McEpochNumber) -> McEpochNumber {
		McEpochNumber(epoch.0 - 2)
	}

	#[async_trait::async_trait]
	impl AuthoritySelectionDataSource for Follower {
		async fn get_ariadne_parameters(
			&self,
			_epoch: McEpochNumber,
			_d_parameter: PolicyId,
			_permissioned_candidates: PolicyId,
		) -> Result<AriadneParameters, Box<dyn std::error::Error + Send + Sync>> {
			Ok(AriadneParameters {
				d_parameter: DParameter {
					num_permissioned_candidates: 1,
					num_registered_candidates: 0,
				},
				permissioned_candidates: vec![],
			})
		}

		async fn get_candidates(
			&self,
			_epoch: McEpochNumber,
			_committee_candidate_address: MainchainAddress,
		) -> Result<Vec<CandidateRegistrations>, Box<dyn std::error::Error + Send + Sync>> {
			Ok(vec![])
		}

		async fn get_epoch_nonce(
			&self,
			epoch: McEpochNumber,
		) -> Result<Option<EpochNonce>, Box<dyn std::error::Error + Send + Sync>> {
			Ok(Some(EpochNonce(stored_for(epoch).0.to_be_bytes().to_vec())))
		}

		async fn data_epoch(
			&self,
			for_epoch: McEpochNumber,
		) -> Result<McEpochNumber, Box<dyn std::error::Error + Send + Sync>> {
			Ok(stored_for(for_epoch))
		}
	}

	/// Every committee drawn under upstream's rule.
	const UPSTREAM: ScEpochNumber = ScEpochNumber(0);
	/// Every committee drawn under the relaxation.
	const RELAXED: ScEpochNumber = ScEpochNumber(u64::MAX);
	/// The committees of sessions before 498_492, which starts on 2026-11-13
	/// at 12:00 UTC, drawn under the relaxation.
	const SWITCH: ScEpochNumber = ScEpochNumber(498_492);

	const HOUR: u64 = 3_600_000;

	/// One-hour sessions: 600 slots of 6 s.
	fn materios_slots() -> ScSlotConfig {
		ScSlotConfig {
			slots_per_epoch: SlotsPerEpoch(600),
			slot_duration: SlotDuration::from_millis(6_000),
		}
	}

	fn five_day_epochs(
		first_epoch_timestamp_millis: u64,
		first_epoch_number: u32,
	) -> MainchainEpochConfig {
		MainchainEpochConfig {
			first_epoch_timestamp_millis: Timestamp::from_unix_millis(first_epoch_timestamp_millis),
			first_epoch_number,
			epoch_duration_millis: Duration::from_millis(120 * HOUR),
			first_slot_number: 0,
		}
	}

	/// Cardano preprod's epochs, which start at 00:00 UTC.
	fn preprod() -> MainchainEpochConfig {
		five_day_epochs(1_654_041_600_000, 0)
	}

	/// When Cardano preprod's epoch `epoch` starts.
	fn preprod_boundary(epoch: u64) -> u64 {
		1_654_041_600_000 + epoch * 120 * HOUR
	}

	/// The MC__ epoch layout the preprod fleet's start scripts set, which
	/// starts every Cardano epoch a day early.
	fn preprod_fleet() -> MainchainEpochConfig {
		five_day_epochs(1_655_683_200_000, 4)
	}

	/// Cardano mainnet's epochs since Shelley.
	fn mainnet() -> MainchainEpochConfig {
		five_day_epochs(1_596_059_091_000, 208)
	}

	/// A Cardano block is stable k blocks deep, k/f of its slots: 432/0.05 s
	/// on preprod, 2160/0.05 s on mainnet.
	const PREPROD_STABILITY: u64 = 8_640_000;
	const MAINNET_STABILITY: u64 = 43_200_000;

	/// The Cardano epoch whose data the provider gives a block for the
	/// committee of session `next_unset`, on epoch layout `node_epochs`, while
	/// the block's stable reference block is in epoch `reference`.
	async fn data_given(
		node_epochs: &MainchainEpochConfig,
		next_unset: u64,
		reference: u32,
		relaxed_until: ScEpochNumber,
	) -> Option<u32> {
		AriadneInherentDataProvider::new(
			&TestApi { next_unset_epoch_number: ScEpochNumber(next_unset) },
			&materios_slots(),
			node_epochs,
			H256::zero(),
			Slot::from(0),
			&Follower,
			McEpochNumber(reference),
			relaxed_until,
		)
		.await
		.unwrap()
		.data
		.map(|inputs| u32::from_be_bytes(inputs.epoch_nonce.0.try_into().unwrap()))
	}

	/// Seconds in which a node with Cardano epoch layout `node_epochs` has no
	/// Ariadne data for the committee its chain asks for next, from `from` to
	/// `to` (Unix ms). Its stable reference block is `reference_age` behind
	/// each slot, in the epochs `cardano_epochs` lays out: from k/f, the newest
	/// stable block, to 3k/f, the oldest the mc-hash inherent accepts.
	///
	/// The chain stores the next committee at the first block that has the
	/// data, and rotates to it at the next session; with none stored, it
	/// keeps the committee in force and asks again for the one after it.
	async fn seconds_without_data(
		node_epochs: &MainchainEpochConfig,
		cardano_epochs: &MainchainEpochConfig,
		(from, to): (u64, u64),
		reference_age: u64,
		relaxed_until: ScEpochNumber,
	) -> u64 {
		let slots = materios_slots();
		let slot_millis = slots.slot_duration.as_millis();
		let (first, last) = (from / slot_millis, to / slot_millis);
		let mut current = slots.epoch_number(Slot::from(first));
		let mut next: Option<ScEpochNumber> = None;
		let mut without = 0;
		for slot in first..last {
			if slots.epoch_number(Slot::from(slot)) > current {
				if let Some(stored) = next.take() {
					current = stored;
				}
			}
			let reference = cardano_epochs
				.timestamp_to_mainchain_epoch(Timestamp::from_unix_millis(
					slot * slot_millis - reference_age,
				))
				.unwrap();
			let client =
				TestApi { next_unset_epoch_number: ScEpochNumber(next.unwrap_or(current).0 + 1) };
			let idp = AriadneInherentDataProvider::new(
				&client,
				&slots,
				node_epochs,
				H256::zero(),
				Slot::from(slot),
				&Follower,
				reference,
				relaxed_until,
			)
			.await
			.unwrap();
			match idp.data {
				None => without += slot_millis / 1000,
				Some(_) if next.is_none() => next = Some(ScEpochNumber(current.0 + 1)),
				Some(_) => {},
			}
		}
		without
	}

	/// Session 497_976 starts with Cardano preprod's epoch 321 on 2026-10-23 at
	/// 00:00 UTC. Upstream's rule draws it from epoch 319's data, which may
	/// still change above a stable reference block in epoch 319, so it gives
	/// none until the reference block is in epoch 320.
	#[tokio::test]
	async fn no_data_from_the_cardano_epoch_of_the_stable_reference_block() {
		assert_eq!(data_given(&preprod(), 497_976, 319, UPSTREAM).await, None);
		assert_eq!(data_given(&preprod(), 497_976, 320, UPSTREAM).await, Some(319));
	}

	/// Preprod block #2102140, 2026-10-01T23:00Z, was authored inside the
	/// relaxation's window with no `set`: its parent asks for session 497_472,
	/// which starts on 2026-10-02 at 00:00 UTC, in epoch 317 on the fleet's
	/// layout, while its stable reference block is in epoch 316. A verifier
	/// with data refuses such a block, so the relaxation gives none, as the
	/// author had; upstream's rule, from the session the relaxation ends with,
	/// gives epoch 315's. Once the reference block is in epoch 317, which is
	/// when the fleet's `set`s resumed (#2118655, 2026-10-03T02:35:30Z), the
	/// relaxation gives that epoch's own data.
	#[tokio::test]
	async fn a_relaxed_session_gets_the_data_its_blocks_were_authored_with() {
		let fleet = preprod_fleet();
		assert_eq!(data_given(&fleet, 497_472, 316, RELAXED).await, None);
		assert_eq!(data_given(&fleet, 497_472, 317, RELAXED).await, Some(317));
		assert_eq!(data_given(&fleet, 497_472, 316, ScEpochNumber(497_473)).await, None);
		assert_eq!(data_given(&fleet, 497_472, 316, ScEpochNumber(497_472)).await, Some(315));
		assert_eq!(data_given(&fleet, 497_472, 316, UPSTREAM).await, Some(315));
	}

	/// Upstream's rule gives every block data, on preprod and mainnet, on the
	/// fleet's early epoch layout as on Cardano's, for any stable reference
	/// block the mc-hash inherent accepts. The relaxation leaves without data
	/// the two sessions that start before each Cardano epoch boundary and the
	/// reference block's age after it: 4.4 h on preprod, whose boundaries
	/// start a session, 13.7 h at a mainnet boundary 44 min 51 s into a
	/// session, and 28.4 h on the fleet's layout.
	#[tokio::test]
	async fn upstreams_rule_leaves_no_block_without_data_where_the_relaxation_has_its_window() {
		let mainnet_boundary = 1_596_059_091_000 + (600 - 208) * 120 * HOUR;
		for (name, node_epochs, cardano_epochs, boundary, stability, relaxed_window) in [
			("preprod", preprod(), preprod(), preprod_boundary(321), PREPROD_STABILITY, 15_834),
			(
				"preprod fleet",
				preprod_fleet(),
				preprod(),
				preprod_boundary(321),
				PREPROD_STABILITY,
				102_234,
			),
			("mainnet", mainnet(), mainnet(), mainnet_boundary, MAINNET_STABILITY, 49_488),
		] {
			let around = (boundary - 30 * HOUR, boundary + 40 * HOUR);
			assert_eq!(
				seconds_without_data(&node_epochs, &cardano_epochs, around, stability, RELAXED)
					.await,
				relaxed_window,
				"{name}, relaxed"
			);
			for reference_age in [stability, 3 * stability] {
				assert_eq!(
					seconds_without_data(
						&node_epochs,
						&cardano_epochs,
						around,
						reference_age,
						UPSTREAM
					)
					.await,
					0,
					"{name}, upstream, reference {reference_age} ms old"
				);
			}
		}
	}

	/// Session 498_492 starts on 2026-11-13 at 12:00 UTC, in epoch 325 on the
	/// fleet's layout. Switching to upstream's rule with it, the session
	/// before is drawn from epoch 325's own data and it from epoch 323's, and
	/// no block lacks data from 30 h before the switch to 40 h after the
	/// Cardano epoch boundary of 2026-11-17, around which the relaxation
	/// leaves its 28.4 h window.
	#[tokio::test]
	async fn switching_to_upstreams_rule_leaves_no_block_without_data() {
		let fleet = preprod_fleet();
		assert_eq!(data_given(&fleet, 498_491, 325, SWITCH).await, Some(325));
		assert_eq!(data_given(&fleet, 498_492, 325, SWITCH).await, Some(323));
		let switch = SWITCH.0 * HOUR;
		let through = (switch - 30 * HOUR, preprod_boundary(326) + 40 * HOUR);
		for (relaxed_until, without) in [(SWITCH, 0), (RELAXED, 102_234)] {
			assert_eq!(
				seconds_without_data(&fleet, &preprod(), through, PREPROD_STABILITY, relaxed_until)
					.await,
				without,
				"relaxed until session {}",
				relaxed_until.0
			);
		}
	}
}
