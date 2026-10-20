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

	pub async fn new<Block, SessionKeys, CrossChainPublic, T>(
		client: &T,
		sc_slot_config: &ScSlotConfig,
		mc_epoch_config: &MainchainEpochConfig,
		parent_hash: <Block as BlockT>::Hash,
		slot: Slot,
		candidate_data_source: &(dyn AuthoritySelectionDataSource + Send + Sync),
		mc_reference_epoch: McEpochNumber,
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
		let for_mc_epoch = mc_epoch_for_next_ariadne_cidp(
			client,
			sc_slot_config,
			mc_epoch_config,
			parent_hash,
			slot,
		)?;

		let data_epoch = candidate_data_source.data_epoch(for_mc_epoch).await?;
		// We could accept mc_reference at last slot of data_epoch, but calculations are much easier like that.
		// Additionally, in current implementation, the inequality below is always true, thus there is no need to make it more accurate.
		let scripts = client.runtime_api().get_main_chain_scripts(parent_hash)?;
		if data_epoch < mc_reference_epoch {
			Ok(AriadneInherentDataProvider::from_mc_data(
				candidate_data_source,
				for_mc_epoch,
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
fn mc_epoch_for_next_ariadne_cidp<Block, SessionKeys, CrossChainPublic, T>(
	client: &T,
	sc_slot_config: &ScSlotConfig,
	epoch_config: &MainchainEpochConfig,
	parent_hash: <Block as BlockT>::Hash,
	slot: Slot,
) -> Result<McEpochNumber, InherentProviderCreationError>
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

	let for_sc_epoch_number = {
		// A special case for the genesis committee (current epoch 0, next unset epoch 1).
		// The genesis committee epoch is initialized with 0, so in the very first block we need to provide
		// the epoch number based on the current slot number
		if next_unset_epoch == ScEpochNumber(1) {
			sc_slot_config.epoch_number(slot)
		} else {
			next_unset_epoch
		}
	};

	sc_epoch_to_mc_epoch(for_sc_epoch_number, sc_slot_config, epoch_config)
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
		)
		.await;

		assert!(empty_ariadne_idp.is_ok());
		assert!(empty_ariadne_idp.unwrap().data.is_none());
	}

	/// Cardano data as a follower serves it: for the epoch `lag` epochs
	/// before the one it is used in.
	struct Follower {
		lag: u32,
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
			_epoch: McEpochNumber,
		) -> Result<Option<EpochNonce>, Box<dyn std::error::Error + Send + Sync>> {
			Ok(Some(EpochNonce(vec![42])))
		}

		async fn data_epoch(
			&self,
			for_epoch: McEpochNumber,
		) -> Result<McEpochNumber, Box<dyn std::error::Error + Send + Sync>> {
			Ok(McEpochNumber(for_epoch.0 - self.lag))
		}
	}

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

	/// Seconds in which a node with Cardano epoch layout `node_epochs`, and
	/// data from `follower`, has no Ariadne data for the committee its chain
	/// asks for next, from 30 h before the Cardano epoch `cardano_epochs`
	/// starts at `boundary` to 40 h after it. Its stable reference block is
	/// `reference_age` behind each slot: from k/f, the newest stable block,
	/// to 3k/f, the oldest the mc-hash inherent accepts.
	///
	/// The chain stores the next committee at the first block that has the
	/// data, and rotates to it at the next session; with none stored, it
	/// keeps the committee in force and asks again for the one after it.
	async fn seconds_without_data(
		node_epochs: &MainchainEpochConfig,
		cardano_epochs: &MainchainEpochConfig,
		boundary: u64,
		reference_age: u64,
		follower: &Follower,
	) -> u64 {
		let slots = materios_slots();
		let slot_millis = slots.slot_duration.as_millis();
		let (first, last) =
			((boundary - 30 * HOUR) / slot_millis, (boundary + 40 * HOUR) / slot_millis);
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
				follower,
				reference,
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

	/// What the provider gives for session 497_976, which starts with Cardano
	/// preprod's epoch 321 on 2026-10-23 at 00:00 UTC and so takes its data
	/// from epoch 319, while the stable reference block is in `epoch`.
	async fn data_for_session_497_976(epoch: u32) -> Option<AuthoritySelectionInputs> {
		AriadneInherentDataProvider::new(
			&TestApi { next_unset_epoch_number: ScEpochNumber(497_976) },
			&materios_slots(),
			&preprod(),
			H256::zero(),
			Slot::from(0),
			&Follower { lag: 2 },
			McEpochNumber(epoch),
		)
		.await
		.unwrap()
		.data
	}

	/// Data from the epoch the stable reference block is in may still change
	/// above that block, so the provider has none to give.
	#[tokio::test]
	async fn no_data_from_the_cardano_epoch_of_the_stable_reference_block() {
		assert!(data_for_session_497_976(319).await.is_none());
		assert!(data_for_session_497_976(320).await.is_some());
	}

	/// Followers that serve data from two epochs back give every block data,
	/// on preprod and mainnet, on the fleet's early epoch layout as on
	/// Cardano's, for any stable reference block the mc-hash inherent
	/// accepts. Followers one epoch back, which give the same blocks data as
	/// no lag under `<=`, leave without data the two sessions that start
	/// before each Cardano epoch boundary and the reference block's age after
	/// it: 4.4 h on preprod, whose boundaries start a session, 13.7 h at a
	/// mainnet boundary 44 min 51 s into a session, and 28.4 h on the fleet's
	/// layout.
	#[tokio::test]
	async fn followers_two_epochs_back_leave_no_block_without_data() {
		let preprod_boundary = 1_654_041_600_000 + 321 * 120 * HOUR;
		let mainnet_boundary = 1_596_059_091_000 + (600 - 208) * 120 * HOUR;
		for (name, node_epochs, cardano_epochs, boundary, stability, one_back) in [
			("preprod", preprod(), preprod(), preprod_boundary, PREPROD_STABILITY, 15_834),
			(
				"preprod fleet",
				preprod_fleet(),
				preprod(),
				preprod_boundary,
				PREPROD_STABILITY,
				102_234,
			),
			("mainnet", mainnet(), mainnet(), mainnet_boundary, MAINNET_STABILITY, 49_488),
		] {
			assert_eq!(
				seconds_without_data(
					&node_epochs,
					&cardano_epochs,
					boundary,
					stability,
					&Follower { lag: 1 }
				)
				.await,
				one_back,
				"{name}, one epoch back"
			);
			for reference_age in [stability, 3 * stability] {
				assert_eq!(
					seconds_without_data(
						&node_epochs,
						&cardano_epochs,
						boundary,
						reference_age,
						&Follower { lag: 2 }
					)
					.await,
					0,
					"{name}, two epochs back, reference {reference_age} ms old"
				);
			}
		}
	}
}
