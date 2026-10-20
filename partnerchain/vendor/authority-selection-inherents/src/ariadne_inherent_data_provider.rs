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

/// [materios-patch: preprod-v6-relaxation] Which Cardano data the provider
/// draws a session's committee from. The node picks the rule per genesis.
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AriadneRule {
	/// Upstream's: the data the follower serves for the Cardano epoch the
	/// session starts in, given once the stable reference block is past the
	/// epoch that data was stored up to.
	Strict,
	/// Preprod v6's, under which every one of its blocks was authored and
	/// verified: the data stored up to the Cardano epoch the session starts
	/// in, given once the stable reference block is in that epoch.
	Relaxed,
}

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
		rule: AriadneRule,
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

		// [materios-patch: preprod-v6-relaxation] A follower serves the data
		// stored up to an epoch for the epoch two after it.
		let usage_epoch = match rule {
			AriadneRule::Strict => for_mc_epoch,
			AriadneRule::Relaxed => McEpochNumber(for_mc_epoch.0 + 2),
		};
		let data_epoch = candidate_data_source.data_epoch(usage_epoch).await?;
		// We could accept mc_reference at last slot of data_epoch, but calculations are much easier like that.
		// The inequality does not always hold. Under Strict it holds for every block a node can author or
		// verify on a Cardano epoch layout at most an epoch less two sessions and 3k/f early; Relaxed
		// fails it around every Cardano epoch boundary. See the tests.
		let scripts = client.runtime_api().get_main_chain_scripts(parent_hash)?;
		let given = match rule {
			AriadneRule::Strict => data_epoch < mc_reference_epoch,
			AriadneRule::Relaxed => data_epoch <= mc_reference_epoch,
		};
		if given {
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
	use crate::mock::{FollowerMock, MockAuthoritySelectionDataSource};
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
			AriadneRule::Strict,
		)
		.await;

		assert!(empty_ariadne_idp.is_ok());
		assert!(empty_ariadne_idp.unwrap().data.is_none());
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

	/// When Cardano preprod's epoch 0 started.
	const PREPROD_EPOCH_0: u64 = 1_654_041_600_000;

	/// When Cardano mainnet's epoch 208, its first under Shelley, started.
	const MAINNET_EPOCH_208: u64 = 1_596_059_091_000;

	/// Cardano preprod's epochs, which start at 00:00 UTC.
	fn preprod() -> MainchainEpochConfig {
		five_day_epochs(PREPROD_EPOCH_0, 0)
	}

	/// When Cardano preprod's epoch `epoch` starts.
	fn preprod_boundary(epoch: u64) -> u64 {
		PREPROD_EPOCH_0 + epoch * 120 * HOUR
	}

	/// The MC__ epoch layout the preprod fleet's start scripts set, which
	/// starts every Cardano epoch a day early.
	fn preprod_fleet() -> MainchainEpochConfig {
		five_day_epochs(1_655_683_200_000, 4)
	}

	/// Cardano mainnet's epochs since Shelley.
	fn mainnet() -> MainchainEpochConfig {
		five_day_epochs(MAINNET_EPOCH_208, 208)
	}

	/// When Cardano mainnet's epoch `epoch` starts.
	fn mainnet_boundary(epoch: u64) -> u64 {
		MAINNET_EPOCH_208 + (epoch - 208) * 120 * HOUR
	}

	/// A Cardano block is stable k blocks deep, k/f of its slots: 432/0.05 s
	/// on preprod, 2160/0.05 s on mainnet.
	const PREPROD_STABILITY: u64 = 8_640_000;
	const MAINNET_STABILITY: u64 = 43_200_000;

	/// From 30 h before `boundary` to 40 h after it (Unix ms).
	fn around(boundary: u64) -> (u64, u64) {
		(boundary - 30 * HOUR, boundary + 40 * HOUR)
	}

	/// A node binary, as far as the committee inputs it draws.
	#[derive(Clone, Copy)]
	enum Binary {
		/// This crate's provider under the rule, with upstream's followers.
		Current(AriadneRule),
		/// The provider and followers of preprod v6's earlier binaries:
		/// followers that serve the data stored up to an epoch for that epoch
		/// itself, and data given while the stable reference block is in that
		/// epoch or later.
		PreprodV6Earlier,
	}

	impl Binary {
		/// The inputs the binary gives a block at `slot` for the committee of
		/// session `next_unset`, on Cardano epoch layout `node_epochs`, while
		/// the block's stable reference block is in epoch `reference`.
		async fn draw(
			self,
			node_epochs: &MainchainEpochConfig,
			next_unset: u64,
			slot: u64,
			reference: u32,
		) -> Option<AuthoritySelectionInputs> {
			let client = TestApi { next_unset_epoch_number: ScEpochNumber(next_unset) };
			let (slot, reference) = (Slot::from(slot), McEpochNumber(reference));
			match self {
				Binary::Current(rule) => AriadneInherentDataProvider::new(
					&client,
					&materios_slots(),
					node_epochs,
					H256::zero(),
					slot,
					&FollowerMock { lag: 2 },
					reference,
					rule,
				)
				.await
				.unwrap()
				.data,
				Binary::PreprodV6Earlier => {
					let follower = FollowerMock { lag: 0 };
					let for_mc_epoch = mc_epoch_for_next_ariadne_cidp(
						&client,
						&materios_slots(),
						node_epochs,
						H256::zero(),
						slot,
					)
					.unwrap();
					let data_epoch = follower.data_epoch(for_mc_epoch).await.unwrap();
					let scripts = client.runtime_api().get_main_chain_scripts(H256::zero()).unwrap();
					if data_epoch <= reference {
						AriadneInherentDataProvider::from_mc_data(&follower, for_mc_epoch, scripts)
							.await
							.unwrap()
							.data
					} else {
						None
					}
				},
			}
		}

		/// The Cardano epoch whose data the binary gives that draw, at slot 0.
		async fn data_given(
			self,
			node_epochs: &MainchainEpochConfig,
			next_unset: u64,
			reference: u32,
		) -> Option<u32> {
			self.draw(node_epochs, next_unset, 0, reference)
				.await
				.map(|inputs| u32::from_be_bytes(inputs.epoch_nonce.0.try_into().unwrap()))
		}
	}

	/// What `binary` gives each slot from `from` to `to` (Unix ms), on Cardano
	/// epoch layout `node_epochs`, while its stable reference block is
	/// `reference_age` behind the slot, in the epochs `cardano_epochs` lays
	/// out: from k/f, the newest stable block, to 3k/f, the oldest the mc-hash
	/// inherent accepts.
	///
	/// The chain stores the next committee at the first block that has the
	/// data, and rotates to it at the next session; with none stored, it
	/// keeps the committee in force and asks again for the one after it.
	async fn draws(
		binary: Binary,
		node_epochs: &MainchainEpochConfig,
		cardano_epochs: &MainchainEpochConfig,
		(from, to): (u64, u64),
		reference_age: u64,
	) -> Vec<Option<AuthoritySelectionInputs>> {
		let slots = materios_slots();
		let slot_millis = slots.slot_duration.as_millis();
		let (first, last) = (from / slot_millis, to / slot_millis);
		let mut current = slots.epoch_number(Slot::from(first));
		let mut next: Option<ScEpochNumber> = None;
		let mut drawn = vec![];
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
			let draw = binary.draw(node_epochs, next.unwrap_or(current).0 + 1, slot, reference.0).await;
			if draw.is_some() && next.is_none() {
				next = Some(ScEpochNumber(current.0 + 1));
			}
			drawn.push(draw);
		}
		drawn
	}

	/// Seconds in which `binary` gives no data, as `draws` sweeps them.
	async fn seconds_without_data(
		binary: Binary,
		node_epochs: &MainchainEpochConfig,
		cardano_epochs: &MainchainEpochConfig,
		from_to: (u64, u64),
		reference_age: u64,
	) -> u64 {
		let drawn = draws(binary, node_epochs, cardano_epochs, from_to, reference_age).await;
		let slot_seconds = materios_slots().slot_duration.as_millis() / 1000;
		drawn.iter().filter(|draw| draw.is_none()).count() as u64 * slot_seconds
	}

	/// Session 497_976 starts with Cardano preprod's epoch 321 on 2026-10-23 at
	/// 00:00 UTC. Upstream's rule draws it from epoch 319's data, which may
	/// still change above a stable reference block in epoch 319, so it gives
	/// none until the reference block is in epoch 320.
	#[tokio::test]
	async fn no_data_from_the_cardano_epoch_of_the_stable_reference_block() {
		let strict = Binary::Current(AriadneRule::Strict);
		assert_eq!(strict.data_given(&preprod(), 497_976, 319).await, None);
		assert_eq!(strict.data_given(&preprod(), 497_976, 320).await, Some(319));
	}

	/// Preprod block #2102140, 2026-10-01T23:00Z, was authored inside the
	/// relaxation's window with no `set`: its parent asks for session 497_472,
	/// which starts on 2026-10-02 at 00:00 UTC, in epoch 317 on the fleet's
	/// layout, while its stable reference block is in epoch 316. A verifier
	/// with data refuses such a block, so preprod v6's rule gives none, as the
	/// author had; upstream's rule gives epoch 315's. Once the reference block
	/// is in epoch 317, which is when the fleet's `set`s resumed (#2118655,
	/// 2026-10-03T02:35:30Z), preprod v6's rule gives that epoch's own data.
	#[tokio::test]
	async fn preprod_v6s_rule_gives_the_data_its_blocks_were_authored_with() {
		let fleet = preprod_fleet();
		let relaxed = Binary::Current(AriadneRule::Relaxed);
		assert_eq!(relaxed.data_given(&fleet, 497_472, 316).await, None);
		assert_eq!(relaxed.data_given(&fleet, 497_472, 317).await, Some(317));
		let strict = Binary::Current(AriadneRule::Strict);
		assert_eq!(strict.data_given(&fleet, 497_472, 316).await, Some(315));
	}

	/// Upstream's rule gives every block data, on preprod and mainnet, on the
	/// fleet's early epoch layout as on Cardano's, for any stable reference
	/// block the mc-hash inherent accepts. Preprod v6's rule leaves without
	/// data the two sessions that start before each Cardano epoch boundary and
	/// the reference block's age after it: 4.4 h on preprod, whose boundaries
	/// start a session, 13.7 h at a mainnet boundary 44 min 51 s into a
	/// session, and 28.4 h on the fleet's layout.
	#[tokio::test]
	async fn upstreams_rule_leaves_no_block_without_data_where_preprod_v6s_has_its_window() {
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
			("mainnet", mainnet(), mainnet(), mainnet_boundary(600), MAINNET_STABILITY, 49_488),
		] {
			let (relaxed, strict) =
				(Binary::Current(AriadneRule::Relaxed), Binary::Current(AriadneRule::Strict));
			assert_eq!(
				seconds_without_data(relaxed, &node_epochs, &cardano_epochs, around(boundary), stability)
					.await,
				relaxed_window,
				"{name}, relaxed"
			);
			for reference_age in [stability, 3 * stability] {
				assert_eq!(
					seconds_without_data(
						strict,
						&node_epochs,
						&cardano_epochs,
						around(boundary),
						reference_age
					)
					.await,
					0,
					"{name}, upstream, reference {reference_age} ms old"
				);
			}
		}
	}

	/// Upstream's rule gives every block data on a Cardano epoch layout that
	/// starts each epoch early by up to an epoch less two sessions and 3k/f:
	/// 110.8 h on preprod and 82 h on mainnet. A block asks for the committee
	/// of a session that starts at most two sessions after it, and its stable
	/// reference block is at most 3k/f old, so on such a layout the two are
	/// never two Cardano epochs apart. An hour earlier still, blocks whose
	/// reference block is 3k/f old go without data.
	#[tokio::test]
	async fn upstreams_rule_gives_data_on_a_layout_up_to_an_epoch_less_two_sessions_and_3k_f_early() {
		let strict = Binary::Current(AriadneRule::Strict);
		for (name, first_epoch, first_epoch_number, boundary, stability) in [
			("preprod", PREPROD_EPOCH_0, 0, preprod_boundary(321), PREPROD_STABILITY),
			("mainnet", MAINNET_EPOCH_208, 208, mainnet_boundary(600), MAINNET_STABILITY),
		] {
			let cardano_epochs = five_day_epochs(first_epoch, first_epoch_number);
			let early = |by: u64| five_day_epochs(first_epoch - by, first_epoch_number);
			let bound = 120 * HOUR - 2 * HOUR - 3 * stability;
			for reference_age in [stability, 3 * stability] {
				assert_eq!(
					seconds_without_data(
						strict,
						&early(bound),
						&cardano_epochs,
						around(boundary),
						reference_age
					)
					.await,
					0,
					"{name}, {bound} ms early, reference {reference_age} ms old"
				);
			}
			let beyond = seconds_without_data(
				strict,
				&early(bound + HOUR),
				&cardano_epochs,
				around(boundary),
				3 * stability,
			)
			.await;
			assert!(beyond > 0, "{name}, an hour beyond the bound");
		}
	}

	/// Under `AriadneRule::Relaxed`, with upstream's followers, the provider
	/// gives exactly the inputs preprod v6's earlier binaries gave, so a fleet
	/// that mixes the two, in any order, stores and accepts the same
	/// committees. Compared slot by slot as the window test sweeps them,
	/// around Cardano epoch boundaries from 2025-12 to 2027-01, on Cardano
	/// preprod's layout, the fleet's and mainnet's, at both ends of the stable
	/// reference window; then for every session in the ten days around the
	/// fleet's epoch boundary of 2026-11-16, as the next unset session and as
	/// the genesis committee's, against every reference epoch from 321 to 331.
	#[tokio::test]
	async fn preprod_v6s_rule_draws_what_its_earlier_binaries_drew() {
		let (earlier, relaxed) = (Binary::PreprodV6Earlier, Binary::Current(AriadneRule::Relaxed));
		for (name, node_epochs, cardano_epochs, boundary, stability) in [
			("preprod, epoch 321", preprod(), preprod(), preprod_boundary(321), PREPROD_STABILITY),
			(
				"preprod fleet, epoch 321",
				preprod_fleet(),
				preprod(),
				preprod_boundary(321),
				PREPROD_STABILITY,
			),
			(
				"preprod fleet, epoch 326",
				preprod_fleet(),
				preprod(),
				preprod_boundary(326),
				PREPROD_STABILITY,
			),
			("mainnet, epoch 600", mainnet(), mainnet(), mainnet_boundary(600), MAINNET_STABILITY),
			("mainnet, epoch 680", mainnet(), mainnet(), mainnet_boundary(680), MAINNET_STABILITY),
		] {
			for reference_age in [stability, 3 * stability] {
				let sweep = |binary| {
					draws(binary, &node_epochs, &cardano_epochs, around(boundary), reference_age)
				};
				let (before, now) = (sweep(earlier).await, sweep(relaxed).await);
				assert_eq!(
					before.iter().zip(&now).position(|(before, now)| before != now),
					None,
					"{name}, reference {reference_age} ms old: the first slot that differs"
				);
			}
		}
		let fleet = preprod_fleet();
		let fleet_boundary = preprod_boundary(326) - 24 * HOUR;
		for session in (fleet_boundary - 120 * HOUR) / HOUR..(fleet_boundary + 120 * HOUR) / HOUR {
			let first_slot = session * HOUR / materios_slots().slot_duration.as_millis();
			for next_unset in [session, 1] {
				for reference in 321..=331 {
					assert_eq!(
						earlier.draw(&fleet, next_unset, first_slot, reference).await,
						relaxed.draw(&fleet, next_unset, first_slot, reference).await,
						"session {session}, next unset {next_unset}, reference epoch {reference}"
					);
				}
			}
		}
	}
}
