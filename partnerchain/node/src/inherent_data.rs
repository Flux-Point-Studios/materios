use crate::chain_spec_preprod::PREPROD_V6_GENESIS;
use authority_selection_inherents::ariadne_inherent_data_provider::{
	AriadneInherentDataProvider as AriadneIDP, AriadneRule,
};
use authority_selection_inherents::authority_selection_inputs::{
	AuthoritySelectionDataSource, AuthoritySelectionInputs,
};
use derive_new::new;
use jsonrpsee::core::async_trait;
use sc_consensus_aura::{find_pre_digest, SlotDuration};
use sc_service::Arc;
use sidechain_domain::mainchain_epoch::MainchainEpochConfig;
use sidechain_domain::{McBlockHash, ScEpochNumber};
use sidechain_mc_hash::McHashDataSource;
use sidechain_mc_hash::McHashInherentDataProvider as McHashIDP;
use materios_runtime::{
	opaque::{Block, SessionKeys},
	BeneficiaryId, CrossChainPublic,
};
use sidechain_slots::ScSlotConfig;
use sp_api::ProvideRuntimeApi;
use sp_block_rewards::BlockBeneficiaryInherentProvider;
use sp_blockchain::HeaderBackend;
use sp_consensus_aura::{
	inherents::InherentDataProvider as AuraIDP, sr25519::AuthorityPair as AuraPair, Slot,
};
use sp_core::Pair;
use sp_inherents::CreateInherentDataProviders;
use sp_native_token_management::{
	NativeTokenManagementApi, NativeTokenManagementDataSource,
	NativeTokenManagementInherentDataProvider as NativeTokenIDP,
};
use sp_partner_chains_consensus_aura::CurrentSlotProvider;
use sp_runtime::traits::{Block as BlockT, Header, Zero};
use sp_session_validator_management::SessionValidatorManagementApi;
use sp_timestamp::{InherentDataProvider as TimestampIDP, Timestamp};
use std::error::Error;
use time_source::TimeSource;

#[derive(new)]
pub struct ProposalCIDP<T> {
	config: CreateInherentDataConfig,
	client: Arc<T>,
	mc_hash_data_source: Arc<dyn McHashDataSource + Send + Sync>,
	authority_selection_data_source: Arc<dyn AuthoritySelectionDataSource + Send + Sync>,
	native_token_data_source: Arc<dyn NativeTokenManagementDataSource + Send + Sync>,
}

#[async_trait]
impl<T> CreateInherentDataProviders<Block, ()> for ProposalCIDP<T>
where
	T: ProvideRuntimeApi<Block> + Send + Sync + 'static,
	T: HeaderBackend<Block>,
	T::Api: SessionValidatorManagementApi<
		Block,
		SessionKeys,
		CrossChainPublic,
		AuthoritySelectionInputs,
		ScEpochNumber,
	>,
	T::Api: NativeTokenManagementApi<Block>,
{
	type InherentDataProviders = (
		AuraIDP,
		TimestampIDP,
		McHashIDP,
		AriadneIDP,
		BlockBeneficiaryInherentProvider<BeneficiaryId>,
		NativeTokenIDP,
	);

	async fn create_inherent_data_providers(
		&self,
		parent_hash: <Block as BlockT>::Hash,
		_extra_args: (),
	) -> Result<Self::InherentDataProviders, Box<dyn std::error::Error + Send + Sync>> {
		let Self {
			config,
			client,
			mc_hash_data_source,
			authority_selection_data_source,
			native_token_data_source,
		} = self;
		let CreateInherentDataConfig { mc_epoch_config, sc_slot_config, time_source, ariadne_rule } =
			config;

		let (slot, timestamp) =
			timestamp_and_slot_cidp(sc_slot_config.slot_duration, time_source.clone());
		let mc_hash = McHashIDP::new_proposal(
			mc_hash_data_source.as_ref(),
			*slot,
			sc_slot_config.slot_duration,
		)
		.await?;

		let ariadne_data_provider = AriadneIDP::new(
			client.as_ref(),
			sc_slot_config,
			mc_epoch_config,
			parent_hash,
			*slot,
			authority_selection_data_source.as_ref(),
			mc_hash.mc_epoch(),
			*ariadne_rule,
		)
		.await?;
		let block_beneficiary_provider =
			BlockBeneficiaryInherentProvider::<BeneficiaryId>::from_env(
				"SIDECHAIN_BLOCK_BENEFICIARY",
			)?;

		let native_token = NativeTokenIDP::new(
			client.clone(),
			native_token_data_source.as_ref(),
			mc_hash.mc_hash(),
			parent_hash,
		)
		.await?;

		Ok((
			slot,
			timestamp,
			mc_hash,
			ariadne_data_provider,
			block_beneficiary_provider,
			native_token,
		))
	}
}

#[derive(new)]
pub struct VerifierCIDP<T> {
	config: CreateInherentDataConfig,
	client: Arc<T>,
	mc_hash_data_source: Arc<dyn McHashDataSource + Send + Sync>,
	authority_selection_data_source: Arc<dyn AuthoritySelectionDataSource + Send + Sync>,
	native_token_data_source: Arc<dyn NativeTokenManagementDataSource + Send + Sync>,
}

impl<T: Send + Sync> CurrentSlotProvider for VerifierCIDP<T> {
	fn slot(&self) -> Slot {
		*timestamp_and_slot_cidp(self.config.slot_duration(), self.config.time_source.clone()).0
	}
}

#[async_trait]
impl<T> CreateInherentDataProviders<Block, (Slot, McBlockHash)> for VerifierCIDP<T>
where
	T: ProvideRuntimeApi<Block> + Send + Sync + HeaderBackend<Block>,
	T::Api: SessionValidatorManagementApi<
		Block,
		SessionKeys,
		CrossChainPublic,
		AuthoritySelectionInputs,
		ScEpochNumber,
	>,
	T::Api: NativeTokenManagementApi<Block>,
{
	type InherentDataProviders = (TimestampIDP, AriadneIDP, NativeTokenIDP);

	async fn create_inherent_data_providers(
		&self,
		parent_hash: <Block as BlockT>::Hash,
		(verified_block_slot, mc_hash): (Slot, McBlockHash),
	) -> Result<Self::InherentDataProviders, Box<dyn Error + Send + Sync>> {
		let Self {
			config,
			client,
			mc_hash_data_source,
			authority_selection_data_source,
			native_token_data_source,
		} = self;
		let CreateInherentDataConfig { mc_epoch_config, sc_slot_config, time_source, ariadne_rule } =
			config;

		let timestamp = TimestampIDP::new(Timestamp::new(time_source.get_current_time_millis()));
		let parent_header = client.expect_header(parent_hash)?;
		let parent_slot = slot_from_predigest(&parent_header)?;
		let mc_state_reference = McHashIDP::new_verification(
			parent_header,
			parent_slot,
			verified_block_slot,
			mc_hash.clone(),
			config.slot_duration(),
			mc_hash_data_source.as_ref(),
		)
		.await?;

		let ariadne_data_provider = AriadneIDP::new(
			client.as_ref(),
			sc_slot_config,
			mc_epoch_config,
			parent_hash,
			verified_block_slot,
			authority_selection_data_source.as_ref(),
			mc_state_reference.epoch,
			*ariadne_rule,
		)
		.await?;

		let native_token = NativeTokenIDP::new(
			client.clone(),
			native_token_data_source.as_ref(),
			mc_hash,
			parent_hash,
		)
		.await?;

		Ok((timestamp, ariadne_data_provider, native_token))
	}
}

pub fn slot_from_predigest(
	header: &<Block as BlockT>::Header,
) -> Result<Option<Slot>, Box<dyn Error + Send + Sync>> {
	if header.number().is_zero() {
		// genesis block doesn't have a slot
		Ok(None)
	} else {
		Ok(Some(find_pre_digest::<Block, <AuraPair as Pair>::Signature>(header)?))
	}
}

#[derive(Clone)]
pub(crate) struct CreateInherentDataConfig {
	pub mc_epoch_config: MainchainEpochConfig,
	pub sc_slot_config: ScSlotConfig,
	pub time_source: Arc<dyn TimeSource + Send + Sync>,
	ariadne_rule: AriadneRule,
}

impl CreateInherentDataConfig {
	/// Preprod v6 keeps its historical rule; all other genesis hashes select Strict.
	pub fn new(
		mc_epoch_config: MainchainEpochConfig,
		sc_slot_config: ScSlotConfig,
		time_source: Arc<dyn TimeSource + Send + Sync>,
		client: &impl HeaderBackend<Block>,
	) -> Self {
		let genesis = client.info().genesis_hash;
		let ariadne_rule =
			if genesis == PREPROD_V6_GENESIS { AriadneRule::Relaxed } else { AriadneRule::Strict };
		log::info!(
			"🗳️  Drawing committees under the {ariadne_rule:?} Ariadne rule for genesis {genesis:?}"
		);
		Self { mc_epoch_config, sc_slot_config, time_source, ariadne_rule }
	}

	pub fn slot_duration(&self) -> SlotDuration {
		self.sc_slot_config.slot_duration
	}
}

fn timestamp_and_slot_cidp(
	slot_duration: SlotDuration,
	time_source: Arc<dyn TimeSource + Send + Sync>,
) -> (AuraIDP, TimestampIDP) {
	let timestamp = TimestampIDP::new(Timestamp::new(time_source.get_current_time_millis()));
	let slot = AuraIDP::from_timestamp_and_slot_duration(*timestamp, slot_duration);
	(slot, timestamp)
}

#[cfg(test)]
mod tests {
	use super::*;
	use authority_selection_inherents::mock::FollowerMock;
	use sidechain_domain::{MainchainBlock, McBlockNumber, McEpochNumber, McSlotNumber};
	use sidechain_mc_hash::mock::MockMcHashDataSource;
	use sidechain_slots::SlotsPerEpoch;
	use sp_core::H256;
	use sp_native_token_management::mock::MockNativeTokenDataSource;

	// Distinct genesis, best and finalized hashes detect selection from the wrong block.
	#[derive(Clone)]
	struct Chain {
		genesis: H256,
		next_unset: ScEpochNumber,
	}

	impl ProvideRuntimeApi<Block> for Chain {
		type Api = Chain;

		fn runtime_api(&self) -> sp_api::ApiRef<Self::Api> {
			self.clone().into()
		}
	}

	sp_api::mock_impl_runtime_apis! {
		impl SessionValidatorManagementApi<
			Block,
			SessionKeys,
			CrossChainPublic,
			AuthoritySelectionInputs,
			ScEpochNumber,
		> for Chain {
			fn get_current_committee() -> (ScEpochNumber, Vec<CrossChainPublic>) {
				unimplemented!()
			}
			fn get_next_unset_epoch_number() -> ScEpochNumber {
				self.next_unset
			}
			fn calculate_committee(
				_authority_selection_inputs: AuthoritySelectionInputs,
				_sidechain_epoch: ScEpochNumber,
			) -> Option<Vec<(CrossChainPublic, SessionKeys)>> {
				unimplemented!()
			}
			fn get_main_chain_scripts() -> sp_session_validator_management::MainChainScripts {
				Default::default()
			}
		}

		impl NativeTokenManagementApi<Block> for Chain {
			fn get_main_chain_scripts() -> Option<sp_native_token_management::MainChainScripts> {
				None
			}
			fn initialized() -> bool {
				unimplemented!()
			}
		}
	}

	impl HeaderBackend<Block> for Chain {
		fn header(
			&self,
			_hash: <Block as BlockT>::Hash,
		) -> sp_blockchain::Result<Option<<Block as BlockT>::Header>> {
			let genesis = materios_runtime::opaque::Header::new(
				0,
				H256::zero(),
				H256::zero(),
				H256::zero(),
				Default::default(),
			);
			Ok(Some(genesis))
		}

		fn info(&self) -> sp_blockchain::Info<Block> {
			sp_blockchain::Info {
				best_hash: H256::repeat_byte(0xbe),
				best_number: 2,
				genesis_hash: self.genesis,
				finalized_hash: H256::repeat_byte(0xf1),
				finalized_number: 1,
				finalized_state: None,
				number_leaves: 1,
				block_gap: None,
			}
		}

		fn status(
			&self,
			_hash: <Block as BlockT>::Hash,
		) -> sp_blockchain::Result<sp_blockchain::BlockStatus> {
			unimplemented!()
		}

		fn number(&self, _hash: <Block as BlockT>::Hash) -> sp_blockchain::Result<Option<u32>> {
			unimplemented!()
		}

		fn hash(&self, _number: u32) -> sp_blockchain::Result<Option<<Block as BlockT>::Hash>> {
			unimplemented!()
		}
	}

	/// The config the service builds for `client`'s chain, with preprod's
	/// one-hour sessions and the fleet's MC__ epoch layout, which starts every
	/// Cardano epoch a day early.
	fn preprod_config(client: &Chain) -> CreateInherentDataConfig {
		let fleet_epochs = MainchainEpochConfig {
			first_epoch_timestamp_millis: sp_core::offchain::Timestamp::from_unix_millis(
				1_655_683_200_000,
			),
			first_epoch_number: 4,
			epoch_duration_millis: sp_core::offchain::Duration::from_millis(432_000_000),
			first_slot_number: 0,
		};
		let sessions = ScSlotConfig {
			slots_per_epoch: SlotsPerEpoch(600),
			slot_duration: SlotDuration::from_millis(6_000),
		};
		let time_source = Arc::new(time_source::SystemTimeSource);
		CreateInherentDataConfig::new(fleet_epochs, sessions, time_source, client)
	}

	/// The Cardano epoch whose data the proposer's and then the verifier's
	/// inherent data provider give a block on the genesis `genesis`, under the
	/// config the service builds for its chain, for the committee of session
	/// `next_unset`, while the block's stable reference block is in epoch
	/// `reference`.
	async fn data_given(genesis: H256, next_unset: u64, reference: u32) -> [Option<u32>; 2] {
		let client = Arc::new(Chain { genesis, next_unset: ScEpochNumber(next_unset) });
		let config = preprod_config(&client);
		let reference_block = MainchainBlock {
			number: McBlockNumber(1),
			hash: McBlockHash([1; 32]),
			epoch: McEpochNumber(reference),
			slot: McSlotNumber(1),
			timestamp: 1,
		};
		let mc_hash = Arc::new(MockMcHashDataSource::from(vec![reference_block.clone()]));
		let follower = Arc::new(FollowerMock { lag: 2 });
		let native_token = Arc::new(MockNativeTokenDataSource::default());
		let (_, _, _, proposed, _, _) = ProposalCIDP::new(
			config.clone(),
			client.clone(),
			mc_hash.clone(),
			follower.clone(),
			native_token.clone(),
		)
		.create_inherent_data_providers(H256::zero(), ())
		.await
		.unwrap();
		let (_, verified, _) =
			VerifierCIDP::new(config, client, mc_hash, follower, native_token)
				.create_inherent_data_providers(H256::zero(), (Slot::from(1), reference_block.hash))
				.await
				.unwrap();
		[proposed, verified].map(|ariadne| {
			ariadne.data.map(|inputs| u32::from_be_bytes(inputs.epoch_nonce.0.try_into().unwrap()))
		})
	}

	/// The service picks the Ariadne rule from the genesis its client reports,
	/// not from its best or finalized block, and the proposer and the verifier
	/// both draw under it: preprod v6's relaxation for v6, and upstream's rule
	/// for any other genesis, v6's with a byte changed among them. The draws,
	/// with upstream's followers:
	/// - preprod block #2102140's, for session 497_472, which starts with
	///   epoch 317 on the fleet's layout, while its stable reference block is
	///   in epoch 316; then with the reference block in 317;
	/// - for session 498_552, which starts on 2026-11-16 at 00:00 UTC with
	///   epoch 326, with the reference block in 325, then in 326.
	#[tokio::test]
	async fn the_proposer_and_the_verifier_draw_under_the_rule_the_genesis_picks() {
		// The proposer reads its block beneficiary from the environment.
		std::env::set_var("SIDECHAIN_BLOCK_BENEFICIARY", format!("0x{}", "01".repeat(32)));
		let mut other = PREPROD_V6_GENESIS;
		other.0[31] ^= 1;
		let draws = [(497_472, 316), (497_472, 317), (498_552, 325), (498_552, 326)];
		for (genesis, data_epochs) in [
			(PREPROD_V6_GENESIS, [None, Some(317), None, Some(326)]),
			(other, [Some(315), Some(315), Some(324), Some(324)]),
		] {
			for ((next_unset, reference), data_epoch) in draws.into_iter().zip(data_epochs) {
				assert_eq!(
					data_given(genesis, next_unset, reference).await,
					[data_epoch, data_epoch],
					"genesis {genesis:?}, session {next_unset}, reference epoch {reference}"
				);
			}
		}
	}
}
