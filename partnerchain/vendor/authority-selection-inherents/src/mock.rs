use crate::authority_selection_inputs::*;
use sidechain_domain::*;

#[derive(Clone)]
pub struct MockAuthoritySelectionDataSource {
	/// Each entry in each field is returned when queried for epoch equal to its index.
	/// For example `candidates[0]` is the list of candidates that will be returned for epoch 0.
	/// `candidates[1]` is the list of candidates that will be returned for epoch 1 and so on.
	pub candidates: Vec<Vec<CandidateRegistrations>>,
	pub permissioned_candidates: Vec<Option<Vec<RawPermissionedCandidateData>>>,
}

impl Default for MockAuthoritySelectionDataSource {
	fn default() -> Self {
		Self {
			candidates: vec![vec![], vec![]],
			permissioned_candidates: vec![Some(vec![]), Some(vec![])],
		}
	}
}

impl MockAuthoritySelectionDataSource {
	pub fn with_candidates_per_epoch(self, candidates: Vec<Vec<CandidateRegistrations>>) -> Self {
		Self { candidates, ..self }
	}

	pub fn with_permissioned_candidates(
		self,
		permissioned_candidates: Vec<Option<Vec<RawPermissionedCandidateData>>>,
	) -> Self {
		Self { permissioned_candidates, ..self }
	}
}

#[async_trait::async_trait]
impl AuthoritySelectionDataSource for MockAuthoritySelectionDataSource {
	async fn get_ariadne_parameters(
		&self,
		epoch_number: McEpochNumber,
		_d_parameter_policy: PolicyId,
		_permissioned_candidates_policy: PolicyId,
	) -> Result<AriadneParameters, Box<dyn std::error::Error + Send + Sync>> {
		match self.permissioned_candidates.get(epoch_number.0 as usize) {
			Some(Some(candidates)) => Ok(AriadneParameters {
				d_parameter: DParameter {
					num_permissioned_candidates: 3,
					num_registered_candidates: 2,
				},
				permissioned_candidates: candidates.clone(),
			}),
			_ => Err(format!("mock was called with unexpected argument").into()),
		}
	}

	async fn get_candidates(
		&self,
		epoch_number: McEpochNumber,
		_committee_candidate_address: MainchainAddress,
	) -> Result<Vec<CandidateRegistrations>, Box<dyn std::error::Error + Send + Sync>> {
		Ok(self.candidates.get(epoch_number.0 as usize).cloned().unwrap_or(vec![]))
	}

	async fn get_epoch_nonce(
		&self,
		_epoch: McEpochNumber,
	) -> Result<Option<EpochNonce>, Box<dyn std::error::Error + Send + Sync>> {
		Ok(Some(EpochNonce(vec![42u8])))
	}

	async fn data_epoch(
		&self,
		for_epoch: McEpochNumber,
	) -> Result<McEpochNumber, Box<dyn std::error::Error + Send + Sync>> {
		Ok(for_epoch)
	}
}

/// [materios-patch: preprod-v6-relaxation] Cardano data as a follower serves
/// it: for each epoch, the data stored up to `lag` epochs before it.
/// Upstream's followers lag two epochs; preprod v6's earlier binaries patched
/// theirs to lag none. Every answer names the epoch whose data it is: the
/// epoch nonce and the permissioned candidate's key are its number, and the
/// registered candidate holds that much stake.
pub struct FollowerMock {
	pub lag: u32,
}

impl FollowerMock {
	fn stored_for(&self, epoch: McEpochNumber) -> u32 {
		epoch.0 - self.lag
	}
}

#[async_trait::async_trait]
impl AuthoritySelectionDataSource for FollowerMock {
	async fn get_ariadne_parameters(
		&self,
		epoch: McEpochNumber,
		_d_parameter_policy: PolicyId,
		_permissioned_candidates_policy: PolicyId,
	) -> Result<AriadneParameters, Box<dyn std::error::Error + Send + Sync>> {
		Ok(AriadneParameters {
			d_parameter: DParameter { num_permissioned_candidates: 1, num_registered_candidates: 1 },
			permissioned_candidates: vec![RawPermissionedCandidateData {
				sidechain_public_key: SidechainPublicKey(
					self.stored_for(epoch).to_be_bytes().to_vec(),
				),
				aura_public_key: AuraPublicKey(vec![]),
				grandpa_public_key: GrandpaPublicKey(vec![]),
			}],
		})
	}

	async fn get_candidates(
		&self,
		epoch: McEpochNumber,
		_committee_candidate_address: MainchainAddress,
	) -> Result<Vec<CandidateRegistrations>, Box<dyn std::error::Error + Send + Sync>> {
		Ok(vec![CandidateRegistrations {
			mainchain_pub_key: MainchainPublicKey([0; 32]),
			registrations: vec![],
			stake_delegation: Some(StakeDelegation(self.stored_for(epoch).into())),
		}])
	}

	async fn get_epoch_nonce(
		&self,
		epoch: McEpochNumber,
	) -> Result<Option<EpochNonce>, Box<dyn std::error::Error + Send + Sync>> {
		Ok(Some(EpochNonce(self.stored_for(epoch).to_be_bytes().to_vec())))
	}

	async fn data_epoch(
		&self,
		for_epoch: McEpochNumber,
	) -> Result<McEpochNumber, Box<dyn std::error::Error + Send + Sync>> {
		Ok(McEpochNumber(self.stored_for(for_epoch)))
	}
}
