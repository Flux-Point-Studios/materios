#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;
pub mod types;
pub mod weights;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod integration_tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

#[frame_support::pallet]
pub mod pallet {
    use alloc::vec::Vec;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_core::H256;

    use crate::types::{AnchorRecord, PlayerSigRecord, ReceiptRecord};
    use crate::weights::WeightInfo;

    /// Mirror of pallet_grandpa's StoredPendingChange (which is pub(crate)).
    /// Must match the SCALE encoding layout exactly.
    /// SDK: polkadot-stable2409-5, pallet-grandpa v38.0.0.
    #[derive(parity_scale_codec::Encode, parity_scale_codec::Decode, Debug, PartialEq)]
    pub(crate) struct GrandpaPendingChange<N: parity_scale_codec::Encode + parity_scale_codec::Decode> {
        pub scheduled_at: N,
        pub delay: N,
        pub next_authorities: sp_consensus_grandpa::AuthorityList,
        pub forced: Option<N>,
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config:
        frame_system::Config
        + pallet_timestamp::Config
        + pallet_aura::Config
        + pallet_grandpa::Config
        + pallet_balances::Config
    {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type WeightInfo: WeightInfo;
        #[pallet::constant]
        type MaxResubmits: Get<u32>;
        #[pallet::constant]
        type MaxCommitteeSize: Get<u32>;
    }

    // ── Storage ──────────────────────────────────────────────────────────

    #[pallet::storage]
    #[pallet::getter(fn receipts)]
    pub type Receipts<T: Config> =
        StorageMap<_, Blake2_128Concat, H256, ReceiptRecord<T::AccountId>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn content_index)]
    pub type ContentIndex<T: Config> =
        StorageMap<_, Blake2_128Concat, H256, BoundedVec<H256, T::MaxResubmits>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn receipt_count)]
    pub type ReceiptCount<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// The set of accounts authorized to attest availability certificates.
    #[pallet::storage]
    #[pallet::getter(fn committee_members)]
    pub type CommitteeMembers<T: Config> = StorageValue<
        _,
        BoundedBTreeSet<T::AccountId, T::MaxCommitteeSize>,
        ValueQuery,
    >;

    /// Number of attestations required to finalize a certificate.
    /// Defaults to 1 so a single-member committee works out of the box.
    #[pallet::storage]
    #[pallet::getter(fn attestation_threshold)]
    pub type AttestationThreshold<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// In-progress attestations: receipt_id -> (cert_hash, set of signers so far).
    #[pallet::storage]
    #[pallet::getter(fn attestations)]
    pub type Attestations<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        H256,
        (H256, BoundedBTreeSet<T::AccountId, T::MaxCommitteeSize>),
        OptionQuery,
    >;

    // ── Validator Reward Storage ──────────────────────────────────────────

    /// Blocks authored by each validator in the current era.
    #[pallet::storage]
    pub type BlocksAuthored<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, u32, ValueQuery>;

    /// Block number when the current reward era started.
    #[pallet::storage]
    pub type EraStartBlock<T: Config> = StorageValue<_, BlockNumberFor<T>, ValueQuery>;

    /// Total tMATRA distributed from the validator reserve so far.
    #[pallet::storage]
    #[pallet::getter(fn total_rewards_distributed)]
    pub type TotalRewardsDistributed<T: Config> = StorageValue<_, u128, ValueQuery>;

    /// Accumulated rewards per validator (lifetime, for display/query).
    #[pallet::storage]
    #[pallet::getter(fn validator_rewards)]
    pub type ValidatorRewards<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, u128, ValueQuery>;

    /// Player anti-cheat signatures, keyed by receipt_id.
    /// Stored separately from ReceiptRecord for backward compatibility.
    #[pallet::storage]
    #[pallet::getter(fn player_signatures)]
    pub type PlayerSignatures<T: Config> =
        StorageMap<_, Blake2_128Concat, H256, PlayerSigRecord, OptionQuery>;

    // ── Attestation Reward Storage ──────────────────────────────────────

    /// Number of receipts certified in the current era (for reward calculation).
    #[pallet::storage]
    pub type ReceiptsCertifiedInEra<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// Accumulated attestation rewards per account (lifetime).
    #[pallet::storage]
    #[pallet::getter(fn attestation_rewards)]
    pub type AttestationRewards<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, u128, ValueQuery>;

    /// Total tMATRA distributed as attestation rewards (lifetime).
    #[pallet::storage]
    #[pallet::getter(fn total_attestation_rewards)]
    pub type TotalAttestationRewards<T: Config> = StorageValue<_, u128, ValueQuery>;

    /// tMATRA distributed as attestation rewards in the current era.
    /// Reset to zero at each era boundary alongside block reward accounting.
    #[pallet::storage]
    pub type AttestationRewardsPaidInEra<T: Config> = StorageValue<_, u128, ValueQuery>;

    /// Anchors submitted via `submit_anchor` — distinct from receipts so the
    /// cert daemon does not try to fetch blobs for anchor-only entries.
    #[pallet::storage]
    #[pallet::getter(fn anchors)]
    pub type Anchors<T: Config> =
        StorageMap<_, Blake2_128Concat, H256, AnchorRecord<T::AccountId>, OptionQuery>;

    // ── Events ───────────────────────────────────────────────────────────

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        ReceiptSubmitted {
            receipt_id: H256,
            content_hash: H256,
            submitter: T::AccountId,
        },
        AvailabilityCertified {
            receipt_id: H256,
            cert_hash: H256,
        },
        CommitteeUpdated {
            members: Vec<T::AccountId>,
            threshold: u32,
        },
        AttestationRecorded {
            receipt_id: H256,
            attester: T::AccountId,
            count: u32,
            threshold: u32,
        },
        AnchorSubmitted {
            anchor_id: H256,
            content_hash: H256,
            submitter: T::AccountId,
        },
        /// An account joined the attestation committee (permissionless).
        CommitteeMemberJoined {
            who: T::AccountId,
            committee_size: u32,
        },
        /// An account left the attestation committee voluntarily.
        CommitteeMemberLeft {
            who: T::AccountId,
            committee_size: u32,
        },
        /// Attestation reward paid to a committee member for certifying a receipt.
        AttestationRewardPaid {
            attester: T::AccountId,
            receipt_id: H256,
            reward: u128,
        },
        /// Validator rewards distributed at end of era.
        ValidatorRewardsDistributed {
            era_blocks: u32,
            total_distributed: u128,
            validators_rewarded: u32,
        },
        /// Consensus authorities rotated. Aura takes effect immediately;
        /// Grandpa takes effect at `apply_at_block`.
        AuthoritiesRotated {
            aura_count: u32,
            grandpa_count: u32,
            grandpa_set_id: u64,
            apply_at_block: BlockNumberFor<T>,
        },
    }

    // ── Errors ───────────────────────────────────────────────────────────
    //
    // NOTE: Doc comments on error variants are included in on-chain metadata
    // and are visible to SDK consumers via `system.metadata()`. Keep them
    // actionable so developers can self-diagnose without reading source.
    //
    // Substrate events can only be emitted on successful dispatch, so
    // failed extrinsics do NOT produce events. Callers should check
    // `system.events` for `ExtrinsicFailed` and inspect the `DispatchError`
    // to find which `Error` variant was returned.

    #[pallet::error]
    pub enum Error<T> {
        /// A receipt with this ID already exists on-chain. Each receipt ID
        /// must be globally unique. Generate a fresh random H256 or use a
        /// deterministic derivation (e.g. hash of content + nonce) to avoid
        /// collisions. Query `orinq_receiptExists` via RPC to pre-check.
        ReceiptAlreadyExists,
        /// No receipt with the given ID was found on-chain. Verify the
        /// receipt ID is correct and that the submission transaction was
        /// finalized. Use `orinq_receiptExists` or `orinq_getReceipt` via
        /// RPC to confirm existence before calling cert/attest extrinsics.
        ReceiptNotFound,
        /// The content index for this content hash has reached its maximum
        /// capacity (`MaxResubmits`). This limits how many distinct receipt
        /// IDs can share the same content hash. Consider using a different
        /// content hash or contact the chain operator to increase the limit.
        ContentIndexFull,
        /// The caller is not a member of the attestation committee. Only
        /// accounts added via `set_committee` (root-only) can attest
        /// availability certificates. Check `committeeMembers` storage
        /// to see the current authorized set.
        NotCommitteeMember,
        /// The cert_hash in this attestation does not match the cert_hash
        /// already recorded by a previous attester for the same receipt.
        /// All committee members must attest the exact same certificate
        /// hash. Verify the cert_hash computation is deterministic across
        /// all attesters.
        CertHashMismatch,
        /// Attempted to add more committee members than `MaxCommitteeSize`
        /// allows. Reduce the member list or ask the chain operator to
        /// increase the `MaxCommitteeSize` constant via a runtime upgrade.
        CommitteeFull,
        /// An anchor with this ID already exists on-chain. Anchor IDs must
        /// be globally unique, similar to receipt IDs.
        AnchorAlreadyExists,
        /// The new authority set cannot be empty. At least one Aura and one
        /// Grandpa authority must be provided for block production and
        /// finality to continue.
        EmptyAuthoritySet,
        /// The caller is already a member of the attestation committee.
        AlreadyCommitteeMember,
        /// The caller is not a member of the attestation committee and
        /// cannot leave it.
        NotCommitteeMemberCantLeave,
        /// The number of Aura authorities must equal the number of Grandpa
        /// authorities. Each validator node needs exactly one key in each
        /// set.
        AuthorityCountMismatch,
        /// The provided authority list exceeds `MaxAuthorities`. Reduce the
        /// number of validators or increase the `MaxAuthorities` constant
        /// via a runtime upgrade.
        TooManyAuthorities,
        /// A Grandpa authority change is already scheduled and has not yet
        /// been applied. Wait for the pending change to take effect (check
        /// `grandpa.PendingChange` storage) before scheduling another
        /// rotation.
        AuthorityChangeAlreadyPending,
    }

    // ── Hooks ────────────────────────────────────────────────────────────

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T>
    where
        T::AccountId: From<[u8; 32]>,
        BlockNumberFor<T>: Into<u32> + From<u32>,
    {
        fn on_initialize(n: BlockNumberFor<T>) -> Weight {
            let mut weight = Weight::zero();

            // REMOVED (flux-point-studios/materios, v3+): a legacy one-time
            // migration that overwrote CommitteeMembers with //Alice/Bob/Charlie/
            // Dave dev keys AND reset Sudo::Key to //Alice. It was a preview-era
            // test helper that leaked into production code, firing on block #1
            // of any fresh chain. With v3's genesis (multisig sudo from block 0,
            // IOG permissioned-candidates list driven by Cardano), the migration
            // is unneeded and actively harmful — it silently replaces a 2-of-3
            // multisig with a publicly-known dev keypair. Do NOT re-introduce.

            // ── Validator rewards: track block author ────────────────────
            // Aura round-robin: author = authorities[slot % len]
            // We use the Aura author digest to identify who produced this block.
            if let Some(author) = Self::find_block_author() {
                BlocksAuthored::<T>::mutate(&author, |count| *count = count.saturating_add(1));
            }

            // ── Validator rewards: era distribution ──────────────────────
            // Era length: 14400 blocks (~24h at 6s block time)
            // Reward pool: 150,000,000 MATRA (with 6 decimals = 150_000_000_000_000)
            // Over ~4 years (1460 days) = ~102,739,726 units/day = ~102_739_726_000_000 base/day
            // Per era (14400 blocks): 102_739_726_000_000 base units
            const ERA_LENGTH: u32 = 14400;
            const REWARD_PER_ERA: u128 = 102_739_726_000_000; // ~102.7M base units (~102.7 MATRA/era)
            const VALIDATOR_RESERVE: u128 = 150_000_000_000_000_000_000; // 150M MATRA in base units

            let block_num: u32 = n.into();
            let era_start: u32 = EraStartBlock::<T>::get().into();

            if block_num > 0 && block_num.saturating_sub(era_start) >= ERA_LENGTH {
                // Distribute rewards for this era
                let total_distributed = TotalRewardsDistributed::<T>::get();
                if total_distributed < VALIDATOR_RESERVE {
                    let remaining = VALIDATOR_RESERVE.saturating_sub(total_distributed);
                    let era_reward = core::cmp::min(REWARD_PER_ERA, remaining);

                    // Sum total blocks authored this era
                    let mut authored: Vec<(T::AccountId, u32)> = Vec::new();
                    let mut total_blocks: u32 = 0;
                    for (account, count) in BlocksAuthored::<T>::iter() {
                        if count > 0 {
                            total_blocks = total_blocks.saturating_add(count);
                            authored.push((account, count));
                        }
                    }

                    if total_blocks > 0 {
                        let mut distributed_this_era: u128 = 0;
                        let validators_count = authored.len() as u32;

                        for (account, blocks) in &authored {
                            // Pro-rata: reward = era_reward * blocks / total_blocks
                            let reward = era_reward
                                .saturating_mul(*blocks as u128)
                                / (total_blocks as u128);

                            if reward > 0 {
                                // Credit the validator's MATRA balance via Balances pallet
                                use frame_support::traits::Currency;
                                let balance: <T as pallet_balances::Config>::Balance =
                                    reward.try_into().unwrap_or_default();
                                let _ = pallet_balances::Pallet::<T>::deposit_creating(
                                    account,
                                    balance,
                                );

                                // Track lifetime rewards
                                ValidatorRewards::<T>::mutate(account, |total| {
                                    *total = total.saturating_add(reward);
                                });
                                distributed_this_era = distributed_this_era.saturating_add(reward);
                            }
                        }

                        TotalRewardsDistributed::<T>::mutate(|total| {
                            *total = total.saturating_add(distributed_this_era);
                        });

                        Self::deposit_event(Event::ValidatorRewardsDistributed {
                            era_blocks: total_blocks,
                            total_distributed: distributed_this_era,
                            validators_rewarded: validators_count,
                        });

                        log::info!(
                            "Validator rewards distributed: {} to {} validators ({} blocks)",
                            distributed_this_era, validators_count, total_blocks
                        );
                    }

                    // Reset for next era
                    let _ = BlocksAuthored::<T>::clear(u32::MAX, None);
                    ReceiptsCertifiedInEra::<T>::put(0u32);
                    AttestationRewardsPaidInEra::<T>::put(0u128);
                    EraStartBlock::<T>::put(n);
                }
            }

            weight.saturating_add(Weight::from_parts(10_000_000, 0))
        }
    }

    impl<T: Config> Pallet<T>
    where
        T::AccountId: From<[u8; 32]>,
    {
        /// Find the block author from the Aura pre-runtime digest.
        /// Aura AuthorityId (sr25519 public key) shares the same 32-byte
        /// representation as AccountId32, so we can convert directly.
        fn find_block_author() -> Option<T::AccountId> {
            let digest = <frame_system::Pallet<T>>::digest();
            for log in digest.logs.iter() {
                if let sp_runtime::DigestItem::PreRuntime(engine, data) = log {
                    if engine == b"aura" {
                        if let Ok(slot) = <u64 as parity_scale_codec::Decode>::decode(&mut &data[..]) {
                            let authorities = pallet_aura::Authorities::<T>::get();
                            if !authorities.is_empty() {
                                let idx = (slot % authorities.len() as u64) as usize;
                                let author_pubkey = &authorities[idx];
                                // AuthorityId encodes to 32 bytes (sr25519 public key)
                                let encoded = parity_scale_codec::Encode::encode(author_pubkey);
                                if encoded.len() >= 32 {
                                    let mut bytes = [0u8; 32];
                                    bytes.copy_from_slice(&encoded[..32]);
                                    return Some(T::AccountId::from(bytes));
                                }
                            }
                        }
                    }
                }
            }
            None
        }
    }

    // ── Extrinsics ───────────────────────────────────────────────────────

    #[pallet::call]
    impl<T: Config> Pallet<T>
    where
        T::Moment: Into<u64>,
    {
        /// Submit a new receipt on-chain.
        #[pallet::call_index(0)]
        #[pallet::weight(<T as crate::pallet::Config>::WeightInfo::submit_receipt())]
        pub fn submit_receipt(
            origin: OriginFor<T>,
            receipt_id: H256,
            content_hash: H256,
            base_root_sha256: [u8; 32],
            zk_root_poseidon: Option<[u8; 32]>,
            poseidon_params_hash: Option<[u8; 32]>,
            base_manifest_hash: [u8; 32],
            safety_manifest_hash: [u8; 32],
            monitor_config_hash: [u8; 32],
            attestation_evidence_hash: [u8; 32],
            storage_locator_hash: [u8; 32],
            schema_hash: [u8; 32],
        ) -> DispatchResult {
            let submitter = ensure_signed(origin)?;
            ensure!(!Receipts::<T>::contains_key(receipt_id), Error::<T>::ReceiptAlreadyExists);
            let now: u64 = pallet_timestamp::Pallet::<T>::get().into();
            let record = ReceiptRecord {
                schema_hash,
                content_hash: content_hash.0,
                base_root_sha256,
                zk_root_poseidon,
                poseidon_params_hash,
                base_manifest_hash,
                safety_manifest_hash,
                monitor_config_hash,
                attestation_evidence_hash,
                storage_locator_hash,
                availability_cert_hash: [0u8; 32],
                created_at_millis: now,
                submitter: submitter.clone(),
            };
            Receipts::<T>::insert(receipt_id, record);
            ContentIndex::<T>::try_mutate(content_hash, |ids| {
                ids.try_push(receipt_id).map_err(|_| Error::<T>::ContentIndexFull)
            })?;
            ReceiptCount::<T>::mutate(|c| *c = c.saturating_add(1));
            Self::deposit_event(Event::ReceiptSubmitted { receipt_id, content_hash, submitter });
            Ok(())
        }

        /// Root-only: directly set an availability certificate on a receipt.
        /// Retained for backward compatibility / emergency override.
        #[pallet::call_index(1)]
        #[pallet::weight(<T as crate::pallet::Config>::WeightInfo::set_availability_cert())]
        pub fn set_availability_cert(
            origin: OriginFor<T>,
            receipt_id: H256,
            cert_hash: [u8; 32],
        ) -> DispatchResult {
            ensure_root(origin)?;
            Receipts::<T>::try_mutate(receipt_id, |maybe_record| {
                let record = maybe_record.as_mut().ok_or(Error::<T>::ReceiptNotFound)?;
                record.availability_cert_hash = cert_hash;
                Ok::<(), DispatchError>(())
            })?;
            Self::deposit_event(Event::AvailabilityCertified {
                receipt_id,
                cert_hash: H256::from(cert_hash),
            });
            Ok(())
        }

        /// Root-only: set the attestation committee members and threshold.
        ///
        /// `members` — accounts authorized to call `attest_availability_cert`.
        /// `threshold` — number of unique attestations required to finalize.
        ///               Clamped to `1..=members.len()`.
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(10_000, 0).saturating_add(T::DbWeight::get().writes(2)))]
        pub fn set_committee(
            origin: OriginFor<T>,
            members: Vec<T::AccountId>,
            threshold: u32,
        ) -> DispatchResult {
            ensure_root(origin)?;

            let mut set = BoundedBTreeSet::<T::AccountId, T::MaxCommitteeSize>::new();
            for m in members.iter() {
                set.try_insert(m.clone()).map_err(|_| Error::<T>::CommitteeFull)?;
            }

            // Clamp threshold: at least 1, at most the committee size.
            let effective_threshold = threshold
                .max(1)
                .min(set.len() as u32);

            CommitteeMembers::<T>::put(&set);
            AttestationThreshold::<T>::put(effective_threshold);

            Self::deposit_event(Event::CommitteeUpdated {
                members: set.into_inner().into_iter().collect(),
                threshold: effective_threshold,
            });
            Ok(())
        }

        /// Committee member attests an availability certificate for a receipt.
        ///
        /// When the number of unique attestations reaches the threshold the
        /// certificate is finalized on the receipt record (same effect as
        /// `set_availability_cert`).
        #[pallet::call_index(3)]
        #[pallet::weight(Weight::from_parts(15_000, 0)
            .saturating_add(T::DbWeight::get().reads(3))
            .saturating_add(T::DbWeight::get().writes(2)))]
        pub fn attest_availability_cert(
            origin: OriginFor<T>,
            receipt_id: H256,
            cert_hash: [u8; 32],
        ) -> DispatchResult {
            let attester = ensure_signed(origin)?;

            // 1. Caller must be a committee member.
            let committee = CommitteeMembers::<T>::get();
            ensure!(committee.contains(&attester), Error::<T>::NotCommitteeMember);

            // 2. Receipt must exist.
            ensure!(Receipts::<T>::contains_key(receipt_id), Error::<T>::ReceiptNotFound);

            let cert_h256 = H256::from(cert_hash);

            // 3. Insert or update the attestation record.
            let count = Attestations::<T>::try_mutate(receipt_id, |maybe_att| -> Result<u32, DispatchError> {
                match maybe_att {
                    Some((existing_hash, ref mut signers)) => {
                        // All attesters must agree on the same cert hash.
                        ensure!(*existing_hash == cert_h256, Error::<T>::CertHashMismatch);
                        // Insert is idempotent — re-attesting is a no-op.
                        let _ = signers.try_insert(attester.clone());
                        Ok(signers.len() as u32)
                    },
                    None => {
                        let mut signers = BoundedBTreeSet::<T::AccountId, T::MaxCommitteeSize>::new();
                        let _ = signers.try_insert(attester.clone());
                        *maybe_att = Some((cert_h256, signers));
                        Ok(1u32)
                    },
                }
            })?;

            let threshold = AttestationThreshold::<T>::get().max(1);

            Self::deposit_event(Event::AttestationRecorded {
                receipt_id,
                attester,
                count,
                threshold,
            });

            // 4. If threshold reached, finalize the cert on the receipt.
            if count >= threshold {
                // Pay attestation rewards BEFORE removing the attestation record.
                // Each signer gets an equal share of the per-receipt reward.
                //
                // Attestation reward pool: 50M MATRA over ~4 years
                // = ~34,246,575 base units per day = ~34.2 MATRA/day
                // Per receipt: daily_pool / avg_receipts_per_day (dynamic)
                // Simplified: fixed reward per attester per certification = 10 MATRA base units
                // (This will be tuned via governance on mainnet)
                const ATTESTATION_REWARD_PER_SIGNER: u128 = 10_000_000; // 10 MATRA (6 decimals)
                const ATTESTATION_RESERVE: u128 = 50_000_000_000_000_000_000; // 50M MATRA
                // Cap attestation rewards per era to prevent reserve drain.
                // 50M MATRA / ~1,461 eras (4 years) ≈ 34,223 MATRA/era.
                // Set slightly higher to allow for burst activity.
                const ATTESTATION_ERA_CAP: u128 = 50_000_000_000; // 50,000 MATRA per era

                let total_att_paid = TotalAttestationRewards::<T>::get();
                let era_att_paid = AttestationRewardsPaidInEra::<T>::get();
                if total_att_paid < ATTESTATION_RESERVE && era_att_paid < ATTESTATION_ERA_CAP {
                    // Get signers before we remove the attestation
                    if let Some((_, ref signers)) = Attestations::<T>::get(receipt_id) {
                        for signer in signers.iter() {
                            // Re-check era cap inside loop (multiple signers per cert)
                            let current_era_paid = AttestationRewardsPaidInEra::<T>::get();
                            if current_era_paid >= ATTESTATION_ERA_CAP {
                                break;
                            }
                            let reward = ATTESTATION_REWARD_PER_SIGNER;
                            use frame_support::traits::Currency;
                            let balance: <T as pallet_balances::Config>::Balance =
                                reward.try_into().unwrap_or_default();
                            let _ = pallet_balances::Pallet::<T>::deposit_creating(signer, balance);

                            AttestationRewards::<T>::mutate(signer, |total| {
                                *total = total.saturating_add(reward);
                            });
                            TotalAttestationRewards::<T>::mutate(|total| {
                                *total = total.saturating_add(reward);
                            });
                            AttestationRewardsPaidInEra::<T>::mutate(|total| {
                                *total = total.saturating_add(reward);
                            });

                            Self::deposit_event(Event::AttestationRewardPaid {
                                attester: signer.clone(),
                                receipt_id,
                                reward,
                            });
                        }
                    }
                    ReceiptsCertifiedInEra::<T>::mutate(|n| *n = n.saturating_add(1));
                }

                Receipts::<T>::try_mutate(receipt_id, |maybe_record| {
                    let record = maybe_record.as_mut().ok_or(Error::<T>::ReceiptNotFound)?;
                    record.availability_cert_hash = cert_hash;
                    Ok::<(), DispatchError>(())
                })?;

                // Clean up the attestation record — it's no longer needed.
                Attestations::<T>::remove(receipt_id);

                Self::deposit_event(Event::AvailabilityCertified {
                    receipt_id,
                    cert_hash: cert_h256,
                });
            }

            Ok(())
        }

        /// Submit an anchor — a lightweight on-chain binding for SDK-originated
        /// content (PoI traces, checkpoints, etc.). Distinct from receipts:
        /// the cert daemon ignores `AnchorSubmitted` events.
        #[pallet::call_index(4)]
        #[pallet::weight(Weight::from_parts(10_000, 0)
            .saturating_add(T::DbWeight::get().reads(1))
            .saturating_add(T::DbWeight::get().writes(1)))]
        pub fn submit_anchor(
            origin: OriginFor<T>,
            anchor_id: H256,
            content_hash: H256,
            root_hash: H256,
            manifest_hash: H256,
        ) -> DispatchResult {
            let submitter = ensure_signed(origin)?;

            ensure!(
                !Anchors::<T>::contains_key(anchor_id),
                Error::<T>::AnchorAlreadyExists
            );

            let now: u64 = pallet_timestamp::Pallet::<T>::get().into();

            let record = AnchorRecord {
                content_hash: content_hash.0,
                root_hash: root_hash.0,
                manifest_hash: manifest_hash.0,
                created_at_millis: now,
                submitter: submitter.clone(),
            };

            Anchors::<T>::insert(anchor_id, record);

            Self::deposit_event(Event::AnchorSubmitted {
                anchor_id,
                content_hash,
                submitter,
            });

            Ok(())
        }

        /// Root-only: rotate Aura and Grandpa authorities.
        ///
        /// Replaces `Sudo(System.set_storage)` for authority changes.
        /// Aura authorities take effect immediately. Grandpa authorities
        /// are scheduled via PendingChange and take effect after
        /// `delay_blocks` blocks.
        ///
        /// `new_aura` — sr25519 public keys for block production.
        /// `new_grandpa` — (ed25519 public key, weight) pairs for finality.
        /// `delay_blocks` — blocks before Grandpa change takes effect (min 1).
        #[pallet::call_index(5)]
        #[pallet::weight(Weight::from_parts(50_000, 0)
            .saturating_add(T::DbWeight::get().reads(2))
            .saturating_add(T::DbWeight::get().writes(4)))]
        pub fn rotate_authorities(
            origin: OriginFor<T>,
            new_aura: Vec<<T as pallet_aura::Config>::AuthorityId>,
            new_grandpa: sp_consensus_grandpa::AuthorityList,
            delay_blocks: u32,
        ) -> DispatchResult {
            ensure_root(origin)?;

            // Validate inputs
            ensure!(!new_aura.is_empty(), Error::<T>::EmptyAuthoritySet);
            ensure!(!new_grandpa.is_empty(), Error::<T>::EmptyAuthoritySet);
            ensure!(
                new_aura.len() == new_grandpa.len(),
                Error::<T>::AuthorityCountMismatch
            );

            // --- Update Aura authorities (immediate) ---
            let bounded_aura: BoundedVec<
                <T as pallet_aura::Config>::AuthorityId,
                <T as pallet_aura::Config>::MaxAuthorities,
            > = new_aura
                .try_into()
                .map_err(|_| Error::<T>::TooManyAuthorities)?;
            pallet_aura::Authorities::<T>::put(bounded_aura);

            // --- Schedule Grandpa authority change via the pallet's public API ---
            // Using pallet_grandpa::Pallet::schedule_change() ensures correct
            // SCALE encoding of StoredPendingChange (including WeakBoundedVec
            // for authorities). Raw storage writes caused "Invalid authority set"
            // errors due to encoding mismatches.
            let delay: BlockNumberFor<T> = delay_blocks.max(2).into();
            pallet_grandpa::Pallet::<T>::schedule_change(
                new_grandpa.clone(),
                delay,
                Some(delay), // FORCED — applies at block height regardless of finality
            )?;

            // Increment CurrentSetId so GRANDPA voters track the new authority set.
            // schedule_change() does not do this (it's normally done by pallet_session).
            let set_id_key = frame_support::storage::storage_prefix(b"Grandpa", b"CurrentSetId");
            let new_set_id: u64 = frame_support::storage::unhashed::get(&set_id_key)
                .unwrap_or(0u64)
                .saturating_add(1);
            frame_support::storage::unhashed::put(&set_id_key, &new_set_id);

            let current_block = frame_system::Pallet::<T>::block_number();
            let apply_at = current_block + delay;
            Self::deposit_event(Event::AuthoritiesRotated {
                aura_count: new_grandpa.len() as u32,
                grandpa_count: new_grandpa.len() as u32,
                grandpa_set_id: new_set_id,
                apply_at_block: apply_at,
            });

            Ok(())
        }

        /// Submit a receipt with player-attributable anti-cheat signature.
        /// The studio wallet (origin) pays fees, while the player's sr25519
        /// signature proves the player produced the game telemetry.
        ///
        /// `player_pubkey` — Player's sr25519 public key (32 bytes).
        /// `player_sig` — Player's sr25519 signature over the receipt payload (64 bytes).
        /// `sig_type` — 0 = ed25519, 1 = sr25519.
        /// Remaining params are identical to `submit_receipt`.
        #[pallet::call_index(6)]
        #[pallet::weight(<T as crate::pallet::Config>::WeightInfo::submit_receipt())]
        pub fn submit_receipt_v2(
            origin: OriginFor<T>,
            player_pubkey: [u8; 32],
            player_sig: [u8; 64],
            sig_type: u8,
            receipt_id: H256,
            content_hash: H256,
            base_root_sha256: [u8; 32],
            zk_root_poseidon: Option<[u8; 32]>,
            poseidon_params_hash: Option<[u8; 32]>,
            base_manifest_hash: [u8; 32],
            safety_manifest_hash: [u8; 32],
            monitor_config_hash: [u8; 32],
            attestation_evidence_hash: [u8; 32],
            storage_locator_hash: [u8; 32],
            schema_hash: [u8; 32],
        ) -> DispatchResult {
            let submitter = ensure_signed(origin)?;
            ensure!(!Receipts::<T>::contains_key(receipt_id), Error::<T>::ReceiptAlreadyExists);
            let now: u64 = pallet_timestamp::Pallet::<T>::get().into();
            let record = ReceiptRecord {
                schema_hash,
                content_hash: content_hash.0,
                base_root_sha256,
                zk_root_poseidon,
                poseidon_params_hash,
                base_manifest_hash,
                safety_manifest_hash,
                monitor_config_hash,
                attestation_evidence_hash,
                storage_locator_hash,
                availability_cert_hash: [0u8; 32],
                created_at_millis: now,
                submitter: submitter.clone(),
            };
            Receipts::<T>::insert(receipt_id, record);

            // Store player signature separately for backward compatibility
            PlayerSignatures::<T>::insert(receipt_id, PlayerSigRecord {
                player_pubkey,
                player_sig,
                sig_type,
            });

            ContentIndex::<T>::try_mutate(content_hash, |ids| {
                ids.try_push(receipt_id).map_err(|_| Error::<T>::ContentIndexFull)
            })?;
            ReceiptCount::<T>::mutate(|c| *c = c.saturating_add(1));
            Self::deposit_event(Event::ReceiptSubmitted { receipt_id, content_hash, submitter });
            Ok(())
        }

        /// Permissionless: any signed account can join the attestation
        /// committee. Once joined, the account can call
        /// `attest_availability_cert` and earn attestation rewards.
        ///
        /// Fails if the committee is already at `MaxCommitteeSize` or the
        /// caller is already a member.
        #[pallet::call_index(7)]
        #[pallet::weight(Weight::from_parts(10_000, 0)
            .saturating_add(T::DbWeight::get().reads(1))
            .saturating_add(T::DbWeight::get().writes(1)))]
        pub fn join_committee(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;

            CommitteeMembers::<T>::try_mutate(|set| {
                ensure!(!set.contains(&who), Error::<T>::AlreadyCommitteeMember);
                set.try_insert(who.clone()).map_err(|_| Error::<T>::CommitteeFull)?;
                let size = set.len() as u32;
                Self::deposit_event(Event::CommitteeMemberJoined {
                    who,
                    committee_size: size,
                });
                Ok(())
            })
        }

        /// Voluntarily leave the attestation committee. The caller stops
        /// receiving attestation rewards and can no longer attest.
        #[pallet::call_index(8)]
        #[pallet::weight(Weight::from_parts(10_000, 0)
            .saturating_add(T::DbWeight::get().reads(1))
            .saturating_add(T::DbWeight::get().writes(1)))]
        pub fn leave_committee(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;

            CommitteeMembers::<T>::try_mutate(|set| {
                ensure!(set.contains(&who), Error::<T>::NotCommitteeMemberCantLeave);
                set.remove(&who);
                let size = set.len() as u32;
                Self::deposit_event(Event::CommitteeMemberLeft {
                    who,
                    committee_size: size,
                });
                Ok(())
            })
        }
    }
}
