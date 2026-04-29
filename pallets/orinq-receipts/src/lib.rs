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
    use frame_support::traits::{BalanceStatus, ReservableCurrency};
    use frame_support::PalletId;
    use frame_system::pallet_prelude::*;
    use sp_core::H256;
    use sp_runtime::Perbill;
    use sp_runtime::traits::{AccountIdConversion, Saturating};

    use crate::types::{AnchorRecord, PlayerSigRecord, ReceiptRecord, SlashReason};
    use crate::weights::WeightInfo;

    /// Alias for the reservable balance type exposed by `T::Currency`.
    pub(crate) type BalanceOf<T> =
        <<T as Config>::Currency as frame_support::traits::Currency<
            <T as frame_system::Config>::AccountId,
        >>::Balance;

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

    /// Minimum allowed value for `ReceiptExpiryBlocks`, enforced by
    /// `set_receipt_expiry_blocks`. Set at 10 blocks (~60s at 6s/block).
    ///
    /// Lower values create a grief vector where a root/governance key could
    /// set expiry=0 and call `expire_receipt_fee` on an in-flight receipt
    /// whose signers are attesting but have not yet crossed the threshold
    /// — stealing the submitter→signer flow. 10 blocks is large enough to
    /// make the race implausible under normal block times while still
    /// leaving room for legitimate tight-window regimes during preprod
    /// rehearsals. If a real use case emerges that needs lower, this
    /// constant can be dropped in a runtime upgrade.
    pub const MIN_RECEIPT_EXPIRY_BLOCKS: u32 = 10;

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

        /// Reservable currency used for attestor bonds. Bond funds are
        /// reserved on `bond`, unreserved on `unbond`, and
        /// `repatriate_reserved`-ed to the attestor reserve pot on slash.
        type Currency: ReservableCurrency<Self::AccountId>;

        /// PalletId used to derive the attestor reserve pot account. Must
        /// match the runtime's `mat/attr` id so slashed funds land in the
        /// same pot that the fee router's 30% share funds.
        #[pallet::constant]
        type AttestorReservePotId: Get<PalletId>;

        /// PalletId used to derive the treasury pot account. Must match the
        /// runtime's `mat/trsy` id so the 20% treasury share of receipt
        /// submission fees lands in the same pot that pallet_treasury and
        /// the fee-router's 20% share credit to (Component 4).
        #[pallet::constant]
        type TreasuryPotId: Get<PalletId>;

        /// Fraction of each era's `REWARD_PER_ERA` routed to the treasury
        /// (the complement goes to block-authoring validators pro-rata).
        /// Default: 15% (Perbill::from_percent(15)). Governance can retune
        /// this via runtime upgrade without code change — it's the single
        /// tunable knob for validator ↔ treasury emission balance.
        ///
        /// Rounding residue from the Perbill multiplication is always routed
        /// to treasury (safer sink), regardless of the share value.
        #[pallet::constant]
        type TreasuryEmissionShare: Get<Perbill>;
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

    // ── Component 5: dynamic attestation reward + era cap ───────────────
    //
    // Replace the previous hard-coded constants with governance-tunable
    // storage. Defaults match the original constants for migration safety.
    // The effective era cap auto-scales linearly with the number of active
    // attestors (CommitteeMembers::len) relative to `EraCapBaselineAttestorCount`,
    // so reward capacity grows as the committee grows without requiring a
    // runtime upgrade.

    /// Reward paid to each signer per certified receipt, in MATRA base units
    /// (6 decimals). Default: 10 MATRA per signer per cert.
    #[pallet::storage]
    #[pallet::getter(fn attestation_reward_per_signer)]
    pub type AttestationRewardPerSigner<T: Config> = StorageValue<_, u128, ValueQuery>;

    /// Base cap on total attestation rewards paid out per era, in MATRA base
    /// units (6 decimals). The effective cap scales linearly with the number
    /// of active attestors relative to `EraCapBaselineAttestorCount`.
    /// Default: 50,000 MATRA (=50_000_000_000 base units).
    #[pallet::storage]
    #[pallet::getter(fn era_cap_base)]
    pub type EraCapBase<T: Config> = StorageValue<_, u128, ValueQuery>;

    /// The attestor-count at which `effective_era_cap()` equals `era_cap_base`.
    /// Defaults to 16 (the original `MaxCommitteeSize`). Raising this widens
    /// the committee without increasing total per-era reward emission; at
    /// `active_count == baseline`, the effective cap equals the base.
    #[pallet::storage]
    #[pallet::getter(fn era_cap_baseline_attestor_count)]
    pub type EraCapBaselineAttestorCount<T: Config> = StorageValue<_, u32, ValueQuery>;

    // ── Component 8: attestor bond + slashing ───────────────────────────
    //
    // Attestors must lock a bond before joining the committee. Misbehaviour
    // is punished by slashing the bond; slashed funds are repatriated (not
    // burned) to the attestor reserve pot (`mat/attr`) so MATRA accumulates
    // for future reward payouts. Auto-eject if the remaining bond drops
    // below `BondRequirement`.

    /// Bonded amount per attestor, in MATRA base units (6 decimals). Tracks
    /// the value reserved via `T::Currency::reserve` — kept in a dedicated
    /// map because reserve identifiers aren't inspectable cross-pallet and
    /// we want a single-read authoritative source of truth.
    #[pallet::storage]
    #[pallet::getter(fn attestor_bonds)]
    pub type AttestorBonds<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, u128, ValueQuery>;

    /// Minimum bond required to join the committee. Governance-tunable; a
    /// zero value effectively disables the bond check (useful during
    /// preprod rehearsals but MUST NOT be 0 on mainnet).
    #[pallet::storage]
    #[pallet::getter(fn bond_requirement)]
    pub type BondRequirement<T: Config> = StorageValue<_, u128, ValueQuery>;

    // ── Component 4: per-receipt submission fee + signer payout ─────────
    //
    // Submitter pays a flat fee per receipt, held in reserved balance with
    // ReceiptFeeEscrow as the tag-like tracking map. On threshold-hit the
    // fee is split 80% / 20% between the actual signers and the treasury
    // pot. On expiry (pre-threshold) the fee refunds to the submitter.
    //
    // Storage layout:
    //   ReceiptSubmissionFee      — flat per-receipt fee (governance-tunable)
    //   ReceiptSubmissionFeeFloor — minimum allowed fee (governance-tunable)
    //   ReceiptExpiryBlocks       — blocks before a submitted, uncertified
    //                               receipt can be refunded (governance-tunable)
    //   ReceiptFeeEscrow          — receipt_id -> (submitter, reserved_amount)
    //   ReceiptSubmittedAt        — receipt_id -> block_number (expiry anchor)

    /// Per-receipt submission fee in MATRA base units (6 decimals).
    /// Default: 1_000_000 base units (1 MATRA). Must be >= ReceiptSubmissionFeeFloor
    /// when updated via governance.
    #[pallet::storage]
    #[pallet::getter(fn receipt_submission_fee)]
    pub type ReceiptSubmissionFee<T: Config> = StorageValue<_, u128, ValueQuery>;

    /// Minimum allowed value of `ReceiptSubmissionFee`. Prevents governance
    /// from accidentally zero-ing out the fee (which would disable the
    /// recycling mechanism entirely). Default: 100_000 (0.1 MATRA).
    #[pallet::storage]
    #[pallet::getter(fn receipt_submission_fee_floor)]
    pub type ReceiptSubmissionFeeFloor<T: Config> = StorageValue<_, u128, ValueQuery>;

    /// Number of blocks after `ReceiptSubmittedAt` at which an uncertified
    /// receipt becomes eligible for fee refund via `expire_receipt_fee`.
    /// Default: 14_400 (~24h at 6s block time). Governance-tunable.
    #[pallet::storage]
    #[pallet::getter(fn receipt_expiry_blocks)]
    pub type ReceiptExpiryBlocks<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// Per-receipt fee escrow. Populated on `submit_receipt`; drained on
    /// threshold-hit payout OR `expire_receipt_fee`. Missing entry means
    /// either the receipt predates Component 4 (legacy) or the fee has
    /// already been settled.
    ///
    /// Key: receipt_id -> (submitter_account, reserved_amount)
    #[pallet::storage]
    pub type ReceiptFeeEscrow<T: Config> =
        StorageMap<_, Blake2_128Concat, H256, (T::AccountId, u128), OptionQuery>;

    /// Block number at which a receipt was submitted. Used as the anchor
    /// for computing expiry eligibility in `expire_receipt_fee`. Only
    /// populated for Component-4+ submissions.
    #[pallet::storage]
    pub type ReceiptSubmittedAt<T: Config> =
        StorageMap<_, Blake2_128Concat, H256, BlockNumberFor<T>, OptionQuery>;

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
        /// `AttestationRewardPerSigner` was updated by governance.
        AttestationRewardPerSignerUpdated { new_value: u128 },
        /// `EraCapBase` was updated by governance.
        EraCapBaseUpdated { new_value: u128 },
        /// `EraCapBaselineAttestorCount` was updated by governance.
        EraCapBaselineAttestorCountUpdated { new_value: u32 },
        /// An attestor added to their bond. `new_total` is the bond after
        /// the call.
        Bonded {
            who: T::AccountId,
            amount: u128,
            new_total: u128,
        },
        /// An attestor withdrew their entire bond. `amount` is what was
        /// unreserved back to free balance.
        Unbonded { who: T::AccountId, amount: u128 },
        /// A portion of an attestor's bond was slashed and repatriated to
        /// the attestor reserve pot.
        Slashed {
            who: T::AccountId,
            amount: u128,
            reason: SlashReason,
            remaining_bond: u128,
        },
        /// `BondRequirement` was updated by governance.
        BondRequirementUpdated { new_value: u128 },
        /// An attestor was automatically removed from the committee because
        /// their post-slash bond fell below `BondRequirement`.
        AutoEjected { who: T::AccountId, remaining_bond: u128 },
        /// Submission-fee escrow was distributed on threshold hit. `total_fee`
        /// is the full escrow amount; `per_signer_amount` is the flat share
        /// each of the `signer_count` actual signers received; `treasury_amount`
        /// is the residual (20% + any rounding dust).
        ReceiptFeeDistributed {
            receipt_id: H256,
            submitter: T::AccountId,
            total_fee: u128,
            per_signer_amount: u128,
            treasury_amount: u128,
            signer_count: u32,
        },
        /// Submission-fee escrow was refunded to the submitter because the
        /// receipt expired without reaching the attestation threshold.
        ReceiptFeeRefunded {
            receipt_id: H256,
            submitter: T::AccountId,
            amount: u128,
        },
        /// Per-receipt submission fee was successfully reserved from the
        /// submitter and escrowed (Component 4). Emitted by `submit_receipt`
        /// so auditors have a direct on-chain trace of the reservation —
        /// previously only `ReceiptSubmitted` fired, which says nothing
        /// about the fee flow.
        ReceiptFeeReserved {
            receipt_id: H256,
            submitter: T::AccountId,
            amount: u128,
        },
        /// `ReceiptSubmissionFee` was updated by governance.
        ReceiptSubmissionFeeUpdated { new_value: u128 },
        /// `ReceiptSubmissionFeeFloor` was updated by governance.
        ReceiptSubmissionFeeFloorUpdated { new_value: u128 },
        /// `ReceiptExpiryBlocks` was updated by governance.
        ReceiptExpiryBlocksUpdated { new_value: u32 },
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
        /// `EraCapBaselineAttestorCount` cannot be zero — it is the divisor
        /// in `effective_era_cap()` and zero would panic/saturate.
        InvalidBaseline,
        /// The attestor's bond is below `BondRequirement`. Top up via
        /// `bond(extra)` and retry `join_committee`.
        InsufficientBond,
        /// The attestor is still a committee member and cannot unbond.
        /// Call `leave_committee` first, then `unbond`.
        StillInCommittee,
        /// The caller has no bond to unbond. Call `bond(amount)` first.
        NothingToUnbond,
        /// The submitter could not reserve enough balance to cover the
        /// per-receipt submission fee. Top up free balance and retry.
        InsufficientFee,
        /// A governance update to `ReceiptSubmissionFee` was rejected
        /// because the new value is below `ReceiptSubmissionFeeFloor`.
        /// Either raise the proposed value or lower the floor first.
        FeeBelowFloor,
        /// `expire_receipt_fee` called before `ReceiptExpiryBlocks` have
        /// elapsed since submission. Wait for the deadline to pass.
        ReceiptNotExpired,
        /// `bond(amount)` would leave the caller's free balance below
        /// `ExistentialDeposit` post-reserve, which `pallet_balances` rejects
        /// silently at mempool pre-validation per `feedback_bond_dust_bug.md`.
        /// We surface this explicitly so daemons can react to the error
        /// instead of looping forever on `bond() failed: None`. (W-15.)
        BondLeavesAccountDusty,
        /// `set_bond_requirement(value)` rejected because `value` is below
        /// `MIN_VIABLE_BOND` (100 MATRA at 6-dec). Prevents accidentally
        /// nuking attestor security via a sudo typo. (W-12.)
        BondRequirementTooLow,
        /// `expire_receipt_fee` called on a receipt that has already been
        /// certified — the escrow was already drained via the signer
        /// payout path. No action is required.
        ReceiptAlreadyCertified,
        /// `set_receipt_expiry_blocks` was called with a value below
        /// `MIN_RECEIPT_EXPIRY_BLOCKS`. Very low expiry windows create a
        /// grief vector where root (or a compromised governance key) could
        /// race-refund in-flight receipts whose signers are still attesting,
        /// stealing the submitter→signer flow. Raise the proposed value.
        ReceiptExpiryBlocksTooLow,
    }

    // ── Genesis ──────────────────────────────────────────────────────────
    //
    // Genesis config exists to seed the Component-5 dynamic storage on
    // *new* chains. On existing chains (v3/v4/v5 preprod), the values
    // come from the runtime-upgrade migration (see `on_runtime_upgrade`).

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        /// Initial reward per signer, in MATRA base units (6 decimals).
        pub attestation_reward_per_signer: u128,
        /// Initial base cap on attestation rewards per era.
        pub era_cap_base: u128,
        /// Initial baseline attestor count for cap auto-scaling.
        pub era_cap_baseline_attestor_count: u32,
        /// Initial bond requirement for joining the committee
        /// (Component 8). Defaults to 1K MATRA.
        pub bond_requirement: u128,
        /// Initial per-receipt submission fee (Component 4). Defaults to
        /// 1 MATRA (1_000_000 base units).
        pub receipt_submission_fee: u128,
        /// Initial fee floor (Component 4). Defaults to 0.1 MATRA
        /// (100_000 base units).
        pub receipt_submission_fee_floor: u128,
        /// Initial expiry deadline in blocks (Component 4). Defaults to
        /// 14_400 blocks (~24h at 6s/block).
        pub receipt_expiry_blocks: u32,
        #[serde(skip)]
        pub _phantom: core::marker::PhantomData<T>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            // Respect explicit genesis values; otherwise fall back to the
            // documented defaults that match the prior const values.
            let reward = if self.attestation_reward_per_signer == 0 {
                10_000_000u128 // 10 MATRA
            } else {
                self.attestation_reward_per_signer
            };
            let cap = if self.era_cap_base == 0 {
                50_000_000_000u128 // 50K MATRA
            } else {
                self.era_cap_base
            };
            let baseline = if self.era_cap_baseline_attestor_count == 0 {
                16u32
            } else {
                self.era_cap_baseline_attestor_count
            };
            let bond_req = if self.bond_requirement == 0 {
                1_000_000_000u128 // 1K MATRA (6 decimals)
            } else {
                self.bond_requirement
            };
            let fee = if self.receipt_submission_fee == 0 {
                1_000_000u128 // 1 MATRA (6 decimals)
            } else {
                self.receipt_submission_fee
            };
            let floor = if self.receipt_submission_fee_floor == 0 {
                100_000u128 // 0.1 MATRA (6 decimals)
            } else {
                self.receipt_submission_fee_floor
            };
            let expiry = if self.receipt_expiry_blocks == 0 {
                14_400u32 // ~24h at 6s/block
            } else {
                self.receipt_expiry_blocks
            };
            AttestationRewardPerSigner::<T>::put(reward);
            EraCapBase::<T>::put(cap);
            EraCapBaselineAttestorCount::<T>::put(baseline);
            BondRequirement::<T>::put(bond_req);
            ReceiptSubmissionFee::<T>::put(fee);
            ReceiptSubmissionFeeFloor::<T>::put(floor);
            ReceiptExpiryBlocks::<T>::put(expiry);
        }
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
            // Reward pool: 150,000,000 MATRA (6 decimals = 150_000_000_000_000 base units)
            // Over ~4 years (1460 days) = ~102.74 MATRA/era at 14400 blocks/era
            const ERA_LENGTH: u32 = 14400;
            const REWARD_PER_ERA: u128 = 102_739_726; // ~102.74 MATRA/era (6 decimals)
            const VALIDATOR_RESERVE: u128 = 150_000_000_000_000; // 150M MATRA (6 decimals)

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
                        // Validator emission split: runtime-tunable validator/treasury share (Option A — 2026-04-21).
                        //
                        // Future upgrade path (Option B — block-fullness-weighted):
                        // Per Midnight whitepaper (2025-06) §5, block rewards can be split into:
                        //   - fixed subsidy (100% to producer, guarantees floor reward)
                        //   - variable component (producer/treasury split by block fullness)
                        // Defer until preprod mainnet has organic tx volume; block-fullness signal
                        // is noise at current preprod volumes. Flag for re-eval post-mainnet TGE.
                        //
                        // Rounding residue → treasury (safer sink than validators).
                        // `T::TreasuryEmissionShare` is a runtime-tunable `Get<Perbill>`
                        // (defaults to 15% in the runtime's `parameter_types!`) so governance
                        // can retune via runtime upgrade without code change.
                        //
                        // NOTE: pre-202 the full `era_reward` went to validators; `total_distributed`
                        // and `ValidatorRewards` tracked the lifetime-paid validator figure only.
                        // With the split, BOTH go through the pool: validators track their share,
                        // treasury emission is accounted under `TotalRewardsDistributed` as well
                        // so the VALIDATOR_RESERVE cap still gates the full emission envelope.
                        let treasury_share: Perbill = T::TreasuryEmissionShare::get();
                        // Validator gets the complement of the treasury share, computed via
                        // `Perbill::saturating_sub` to stay in the Perbill domain. At
                        // treasury_share=15% this is validator_share=85%.
                        let validator_share: Perbill =
                            Perbill::one().saturating_sub(treasury_share);
                        let validator_pool = validator_share.mul_floor(era_reward);
                        // Treasury gets the exact complement — this ensures
                        // validator_pool + treasury_pool == era_reward with zero leak,
                        // and rolls any residue from the percent multiplication into
                        // treasury (the safer sink per spec).
                        let treasury_pool = era_reward.saturating_sub(validator_pool);

                        let mut distributed_to_validators: u128 = 0;
                        let validators_count = authored.len() as u32;

                        // Pro-rata pay validators from the 85% pool. Any floor()
                        // residue here also rolls into treasury below.
                        for (account, blocks) in &authored {
                            // Pro-rata: reward = validator_pool * blocks / total_blocks
                            let reward = validator_pool
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
                                distributed_to_validators =
                                    distributed_to_validators.saturating_add(reward);
                            }
                        }

                        // Credit treasury: baseline 15% pool + pro-rata residue
                        // from the validator loop. `residue` can legitimately be 0
                        // when `validator_pool` divides evenly by total_blocks.
                        let pro_rata_residue =
                            validator_pool.saturating_sub(distributed_to_validators);
                        let treasury_emission = treasury_pool.saturating_add(pro_rata_residue);
                        let distributed_this_era = distributed_to_validators
                            .saturating_add(treasury_emission);

                        if treasury_emission > 0 {
                            use frame_support::traits::Currency;
                            let balance: <T as pallet_balances::Config>::Balance =
                                treasury_emission.try_into().unwrap_or_default();
                            let _ = pallet_balances::Pallet::<T>::deposit_creating(
                                &Self::treasury_account(),
                                balance,
                            );
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
                            "Era emission: validators={} ({} blocks), treasury={}, total={}",
                            distributed_to_validators, total_blocks,
                            treasury_emission, distributed_this_era,
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

        /// Populate Component-5 storage values on existing chains that did
        /// not run `build_genesis` (everything >= preprod v3). Idempotent:
        /// only writes when a key is missing so a re-run is a no-op.
        ///
        /// Safe to leave in place across future upgrades — after the first
        /// upgrade the three storage values are all populated and the
        /// migration short-circuits with three reads.
        fn on_runtime_upgrade() -> Weight {
            let mut writes = 0u64;
            let reads = 7u64;

            if !AttestationRewardPerSigner::<T>::exists() {
                AttestationRewardPerSigner::<T>::put(10_000_000u128);
                writes += 1;
            }
            if !EraCapBase::<T>::exists() {
                EraCapBase::<T>::put(50_000_000_000u128);
                writes += 1;
            }
            if !EraCapBaselineAttestorCount::<T>::exists() {
                EraCapBaselineAttestorCount::<T>::put(16u32);
                writes += 1;
            }
            // Component 8: seed the default bond requirement. 1K MATRA at
            // 6 decimals = 1_000_000_000 base units. Preprod can override
            // via `set_bond_requirement` after the upgrade lands.
            if !BondRequirement::<T>::exists() {
                BondRequirement::<T>::put(1_000_000_000u128);
                writes += 1;
            }
            // Component 4: seed the per-receipt submission fee + floor +
            // expiry deadline. Defaults match the brief (1 MATRA / 0.1 MATRA /
            // ~24h). Idempotent: re-running the migration after all three
            // are set short-circuits to reads-only.
            if !ReceiptSubmissionFee::<T>::exists() {
                ReceiptSubmissionFee::<T>::put(1_000_000u128);
                writes += 1;
            }
            if !ReceiptSubmissionFeeFloor::<T>::exists() {
                ReceiptSubmissionFeeFloor::<T>::put(100_000u128);
                writes += 1;
            }
            if !ReceiptExpiryBlocks::<T>::exists() {
                ReceiptExpiryBlocks::<T>::put(14_400u32);
                writes += 1;
            }

            T::DbWeight::get().reads_writes(reads, writes)
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

    // ── Component 5 + 8 helpers (no AccountId bound needed) ─────────────

    impl<T: Config> Pallet<T> {
        /// The derived attestor reserve pot account (`mat/attr`). Slashed
        /// bonds are repatriated here; the fee router also credits its
        /// 30% share to this account.
        pub fn attestor_reserve_account() -> T::AccountId {
            T::AttestorReservePotId::get().into_account_truncating()
        }

        /// The derived treasury pot account (`mat/trsy`). The 20% share of
        /// each per-receipt submission fee is credited here on threshold
        /// hit; rounding residue from the 80% signer split also ends up
        /// here rather than being burned.
        pub fn treasury_account() -> T::AccountId {
            T::TreasuryPotId::get().into_account_truncating()
        }

        /// Component 4 helper: reserve the current `ReceiptSubmissionFee`
        /// from `submitter` and populate `ReceiptFeeEscrow` +
        /// `ReceiptSubmittedAt` for the given receipt. Callers must fire
        /// `ReceiptSubmitted` separately. Returns the reserved fee amount
        /// on success.
        fn charge_submission_fee(
            submitter: &T::AccountId,
            receipt_id: H256,
        ) -> Result<u128, DispatchError> {
            let fee = ReceiptSubmissionFee::<T>::get();
            if fee > 0 {
                let balance: BalanceOf<T> = fee.try_into().unwrap_or_default();
                // Map any reserve failure (free balance < fee, or
                // ExistentialDeposit check against remaining free balance)
                // onto our own `InsufficientFee` so SDK callers get a
                // deterministic, Component-4-scoped error.
                T::Currency::reserve(submitter, balance)
                    .map_err(|_| Error::<T>::InsufficientFee)?;
            }
            ReceiptFeeEscrow::<T>::insert(receipt_id, (submitter.clone(), fee));
            ReceiptSubmittedAt::<T>::insert(
                receipt_id,
                frame_system::Pallet::<T>::block_number(),
            );
            // Emit a dedicated reservation event so auditors/explorers can
            // trace the escrow lifecycle without scraping the Balances
            // pallet's `Reserved` events (which aren't scoped to orinq).
            Self::deposit_event(Event::ReceiptFeeReserved {
                receipt_id,
                submitter: submitter.clone(),
                amount: fee,
            });
            Ok(fee)
        }

        /// Component 4 helper: distribute the escrowed fee for a freshly
        /// certified receipt. 80% pro-rata-flat to `signers`, 20% plus
        /// rounding residue to the treasury pot. No-op if the receipt has
        /// no escrow (legacy / pre-Component-4) or if `signers` is empty
        /// (defensive — threshold is always >= 1).
        ///
        /// Uses `repatriate_reserved` with `BalanceStatus::Free` to move
        /// funds directly from the submitter's reserved balance into each
        /// beneficiary's free balance, keeping the invariant that the fee
        /// is only ever in one place: submitter's reserve -> recipients.
        fn distribute_submission_fee(
            receipt_id: H256,
            signers: &BoundedBTreeSet<T::AccountId, T::MaxCommitteeSize>,
        ) {
            let (submitter, reserved_fee) = match ReceiptFeeEscrow::<T>::take(receipt_id) {
                Some(v) => v,
                None => return, // pre-Component-4 receipt — nothing to pay out
            };
            ReceiptSubmittedAt::<T>::remove(receipt_id);

            if reserved_fee == 0 || signers.is_empty() {
                // Defensive: an escrow of 0 is possible if governance set
                // the fee to 0 after submission (even though the floor
                // rule prevents <floor, an empty-fee era is still legal).
                // Unreserve anything that might somehow still be held and
                // return without firing a distributed event.
                if reserved_fee > 0 {
                    let balance: BalanceOf<T> = reserved_fee.try_into().unwrap_or_default();
                    let _ = T::Currency::unreserve(&submitter, balance);
                }
                return;
            }

            let signer_count = signers.len() as u32;
            let to_signers = reserved_fee.saturating_mul(80) / 100;
            let per_signer = to_signers / (signer_count as u128);
            let signer_paid = per_signer.saturating_mul(signer_count as u128);
            // Rounding dust from the 80% bucket is routed to treasury
            // rather than dropped/burned — per Component-4 anti-BS rules.
            let to_treasury = reserved_fee.saturating_sub(signer_paid);

            // Move each signer's flat share from submitter's reserved
            // balance into their free balance. repatriate_reserved returns
            // any un-moved remainder; we ignore it because in practice
            // the reserve is exactly `reserved_fee` (set in submit).
            if per_signer > 0 {
                for signer in signers.iter() {
                    let balance: BalanceOf<T> = per_signer.try_into().unwrap_or_default();
                    let _ = T::Currency::repatriate_reserved(
                        &submitter,
                        signer,
                        balance,
                        BalanceStatus::Free,
                    );
                }
            }

            // Remaining reserve -> treasury. This captures the 20% base
            // share plus any rounding residue from the integer-division
            // above. We use repatriate_reserved here for the same reason:
            // the invariant is that all reserved fee leaves the submitter.
            //
            // On a fresh chain the treasury pot may be "dead" (free balance
            // below ED with no providers). In that case pallet_balances'
            // `repatriate_reserved` returns `Err(DeadAccount)` rather than
            // a non-zero remainder — see `do_transfer_reserved` which
            // `ensure!(!is_new, ...)` before moving funds. A `Polite`
            // partial success would return `Ok(remainder)`.
            //
            // We handle both cases: map `Err` to "full amount un-moved"
            // and unreserve whatever remains on the submitter. Net effect:
            // either the treasury got its cut, or the submitter got it
            // back. The event reports what actually moved, never the
            // intended amount. Keeps the math honest for explorers that
            // sum `treasury_amount` across events.
            let mut actual_to_treasury = 0u128;
            if to_treasury > 0 {
                let treasury_acct = Self::treasury_account();
                let balance: BalanceOf<T> = to_treasury.try_into().unwrap_or_default();
                let remainder_u128: u128 = match T::Currency::repatriate_reserved(
                    &submitter,
                    &treasury_acct,
                    balance,
                    BalanceStatus::Free,
                ) {
                    Ok(remainder_bal) => remainder_bal.try_into().unwrap_or_default(),
                    // Treasury pot is dead / below ED — no funds moved.
                    // Full requested amount is still reserved on submitter.
                    Err(_) => to_treasury,
                };
                if remainder_u128 > 0 {
                    let remainder_bal: BalanceOf<T> =
                        remainder_u128.try_into().unwrap_or_default();
                    // Release the un-moved remainder back to submitter's
                    // free balance. Falling back to `unreserve` (not a
                    // retry of repatriate) because the treasury pot is
                    // demonstrably un-openable for this call; retrying
                    // would just fail again.
                    T::Currency::unreserve(&submitter, remainder_bal);
                }
                actual_to_treasury = to_treasury.saturating_sub(remainder_u128);
            }

            Self::deposit_event(Event::ReceiptFeeDistributed {
                receipt_id,
                submitter,
                total_fee: reserved_fee,
                per_signer_amount: per_signer,
                treasury_amount: actual_to_treasury,
                signer_count,
            });
        }

        /// Effective per-era cap on attestation rewards.
        ///
        /// Formula: `era_cap_base * active_attestor_count / baseline`.
        /// When `active_attestor_count == baseline`, the effective cap
        /// equals the base. Scales linearly up (more attestors = more
        /// capacity) or down (fewer attestors = less capacity, including
        /// zero when the committee is empty).
        ///
        /// Uses `saturating_mul` to prevent overflow and relies on the
        /// extrinsic that sets `EraCapBaselineAttestorCount` to reject
        /// zero (see `InvalidBaseline`). If somehow zero leaks in, we
        /// fall back to the base cap so rewards aren't silently disabled
        /// by a governance-config bug.
        pub fn effective_era_cap() -> u128 {
            let base = EraCapBase::<T>::get();
            // NOTE: BoundedBTreeSet does not implement `decode_len`, so we
            // have to decode the whole set to count it. This is O(n) in the
            // committee size, but n is bounded by MaxCommitteeSize (typically
            // small), so the cost is acceptable for a helper that's only
            // called inside `set_availability_cert` on threshold hit.
            let active = CommitteeMembers::<T>::get().len() as u128;
            let baseline = EraCapBaselineAttestorCount::<T>::get() as u128;
            if baseline == 0 {
                return base;
            }
            base.saturating_mul(active) / baseline
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

            // Component 4: reserve the per-receipt submission fee from the
            // submitter BEFORE mutating any receipt storage. On failure the
            // whole extrinsic unwinds so no orphan state is left behind.
            Self::charge_submission_fee(&submitter, receipt_id)?;

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
        ///
        /// Component-4 invariant: if the receipt has an open fee escrow,
        /// the root override has no actual signers to reward — so the
        /// cleanest policy is to refund the submitter in full and clear
        /// the escrow storage. Without this, the reserved balance would
        /// be stranded forever: `expire_receipt_fee` rejects certified
        /// receipts with `ReceiptAlreadyCertified`, and no other code path
        /// drains `ReceiptFeeEscrow`. Mirrors the expire-refund event for
        /// auditability.
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

            // Refund any open escrow to the submitter. Legacy (pre-Component-4)
            // receipts have no escrow entry and this is a silent no-op —
            // preserving the prior behaviour for any stale data on-chain.
            if let Some((submitter, amount_u128)) = ReceiptFeeEscrow::<T>::take(&receipt_id) {
                if amount_u128 > 0 {
                    let amount_bal: BalanceOf<T> =
                        amount_u128.try_into().unwrap_or_default();
                    let _ = T::Currency::unreserve(&submitter, amount_bal);
                }
                Self::deposit_event(Event::ReceiptFeeRefunded {
                    receipt_id,
                    submitter,
                    amount: amount_u128,
                });
            }
            ReceiptSubmittedAt::<T>::remove(&receipt_id);

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
                //
                // The per-signer reward and the per-era cap are now
                // governance-tunable via `set_attestation_reward_per_signer`
                // and `set_era_cap_base` (see Component 5). The effective
                // cap auto-scales linearly with active committee size via
                // `effective_era_cap()`. ATTESTATION_RESERVE remains a
                // constant — it is the 4-year pool ceiling, not a per-era
                // knob, and resizing it is a conscious economic decision
                // that belongs to a runtime upgrade.
                const ATTESTATION_RESERVE: u128 = 50_000_000_000_000; // 50M MATRA (6 decimals)
                let reward_per_signer = AttestationRewardPerSigner::<T>::get();
                let era_cap = Self::effective_era_cap();

                let total_att_paid = TotalAttestationRewards::<T>::get();
                let era_att_paid = AttestationRewardsPaidInEra::<T>::get();
                if total_att_paid < ATTESTATION_RESERVE && era_att_paid < era_cap {
                    // Get signers before we remove the attestation
                    if let Some((_, ref signers)) = Attestations::<T>::get(receipt_id) {
                        for signer in signers.iter() {
                            // Re-check era cap inside loop (multiple signers per cert)
                            let current_era_paid = AttestationRewardsPaidInEra::<T>::get();
                            if current_era_paid >= era_cap {
                                break;
                            }
                            let reward = reward_per_signer;
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

                // Component 4: distribute the escrowed submission fee to
                // the actual signers and the treasury pot BEFORE removing
                // the attestation record (we need the signer set).
                if let Some((_, ref signers)) = Attestations::<T>::get(receipt_id) {
                    Self::distribute_submission_fee(receipt_id, signers);
                }

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
        ///
        /// REMOVED in spec-210 (2026-04-28) per wedge audit W-1. This extrinsic
        /// directly mutated the GRANDPA authority set, bypassing the partner-
        /// chain session pallet, and desynced `Grandpa::CurrentSetId` from
        /// `Grandpa::SetIdSession`. Every prior use triggered a forced-change
        /// loop firing every ~18s and finality stalled — see
        /// `feedback_rotate_authorities_wedge.md`. Authority rotation now
        /// flows EXCLUSIVELY through Cardano permissioned_candidates (the
        /// proper IOG path). Any operator reaching for emergency rotation
        /// should instead call `partner-chains-node smart-contracts
        /// upsert-permissioned-candidates` against Cardano.
        ///
        /// call_index(5) is intentionally left unused — DO NOT REUSE for
        /// future extrinsics, since clients may have cached the old encoding
        /// and would silently dispatch the wrong call.

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

            // Component 4: same fee charge as submit_receipt. submit_receipt_v2
            // is the studio-pays-fees-with-player-signed-receipt path and
            // the fee flow must be identical.
            Self::charge_submission_fee(&submitter, receipt_id)?;

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

            // Component 8: require a bond at or above BondRequirement.
            // BondRequirement == 0 intentionally permits joins without a
            // bond (preprod bootstrap / upgrade grace window).
            let required = BondRequirement::<T>::get();
            if required > 0 {
                let posted = AttestorBonds::<T>::get(&who);
                ensure!(posted >= required, Error::<T>::InsufficientBond);
            }

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

        // ── Component 5: governance setters for dynamic reward config ────

        /// Update the per-signer attestation reward. Root-only. Takes effect
        /// immediately; future certifications pay out at the new rate.
        #[pallet::call_index(9)]
        #[pallet::weight(Weight::from_parts(10_000, 0)
            .saturating_add(T::DbWeight::get().writes(1)))]
        pub fn set_attestation_reward_per_signer(
            origin: OriginFor<T>,
            value: u128,
        ) -> DispatchResult {
            ensure_root(origin)?;
            AttestationRewardPerSigner::<T>::put(value);
            Self::deposit_event(Event::AttestationRewardPerSignerUpdated { new_value: value });
            Ok(())
        }

        /// Update the base per-era attestation-reward cap. Root-only. The
        /// effective cap auto-scales via `effective_era_cap()`; callers
        /// should pass the cap value that would apply at
        /// `baseline_attestor_count` exactly.
        #[pallet::call_index(10)]
        #[pallet::weight(Weight::from_parts(10_000, 0)
            .saturating_add(T::DbWeight::get().writes(1)))]
        pub fn set_era_cap_base(origin: OriginFor<T>, value: u128) -> DispatchResult {
            ensure_root(origin)?;
            EraCapBase::<T>::put(value);
            Self::deposit_event(Event::EraCapBaseUpdated { new_value: value });
            Ok(())
        }

        /// Update the baseline attestor count used as the denominator in
        /// `effective_era_cap()`. Must be non-zero (rejected otherwise with
        /// `InvalidBaseline`). Root-only.
        #[pallet::call_index(11)]
        #[pallet::weight(Weight::from_parts(10_000, 0)
            .saturating_add(T::DbWeight::get().writes(1)))]
        pub fn set_era_cap_baseline_attestor_count(
            origin: OriginFor<T>,
            value: u32,
        ) -> DispatchResult {
            ensure_root(origin)?;
            ensure!(value > 0, Error::<T>::InvalidBaseline);
            EraCapBaselineAttestorCount::<T>::put(value);
            Self::deposit_event(Event::EraCapBaselineAttestorCountUpdated { new_value: value });
            Ok(())
        }

        // ── Component 8: attestor bond + slashing ────────────────────────

        /// Lock `amount` of MATRA as an attestor bond.
        ///
        /// Reserves the amount via `T::Currency::reserve`, which fails with
        /// `pallet_balances::Error::InsufficientBalance` if free balance is
        /// too low. Calling `bond` multiple times extends the existing
        /// reservation — bond totals accumulate, they do not clobber.
        ///
        /// The bond is required to join the committee (see `join_committee`).
        /// It can be withdrawn via `unbond` when the attestor is not in the
        /// committee.
        #[pallet::call_index(12)]
        #[pallet::weight(Weight::from_parts(20_000, 0)
            .saturating_add(T::DbWeight::get().reads(1))
            .saturating_add(T::DbWeight::get().writes(2)))]
        pub fn bond(origin: OriginFor<T>, amount: u128) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // Reserve the amount; propagates balances::Error::InsufficientBalance
            // on failure. `try_into` here collapses u128 into Currency::Balance
            // (which is u128 on Materios but kept generic for portability).
            // If the pallet's Currency::Balance is narrower than u128 and
            // `amount` overflows, we default to 0 and the reserve call below
            // will simply succeed as a no-op — the bookkeeping below records
            // 0, keeping the extrinsic infallible rather than panicking.
            let balance: BalanceOf<T> = amount.try_into().unwrap_or_default();

            // W-15 fix (spec-210, 2026-04-28): explicit dust check BEFORE
            // calling reserve(). Without this, when the caller's free balance
            // == BondRequirement exactly, reserve()'s post-condition would
            // leave free=0 < ExistentialDeposit (500 base), and `pallet_balances`
            // refuses the reserve. Crucially that refusal happens at mempool
            // pre-validation, so the tx is silently DROPPED rather than landing
            // with an error event — the daemon's `wait_for_inclusion` returns
            // is_success=False with error_message=None, and auto-bond loops
            // forever burning MOTRA. Surfacing as a pallet error means the
            // tx now lands with ExtrinsicFailed{Error::BondLeavesAccountDusty}
            // and the daemon's catch path can react. See
            // `feedback_bond_dust_bug.md` for the operator-rescue history.
            //
            // Currency import follows existing inline-import pattern (cf.
            // lines 736, 763, 1305 in this same file).
            //
            // Dust check ONLY fires when `balance <= free` — otherwise we
            // skip and let `reserve()` return the more-specific
            // `InsufficientBalance` error. This keeps the existing test
            // `bond_rejects_insufficient_balance` semantics intact.
            use frame_support::traits::Currency;
            let free = T::Currency::free_balance(&who);
            let ed = T::Currency::minimum_balance();
            if free >= balance {
                let post_reserve = free.saturating_sub(balance);
                ensure!(
                    post_reserve >= ed,
                    Error::<T>::BondLeavesAccountDusty
                );
            }

            T::Currency::reserve(&who, balance)?;

            let new_total = AttestorBonds::<T>::mutate(&who, |total| {
                *total = total.saturating_add(amount);
                *total
            });

            Self::deposit_event(Event::Bonded {
                who,
                amount,
                new_total,
            });
            Ok(())
        }

        /// Withdraw the entire bond. Fails if the caller is still a
        /// committee member — call `leave_committee` first.
        #[pallet::call_index(13)]
        #[pallet::weight(Weight::from_parts(20_000, 0)
            .saturating_add(T::DbWeight::get().reads(2))
            .saturating_add(T::DbWeight::get().writes(2)))]
        pub fn unbond(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;

            ensure!(
                !CommitteeMembers::<T>::get().contains(&who),
                Error::<T>::StillInCommittee
            );

            let bonded = AttestorBonds::<T>::get(&who);
            ensure!(bonded > 0, Error::<T>::NothingToUnbond);

            let balance: BalanceOf<T> = bonded.try_into().unwrap_or_default();
            // `unreserve` returns any remainder it couldn't unreserve; we
            // ignore it because the stored `bonded` is our own accounting
            // and we just cleared it.
            let _ = T::Currency::unreserve(&who, balance);
            AttestorBonds::<T>::remove(&who);

            Self::deposit_event(Event::Unbonded { who, amount: bonded });
            Ok(())
        }

        /// Root-only: slash `amount` from `attestor`'s bond, repatriating
        /// the funds to the attestor reserve pot (NOT burning). If the
        /// post-slash bond drops below `BondRequirement`, the attestor is
        /// automatically ejected from the committee.
        ///
        /// Uses `repatriate_reserved` instead of `slash` by design — we
        /// want MATRA to accumulate in `mat/attr` for future reward
        /// payouts, not to shrink total issuance.
        #[pallet::call_index(14)]
        #[pallet::weight(Weight::from_parts(30_000, 0)
            .saturating_add(T::DbWeight::get().reads(3))
            .saturating_add(T::DbWeight::get().writes(3)))]
        pub fn slash_attestor(
            origin: OriginFor<T>,
            attestor: T::AccountId,
            amount: u128,
            reason: SlashReason,
        ) -> DispatchResult {
            ensure_root(origin)?;

            let current_bond = AttestorBonds::<T>::get(&attestor);
            // Cap the slash at the actual bonded amount so repatriate_reserved
            // can never ask for more than has been reserved.
            let slash_amount = core::cmp::min(amount, current_bond);

            if slash_amount > 0 {
                let reserve_acct = Self::attestor_reserve_account();
                let balance: BalanceOf<T> = slash_amount.try_into().unwrap_or_default();
                // `repatriate_reserved` returns any amount it could not move
                // (e.g. if the reserve pot account doesn't pass the ED check
                // as the beneficiary). We do not propagate this — the caller
                // is Root and the reserve pot is a known runtime-fixed
                // account, so any shortfall is an infrastructure bug rather
                // than a user-facing error.
                let _ = T::Currency::repatriate_reserved(
                    &attestor,
                    &reserve_acct,
                    balance,
                    BalanceStatus::Free,
                )?;

                AttestorBonds::<T>::mutate(&attestor, |total| {
                    *total = total.saturating_sub(slash_amount);
                });
            }

            let remaining_bond = AttestorBonds::<T>::get(&attestor);

            Self::deposit_event(Event::Slashed {
                who: attestor.clone(),
                amount: slash_amount,
                reason,
                remaining_bond,
            });

            // Auto-eject if the remaining bond is below the requirement
            // AND the attestor is currently in the committee.
            let required = BondRequirement::<T>::get();
            if remaining_bond < required {
                let was_member = CommitteeMembers::<T>::mutate(|set| {
                    let was = set.contains(&attestor);
                    if was {
                        set.remove(&attestor);
                    }
                    was
                });
                if was_member {
                    Self::deposit_event(Event::AutoEjected {
                        who: attestor,
                        remaining_bond,
                    });
                }
            }

            Ok(())
        }

        /// Update the minimum bond required to join the committee.
        /// Root-only. Takes effect immediately; new joins must meet the
        /// new requirement, but existing members are NOT retroactively
        /// ejected (prevents a governance key from booting the committee
        /// by raising the bar).
        #[pallet::call_index(15)]
        #[pallet::weight(Weight::from_parts(10_000, 0)
            .saturating_add(T::DbWeight::get().writes(1)))]
        pub fn set_bond_requirement(
            origin: OriginFor<T>,
            value: u128,
        ) -> DispatchResult {
            ensure_root(origin)?;
            // W-12 fix (spec-210, 2026-04-28): defensive floor. A sudo dispatch
            // that accidentally sets BondRequirement = 0 (or near-0) would
            // let new joiners bond(0) and pass join_committee with no real
            // stake — Sybil flood. 100 MATRA is the conservative floor:
            // high enough to require meaningful stake, low enough to never
            // legitimately need to be undercut. Existing bonds are unaffected
            // by this check (only the new-requirement value matters).
            const MIN_VIABLE_BOND: u128 = 100_000_000; // 100 MATRA at 6-dec
            ensure!(
                value >= MIN_VIABLE_BOND,
                Error::<T>::BondRequirementTooLow
            );
            BondRequirement::<T>::put(value);
            Self::deposit_event(Event::BondRequirementUpdated { new_value: value });
            Ok(())
        }

        // ── Component 4: per-receipt submission fee governance ───────────

        /// Update the per-receipt submission fee. Root-only. The new value
        /// must be at or above `ReceiptSubmissionFeeFloor`; otherwise
        /// rejected with `FeeBelowFloor`.
        #[pallet::call_index(16)]
        #[pallet::weight(Weight::from_parts(10_000, 0)
            .saturating_add(T::DbWeight::get().reads(1))
            .saturating_add(T::DbWeight::get().writes(1)))]
        pub fn set_receipt_submission_fee(
            origin: OriginFor<T>,
            value: u128,
        ) -> DispatchResult {
            ensure_root(origin)?;
            let floor = ReceiptSubmissionFeeFloor::<T>::get();
            ensure!(value >= floor, Error::<T>::FeeBelowFloor);
            ReceiptSubmissionFee::<T>::put(value);
            Self::deposit_event(Event::ReceiptSubmissionFeeUpdated { new_value: value });
            Ok(())
        }

        /// Update the minimum allowed value of `ReceiptSubmissionFee`.
        /// Root-only. Does NOT retroactively invalidate an already-set fee
        /// that falls below the new floor — only future `set_receipt_submission_fee`
        /// calls are gated.
        #[pallet::call_index(17)]
        #[pallet::weight(Weight::from_parts(10_000, 0)
            .saturating_add(T::DbWeight::get().writes(1)))]
        pub fn set_receipt_submission_fee_floor(
            origin: OriginFor<T>,
            value: u128,
        ) -> DispatchResult {
            ensure_root(origin)?;
            ReceiptSubmissionFeeFloor::<T>::put(value);
            Self::deposit_event(Event::ReceiptSubmissionFeeFloorUpdated { new_value: value });
            Ok(())
        }

        /// Update the expiry window (in blocks) after which an uncertified
        /// receipt's escrow can be refunded via `expire_receipt_fee`.
        /// Root-only.
        ///
        /// Rejects values below `MIN_RECEIPT_EXPIRY_BLOCKS` (10). Very low
        /// expiry windows create a grief vector: a compromised root key
        /// could set expiry=0 and race-refund receipts whose signers are
        /// mid-attestation, stealing the submitter→signer flow. See
        /// `MIN_RECEIPT_EXPIRY_BLOCKS` docs for the threat model.
        #[pallet::call_index(18)]
        #[pallet::weight(Weight::from_parts(10_000, 0)
            .saturating_add(T::DbWeight::get().writes(1)))]
        pub fn set_receipt_expiry_blocks(
            origin: OriginFor<T>,
            value: u32,
        ) -> DispatchResult {
            ensure_root(origin)?;
            ensure!(
                value >= MIN_RECEIPT_EXPIRY_BLOCKS,
                Error::<T>::ReceiptExpiryBlocksTooLow
            );
            ReceiptExpiryBlocks::<T>::put(value);
            Self::deposit_event(Event::ReceiptExpiryBlocksUpdated { new_value: value });
            Ok(())
        }

        /// Permissionless: refund the escrowed submission fee back to the
        /// submitter's free balance once the receipt has expired without
        /// reaching the attestation threshold.
        ///
        /// Fails with:
        /// * `ReceiptNotFound` — the escrow entry is absent (receipt was
        ///   never submitted, was already refunded, or predates Component 4).
        /// * `ReceiptAlreadyCertified` — the receipt's availability cert
        ///   hash is non-zero (threshold already hit; payout already ran).
        /// * `ReceiptNotExpired` — `ReceiptExpiryBlocks` have not yet
        ///   elapsed since submission.
        #[pallet::call_index(19)]
        #[pallet::weight(Weight::from_parts(25_000, 0)
            .saturating_add(T::DbWeight::get().reads(3))
            .saturating_add(T::DbWeight::get().writes(2)))]
        pub fn expire_receipt_fee(
            origin: OriginFor<T>,
            receipt_id: H256,
        ) -> DispatchResult {
            // Origin is required to be signed but has no other restriction —
            // anyone can kick the refund once the deadline has passed so
            // stuck reserves don't require submitter action.
            let _caller = ensure_signed(origin)?;

            // Defensive error ordering: verify cert-not-set BEFORE checking
            // the escrow. If the receipt was certified the escrow is already
            // drained; returning `ReceiptNotFound` in that case would be
            // misleading. Also surfaces a clear error when the submitter
            // accidentally calls expire on a cert'd receipt.
            if let Some(record) = Receipts::<T>::get(receipt_id) {
                ensure!(
                    record.availability_cert_hash == [0u8; 32],
                    Error::<T>::ReceiptAlreadyCertified
                );
            }

            // Compute the expiry deadline.
            let submitted_at = ReceiptSubmittedAt::<T>::get(receipt_id)
                .ok_or(Error::<T>::ReceiptNotFound)?;
            let expiry_blocks: BlockNumberFor<T> =
                ReceiptExpiryBlocks::<T>::get().into();
            let deadline = submitted_at.saturating_add(expiry_blocks);
            let now = frame_system::Pallet::<T>::block_number();
            ensure!(now > deadline, Error::<T>::ReceiptNotExpired);

            let (submitter, reserved_fee) = ReceiptFeeEscrow::<T>::take(receipt_id)
                .ok_or(Error::<T>::ReceiptNotFound)?;
            ReceiptSubmittedAt::<T>::remove(receipt_id);

            if reserved_fee > 0 {
                let balance: BalanceOf<T> = reserved_fee.try_into().unwrap_or_default();
                // Unreserve returns any amount it couldn't return (e.g. if
                // the reserved balance is somehow lower than the escrow
                // value). We ignore it: the stored escrow is our source of
                // truth and the event reports what we _intended_ to refund.
                let _ = T::Currency::unreserve(&submitter, balance);
            }

            Self::deposit_event(Event::ReceiptFeeRefunded {
                receipt_id,
                submitter,
                amount: reserved_fee,
            });
            Ok(())
        }
    }
}
