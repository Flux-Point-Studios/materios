#![cfg_attr(not(feature = "std"), no_std)]
// `construct_runtime!` does a lot of recursion and requires us to increase the limit.
#![recursion_limit = "256"]

extern crate alloc;

#[cfg(test)]
mod tests;

// v5.1 Midnight-style fees: the 40/30/20/10 MATRA fee-router (see
// `fee_router.rs` on main up to spec 201) is DELETED. MATRA is no longer
// charged on transactions — MOTRA is the sole tx-fee mechanism via
// `pallet_motra::fee::ChargeMotra`. The no-op adapter below replaces it.
pub mod no_op_charge;
pub mod input_sanity;
pub mod migrations;

#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

use alloc::vec::Vec;
use authority_selection_inherents::authority_selection_inputs::AuthoritySelectionInputs;
use authority_selection_inherents::select_authorities::select_authorities;
use frame_support::{
    construct_runtime, derive_impl, parameter_types,
    traits::{ConstBool, ConstU32, ConstU64, WithdrawReasons},
    weights::{
        constants::{BlockExecutionWeight, ExtrinsicBaseWeight, RocksDbWeight as RuntimeDbWeight, WEIGHT_REF_TIME_PER_SECOND},
        IdentityFee, Weight,
    },
    genesis_builder_helper::{build_state, get_preset},
    BoundedVec, PalletId,
};
use frame_system::{EnsureRoot, EnsureRootWithSuccess};
use frame_system::limits::{BlockLength, BlockWeights};
// `FungibleAdapter` is no longer used — see `no_op_charge::NoOpCharge`.
use session_manager::ValidatorManagementSessionManager;
use sidechain_domain::{
    NativeTokenAmount, ScEpochNumber, ScSlotNumber, UtxoId,
};
use sp_api::impl_runtime_apis;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
use sp_core::{crypto::KeyTypeId, OpaqueMetadata, H256};
use sp_runtime::{
    create_runtime_str,
    generic,
    traits::{
        AccountIdConversion, BlakeTwo256, Block as BlockT, ConvertInto, IdentifyAccount,
        IdentityLookup, NumberFor, OpaqueKeys, Verify,
    },
    transaction_validity::{TransactionSource, TransactionValidity},
    ApplyExtrinsicResult, DispatchResult, MultiSignature, Permill,
};
use sp_sidechain::SidechainStatus;
use sp_version::RuntimeVersion;
use sp_weights;

#[cfg(feature = "std")]
use sp_version::NativeVersion;

// Re-export pallets so they can be used in construct_runtime.
pub use frame_system;
pub use pallet_balances;
pub use pallet_motra;
pub use pallet_session_validator_management;
pub use pallet_timestamp;

// ---------------------------------------------------------------------------
// Basic types
// ---------------------------------------------------------------------------

/// An index to a block.
pub type BlockNumber = u32;

/// Alias to 512-bit hash when used in the context of a transaction signature on the chain.
pub type Signature = MultiSignature;

/// Identifies an account on the chain.
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

/// Balance of an account.
pub type Balance = u128;

/// Nonce of a transaction in the chain.
pub type Nonce = u32;

/// A hash of some data.
pub type Hash = H256;

/// Opaque types for the node.
pub mod opaque {
    use super::*;
    use parity_scale_codec::MaxEncodedLen;
    use sp_core::{ed25519, sr25519};
    pub use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;

    /// Opaque block header type.
    pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
    /// Opaque block type.
    pub type Block = generic::Block<Header, UncheckedExtrinsic>;
    /// Opaque block identifier type.
    pub type BlockId = generic::BlockId<Block>;

    pub const CROSS_CHAIN: KeyTypeId = KeyTypeId(*b"crch");
    pub struct CrossChainRuntimeAppPublic;

    pub mod cross_chain_app {
        use super::CROSS_CHAIN;
        use parity_scale_codec::MaxEncodedLen;
        use sidechain_domain::SidechainPublicKey;
        use sp_core::crypto::AccountId32;
        use sp_runtime::app_crypto::{app_crypto, ecdsa};
        use sp_runtime::traits::IdentifyAccount;
        use sp_runtime::MultiSigner;
        use sp_std::vec::Vec;

        app_crypto!(ecdsa, CROSS_CHAIN);
        impl MaxEncodedLen for Signature {
            fn max_encoded_len() -> usize {
                ecdsa::Signature::max_encoded_len()
            }
        }

        impl From<Signature> for Vec<u8> {
            fn from(value: Signature) -> Self {
                value.into_inner().0.to_vec()
            }
        }

        impl From<Public> for AccountId32 {
            fn from(value: Public) -> Self {
                MultiSigner::from(ecdsa::Public::from(value)).into_account()
            }
        }

        impl From<Public> for Vec<u8> {
            fn from(value: Public) -> Self {
                value.into_inner().0.to_vec()
            }
        }

        impl TryFrom<SidechainPublicKey> for Public {
            type Error = SidechainPublicKey;
            fn try_from(pubkey: SidechainPublicKey) -> Result<Self, Self::Error> {
                let cross_chain_public_key =
                    Public::try_from(pubkey.0.as_slice()).map_err(|_| pubkey)?;
                Ok(cross_chain_public_key)
            }
        }
    }

    sp_runtime::impl_opaque_keys! {
        #[derive(MaxEncodedLen, PartialOrd, Ord)]
        pub struct SessionKeys {
            pub aura: Aura,
            pub grandpa: Grandpa,
        }
    }
    impl From<(sr25519::Public, ed25519::Public)> for SessionKeys {
        fn from((aura, grandpa): (sr25519::Public, ed25519::Public)) -> Self {
            Self { aura: aura.into(), grandpa: grandpa.into() }
        }
    }

    sp_runtime::impl_opaque_keys! {
        pub struct CrossChainKey {
            pub account: CrossChainPublic,
        }
    }
}

pub type CrossChainPublic = opaque::cross_chain_app::Public;
use opaque::SessionKeys;

// ---------------------------------------------------------------------------
// Runtime version
// ---------------------------------------------------------------------------

#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: create_runtime_str!("materios"),
    impl_name: create_runtime_str!("materios-node"),
    authoring_version: 1,
    // 202 = v5.1 Midnight-style fees (MATRA no longer charged, MOTRA-only;
    //        85/15 validator/treasury emission split; one-shot sweep of
    //        residual mat/auth + mat/attr balances into mat/trsy, 2026-04-21).
    spec_version: 202,
    impl_version: 1,
    apis: RUNTIME_API_VERSIONS,
    transaction_version: 1,
    state_version: 1,
};

/// The version information used to identify this runtime when compiled natively.
#[cfg(feature = "std")]
pub fn native_version() -> NativeVersion {
    NativeVersion {
        runtime_version: VERSION,
        can_author_with: Default::default(),
    }
}

// ---------------------------------------------------------------------------
// Parameter types / constants
// ---------------------------------------------------------------------------

const NORMAL_DISPATCH_RATIO: sp_runtime::Perbill = sp_runtime::Perbill::from_percent(75);

// Maximum block weight: 2 seconds of compute with 75% normal dispatch.
parameter_types! {
    pub const BlockHashCount: BlockNumber = 2400;
    pub const Version: RuntimeVersion = VERSION;
    pub RuntimeBlockLength: BlockLength =
        BlockLength::max_with_normal_ratio(5 * 1024 * 1024, NORMAL_DISPATCH_RATIO);
    pub RuntimeBlockWeights: BlockWeights = BlockWeights::builder()
        .base_block(BlockExecutionWeight::get())
        .for_class(frame_support::dispatch::DispatchClass::all(), |weights| {
            weights.base_extrinsic = ExtrinsicBaseWeight::get();
        })
        .for_class(frame_support::dispatch::DispatchClass::Normal, |weights| {
            weights.max_total = Some(NORMAL_DISPATCH_RATIO * Weight::from_parts(
                2u64 * WEIGHT_REF_TIME_PER_SECOND,
                u64::MAX,
            ));
        })
        .for_class(frame_support::dispatch::DispatchClass::Operational, |weights| {
            weights.max_total = Some(Weight::from_parts(
                2u64 * WEIGHT_REF_TIME_PER_SECOND,
                u64::MAX,
            ));
        })
        .build_or_panic();
}

// ---------------------------------------------------------------------------
// Frame system
// ---------------------------------------------------------------------------

#[derive_impl(frame_system::config_preludes::SolochainDefaultConfig)]
impl frame_system::Config for Runtime {
    type Block = Block;
    type BlockWeights = RuntimeBlockWeights;
    type BlockLength = RuntimeBlockLength;
    type BlockHashCount = BlockHashCount;
    type Nonce = Nonce;
    type Hash = Hash;
    type AccountId = AccountId;
    type AccountData = pallet_balances::AccountData<Balance>;
    type Version = Version;
}

// ---------------------------------------------------------------------------
// Timestamp
// ---------------------------------------------------------------------------

parameter_types! {
    pub const MinimumPeriod: u64 = 3_000; // 6 s block time => 3 s minimum period
}

impl pallet_timestamp::Config for Runtime {
    type Moment = u64;
    type OnTimestampSet = Aura;
    type MinimumPeriod = MinimumPeriod;
    type WeightInfo = ();
}

// ---------------------------------------------------------------------------
// Aura
// ---------------------------------------------------------------------------

/// Block time: 6 seconds.
pub const MILLISECS_PER_BLOCK: u64 = 6000;
pub const SLOT_DURATION: u64 = MILLISECS_PER_BLOCK;

impl pallet_aura::Config for Runtime {
    type AuthorityId = AuraId;
    type DisabledValidators = ();
    type MaxAuthorities = MaxValidators;
    type AllowMultipleBlocksPerSlot = ConstBool<false>;
    type SlotDuration = ConstU64<SLOT_DURATION>;
}

// ---------------------------------------------------------------------------
// Grandpa
// ---------------------------------------------------------------------------

impl pallet_grandpa::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = ();
    type MaxAuthorities = MaxValidators;
    type MaxNominators = ConstU32<0>;
    type MaxSetIdSessionEntries = ConstU64<0>;
    type KeyOwnerProof = sp_core::Void;
    type EquivocationReportSystem = ();
}

// ---------------------------------------------------------------------------
// Balances
// ---------------------------------------------------------------------------

parameter_types! {
    pub const ExistentialDeposit: Balance = 500;
}

impl pallet_balances::Config for Runtime {
    type MaxLocks = ConstU32<50>;
    type MaxReserves = ConstU32<50>;
    type ReserveIdentifier = [u8; 8];
    type Balance = Balance;
    type RuntimeEvent = RuntimeEvent;
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = pallet_balances::weights::SubstrateWeight<Runtime>;
    type FreezeIdentifier = ();
    type MaxFreezes = ConstU32<0>;
    type RuntimeHoldReason = RuntimeHoldReason;
    type RuntimeFreezeReason = RuntimeFreezeReason;
}

// ---------------------------------------------------------------------------
// Transaction payment
// ---------------------------------------------------------------------------

impl pallet_transaction_payment::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    // v5.1 Midnight-style fees (spec 202, 2026-04-21): MATRA is not charged
    // on transactions. MOTRA is the sole tx-fee via
    // `pallet_motra::fee::ChargeMotra` in `SignedExtra`. `NoOpCharge` makes
    // `withdraw_fee` / `correct_and_deposit_fee` zero-effect, so MATRA
    // total_issuance is conserved. `WeightToFee` / `LengthToFee` still
    // compute nominal figures for the RPC surface (wallets call them).
    type OnChargeTransaction = no_op_charge::NoOpCharge<Balances>;
    type OperationalFeeMultiplier = ConstU8<5>;
    type WeightToFee = IdentityFee<Balance>;
    type LengthToFee = IdentityFee<Balance>;
    type FeeMultiplierUpdate = ();
}

use frame_support::traits::ConstU8;

// ---------------------------------------------------------------------------
// v5.1 tokenomics: Treasury
// ---------------------------------------------------------------------------
//
// Canonical PalletId for the Materios treasury account. Changing this value
// reroutes the 20% fee share and breaks on-chain governance — do NOT change
// once the runtime ships. See `feedback_chain_reset_runbook.md`.
parameter_types! {
    pub const TreasuryPalletId: PalletId = PalletId(*b"mat/trsy");
    /// Governance SpendPeriod — how often queued approvals are paid out.
    ///
    /// 7 days @ 6s blocks = 100_800 blocks. Tests re-export this as
    /// `SPEND_PERIOD_BLOCKS`; mainnet governance should review at every
    /// runtime upgrade.
    pub const SpendPeriod: BlockNumber = 100_800;
    /// Mainnet-safe burn fraction. Set to 0% to avoid surprising fund loss
    /// on idle SpendPeriod ticks; the 10% fee-router burn is the sole burn
    /// path. Can be raised by governance via `set_code`.
    pub const TreasuryBurn: Permill = Permill::from_percent(0);
    pub const MaxApprovals: u32 = 100;
    /// Upper bound on a single `spend_local` approval. Even Root cannot
    /// approve more than this in one call — a mainnet-safety rail.
    pub const MaxSpend: Balance = 1_000_000_000_000_000; // 1e15 base units (~1B MATRA @ 6 dec)
    pub const PayoutPeriod: BlockNumber = 30 * DAYS;
}

// Re-export for tests: `run_to_block(SPEND_PERIOD_BLOCKS + 1)` must tick past
// the period to trigger payout. Using the `Get` value keeps tests in sync
// with the production constant.
pub const SPEND_PERIOD_BLOCKS: BlockNumber = 100_800;

/// Convenience alias for the treasury account ID (derived from TreasuryPalletId).
pub fn treasury_account() -> AccountId {
    TreasuryPalletId::get().into_account_truncating()
}

pub const DAYS: BlockNumber = 24 * 60 * 60 * 1000 / (MILLISECS_PER_BLOCK as BlockNumber);

impl pallet_treasury::Config for Runtime {
    type PalletId = TreasuryPalletId;
    type Currency = Balances;
    // Root (via sudo or the multisig) is the only path to reject proposals.
    type RejectOrigin = EnsureRoot<AccountId>;
    type RuntimeEvent = RuntimeEvent;
    type SpendPeriod = SpendPeriod;
    type Burn = TreasuryBurn;
    // Burn path: when Burn>0, unbalanced imbalance is dropped (= burned) by ().
    type BurnDestination = ();
    // No bounties pallet integrated; SpendFunds is a no-op handler.
    type SpendFunds = ();
    type WeightInfo = pallet_treasury::weights::SubstrateWeight<Runtime>;
    type MaxApprovals = MaxApprovals;
    // SpendOrigin caps individual spend_local amounts at MaxSpend even when
    // Root is used, as a mainnet safety rail.
    type SpendOrigin = EnsureRootWithSuccess<AccountId, MaxSpend>;
    // This runtime has no Assets pallet; native-only treasury.
    type AssetKind = ();
    type Beneficiary = AccountId;
    type BeneficiaryLookup = IdentityLookup<Self::Beneficiary>;
    type Paymaster = frame_support::traits::tokens::PayFromAccount<Balances, TreasuryAccountSource>;
    type BalanceConverter = frame_support::traits::tokens::UnityAssetBalanceConversion;
    type PayoutPeriod = PayoutPeriod;
    #[cfg(feature = "runtime-benchmarks")]
    type BenchmarkHelper = ();
}

// `PayFromAccount` takes a `TypedGet<Type = AccountId>` (not a PalletId). We
// use `parameter_types!` which implements both `Get` and `TypedGet` so the
// treasury paymaster's constraint is satisfied.
parameter_types! {
    pub TreasuryAccountSource: AccountId = TreasuryPalletId::get().into_account_truncating();
}

// ---------------------------------------------------------------------------
// v5.1 tokenomics: Fee router (40/30/20/10)
// ---------------------------------------------------------------------------
//
// The reserve account for the attestor slashing pallet (Component 8). Until
// Component 8 lands, the 30% share accumulates on this PalletId-derived
// account, where governance can drain it via `Sudo::sudo_as`.
parameter_types! {
    pub const AttestorReservePalletId: PalletId = PalletId(*b"mat/attr");
}

pub fn attestor_reserve_account() -> AccountId {
    AttestorReservePalletId::get().into_account_truncating()
}

// ---------------------------------------------------------------------------
// v5.1 tokenomics: Vesting
// ---------------------------------------------------------------------------

parameter_types! {
    /// Minimum amount for a `vested_transfer` to be accepted. Prevents lock
    /// spam / dust attacks on accounts. 1 MATRA (6 dec) == 1_000_000.
    pub const MinVestedTransfer: Balance = 1_000_000;
    /// Even while vested, accounts can still pay tx fees and reserve funds
    /// for multisig/governance operations; only `TRANSFER` and `RESERVE` are
    /// blocked by the lock.
    pub UnvestedFundsAllowedWithdrawReasons: WithdrawReasons =
        WithdrawReasons::except(WithdrawReasons::TRANSFER | WithdrawReasons::RESERVE);
}

impl pallet_vesting::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type BlockNumberToBalance = ConvertInto;
    type MinVestedTransfer = MinVestedTransfer;
    type WeightInfo = pallet_vesting::weights::SubstrateWeight<Runtime>;
    type UnvestedFundsAllowedWithdrawReasons = UnvestedFundsAllowedWithdrawReasons;
    type BlockNumberProvider = System;
    // 28 distinct schedules per account is the standard Polkadot value;
    // gives room for Strategic+Investor+Team+Advisor+community schedules.
    const MAX_VESTING_SCHEDULES: u32 = 28;
}

// ---------------------------------------------------------------------------
// Sudo
// ---------------------------------------------------------------------------

impl pallet_sudo::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type WeightInfo = pallet_sudo::weights::SubstrateWeight<Runtime>;
}

// ---------------------------------------------------------------------------
// Multisig
// ---------------------------------------------------------------------------

parameter_types! {
    pub const DepositBase: Balance = 1_000;        // ~2x ExistentialDeposit
    pub const DepositFactor: Balance = 500;         // per additional signatory
}

impl pallet_multisig::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type Currency = Balances;
    type DepositBase = DepositBase;
    type DepositFactor = DepositFactor;
    type MaxSignatories = ConstU32<10>;
    type WeightInfo = pallet_multisig::weights::SubstrateWeight<Runtime>;
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

impl pallet_utility::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type PalletsOrigin = OriginCaller;
    type WeightInfo = pallet_utility::weights::SubstrateWeight<Runtime>;
}

// ---------------------------------------------------------------------------
// Orinq Receipts
// ---------------------------------------------------------------------------

impl pallet_orinq_receipts::pallet::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = pallet_orinq_receipts::weights::SubstrateWeight;
    type MaxResubmits = ConstU32<64>;
    type MaxCommitteeSize = ConstU32<16>;
    // Component 8: attestor bonds are held as reserved MATRA on Balances.
    type Currency = Balances;
    // Slashed bonds repatriate to the attestor reserve pot (`mat/attr`),
    // the same PalletId the fee router's 30% share credits to, so the
    // reserve pot funds accumulate from both sources.
    type AttestorReservePotId = AttestorReservePalletId;
    // Component 4: the 20% share of the per-receipt submission fee (plus
    // any rounding residue from the 80% signer split) is routed here.
    // `TreasuryPalletId` already exists for `pallet_treasury`; reusing it
    // keeps the treasury pot as a single canonical account.
    type TreasuryPotId = TreasuryPalletId;
}

// ---------------------------------------------------------------------------
// MOTRA (capacity token)
// ---------------------------------------------------------------------------

impl pallet_motra::pallet::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = pallet_motra::weights::SubstrateWeight;
}

// ---------------------------------------------------------------------------
// IOG Partner Chains: Sidechain
// ---------------------------------------------------------------------------

impl pallet_sidechain::Config for Runtime {
    fn current_slot_number() -> ScSlotNumber {
        ScSlotNumber(*pallet_aura::CurrentSlot::<Self>::get())
    }
    type OnNewEpoch = LogBeneficiaries;
}

pub struct LogBeneficiaries;
impl sp_sidechain::OnNewEpoch for LogBeneficiaries {
    fn on_new_epoch(old_epoch: ScEpochNumber, _new_epoch: ScEpochNumber) -> sp_weights::Weight {
        let rewards = BlockRewards::get_rewards_and_clear();
        log::info!("Rewards accrued in epoch {old_epoch}: {rewards:?}");
        RuntimeDbWeight::get().reads_writes(1, 1)
    }
}

// ---------------------------------------------------------------------------
// IOG Partner Chains: Block Rewards
// ---------------------------------------------------------------------------

pub type BeneficiaryId = sidechain_domain::byte_string::SizedByteString<32>;

impl pallet_block_rewards::Config for Runtime {
    type BeneficiaryId = BeneficiaryId;
    type BlockRewardPoints = u32;
    type GetBlockRewardPoints = sp_block_rewards::SimpleBlockCount;
}

// ---------------------------------------------------------------------------
// IOG Partner Chains: Session Validator Management
// ---------------------------------------------------------------------------

/// Shared upper bound on committee size. Referenced by the session pallet's
/// `MaxValidators` AND by `input_sanity::MAX_COMMITTEE_SIZE`. Changing this
/// value is load-bearing — the sanity layer has a compile-time assertion
/// that its own constant equals this one, so bumping it here keeps the two
/// in lockstep automatically.
pub const MAX_VALIDATORS: u32 = 32;

parameter_types! {
    pub const MaxValidators: u32 = MAX_VALIDATORS;
}

impl pallet_session_validator_management::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type MaxValidators = MaxValidators;
    type AuthorityId = CrossChainPublic;
    type AuthorityKeys = SessionKeys;
    type AuthoritySelectionInputs = AuthoritySelectionInputs;
    type ScEpochNumber = ScEpochNumber;
    type WeightInfo = pallet_session_validator_management::weights::SubstrateWeight<Runtime>;

    fn select_authorities(
        input: AuthoritySelectionInputs,
        sidechain_epoch: ScEpochNumber,
    ) -> Option<BoundedVec<(Self::AuthorityId, Self::AuthorityKeys), Self::MaxValidators>> {
        // Security hardening: before D<1.0 the registered-candidates list
        // is untrusted db-sync output. Filter out duplicate keys, cap list
        // sizes, and reject whole-input invariant violations. See
        // `docs/d-param-sanity-checks-design.md`.
        let sanitized = match input_sanity::sanitize_and_log(input) {
            Ok(cleaned) => cleaned,
            Err(_) => return None,
        };
        select_authorities(Sidechain::genesis_utxo(), sanitized, sidechain_epoch)
    }

    fn current_epoch_number() -> ScEpochNumber {
        Sidechain::current_epoch_number()
    }
}

// ---------------------------------------------------------------------------
// IOG Partner Chains: Partner Chains Session
// ---------------------------------------------------------------------------

impl pallet_partner_chains_session::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type ValidatorId = <Self as frame_system::Config>::AccountId;
    type ShouldEndSession = ValidatorManagementSessionManager<Runtime>;
    type NextSessionRotation = ();
    type SessionManager = ValidatorManagementSessionManager<Runtime>;
    type SessionHandler = <opaque::SessionKeys as OpaqueKeys>::KeyTypeIdProviders;
    type Keys = opaque::SessionKeys;
}

// ---------------------------------------------------------------------------
// IOG Partner Chains: pallet-session stub (required by pallet-grandpa)
// ---------------------------------------------------------------------------

pallet_session_runtime_stub::impl_pallet_session_config!(Runtime);

// ---------------------------------------------------------------------------
// IOG Partner Chains: Native Token Management
// ---------------------------------------------------------------------------

pub struct TokenTransferHandler;

impl pallet_native_token_management::TokenTransferHandler for TokenTransferHandler {
    fn handle_token_transfer(token_amount: NativeTokenAmount) -> DispatchResult {
        log::info!("Registered transfer of {} native tokens", token_amount.0);
        Ok(())
    }
}

impl pallet_native_token_management::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type TokenTransferHandler = TokenTransferHandler;
}

// ---------------------------------------------------------------------------
// Construct runtime
// ---------------------------------------------------------------------------

construct_runtime! {
    pub enum Runtime {
        System: frame_system,
        Timestamp: pallet_timestamp,
        Aura: pallet_aura,
        Grandpa: pallet_grandpa,
        Balances: pallet_balances,
        TransactionPayment: pallet_transaction_payment,
        Sudo: pallet_sudo,
        Multisig: pallet_multisig,
        Utility: pallet_utility,
        // v5.1 tokenomics foundation
        Treasury: pallet_treasury,
        Vesting: pallet_vesting,
        OrinqReceipts: pallet_orinq_receipts,
        Motra: pallet_motra,
        // IOG Partner Chains pallets
        // Sidechain must come after Aura (reads current slot from it)
        Sidechain: pallet_sidechain,
        SessionCommitteeManagement: pallet_session_validator_management,
        BlockRewards: pallet_block_rewards,
        // pallet_session stub (needed by pallet_grandpa for CurrentIndex)
        PalletSession: pallet_session,
        // pallet_partner_chains_session must come last for correct initialization order
        Session: pallet_partner_chains_session,
        NativeTokenManagement: pallet_native_token_management,
    }
}

/// The address format for describing accounts.
pub type Address = sp_runtime::MultiAddress<AccountId, ()>;
/// Block header type.
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
/// Block type.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;
/// The SignedExtension to the basic transaction logic.
pub type SignedExtra = (
    frame_system::CheckNonZeroSender<Runtime>,
    frame_system::CheckSpecVersion<Runtime>,
    frame_system::CheckTxVersion<Runtime>,
    frame_system::CheckGenesis<Runtime>,
    frame_system::CheckEra<Runtime>,
    frame_system::CheckNonce<Runtime>,
    frame_system::CheckWeight<Runtime>,
    pallet_motra::fee::ChargeMotra<Runtime>,
);
/// Unchecked extrinsic type.
pub type UncheckedExtrinsic =
    generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, SignedExtra>;
/// Executive: handles dispatch to the various modules.
///
/// The 6th type parameter is `COnRuntimeUpgrade`: extra migrations that run
/// BEFORE `AllPalletsWithSystem::on_runtime_upgrade`. Our v5.1 sweep migration
/// is placed here so it runs first on the 201 → 202 upgrade block, then the
/// per-pallet hooks (including orinq-receipts' Component-4 defaults seeder)
/// run after. The migration is self-gated on a dedicated storage version so
/// subsequent upgrades short-circuit.
pub type Executive = frame_executive::Executive<
    Runtime,
    Block,
    frame_system::ChainContext<Runtime>,
    Runtime,
    AllPalletsWithSystem,
    migrations::SweepFeeRouterPotsIntoTreasury,
>;

// ---------------------------------------------------------------------------
// Runtime APIs
// ---------------------------------------------------------------------------

impl_runtime_apis! {
    impl sp_api::Core<Block> for Runtime {
        fn version() -> RuntimeVersion {
            VERSION
        }

        fn execute_block(block: Block) {
            Executive::execute_block(block);
        }

        fn initialize_block(header: &<Block as BlockT>::Header) -> sp_runtime::ExtrinsicInclusionMode {
            Executive::initialize_block(header)
        }
    }

    impl sp_api::Metadata<Block> for Runtime {
        fn metadata() -> OpaqueMetadata {
            OpaqueMetadata::new(Runtime::metadata().into())
        }

        fn metadata_at_version(version: u32) -> Option<OpaqueMetadata> {
            Runtime::metadata_at_version(version)
        }

        fn metadata_versions() -> Vec<u32> {
            Runtime::metadata_versions()
        }
    }

    impl sp_block_builder::BlockBuilder<Block> for Runtime {
        fn apply_extrinsic(extrinsic: <Block as BlockT>::Extrinsic) -> ApplyExtrinsicResult {
            Executive::apply_extrinsic(extrinsic)
        }

        fn finalize_block() -> <Block as BlockT>::Header {
            Executive::finalize_block()
        }

        fn inherent_extrinsics(data: sp_inherents::InherentData) -> Vec<<Block as BlockT>::Extrinsic> {
            data.create_extrinsics()
        }

        fn check_inherents(
            block: Block,
            data: sp_inherents::InherentData,
        ) -> sp_inherents::CheckInherentsResult {
            data.check_extrinsics(&block)
        }
    }

    impl sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block> for Runtime {
        fn validate_transaction(
            source: TransactionSource,
            tx: <Block as BlockT>::Extrinsic,
            block_hash: <Block as BlockT>::Hash,
        ) -> TransactionValidity {
            Executive::validate_transaction(source, tx, block_hash)
        }
    }

    impl sp_offchain::OffchainWorkerApi<Block> for Runtime {
        fn offchain_worker(header: &<Block as BlockT>::Header) {
            Executive::offchain_worker(header)
        }
    }

    impl sp_session::SessionKeys<Block> for Runtime {
        fn generate_session_keys(seed: Option<Vec<u8>>) -> Vec<u8> {
            // Also generate the cross-chain key alongside the session keys
            opaque::CrossChainKey::generate(seed.clone());
            opaque::SessionKeys::generate(seed)
        }

        fn decode_session_keys(encoded: Vec<u8>) -> Option<Vec<(Vec<u8>, KeyTypeId)>> {
            opaque::SessionKeys::decode_into_raw_public_keys(&encoded)
        }
    }

    impl sp_consensus_aura::AuraApi<Block, AuraId> for Runtime {
        fn slot_duration() -> sp_consensus_aura::SlotDuration {
            sp_consensus_aura::SlotDuration::from_millis(Aura::slot_duration())
        }

        fn authorities() -> Vec<AuraId> {
            pallet_aura::Authorities::<Runtime>::get().into_inner()
        }
    }

    impl sp_consensus_grandpa::GrandpaApi<Block> for Runtime {
        fn grandpa_authorities() -> sp_consensus_grandpa::AuthorityList {
            Grandpa::grandpa_authorities()
        }

        fn current_set_id() -> sp_consensus_grandpa::SetId {
            Grandpa::current_set_id()
        }

        fn submit_report_equivocation_unsigned_extrinsic(
            _equivocation_proof: sp_consensus_grandpa::EquivocationProof<
                <Block as BlockT>::Hash,
                NumberFor<Block>,
            >,
            _key_owner_proof: sp_consensus_grandpa::OpaqueKeyOwnershipProof,
        ) -> Option<()> {
            None
        }

        fn generate_key_ownership_proof(
            _set_id: sp_consensus_grandpa::SetId,
            _authority_id: GrandpaId,
        ) -> Option<sp_consensus_grandpa::OpaqueKeyOwnershipProof> {
            None
        }
    }

    impl frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, Nonce> for Runtime {
        fn account_nonce(account: AccountId) -> Nonce {
            System::account_nonce(account)
        }
    }

    impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<Block, Balance> for Runtime {
        fn query_info(
            uxt: <Block as BlockT>::Extrinsic,
            len: u32,
        ) -> pallet_transaction_payment_rpc_runtime_api::RuntimeDispatchInfo<Balance> {
            TransactionPayment::query_info(uxt, len)
        }

        fn query_fee_details(
            uxt: <Block as BlockT>::Extrinsic,
            len: u32,
        ) -> pallet_transaction_payment::FeeDetails<Balance> {
            TransactionPayment::query_fee_details(uxt, len)
        }

        fn query_weight_to_fee(weight: Weight) -> Balance {
            TransactionPayment::weight_to_fee(weight)
        }

        fn query_length_to_fee(length: u32) -> Balance {
            TransactionPayment::length_to_fee(length)
        }
    }

    impl orinq_receipts_primitives::OrinqReceiptsApi<Block, AccountId> for Runtime {
        fn get_receipt(id: H256) -> Option<orinq_receipts_primitives::ReceiptRecord<AccountId>> {
            pallet_orinq_receipts::Receipts::<Runtime>::get(id).map(|r| {
                orinq_receipts_primitives::ReceiptRecord {
                    schema_hash: r.schema_hash,
                    content_hash: r.content_hash,
                    base_root_sha256: r.base_root_sha256,
                    zk_root_poseidon: r.zk_root_poseidon,
                    poseidon_params_hash: r.poseidon_params_hash,
                    base_manifest_hash: r.base_manifest_hash,
                    safety_manifest_hash: r.safety_manifest_hash,
                    monitor_config_hash: r.monitor_config_hash,
                    attestation_evidence_hash: r.attestation_evidence_hash,
                    storage_locator_hash: r.storage_locator_hash,
                    availability_cert_hash: r.availability_cert_hash,
                    created_at_millis: r.created_at_millis,
                    submitter: r.submitter,
                }
            })
        }

        fn get_receipts_by_content(content_hash: H256) -> Vec<H256> {
            pallet_orinq_receipts::ContentIndex::<Runtime>::get(content_hash).into_inner()
        }

        fn receipt_count() -> u64 {
            pallet_orinq_receipts::ReceiptCount::<Runtime>::get()
        }

        fn receipt_exists(receipt_id: H256) -> bool {
            pallet_orinq_receipts::Receipts::<Runtime>::contains_key(receipt_id)
        }

        fn get_receipt_status(receipt_id: H256) -> Option<orinq_receipts_primitives::ReceiptStatus> {
            pallet_orinq_receipts::Receipts::<Runtime>::get(receipt_id).map(|r| {
                if r.availability_cert_hash == [0u8; 32] {
                    orinq_receipts_primitives::ReceiptStatus::Pending
                } else {
                    orinq_receipts_primitives::ReceiptStatus::Certified
                }
            })
        }
    }

    impl motra_primitives::MotraApi<Block> for Runtime {
        fn motra_balance(account: sp_core::crypto::AccountId32) -> u128 {
            // Convert AccountId32 to runtime AccountId
            use parity_scale_codec::Decode;
            let account_id = match AccountId::decode(&mut account.as_ref())
                { Ok(id) => id, Err(_) => return 0 };
            // Use projected_balance for read-only lazy computation (includes
            // pending generation from MATRA holdings without writing to storage).
            pallet_motra::Pallet::<Runtime>::projected_balance(&account_id)
        }

        fn motra_params() -> motra_primitives::MotraParams {
            let p = pallet_motra::Params::<Runtime>::get();
            motra_primitives::MotraParams {
                min_fee: p.min_fee,
                congestion_rate: p.congestion_rate,
                target_fullness: p.target_fullness,
                decay_rate_per_block: p.decay_rate_per_block,
                generation_per_matra_per_block: p.generation_per_matra_per_block,
                max_balance: p.max_balance,
                max_congestion_step: p.max_congestion_step,
                length_fee_per_byte: p.length_fee_per_byte,
                congestion_smoothing: p.congestion_smoothing,
            }
        }

        fn estimate_fee(weight_ref_time: u64) -> u128 {
            pallet_motra::Pallet::<Runtime>::compute_fee(
                frame_support::weights::Weight::from_parts(weight_ref_time, 0),
                0, // length not known at estimation time; weight-only estimate
            )
        }

        fn total_motra_issued() -> u128 {
            pallet_motra::TotalIssued::<Runtime>::get()
        }

        fn total_motra_burned() -> u128 {
            pallet_motra::TotalBurned::<Runtime>::get()
        }

        fn insufficient_motra_failures() -> u64 {
            pallet_motra::InsufficientMotraFailures::<Runtime>::get()
        }
    }

    impl sp_sidechain::GetGenesisUtxo<Block> for Runtime {
        fn genesis_utxo() -> UtxoId {
            Sidechain::genesis_utxo()
        }
    }

    impl sp_sidechain::GetSidechainStatus<Block> for Runtime {
        fn get_sidechain_status() -> SidechainStatus {
            SidechainStatus {
                epoch: Sidechain::current_epoch_number(),
                slot: ScSlotNumber(*pallet_aura::CurrentSlot::<Runtime>::get()),
                slots_per_epoch: Sidechain::slots_per_epoch().0,
            }
        }
    }

    impl sidechain_slots::SlotApi<Block> for Runtime {
        fn slot_config() -> sidechain_slots::ScSlotConfig {
            sidechain_slots::ScSlotConfig {
                slots_per_epoch: Sidechain::slots_per_epoch(),
                slot_duration: <Self as sp_consensus_aura::runtime_decl_for_aura_api::AuraApi<Block, AuraId>>::slot_duration()
            }
        }
    }

    impl sp_session_validator_management::SessionValidatorManagementApi<Block, SessionKeys, CrossChainPublic, AuthoritySelectionInputs, ScEpochNumber> for Runtime {
        fn get_current_committee() -> (ScEpochNumber, Vec<CrossChainPublic>) {
            SessionCommitteeManagement::get_current_committee()
        }
        fn get_next_committee() -> Option<(ScEpochNumber, Vec<CrossChainPublic>)> {
            SessionCommitteeManagement::get_next_committee()
        }
        fn get_next_unset_epoch_number() -> ScEpochNumber {
            SessionCommitteeManagement::get_next_unset_epoch_number()
        }
        fn calculate_committee(authority_selection_inputs: AuthoritySelectionInputs, sidechain_epoch: ScEpochNumber) -> Option<Vec<(CrossChainPublic, SessionKeys)>> {
            SessionCommitteeManagement::calculate_committee(authority_selection_inputs, sidechain_epoch)
        }
        fn get_main_chain_scripts() -> sp_session_validator_management::MainChainScripts {
            SessionCommitteeManagement::get_main_chain_scripts()
        }
    }

    impl sp_native_token_management::NativeTokenManagementApi<Block> for Runtime {
        fn get_main_chain_scripts() -> Option<sp_native_token_management::MainChainScripts> {
            NativeTokenManagement::get_main_chain_scripts()
        }
        fn initialized() -> bool {
            NativeTokenManagement::initialized()
        }
    }

    impl sp_genesis_builder::GenesisBuilder<Block> for Runtime {
        fn build_state(config: Vec<u8>) -> sp_genesis_builder::Result {
            build_state::<RuntimeGenesisConfig>(config)
        }

        fn get_preset(id: &Option<sp_genesis_builder::PresetId>) -> Option<Vec<u8>> {
            get_preset::<RuntimeGenesisConfig>(id, |_| None)
        }

        fn preset_names() -> Vec<sp_genesis_builder::PresetId> {
            alloc::vec![]
        }
    }
}


