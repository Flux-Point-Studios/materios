#![cfg_attr(not(feature = "std"), no_std)]
// `construct_runtime!` does a lot of recursion and requires us to increase the limit.
#![recursion_limit = "256"]

extern crate alloc;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod seating_model_check;

pub mod committee_liveness;
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
        Weight,
    },
    genesis_builder_helper::{build_state, get_preset},
    BoundedVec, PalletId,
};
use frame_system::{EnsureRoot, EnsureRootWithSuccess};
use frame_system::limits::{BlockLength, BlockWeights};
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
    ApplyExtrinsicResult, DispatchResult, MultiSignature, Perbill, Permill,
};
use sp_sidechain::SidechainStatus;
use sp_version::RuntimeVersion;

#[cfg(feature = "std")]
use sp_version::NativeVersion;

// Re-export pallets so they can be used in construct_runtime.
pub use frame_system;
pub use pallet_balances;
pub use pallet_billing;
pub use pallet_motra;
pub use pallet_oracle;
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

/// Rebuild a committee tuple `(CrossChainPublic, SessionKeys)` from an emergency
/// pinned member's raw keys (mainnet-resilience #491). Mirrors the vendor's
/// committee construction exactly — `account_id: ecdsa::Public.into()`,
/// `account_keys: (sr25519::Public, ed25519::Public).into()` — so a pinned member
/// installs the identical authority tuple the Ariadne path would for the same
/// keys, and the session pallet maps validators to the keys their nodes hold.
fn reconstruct_pinned_member(
    m: &pallet_orinq_receipts::types::PinnedMember,
) -> (CrossChainPublic, SessionKeys) {
    let account: CrossChainPublic = sp_core::ecdsa::Public::from(m.cross_chain).into();
    let keys: SessionKeys = (
        sp_core::sr25519::Public::from(m.aura),
        sp_core::ed25519::Public::from(m.grandpa),
    )
        .into();
    (account, keys)
}

// ---------------------------------------------------------------------------
// Runtime version
// ---------------------------------------------------------------------------

#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: create_runtime_str!("materios"),
    impl_name: create_runtime_str!("materios-node"),
    authoring_version: 1,
    spec_version: 237,
    impl_version: 1,
    apis: RUNTIME_API_VERSIONS,
    transaction_version: 4,
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
// Treasury
// ---------------------------------------------------------------------------

parameter_types! {
    pub const TreasuryPalletId: PalletId = PalletId(*b"mat/trsy");
    /// 7 days @ 6s blocks = 100_800 blocks.
    pub const SpendPeriod: BlockNumber = 100_800;
    pub const TreasuryBurn: Permill = Permill::from_percent(0);
    pub const MaxApprovals: u32 = 100;
    /// Upper bound on a single `spend_local` approval. Even Root cannot
    /// approve more than this in one call.
    pub const MaxSpend: Balance = 1_000_000_000_000_000; // 1e15 base units (~1B MATRA @ 6 dec)
    pub const PayoutPeriod: BlockNumber = 30 * DAYS;
}

pub const SPEND_PERIOD_BLOCKS: BlockNumber = 100_800;

pub fn treasury_account() -> AccountId {
    TreasuryPalletId::get().into_account_truncating()
}

pub const DAYS: BlockNumber = 24 * 60 * 60 * 1000 / (MILLISECS_PER_BLOCK as BlockNumber);

impl pallet_treasury::Config for Runtime {
    type PalletId = TreasuryPalletId;
    type Currency = Balances;
    type RejectOrigin = EnsureRoot<AccountId>;
    type RuntimeEvent = RuntimeEvent;
    type SpendPeriod = SpendPeriod;
    type Burn = TreasuryBurn;
    type BurnDestination = ();
    type SpendFunds = ();
    type WeightInfo = pallet_treasury::weights::SubstrateWeight<Runtime>;
    type MaxApprovals = MaxApprovals;
    type SpendOrigin = EnsureRootWithSuccess<AccountId, MaxSpend>;
    type AssetKind = ();
    type Beneficiary = AccountId;
    type BeneficiaryLookup = IdentityLookup<Self::Beneficiary>;
    type Paymaster = frame_support::traits::tokens::PayFromAccount<Balances, TreasuryAccountSource>;
    type BalanceConverter = frame_support::traits::tokens::UnityAssetBalanceConversion;
    type PayoutPeriod = PayoutPeriod;
    #[cfg(feature = "runtime-benchmarks")]
    type BenchmarkHelper = ();
}

// `PayFromAccount` requires a `TypedGet<Type = AccountId>`, not a PalletId;
// `parameter_types!` implements both `Get` and `TypedGet`.
parameter_types! {
    pub TreasuryAccountSource: AccountId = TreasuryPalletId::get().into_account_truncating();
}

parameter_types! {
    pub const AttestorReservePalletId: PalletId = PalletId(*b"mat/attr");
    /// Validator-emission treasury share: fraction of each era's
    /// validator-reserve emission routed to `mat/trsy`; the rest goes to
    /// block-authoring validators pro-rata. Rounding residue lands in
    /// treasury.
    pub const TreasuryEmissionShare: Perbill = Perbill::from_percent(15);
}

pub fn attestor_reserve_account() -> AccountId {
    AttestorReservePalletId::get().into_account_truncating()
}

// ---------------------------------------------------------------------------
// v5.1 tokenomics: Vesting
// ---------------------------------------------------------------------------

parameter_types! {
    /// 1 MATRA (6 dec) == 1_000_000.
    pub const MinVestedTransfer: Balance = 1_000_000;
    /// Vested accounts may still pay tx fees and reserve funds; only TRANSFER
    /// and RESERVE are blocked by the vesting lock.
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
    pub const DepositBase: Balance = 1_000;
    pub const DepositFactor: Balance = 500;
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
// Recovery (mainnet-resilience #492)
// ---------------------------------------------------------------------------
//
// The SECOND, independent path to Root. `pallet_sudo` alone is the bootstrap
// paradox: lose the sudo key and every governance lever (authorize_upgrade,
// the break-glass/PinnedCommittee setters, note_stalled-via-sudo) is closed
// forever — a reset-class outcome no forkless upgrade can reach. Social recovery
// gives a separate, geo-distributed friend set (independent custody domain, not
// the sudo multisig signatories) a delayed path to recover the sudo ACCOUNT and
// re-key sudo, surviving a custody-correlated loss of the primary multisig.
//
// DEFAULT-INERT: with no `create_recovery` configured on the sudo account this
// pallet does nothing — byte-identical governance to today. Arming is a ceremony
// (the sudo account calls `create_recovery(friends, threshold, delay_period)`
// with the real recovery keys). The delay_period + `cancel_recovered`/
// `remove_recovery` give the legitimate holders a veto window against a malicious
// recovery, so the second path never weakens the first.
parameter_types! {
    pub const RecoveryConfigDepositBase: Balance = 1_000;
    pub const RecoveryFriendDepositFactor: Balance = 500;
    pub const RecoveryDeposit: Balance = 1_000;
}

impl pallet_recovery::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type Currency = Balances;
    type ConfigDepositBase = RecoveryConfigDepositBase;
    type FriendDepositFactor = RecoveryFriendDepositFactor;
    type MaxFriends = ConstU32<9>;
    type RecoveryDeposit = RecoveryDeposit;
    type WeightInfo = pallet_recovery::weights::SubstrateWeight<Runtime>;
}

// ---------------------------------------------------------------------------
// Orinq Receipts
// ---------------------------------------------------------------------------

impl pallet_orinq_receipts::pallet::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = pallet_orinq_receipts::weights::SubstrateWeight;
    type MaxResubmits = ConstU32<64>;
    // MUST stay in lockstep with `input_sanity::MAX_COMMITTEE_SIZE`.
    type MaxCommitteeSize = ConstU32<96>;
    type Currency = Balances;
    type AttestorReservePotId = AttestorReservePalletId;
    type TreasuryPotId = TreasuryPalletId;
    type TreasuryEmissionShare = TreasuryEmissionShare;
}

// ---------------------------------------------------------------------------
// Intent Settlement
// ---------------------------------------------------------------------------
//
// The `pallet_intent_settlement` pallet implements user-intent lifecycle,
// M-of-N committee attestation, Cardano-side settlement mirroring, and the
// per-account ADA credit ledger. `CommitteeMembership` is satisfied by a
// READ-ONLY adapter over `pallet_orinq_receipts` committee-set + threshold
// storage; OrinqReceipts is the sole writer of committee membership.

/// Adapter exposing the on-chain `OrinqReceipts` committee set to
/// `pallet_intent_settlement`.
///
/// For `AccountId = AccountId32` the pubkey IS the raw 32 bytes of the
/// account, so the mapping is injective and round-trips without registry
/// storage.
pub struct OrinqCommitteeAdapter;

impl pallet_intent_settlement::IsCommitteeMember<AccountId> for OrinqCommitteeAdapter {
    fn is_member(who: &AccountId) -> bool {
        pallet_orinq_receipts::CommitteeMembers::<Runtime>::get().contains(who)
    }

    fn threshold() -> u32 {
        // Clamp to 1: an M-of-N gate of 0 would accept zero sigs.
        pallet_orinq_receipts::AttestationThreshold::<Runtime>::get().max(1)
    }

    fn member_count() -> u32 {
        pallet_orinq_receipts::CommitteeMembers::<Runtime>::get().len() as u32
    }

    fn pubkey_of(who: &AccountId) -> [u8; 32] {
        let bytes: &[u8; 32] = who.as_ref();
        *bytes
    }

    fn account_of_pubkey(pubkey: &[u8; 32]) -> Option<AccountId> {
        // Gate on current membership so callers can't forge a non-member
        // account by supplying an arbitrary pubkey.
        let candidate = AccountId::from(*pubkey);
        if <Self as pallet_intent_settlement::IsCommitteeMember<AccountId>>::is_member(&candidate) {
            Some(candidate)
        } else {
            None
        }
    }
}

parameter_types! {
    /// MUST match `OrinqReceipts::MaxCommitteeSize` to avoid an adapter
    /// mismatch where OrinqReceipts admits a member but intent-settlement
    /// BoundedVec overflows.
    pub const IntentSettlementMaxCommittee: u32 = 96;
    /// TTL-sweep bound per block; bounds the on_initialize cost.
    pub const IntentSettlementMaxExpirePerBlock: u32 = 64;
    /// 600 blocks ≈ 1h @ 6s.
    pub const IntentSettlementDefaultIntentTTL: BlockNumber = 600;
    /// 28_800 blocks ≈ 48h @ 6s.
    pub const IntentSettlementDefaultClaimTTL: BlockNumber = 28_800;
    pub const IntentSettlementMaxPendingBatches: u32 = 10_000;
    pub const IntentSettlementDefaultMinSignerThreshold: u32 = 1;
    pub const IntentSettlementMaxSettleBatch: u32 = 256;
    pub const IntentSettlementMaxAttestBatch: u32 = 256;
    pub const IntentSettlementMaxVoucherBatch: u32 = 256;
    pub const IntentSettlementMaxSubmitBatch: u32 = 256;
    /// 32-byte Materios chain identity (preprod v6 genesis hash). Pinned
    /// into committee-signed bundles to domain-separate across networks/
    /// resets.
    pub IntentSettlementMateriosChainId: sp_core::H256 = sp_core::H256([
        0x0e, 0x46, 0xe3, 0x3f, 0x63, 0x9a, 0x56, 0xcc,
        0x87, 0x80, 0xfd, 0x87, 0x1d, 0x9a, 0x15, 0xe1,
        0x6d, 0x99, 0xaf, 0x24, 0x85, 0x26, 0xf9, 0x07,
        0xcb, 0x56, 0x0c, 0xb4, 0x08, 0x49, 0xf7, 0xbf,
    ]);
    /// Cardano preprod network magic. Mainnet flip: 764824073.
    pub const IntentSettlementNetworkMagic: u32 = 1;
    /// 28-byte blake2b224 of the deployed `aegis_policy_v1` script.
    /// Production runtime MUST pin the real script hash from `aiken build`.
    pub const IntentSettlementAegisPolicyV1ScriptHash: [u8; 28] = [0u8; 28];
    /// Settlement-protocol semver. Bump on any breaking preimage change.
    pub const IntentSettlementSettlementVersion: u32 = 1;
    /// Cardano block depth that a `request_settle` / `request_expire_policy`
    /// evidence blob MUST claim before its `attest_*` counterpart is
    /// accepted.
    pub const IntentSettlementMinFinalityDepth: u32 = 15;
    /// 2400 blocks @ 6s = 4 hours.
    pub const IntentSettlementSettlementRequestTtl: u32 = 2400;
    /// Cardano preprod Shelley genesis hash pin. Rejects any
    /// `SettlementEvidence` / `ExpiryEvidence` whose `mainchain_genesis_hash`
    /// ≠ this constant — prevents preprod bundles from ever settling
    /// mainnet claims (and vice versa). Mainnet flip: replace with the
    /// mainnet `ShelleyGenesisHash`.
    pub const IntentSettlementMainchainGenesisHash: [u8; 32] = [
        0x16, 0x2d, 0x29, 0xc4, 0xe1, 0xcf, 0x6b, 0x8a,
        0x84, 0xf2, 0xd6, 0x92, 0xe6, 0x7a, 0x3a, 0xc6,
        0xbc, 0x78, 0x51, 0xbc, 0x3e, 0x6e, 0x4a, 0xfe,
        0x64, 0xd1, 0x57, 0x78, 0xbe, 0xd8, 0xbd, 0x86,
    ];
    /// Basis-point share of a slashed settlement bond paid to the watcher
    /// who proved the fraud. Pallet clamps at the call site to [0, 10_000].
    pub const IntentSettlementSlashWatcherShareBps: u32 = 5000;
    /// Minimum Materios blocks between `attest_settle` and
    /// `release_settlement_bond`. Set to 2 × MinFinalityDepth so Cardano
    /// has had two finality windows to surface any reorg.
    pub const IntentSettlementBondReleaseDelayBlocks: u32 = 30;
    /// Minimum bond a requester must reserve via `post_settlement_bond`.
    /// Defaults to zero (opt-in); production bumps via governance.
    pub const IntentSettlementMinSettlementBond: u128 = 0;
}

impl pallet_intent_settlement::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type MaxCommittee = IntentSettlementMaxCommittee;
    type MaxExpirePerBlock = IntentSettlementMaxExpirePerBlock;
    type DefaultIntentTTL = IntentSettlementDefaultIntentTTL;
    type DefaultClaimTTL = IntentSettlementDefaultClaimTTL;
    type CommitteeMembership = OrinqCommitteeAdapter;
    type MaxPendingBatches = IntentSettlementMaxPendingBatches;
    type DefaultMinSignerThreshold = IntentSettlementDefaultMinSignerThreshold;
    #[cfg(not(feature = "runtime-benchmarks"))]
    type SigVerifier = pallet_intent_settlement::Sr25519Verifier;
    #[cfg(feature = "runtime-benchmarks")]
    type SigVerifier = pallet_intent_settlement::BenchAllowAnyVerifier;
    type MaxSettleBatch = IntentSettlementMaxSettleBatch;
    type MaxAttestBatch = IntentSettlementMaxAttestBatch;
    type MaxVoucherBatch = IntentSettlementMaxVoucherBatch;
    type MaxSubmitBatch = IntentSettlementMaxSubmitBatch;
    type MateriosChainId = IntentSettlementMateriosChainId;
    type NetworkMagic = IntentSettlementNetworkMagic;
    type AegisPolicyV1ScriptHash = IntentSettlementAegisPolicyV1ScriptHash;
    type SettlementVersion = IntentSettlementSettlementVersion;
    type MinFinalityDepth = IntentSettlementMinFinalityDepth;
    type SettlementRequestTtl = IntentSettlementSettlementRequestTtl;
    type MainchainGenesisHash = IntentSettlementMainchainGenesisHash;
    type Currency = Balances;
    type SlashWatcherShareBps = IntentSettlementSlashWatcherShareBps;
    type BondReleaseDelayBlocks = IntentSettlementBondReleaseDelayBlocks;
    type MinSettlementBond = IntentSettlementMinSettlementBond;
    type SettlementTreasuryPalletId = TreasuryPalletId;
    #[cfg(feature = "runtime-benchmarks")]
    type BenchmarkHelper = IntentSettlementBenchmarkHelper;
    type WeightInfo = pallet_intent_settlement::weights::SubstrateWeight<Runtime>;
}

#[cfg(feature = "runtime-benchmarks")]
pub struct IntentSettlementBenchmarkHelper;

#[cfg(feature = "runtime-benchmarks")]
impl pallet_intent_settlement::BenchmarkHelper<AccountId>
    for IntentSettlementBenchmarkHelper
{
    fn whitelist_as_committee(who: &AccountId) {
        let mut members =
            pallet_orinq_receipts::CommitteeMembers::<Runtime>::get();
        if !members.contains(who) {
            let _ = members.try_insert(who.clone());
            pallet_orinq_receipts::CommitteeMembers::<Runtime>::put(members);
        }
        // Clamp to 1 so the single-signer bench bundle satisfies M-of-N.
        pallet_orinq_receipts::AttestationThreshold::<Runtime>::put(1u32);
    }
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
/// `MaxValidators` AND by `input_sanity::MAX_COMMITTEE_SIZE` — `input_sanity`
/// has a compile-time assertion that its constant equals this one.
pub const MAX_VALIDATORS: u32 = 32;

parameter_types! {
    pub const MaxValidators: u32 = MAX_VALIDATORS;
}

/// Committee liveness filter (task #410). A registered (trustless) SPO
/// candidate selectable for longer than the grace window yet producing no
/// block within the liveness window is dropped from selection, so a dead
/// registration cannot inflate the GRANDPA quorum and wedge finality. Grace is
/// 1_800 blocks (~3h @ 6s) — long enough for a snapshot-bootstrapped node to be
/// selected and author its first block, short enough that a never-authoring
/// dead registration vacates its committee seat (and the finality slack it
/// holds) in ~3h instead of a full era. Eras are ~14_400 blocks (~24h @ 6s);
/// permissioned (FPS) candidates are never filtered. MAINNET: retune to mainnet
/// block time and ensure the preprod vendor relaxations (ariadne `<=`, db-sync
/// offset 0) are reverted first.
const LIVENESS_GRACE_BLOCKS: u32 = 1_800; // ~3h @ 6s
const LIVENESS_WINDOW_BLOCKS: u32 = 28_800; // 2 eras (~48h)

/// Dead-CORE eviction (Residual #2, activated by spec-233 — the ceremony owns
/// the single 232→233 spec_version bump, this source does not bump it). Cores
/// are exempt from the registered filter by design, so a genuinely-dead core
/// otherwise inflates the GRANDPA quorum forever and the only remedy would be
/// the forbidden L1 D-param re-shrink. `filter_dead_permissioned` instead drops
/// the dead core from the permissioned pool before the draw; the vendor's dedup
/// then collapses the distinct committee, so the quorum shrinks WITHOUT touching
/// the L1 D-parameter. Because cores are trusted and few, the thresholds are
/// MUCH longer than the registered ones — no reboot, deploy, snapshot restore,
/// or brief partition flaps a healthy core out; only a multi-day silence reads
/// as dead. Gated OFF by the `CoreEvictionEnabled` governance flag and capped at
/// one eviction per selection. MAINNET: retune to mainnet block time alongside
/// the registered constants.
const CORE_LIVENESS_GRACE_BLOCKS: u32 = 14_400; // ~24h @ 6s (vs registered 1_800)
const CORE_LIVENESS_WINDOW_BLOCKS: u32 = 100_800; // ~7d @ 6s (vs registered 28_800)
/// At most this many dead cores leave per selection — the rate cap that makes a
/// buggy or hostile predicate unable to collapse the FPS backbone in one epoch.
const CORE_MAX_EVICTIONS_PER_SELECTION: usize = 1;

// Cores must be strictly harder to evict than registered candidates.
const _: () = assert!(CORE_LIVENESS_GRACE_BLOCKS > LIVENESS_GRACE_BLOCKS);
const _: () = assert!(CORE_LIVENESS_WINDOW_BLOCKS > LIVENESS_WINDOW_BLOCKS);

/// R1 Lever 1 (Residual #1, activated by spec-233 — the ceremony owns the single
/// 232→233 spec_version bump, this source does not bump it). When the
/// `ContributionWindowEnabled` governance flag is ON, `select_authorities` judges
/// the registered (external) liveness filter against this short "currently
/// contributing" horizon instead of `LIVENESS_WINDOW_BLOCKS`, so a seated
/// external that goes silent mid-epoch is shed from the NEXT Ariadne draw within
/// ~1 epoch rather than after ~48h. That makes `NextCommittee` a cores-only fire
/// target fast enough for R1's `Grandpa::note_stalled` break-glass G2 fire-gate
/// during a `>f` external-failure wedge, with no Cardano D-param round-trip. ~3h
/// ≈ the grace magnitude and > the ~200–450-block snapshot-to-tip restore with
/// ~4× margin, so routine restarts do not flap a healthy external out. Cores are
/// never registered-filtered, so the backbone is untouched; the post-draw floor
/// keeps the full window, so the change can only SHED a draw, never strand
/// quorum. Gated OFF by default (identical to spec-231/232). MAINNET: retune to
/// mainnet block time alongside the registered constants.
const LIVENESS_CONTRIBUTION_WINDOW: u32 = 1_800; // ~3h @ 6s

/// One drawn seat may be an unproven newcomer without paying for the quorum it
/// adds; a second may not (mainnet-resilience #505). The growth-direction mirror
/// of `CORE_MAX_EVICTIONS_PER_SELECTION`: bounded change per rotation.
const UNPROVEN_SEAT_CREDIT: usize = 1;

/// Finality slack a GROWN committee must retain beyond quorum.
///
/// ZERO, and it cannot be raised. `live_current` can never exceed `n_current` —
/// a committee has no more live members than seats — so growth from n to n+1
/// needs `n >= q(n+1) + SLACK_MARGIN`. At n=4 that is `4 >= 4 + margin`, so any
/// margin above zero makes growth from a small committee *unsatisfiable*, not
/// merely conservative: the chain can never add a seat again. Shipped as 1 in
/// spec-236, deadlocked the ramp at n=5, corrected here.
///
/// Zero still leaves three real constraints on growth: the unchanged live-quorum
/// floor, at most `UNPROVEN_SEAT_CREDIT` never-authored seats per rotation, and
/// at most one quorum step per rotation. What it gives up is the demand for a
/// SPARE at the moment of growth — which at 4 cores is unreachable anyway, since
/// q(6)=5 already equals the whole live set.
const SLACK_MARGIN: usize = 0;

/// The deadlock above, as a compile error rather than a runbook entry: growth
/// off the smallest committee we run (n=4 → 5, q(5)=4) must be satisfiable by a
/// fully-live committee. Raising SLACK_MARGIN breaks the build.
const _: () = assert!(4 >= (5 - (5 - 1) / 3) + SLACK_MARGIN);

// The contribution window only ever SHORTENS the registered eviction horizon.
const _: () = assert!(LIVENESS_CONTRIBUTION_WINDOW <= LIVENESS_WINDOW_BLOCKS);

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
        // Emergency pinned committee (mainnet-resilience #491): the L1-independent
        // override. Read FIRST — a committed-storage read so author and verifier
        // agree — and while it is set and unexpired, return the reconstructed
        // committee VERBATIM, bypassing the entire Ariadne draw, liveness filter,
        // and quorum/break-glass floors. Reconstruction mirrors the vendor's
        // committee-tuple construction exactly (ecdsa -> CrossChainPublic;
        // (sr25519, ed25519) -> SessionKeys). Any malformed/oversized/empty pin
        // fails safe: fall through to the normal L1-driven selection.
        if let Some((members, until_epoch)) =
            pallet_orinq_receipts::Pallet::<Runtime>::pinned_committee()
        {
            if sidechain_epoch.0 <= until_epoch && !members.is_empty() {
                let chosen: Vec<(CrossChainPublic, SessionKeys)> =
                    members.iter().map(reconstruct_pinned_member).collect();
                match BoundedVec::try_from(chosen) {
                    Ok(bounded) => {
                        log::warn!(
                            target: "runtime::committee-liveness",
                            "PINNED COMMITTEE active for epoch {} (until {}): installing {} members verbatim, bypassing Ariadne selection",
                            sidechain_epoch.0,
                            until_epoch,
                            bounded.len(),
                        );
                        return Some(bounded);
                    }
                    Err(_) => log::error!(
                        target: "runtime::committee-liveness",
                        "pinned committee ({} members) exceeds MaxValidators; ignoring pin, using Ariadne selection",
                        members.len(),
                    ),
                }
            }
        }

        // Filter out duplicate keys, cap list sizes, and reject whole-input
        // invariant violations: the registered-candidates list is untrusted
        // db-sync output until D<1.0.
        let sanitized = match input_sanity::sanitize_and_log(input) {
            Ok(cleaned) => cleaned,
            Err(_) => return None,
        };

        // Liveness facts for the filter and the quorum floor below, keyed by
        // the Aura-key account `pallet_orinq_receipts` writes for authors.
        fn liveness_of(acct: [u8; 32]) -> committee_liveness::CandidateLiveness {
            let who = AccountId::from(acct);
            committee_liveness::CandidateLiveness {
                first_selected: pallet_orinq_receipts::Pallet::<Runtime>::candidate_first_selected(
                    &who,
                ),
                last_authored: pallet_orinq_receipts::Pallet::<Runtime>::last_authored_block(&who),
            }
        }

        // Drop registered (trustless) candidates that have been selectable
        // past the grace window yet never produced a block within the
        // liveness window. A permanently-dead SPO registration otherwise
        // inflates the GRANDPA authority set N — raising the finality quorum
        // above the live-voter count and wedging finality (the 2026-06 six-day
        // stall). Permissioned (FPS) candidates are never filtered.
        let now: u32 = frame_system::Pallet::<Runtime>::block_number();
        // R1 Lever 1 (Residual #1 / spec-233), gated OFF by the Root-set
        // `ContributionWindowEnabled` flag. When armed, the registered filter
        // judges a seated external silent past the short LIVENESS_CONTRIBUTION_WINDOW
        // (~3h) as dead instead of waiting the full ~48h LIVENESS_WINDOW_BLOCKS, so
        // NextCommittee sheds a silently-failed external within ~1 epoch — fast
        // enough that R1's note_stalled break-glass has a cores-only fire target
        // during a >f mid-epoch external failure, with no Cardano D-param
        // round-trip. Cores are never registered-filtered, and the post-draw floor
        // below still uses the full window, so this can only SHED a draw, never
        // strand quorum. OFF → identical to spec-231/232 (~48h horizon).
        let registered_window =
            if pallet_orinq_receipts::Pallet::<Runtime>::contribution_window_enabled() {
                LIVENESS_CONTRIBUTION_WINDOW
            } else {
                LIVENESS_WINDOW_BLOCKS
            };
        let (sanitized, dropped) = committee_liveness::filter_dead_registered(
            sanitized,
            now,
            LIVENESS_GRACE_BLOCKS,
            registered_window,
            liveness_of,
        );
        if dropped > 0 {
            log::warn!(
                target: "committee_liveness",
                "dropped {} dead registered candidate(s) from selection at block {}",
                dropped, now,
            );
        }

        // Dead-CORE eviction (Residual #2 / spec-233), gated OFF by the Root-set
        // `CoreEvictionEnabled` flag — shipped false, flipped ON via the 2-of-3
        // multisig-sudo ceremony only after the Group-J harness proof and the
        // multi-node devnet cascade are green. Removing a genuinely-dead FPS core
        // from the permissioned pool lets the remaining permissioned draws
        // redistribute over the live cores; the vendor dedup then collapses the
        // distinct committee, so the GRANDPA quorum shrinks WITHOUT touching the
        // L1 D-parameter (the count stays put; only the runtime candidate pool
        // shrinks). Core constants are far longer than the registered ones and at
        // most CORE_MAX_EVICTIONS_PER_SELECTION leave per epoch, so a buggy or
        // hostile predicate cannot collapse the FPS backbone in one rotation. The
        // post-draw live-quorum floor below still judges the shrunk set, so a
        // shrink that would strand quorum is refused (keep-current) — eviction can
        // never install a sub-quorum committee. It is preventive: a standard
        // scheduled set-change that enacts only while the old set still finalizes
        // it; a finality-frozen chain still needs R1's `Grandpa::note_stalled`
        // break-glass (the existing 2-of-3 ceremony — no new extrinsic).
        let (sanitized, cores_dropped) =
            if pallet_orinq_receipts::Pallet::<Runtime>::core_eviction_enabled() {
                committee_liveness::filter_dead_permissioned(
                    sanitized,
                    now,
                    CORE_LIVENESS_GRACE_BLOCKS,
                    CORE_LIVENESS_WINDOW_BLOCKS,
                    CORE_MAX_EVICTIONS_PER_SELECTION,
                    liveness_of,
                )
            } else {
                (sanitized, 0)
            };
        if cores_dropped > 0 {
            log::warn!(
                target: "committee_liveness",
                "evicted {} dead permissioned core(s) from selection at block {}",
                cores_dropped, now,
            );
        }

        // Current-committee facts, read once and shared by both #505 halves.
        // `ext_current` is COUNTED (seated members absent from the permissioned
        // pool), not inferred as n_current − p_eff: those agree only while the
        // pool is unchanged, and an L1 core upsert makes the subtraction shrink
        // one-for-one — silently turning "never de-seat a live external" into
        // its opposite.
        let current_committee = SessionCommitteeManagement::current_committee_storage().committee;
        let n_current = current_committee.len();
        let current_aura: Vec<Vec<u8>> = current_committee
            .iter()
            .map(|(_, keys)| parity_scale_codec::Encode::encode(&keys.aura))
            .collect();
        let live_current = committee_liveness::live_member_count(
            &current_aura,
            now,
            LIVENESS_WINDOW_BLOCKS,
            liveness_of,
        );
        let permissioned_aura: alloc::collections::BTreeSet<Vec<u8>> = sanitized
            .permissioned_candidates
            .iter()
            .map(|c| c.aura_public_key.0.clone())
            .collect();
        let ext_current = current_aura
            .iter()
            .filter(|k| !permissioned_aura.contains(*k))
            .count();

        // D-parameter ramp guard (mainnet-resilience #505), gated OFF by the
        // Root-set `SlackInvariantEnabled` flag. A clamp, never a refusal: it
        // offers at most the external seats the currently-live members can carry
        // and never fewer than the chain already seats, so it cannot itself
        // freeze rotation. OFF (default) → identical to spec-235.
        let sanitized = if pallet_orinq_receipts::Pallet::<Runtime>::slack_invariant_enabled() {
            let mut s = sanitized;
            let requested = s.d_parameter.num_registered_candidates as usize;
            let cap = committee_liveness::registered_pool_cap(
                requested,
                s.permissioned_candidates.len(),
                ext_current,
                n_current,
                live_current,
                SLACK_MARGIN,
                MAX_VALIDATORS as usize,
            );
            if cap < requested {
                // Deterministic across nodes: richest stake first, mainchain key
                // as the tie-break. A node-local ordering would risk divergent
                // committees on otherwise-identical inputs.
                // Sort on the INNER primitives: neither StakeDelegation(u64) nor
                // MainchainPublicKey([u8; N]) derives Ord, but both wrap a type
                // that does.
                s.registered_candidates.sort_by(|a, b| {
                    b.stake_delegation
                        .map(|s| s.0)
                        .cmp(&a.stake_delegation.map(|s| s.0))
                        .then_with(|| a.mainchain_pub_key().0.cmp(&b.mainchain_pub_key().0))
                });
                s.registered_candidates.truncate(cap);
                s.d_parameter.num_registered_candidates = cap as u16;
                log::warn!(
                    target: "runtime::committee-liveness",
                    "ramp guard for epoch {}: capping registered seats {} -> {} \
                     ({} live of {} seated, {} external); D-parameter rewritten for this draw",
                    sidechain_epoch, requested, cap, live_current, n_current, ext_current,
                );
            }
            s
        } else {
            sanitized
        };

        // NOTE: `select_authorities` runs only in the inherent build/verify
        // path (`create_inherent` / `check_inherent`), whose storage writes are
        // discarded — so first-selected is stamped on-chain in
        // `pallet_orinq_receipts::on_initialize` (a committing context) from the
        // enacted Aura authorities, NOT here. Stamping here would never persist,
        // leaving `CandidateFirstSelected` empty and the filter inert.
        let chosen: BoundedVec<(Self::AuthorityId, Self::AuthorityKeys), Self::MaxValidators> =
            select_authorities(Sidechain::genesis_utxo(), sanitized, sidechain_epoch)?;

        // GRANDPA live-quorum floor (spec 230). Permissioned seats are drawn
        // with replacement, so even an all-live candidate list can yield a set
        // whose live members fall short of quorum once dead or never-authored
        // members are seated — twice on 2026-06-12 such draws wedged finality,
        // and a draw with zero live authors would perma-halt rotation (the
        // next rotation needs an authored block). Refuse any set whose
        // known-live members cannot carry quorum: returning None re-seats the
        // current committee for one more epoch via the session pallet's
        // create_inherent fallback, and since first-selected is stamped only
        // from ENACTED authorities (see NOTE above), a refused draw starts no
        // grace clocks for its members.
        let aura_keys: Vec<Vec<u8>> = chosen
            .iter()
            .map(|(_, keys)| parity_scale_codec::Encode::encode(&keys.aura))
            .collect();
        if !committee_liveness::passes_live_quorum_floor(
            &aura_keys,
            now,
            LIVENESS_WINDOW_BLOCKS,
            liveness_of,
        ) {
            log::warn!(
                target: "runtime::committee-liveness",
                "refusing committee for epoch {}: {} live of {} selected < GRANDPA quorum {}; keeping current committee",
                sidechain_epoch,
                committee_liveness::live_member_count(
                    &aura_keys,
                    now,
                    LIVENESS_WINDOW_BLOCKS,
                    liveness_of,
                ),
                aura_keys.len(),
                committee_liveness::grandpa_quorum_threshold(aura_keys.len()),
            );
            return None;
        }

        // Effective-slack invariant (mainnet-resilience #505), gated OFF by the
        // Root-set `SlackInvariantEnabled` flag. The floor above accepts
        // live == q(n) exactly — zero slack, one fault from a wedge. This adds a
        // condition on GROWTH only: a bigger n raises q(n), so growth spends
        // slack, and a seat we have never seen author cannot pay for the quorum
        // it adds. Shrinks and same-size draws are exempt, so the restorative
        // eviction is never refused, and the margin clamps to the current
        // committee's own slack, so a degraded chain is asked for nothing extra —
        // between them this cannot be why rotation stops. OFF → spec-235.
        if pallet_orinq_receipts::Pallet::<Runtime>::slack_invariant_enabled()
            && !committee_liveness::passes_growth_slack_invariant(
                &aura_keys,
                n_current,
                live_current,
                now,
                LIVENESS_WINDOW_BLOCKS,
                UNPROVEN_SEAT_CREDIT,
                SLACK_MARGIN,
                liveness_of,
            )
        {
            log::warn!(
                target: "runtime::committee-liveness",
                "refusing committee for epoch {}: growth {} -> {} would not retain slack \
                 ({} live, {} unproven, quorum {}, current slack {}); keeping current committee",
                sidechain_epoch,
                n_current,
                aura_keys.len(),
                committee_liveness::live_member_count(
                    &aura_keys, now, LIVENESS_WINDOW_BLOCKS, liveness_of),
                committee_liveness::unproven_member_count(&aura_keys, liveness_of),
                committee_liveness::grandpa_quorum_threshold(aura_keys.len()),
                live_current.saturating_sub(
                    committee_liveness::grandpa_quorum_threshold(n_current)),
            );
            return None;
        }

        // Break-glass floor (mainnet-resilience #490), gated OFF by the Root-set
        // `BreakGlassFloorEnabled` flag. When armed, refuse any drawn committee
        // that seats none of the FPS-held `BreakGlassAuraKeys` — returning None
        // keeps the current committee (which, while the floor stays armed, always
        // holds an FPS key) for one more epoch via the session pallet's
        // create_inherent fallback. This guarantees the enacted committee can
        // never drop to zero FPS-controlled seats, so a break-glass recovery
        // (`Grandpa::note_stalled`, an emergency runtime upgrade) always has an
        // FPS author left to include the recovering block — closing the
        // trustless-majority reset corner where a Cardano D-parameter that zeroes
        // the permissioned count would strand FPS with no enacted key. It only
        // ever refuses a draw (keep-current), so it can never itself install an
        // unsafe committee; the inductive base case (current committee holds an
        // FPS key) must hold when armed, which is why arming precedes the seat
        // ramp. OFF (default) → identical to spec-233.
        if pallet_orinq_receipts::Pallet::<Runtime>::break_glass_floor_enabled() {
            let break_glass_keys =
                pallet_orinq_receipts::Pallet::<Runtime>::break_glass_aura_keys();
            if !committee_liveness::committee_covers_break_glass(&aura_keys, &break_glass_keys) {
                log::warn!(
                    target: "runtime::committee-liveness",
                    "refusing committee for epoch {}: none of {} break-glass FPS key(s) seated among {} selected; keeping current committee",
                    sidechain_epoch,
                    break_glass_keys.len(),
                    aura_keys.len(),
                );
                return None;
            }
        }
        Some(chosen)
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
// TEE Attestation
// ---------------------------------------------------------------------------
//
// Pallet ships disabled at genesis via `DefaultDisabled<T>`; sudo flips via
// `set_disabled` once Phase 2.5 binds `attestation_challenge`.

impl pallet_tee_attestation::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
}

// ---------------------------------------------------------------------------
// Billing
// ---------------------------------------------------------------------------

parameter_types! {
    /// 14_400 blocks ≈ 1 day at 6s.
    pub const BillingRequestIdRetentionBlocks: BlockNumber = 14_400;
    /// Caps per-call declared weight so a `prune_paid_requests` batch
    /// cannot blow the per-block normal-class budget.
    pub const BillingMaxPruneBatch: u32 = 256;
}

impl pallet_billing::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type MatraCurrency = Balances;
    // Mainnet migration: switch to a multisig/collective origin before
    // launch — Sudo is not acceptable for production money flows.
    type GovernanceOrigin = EnsureRoot<AccountId>;
    type RequestIdRetentionBlocks = BillingRequestIdRetentionBlocks;
    type MaxPruneBatch = BillingMaxPruneBatch;
    type WeightInfo = pallet_billing::weights::SubstrateWeight;
}

// ---------------------------------------------------------------------------
// Oracle
// ---------------------------------------------------------------------------

parameter_types! {
    /// 32-byte materios chain identity (preprod v6 genesis hash). Pinned
    /// into every PRIC preimage so a price signed on one chain is
    /// structurally invalid on another. Same bytes as
    /// `IntentSettlementMateriosChainId` but typed as a raw `[u8; 32]` to
    /// match the oracle pallet's `Get<[u8; 32]>` Config bound.
    pub const OracleMateriosChainId: [u8; 32] = [
        0x0e, 0x46, 0xe3, 0x3f, 0x63, 0x9a, 0x56, 0xcc,
        0x87, 0x80, 0xfd, 0x87, 0x1d, 0x9a, 0x15, 0xe1,
        0x6d, 0x99, 0xaf, 0x24, 0x85, 0x26, 0xf9, 0x07,
        0xcb, 0x56, 0x0c, 0xb4, 0x08, 0x49, 0xf7, 0xbf,
    ];
    /// Per-pair attestor roster cap.
    pub const OracleMaxAttestors: u32 = 16;
    /// M-of-N aggregation gate. `submit_price` accumulates observations
    /// into `PendingAttestations[pair_id, slot_observed]` until this many
    /// distinct attestor pubkeys have submitted; only then does the pallet
    /// aggregate and write `Prices[pair_id]`. Re-checked on every
    /// `submit_price` so tightening the threshold needs no migration.
    pub const OracleMinAttestorThreshold: u32 = 3;
    /// Reject observations older than `current_block - 60` (≈6min @ 6s).
    pub const OracleMaxStaleSlots: u64 = 60;
    /// Reject observations claiming `slot_observed > current_block + 10`
    /// (≈1min anti-front-run tolerance).
    pub const OracleMaxFutureSlots: u64 = 10;
}

/// Adapter exposing on-chain `pallet_oracle::Attestors` storage to the
/// `IsAttestorFor<AccountId>` trait that `pallet_oracle::Config` requires.
///
/// For `AccountId = AccountId32` the sr25519 pubkey IS the raw 32 bytes of
/// the account, so the mapping is injective and round-trips without
/// per-account registry storage.
pub struct PalletOracleAttestorRegistry;

impl pallet_oracle::IsAttestorFor<AccountId> for PalletOracleAttestorRegistry {
    fn is_attestor(pair_id: &pallet_oracle::PairId, who: &AccountId) -> bool {
        let pubkey: pallet_oracle::AttestorPubkey = *<AccountId as AsRef<[u8; 32]>>::as_ref(who);
        pallet_oracle::Attestors::<Runtime>::get(pair_id).contains(&pubkey)
    }

    fn pubkey_of(who: &AccountId) -> pallet_oracle::AttestorPubkey {
        *<AccountId as AsRef<[u8; 32]>>::as_ref(who)
    }

    fn threshold_for(_pair_id: &pallet_oracle::PairId) -> u32 {
        // `.max(1)` defends against a misconfigured zero genesis value:
        // the aggregation gate is "≥ threshold" and 0 would let a single
        // attestor unilaterally write `Prices`.
        <Runtime as pallet_oracle::Config>::MinAttestorThreshold::get().max(1)
    }
}

impl pallet_oracle::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type MateriosChainId = OracleMateriosChainId;
    type MinAttestorThreshold = OracleMinAttestorThreshold;
    type MaxAttestors = OracleMaxAttestors;
    type MaxStaleSlots = OracleMaxStaleSlots;
    type MaxFutureSlots = OracleMaxFutureSlots;
    type AttestorRegistry = PalletOracleAttestorRegistry;
    type SigVerifier = pallet_oracle::Sr25519Verifier;
}

// ---------------------------------------------------------------------------
// Perp Engine
// ---------------------------------------------------------------------------
//
// Permissionless USD-quoted linear perpetual-futures primitive. Pull-based
// mark prices from `pallet-oracle`, pull-based funding, bond-gated
// permissionless liquidator pool with 100% slash on false trigger.

parameter_types! {
    /// PalletId for the perp-engine MOTRA margin-custody pot. Bytes
    /// `b"perp/v0w"` are distinct from `mat/trsy` and `mat/attr`.
    /// At activation the derived account MUST be pre-funded with
    /// ≥ `ExistentialDeposit` so the FIRST `Currency::transfer` from a
    /// fresh chain cannot stall on a non-existent destination.
    pub const PerpEnginePalletId: PalletId = PalletId(*b"perp/v0w");

    /// 32-byte materios chain identity (preprod v6 genesis hash). Same
    /// bytes as `OracleMateriosChainId`.
    pub const PerpEngineMateriosChainId: [u8; 32] = [
        0x0e, 0x46, 0xe3, 0x3f, 0x63, 0x9a, 0x56, 0xcc,
        0x87, 0x80, 0xfd, 0x87, 0x1d, 0x9a, 0x15, 0xe1,
        0x6d, 0x99, 0xaf, 0x24, 0x85, 0x26, 0xf9, 0x07,
        0xcb, 0x56, 0x0c, 0xb4, 0x08, 0x49, 0xf7, 0xbf,
    ];

    /// Hard cap on leverage across all markets. 5_000 bps = 50×. Each
    /// market's `MarketConfig.max_leverage_bps` MUST be ≤ this value;
    /// `governance_set_market` enforces the bound at registration.
    pub const PerpEngineMaxLeverageBps: u32 = 5_000;

    /// 100 bps = 1×.
    pub const PerpEngineMinLeverageBps: u32 = 100;

    /// Cap on `Markets` cardinality. Bounds per-block work in
    /// `on_initialize` so the hook weight is constant in market-set size.
    pub const PerpEngineMaxMarkets: u32 = 32;

    /// Bounded ring-buffer size for `PremiumIndexSamples[(market, epoch)]`.
    /// 600 samples per epoch (= 1h @ 6s blocks) is exactly one sample
    /// per block.
    pub const PerpEngineMaxFundingSamplesPerEpoch: u32 = 600;

    /// Keeper bond minimum, in MOTRA base units (8 decimals).
    /// 100 MATRA × 10^8 = 10^10. Slashed 100% on false trigger.
    pub const PerpEngineKeeperBondMinimum: Balance = 100u128 * 100_000_000u128;

    /// Mark-price cache freshness threshold, in blocks. 3 blocks (≈18s)
    /// of staleness suffices for the "opens + liquidations reject stale"
    /// gate while not tripping on block-author skips.
    pub const PerpEngineFreshnessLimitBlocks: u32 = 3;

    /// Cap on the premium-index EMA basis added to the oracle price,
    /// in basis points. 200 bps = 2%, clamped symmetrically so the
    /// cached mark stays within ±2% of the oracle.
    pub const PerpEngineMaxMarkBasisBps: u32 = 200;

    /// Bad-debt circuit-breaker threshold, in 1e18-scaled pMATRA-USD.
    /// $10_000 = 10_000 × 10^18; affected market auto-pauses when
    /// rolling-window bad-debt exceeds it.
    pub const PerpEngineBadDebtCircuitBreakerThresholdE18: u128 =
        10_000u128 * 1_000_000_000_000_000_000u128;

    /// Bad-debt rolling-window length, in blocks. 14_400 ≈ 24h @ 6s.
    /// Matches `WithdrawDwellBlocks`.
    pub const PerpEngineBadDebtWindowBlocks: u32 = 14_400;

    /// Withdraw-dwell window, in blocks. 14_400 ≈ 24h @ 6s. A fresh
    /// `deposit_margin` must dwell this long before the same account
    /// can `withdraw_margin` — defends against bridge-deposit replay.
    pub const PerpEngineWithdrawDwellBlocks: u32 = 14_400;

    /// MATRA/USD oracle feed handle. Hashed by `PerpEngineOracleAdapter`
    /// into the 32-byte `pallet_oracle::PairId`. Wrapped in a
    /// `parameter_types!` accessor because `BoundedVec` has no const
    /// constructor.
    pub PerpEngineMatraUsdFeedId: pallet_perp_engine::OracleFeedId =
        pallet_perp_engine::OracleFeedId::try_from(b"MATRA/USD".to_vec())
            .expect("9 bytes < MAX_MARKET_ID_LEN = 16; static literal");
}

/// Adapter implementing `pallet_perp_engine::PriceOracle` on top of
/// `pallet_oracle::Pallet<Runtime>`.
///
/// Type bridge: `pallet-perp-engine` types its feed handle as a bounded
/// UTF-8 byte string; `pallet-oracle` keys its storage by the canonical
/// 32-byte `PairId = sha256(handle_bytes)`. This adapter hashes the
/// perp-engine handle, then forwards through `pallet_oracle::Pallet`.
///
/// Price-scale normalisation: `pallet-oracle` stores `(price: u64,
/// decimals: u8)`; perp-engine consumes 1e18 scale. Decimals are bounded
/// `[0, 18]` by the oracle pallet's `submit_price` validation so the
/// shift is non-negative; `u128` headroom is `10^18 × 10^18 = 10^36`,
/// well clear of overflow.
///
/// `is_fresh` is fail-CLOSED on a missing or paused feed.
pub struct PerpEngineOracleAdapter;

impl pallet_perp_engine::PriceOracle for PerpEngineOracleAdapter {
    fn latest_price_e18(feed_id: &pallet_perp_engine::OracleFeedId) -> Option<u128> {
        let pair_id: pallet_oracle::PairId =
            sp_io::hashing::sha2_256(feed_id.as_slice());
        let (price_u64, decimals, _slot) =
            pallet_oracle::Pallet::<Runtime>::get_price(pair_id)?;
        // Scale `(price, decimals)` up to 1e18. Decimals ≤ 18 (bounded
        // by `submit_price` validation) so the exponent is non-negative.
        let shift = 18u32.saturating_sub(decimals as u32);
        let scale: u128 = 10u128.checked_pow(shift)?;
        (price_u64 as u128).checked_mul(scale)
    }

    fn price_age_blocks(feed_id: &pallet_perp_engine::OracleFeedId) -> u32 {
        let pair_id: pallet_oracle::PairId =
            sp_io::hashing::sha2_256(feed_id.as_slice());
        let feed = match pallet_oracle::Prices::<Runtime>::get(pair_id) {
            Some(f) => f,
            None => return u32::MAX,
        };
        let now: u32 = frame_system::Pallet::<Runtime>::block_number();
        let last: u32 = feed.last_update_block;
        now.saturating_sub(last)
    }

    fn is_fresh(feed_id: &pallet_perp_engine::OracleFeedId) -> bool {
        let pair_id: pallet_oracle::PairId =
            sp_io::hashing::sha2_256(feed_id.as_slice());
        let now_block: u32 = frame_system::Pallet::<Runtime>::block_number();
        let max_age: u64 = <Runtime as pallet_oracle::Config>::MaxStaleSlots::get();
        pallet_oracle::Pallet::<Runtime>::is_price_fresh(
            pair_id,
            now_block as u64,
            max_age,
        )
    }
}

impl pallet_perp_engine::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type PriceOracle = PerpEngineOracleAdapter;
    type PalletId = PerpEnginePalletId;
    type MateriosChainId = PerpEngineMateriosChainId;
    type MaxLeverageBps = PerpEngineMaxLeverageBps;
    type MinLeverageBps = PerpEngineMinLeverageBps;
    type MaxMarkets = PerpEngineMaxMarkets;
    type MaxFundingSamplesPerEpoch = PerpEngineMaxFundingSamplesPerEpoch;
    type KeeperBondMinimum = PerpEngineKeeperBondMinimum;
    type FreshnessLimitBlocks = PerpEngineFreshnessLimitBlocks;
    type MaxMarkBasisBps = PerpEngineMaxMarkBasisBps;
    type BadDebtCircuitBreakerThresholdE18 =
        PerpEngineBadDebtCircuitBreakerThresholdE18;
    type BadDebtWindowBlocks = PerpEngineBadDebtWindowBlocks;
    type MatraUsdFeedId = PerpEngineMatraUsdFeedId;
    type WithdrawDwellBlocks = PerpEngineWithdrawDwellBlocks;
}

// ---------------------------------------------------------------------------
// Construct runtime
// ---------------------------------------------------------------------------

// Pallet indices are EXPLICITLY pinned to defend against index drift when
// pallets are added or removed. An off-by-one shift silently invalidates
// every consumer of the runtime metadata. Removing a pallet leaves a gap
// at that index rather than shifting everything down by one.
construct_runtime! {
    pub enum Runtime {
        System: frame_system = 0,
        Timestamp: pallet_timestamp = 1,
        Aura: pallet_aura = 2,
        Grandpa: pallet_grandpa = 3,
        Balances: pallet_balances = 4,
        // index 5 reserved (vacant)
        Sudo: pallet_sudo = 6,
        Multisig: pallet_multisig = 7,
        Utility: pallet_utility = 8,
        Treasury: pallet_treasury = 9,
        Vesting: pallet_vesting = 10,
        OrinqReceipts: pallet_orinq_receipts = 11,
        Motra: pallet_motra = 12,
        // Sidechain MUST come after Aura (reads current slot from it).
        Sidechain: pallet_sidechain = 13,
        SessionCommitteeManagement: pallet_session_validator_management = 14,
        BlockRewards: pallet_block_rewards = 15,
        // pallet_session stub needed by pallet_grandpa for CurrentIndex.
        PalletSession: pallet_session = 16,
        // pallet_partner_chains_session MUST come last for correct init order.
        Session: pallet_partner_chains_session = 17,
        NativeTokenManagement: pallet_native_token_management = 18,
        IntentSettlement: pallet_intent_settlement = 19,
        TeeAttestation: pallet_tee_attestation = 20,
        Billing: pallet_billing = 21,
        Oracle: pallet_oracle = 22,
        PerpEngine: pallet_perp_engine = 23,
        // Second, independent path to Root (mainnet-resilience #492).
        Recovery: pallet_recovery = 24,
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
/// Executive: handles dispatch to the various modules. The 6th type
/// parameter is `COnRuntimeUpgrade` — migrations that run BEFORE
/// `AllPalletsWithSystem::on_runtime_upgrade`.
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
            use parity_scale_codec::Decode;
            let account_id = match AccountId::decode(&mut account.as_ref())
                { Ok(id) => id, Err(_) => return 0 };
            // Read-only lazy compute; includes pending MATRA-derived generation.
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
                0,
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

    impl authority_selection_inherents::filter_invalid_candidates::CandidateValidationApi<Block> for Runtime {
        fn validate_registered_candidate_data(
            mainchain_pub_key: &sidechain_domain::MainchainPublicKey,
            registration_data: &sidechain_domain::RegistrationData,
        ) -> Option<authority_selection_inherents::filter_invalid_candidates::RegistrationDataError> {
            authority_selection_inherents::filter_invalid_candidates::validate_registration_data(
                mainchain_pub_key,
                registration_data,
                Sidechain::genesis_utxo(),
            ).err()
        }
        fn validate_stake(
            stake: Option<sidechain_domain::StakeDelegation>,
        ) -> Option<authority_selection_inherents::filter_invalid_candidates::StakeError> {
            authority_selection_inherents::filter_invalid_candidates::validate_stake(stake).err()
        }
        fn validate_permissioned_candidate_data(
            candidate: sidechain_domain::PermissionedCandidateData,
        ) -> Option<authority_selection_inherents::filter_invalid_candidates::PermissionedCandidateDataError> {
            authority_selection_inherents::filter_invalid_candidates::validate_permissioned_candidate_data::<CrossChainPublic>(candidate).err()
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
            get_preset::<RuntimeGenesisConfig>(id, |preset_id| {
                // The `development` preset exists only to satisfy
                // frame-omni-bencher's default `--genesis-builder-preset=development`.
                // Returning `{}` lets `build_state` apply each pallet's genesis
                // defaults in isolation — several IOG partner-chains pallets ship
                // `#[derive(DefaultNoBound)]` GenesisConfigs whose serialized form
                // omits a `_marker: PhantomData<T>` field that the deserializer
                // demands, so serializing the default config round-trips into a
                // deserialize error.
                if preset_id.as_ref() == sp_genesis_builder::DEV_RUNTIME_PRESET.as_bytes() {
                    Some(b"{}".to_vec())
                } else {
                    None
                }
            })
        }

        fn preset_names() -> Vec<sp_genesis_builder::PresetId> {
            alloc::vec![sp_genesis_builder::PresetId::from(
                sp_genesis_builder::DEV_RUNTIME_PRESET,
            )]
        }
    }

    #[cfg(feature = "runtime-benchmarks")]
    impl frame_benchmarking::Benchmark<Block> for Runtime {
        fn benchmark_metadata(extra: bool) -> (
            Vec<frame_benchmarking::BenchmarkList>,
            Vec<frame_support::traits::StorageInfo>,
        ) {
            use frame_benchmarking::{Benchmarking, BenchmarkList};
            use frame_support::traits::StorageInfoTrait;
            use frame_system_benchmarking::Pallet as SystemBench;

            let mut list = Vec::<BenchmarkList>::new();
            list_benchmarks!(list, extra);

            let storage_info = AllPalletsWithSystem::storage_info();
            (list, storage_info)
        }

        fn dispatch_benchmark(
            config: frame_benchmarking::BenchmarkConfig,
        ) -> Result<Vec<frame_benchmarking::BenchmarkBatch>, sp_runtime::RuntimeString> {
            use frame_benchmarking::{Benchmarking, BenchmarkBatch};
            use frame_support::traits::WhitelistedStorageKeys;
            use frame_system_benchmarking::Pallet as SystemBench;
            use sp_storage::TrackedStorageKey;

            let whitelist: Vec<TrackedStorageKey> =
                AllPalletsWithSystem::whitelisted_storage_keys();

            let mut batches = Vec::<BenchmarkBatch>::new();
            let params = (&config, &whitelist);
            add_benchmarks!(params, batches);

            Ok(batches)
        }
    }
}

// `frame_system_benchmarking::Config` is implemented at crate root (rather
// than inside `dispatch_benchmark`) to avoid the rustc-1.80+
// `non_local_definitions` warning.
#[cfg(feature = "runtime-benchmarks")]
impl frame_system_benchmarking::Config for Runtime {}

#[cfg(feature = "runtime-benchmarks")]
frame_benchmarking::define_benchmarks!(
    [frame_system, SystemBench::<Runtime>]
    [pallet_balances, Balances]
    [pallet_timestamp, Timestamp]
    [pallet_intent_settlement, IntentSettlement]
    [pallet_oracle, Oracle]
    [pallet_perp_engine, PerpEngine]
);


