#![cfg_attr(not(feature = "std"), no_std)]
// `construct_runtime!` does a lot of recursion and requires us to increase the limit.
#![recursion_limit = "256"]

extern crate alloc;

#[cfg(test)]
mod tests;

// v5.1 Midnight-style fees (spec 202, 2026-04-21): the 40/30/20/10 MATRA
// fee-router (see `fee_router.rs` on main up to spec 201) is DELETED.
// MATRA is no longer charged on transactions — MOTRA is the sole tx-fee
// mechanism via `pallet_motra::fee::ChargeMotra`.
//
// The `pallet_transaction_payment` integration was ALSO removed in the
// HIGH #1 follow-up on the same spec (2026-04-21): it was never actually
// wired into `SignedExtra` in this runtime (see git history), so its
// `OnChargeTransaction` hook was dead code and `NoOpCharge` was dead
// scaffolding. The simpler surface is to delete the pallet entirely —
// `ChargeMotra` is the single fee authority in this runtime.
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
// No MATRA OnChargeTransaction adapter is installed — `pallet_transaction_
// payment` was removed entirely at spec 202 (see deletion note above in the
// `Transaction payment (REMOVED spec 202)` section).
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
    // 203 = MaxCommitteeSize raised 16 → 64 so the attestor committee can
    //        grow past the original 16-seat cap (GoFigure hit CommitteeFull
    //        at member #17 on 2026-04-21). Same bump also widens
    //        input_sanity::MAX_COMMITTEE_SIZE to 64 (decoupled from
    //        MAX_VALIDATORS) so Ariadne d-parameter sanitation does not
    //        silently reject d-params > 32 while the pallet would accept
    //        them. Transaction version unchanged.
    // 204 = Wave 2 W2.2: integrate `pallet_intent_settlement` at index 19
    //        (Aegis intent/claim layer). No storage migrations: the pallet
    //        starts with empty maps + zero-valued singletons. Committee
    //        membership is READ-ONLY, mirrored from OrinqReceipts via the
    //        `OrinqCommitteeAdapter` below — pallet_committee_governance is
    //        intentionally skipped (Option 2, user-confirmed 2026-04-24).
    //        Transaction version unchanged.
    // 205 = Consolidated runtime upgrade (2026-04-26). Three bundled changes:
    //        (1) Track A2 throughput: BlockWeights ref_time 2 s → 4 s,
    //            proof_size u64::MAX → 10 MB on Normal+Operational classes
    //            (NORMAL_DISPATCH_RATIO 75% unchanged).
    //        (2) Ariadne dedupe completeness fix: when valid candidate count
    //            ≤ requested committee size, bypass the with-replacement
    //            weighted sampler and return all distinct candidates in
    //            deterministic (account-id-sorted) order. Eliminates the
    //            chronic n=2-3 oscillation observed on the 4-validator
    //            cluster (see `feedback_committee_shrink_root_cause.md`).
    //        (3) IntentSettlementDefaultMinSignerThreshold 1 → 2: matches
    //            the Aegis 2-of-4 expectation; `settle_claim` and
    //            `credit_deposit` now require ≥2 valid + caller-bound sigs
    //            by default. `request_voucher` is unaffected (no sigs arg
    //            on-chain — separate pallet-code task #174).
    //        Transaction version unchanged — wire format identical.
    // 206 = Spec-206 bundle (2026-04-26):
    //        (1) PR #26: `request_voucher` gains a `signatures: Vec<(CommitteePubkey,
    //            CommitteeSig)>` envelope (M-of-N committee gate). BREAKING wire
    //            change for that one extrinsic — `transaction_version` bumps
    //            1 → 2 to refuse stale-format submissions from un-upgraded
    //            clients.
    //        (2) PR #27: new `settle_batch_atomic` extrinsic at call_index=9.
    //            Settles up to `MaxSettleBatch = 256` claims in one tx,
    //            amortising the dominant per-call M-of-N sig-verification
    //            cost. Lifts user-TPS ceiling from ~0.07 → ~10+ on this
    //            chain's weight budget. Pure addition; no migration.
    //        (3) Runtime wires new `MaxSettleBatch` constant + adds
    //            `pallet-intent-settlement/runtime-benchmarks` to the
    //            `runtime-benchmarks` feature gate.
    // 207 = Spec-207 bundle (2026-04-27): three new batch extrinsics on
    //        `pallet_intent_settlement` (pin tag = "spec207-bundle",
    //        commit cd50c61):
    //        (1) Task #210: `submit_batch_intents` at call_index=10. Submits
    //            up to `MaxSubmitBatch = 256` intents in one tx.
    //        (2) Task #211: `attest_batch_intents` at call_index=11. Attests
    //            up to `MaxAttestBatch = 256` intent_ids in one tx —
    //            collapses M*N per-epoch committee extrinsics into ONE call.
    //        (3) Task #212: `request_batch_vouchers` at call_index=12.
    //            Issues up to `MaxVoucherBatch = 256` vouchers in one tx
    //            (M-of-N gated, mirroring the spec-206 single-call envelope).
    //        Pure call-surface additions; no storage migration. Adding new
    //        call_indexes per project convention bumps `transaction_version`
    //        2 → 3 to refuse stale-format clients that don't recognise the
    //        new dispatchables.
    // 208 = Spec-208 (Task #233 / B3, 2026-04-27): widen all four batch
    //        bounds from 256 → 1024 (Track-B step B3, 4× lift in one shot).
    //          MaxSubmitBatch  : 256 → 1024
    //          MaxAttestBatch  : 256 → 1024
    //          MaxVoucherBatch : 256 → 1024
    //          MaxSettleBatch  : 256 → 1024
    //        Justification: empirical measurement on the live spec-207 chain
    //        (block 0xef7f7113…, 2026-04-27) recorded `submit_batch_intents`
    //        at N=256 producing dispatch_info.weight.proof_size = 1,327,104 B
    //        (= 12.66 % of the 10 MiB max_block / 16.88 % of the 7.5 MiB
    //        Normal-class budget). The pallet weight expression is exact and
    //        linear: proof_size = 16,384 + N · 5,120 B; ref_time = 50M + N · 5M.
    //        Linear extrapolation against the live BlockWeights:
    //          N= 512  →   2.64 MB  (25.16 % block, 33.54 % Normal)
    //          N=1024  →   5.26 MB  (50.16 % block, 66.88 % Normal)  <-- target
    //          N=2048  →  10.50 MB  (100.16 % block, 133.54 % Normal) DOES NOT FIT
    //        N=1024 is the largest power-of-two that fits the Normal-class
    //        proof_size budget with comfortable headroom (~8 % below the 75 %
    //        rule-of-thumb). N=2048 structurally exceeds even the 10 MiB
    //        whole-block budget. Going further would require lifting BlockWeights
    //        proof_size first (separate ceremony, not in scope for B3).
    //        No storage migration; no new call_indexes; the wire format is
    //        unchanged (BoundedVec encoding is identical for any T whose
    //        capacity exceeds the actual length).
    //        REVIEWER QUESTION (carried from the 512 staging): bumping
    //        `transaction_version` 3 → 4 is the conservative call. The on-wire
    //        SCALE encoding of the four batch extrinsics is byte-identical at
    //        any payload size that fit under the old bound (the BoundedVec
    //        generic only constrains decode-side rejection). A purist read
    //        says tx_version SHOULD stay at 3 because no client written for
    //        spec-207 will fail to decode a spec-208 chain's tx. The
    //        conservative read says any time the accepted-set of extrinsics
    //        changes (here: 257..=1024-entry batches now decode where they
    //        previously rejected) we should bump tx_version so old wallets
    //        refuse to sign things they couldn't have signed under the old
    //        runtime. Defaulting to the latter; flip back to 3 if reviewer
    //        prefers.
    // 209 = Spec-209 (Task #245 / #254, 2026-04-27): bundles ONE pallet fix
    //        and confirms (does not re-add) the IDP-None patch.
    //        (a) [materios-patch: ttl-fallback-sweep] — pallet-intent-settlement
    //            now ships an on_initialize fallback sweep that round-robins
    //            through `PendingBatches` (64 entries/block via new
    //            `FallbackSweepCursor`), terminalising past-TTL
    //            Pending/Attested intents that the fast-path
    //            `ExpiryQueue[ttl_block]` BoundedVec dropped on overflow.
    //            Root cause: `do_submit_intent` used best-effort `try_push`
    //            into a `MAX_EXPIRE_PER_BLOCK = 256` bucket, so any batch
    //            with N>256 entries sharing one ttl_block silently leaked
    //            768/1024 entries at spec-208's MaxBatch. 9_861/10_000
    //            `PendingBatches` were saturated by the time we caught it.
    //            Adds storage: `FallbackSweepCursor: u32` (ValueQuery=0),
    //            `FallbackSweepCount: u64` (ValueQuery=0). No migration —
    //            both default to 0 on first read post-upgrade.
    //            New event-reason variant `ExpiryReason::TTLFallback = 2`
    //            (additive). Recovery time at 10k saturation ≈ 16 min.
    //            See feedback_pallet_expiry_queue_overflow_silent.md.
    //        (b) [materios-patch: idp-none-fallback] — VERIFIED already
    //            inlined since spec-201 via the `[patch."partner-chains.git"]`
    //            redirect to `vendor/pallet-session-validator-management`.
    //            The wasm-runtime-overrides file in
    //            `materios-preprod/runtime-overrides/` has been DORMANT since
    //            the spec-202 cutover; the running on-chain WASM has carried
    //            the patch directly since then. Spec-209 keeps the same
    //            vendored fork (no source changes). This is the safety net
    //            for the upcoming mock→real Cardano follower transition.
    //        Pure additive change. No storage migration. `transaction_version`
    //        stays at 4 — call surface unchanged from spec-208.
    //
    // spec-210 (Task #59 / Phase-1 wedge audit): three small pallet patches
    // closing W-12, W-15, W-1.
    //   * pallet-orinq-receipts::bond() now does an explicit dust check
    //     before calling Currency::reserve(); silent mempool drop becomes
    //     a clear ExtrinsicFailed{Error::BondLeavesAccountDusty} (W-15).
    //   * pallet-orinq-receipts::set_bond_requirement() now refuses values
    //     below MIN_VIABLE_BOND=100 MATRA (Error::BondRequirementTooLow);
    //     prevents accidental sudo-zeroing → Sybil flood (W-12).
    //   * pallet-orinq-receipts::rotate_authorities REMOVED. Direct GRANDPA
    //     mutation via root extrinsic was the v3-era footgun that wedged
    //     finality every prior use (`feedback_rotate_authorities_wedge.md`).
    //     call_index(5) intentionally left unused — DO NOT REUSE for new
    //     extrinsics; clients may have cached the old encoding (W-1).
    // Pure additive (W-12/W-15) + removal (W-1). No storage migration.
    // `transaction_version` stays at 4 — removing an extrinsic doesn't
    // change encoding of others (call_index gap is harmless).
    //
    // spec-211 (Task #61 / Phase-1 wedge audit): GuardedSessionManager
    // wraps ValidatorManagementSessionManager. When pallet_grandpa's
    // PendingChange has been stuck for >100 blocks (~10 min at 6s),
    // ShouldEndSession returns false to refuse advancing the session —
    // prevents pallet_grandpa from overwriting SetIdSession[current_set_id]
    // on a subsequent failed schedule_change. Closes W-5 prevention; pairs
    // with the W-5 watchdog alert (#57) at the same threshold.
    // No storage migration needed. transaction_version still 4 — extrinsic
    // surface unchanged.
    //
    // spec-212 (Task #90): MaxCommitteeSize 64 → 256.
    //   On 2026-04-29 the network hit 63/64 attestors when txseppe's RISE
    //   team came in with 9 ARM64 HyperAI boxes. Spec-203's 64-seat cap
    //   was sized for ~4× headroom over the original 16-seat ceiling; we
    //   need similar headroom over today's 63 active. 256 gives 4× over
    //   current usage. Three constants tracked together (assertion-paired
    //   in source comments): pallet-orinq-receipts MaxCommitteeSize,
    //   IntentSettlement MaxCommittee, and input_sanity MAX_COMMITTEE_SIZE.
    //   Cap-only bump — BoundedBTreeSet/BoundedVec accept the larger bound
    //   without storage migration. Verified pre-merge: no committee-signed
    //   pre-image hash includes the cap value (would have caused
    //   CertHashMismatch per feedback_mofn_hash_determinism.md). Sig-verify
    //   weight upper-bound rises ~26ms per attest_availability_cert at
    //   max-fanout — well inside the 6s block budget.
    //   transaction_version stays at 4 — call surface unchanged.
    spec_version: 212,
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

/// Fraction of full block weight available to Normal-dispatch class.
///
/// Made `pub` at spec 205 (A2) so the throughput tests under
/// `tests/block_weights_throughput.rs` can pin-check the resulting
/// per-class weight ceilings against the same constant the runtime uses.
pub const NORMAL_DISPATCH_RATIO: sp_runtime::Perbill = sp_runtime::Perbill::from_percent(75);

// Spec 205 (Track A2 throughput tuning): block-weight budget = 4 s of
// compute + 10 MB of proof_size. Was 2 s + unbounded `u64::MAX`. The
// proof_size dimension is now finite as a defence-in-depth measure
// against pathological extrinsics inflating witness size.
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
                4u64 * WEIGHT_REF_TIME_PER_SECOND,
                10u64 * 1024 * 1024,
            ));
        })
        .for_class(frame_support::dispatch::DispatchClass::Operational, |weights| {
            weights.max_total = Some(Weight::from_parts(
                4u64 * WEIGHT_REF_TIME_PER_SECOND,
                10u64 * 1024 * 1024,
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
// Transaction payment (REMOVED spec 202)
// ---------------------------------------------------------------------------
//
// `pallet_transaction_payment` was removed from the runtime at spec 202 as
// part of the HIGH #1 follow-up to PR #9. Pre-202 the pallet was present in
// construct_runtime! but its `OnChargeTransaction` was never installed into
// `SignedExtra` — so the whole `withdraw_fee` / `correct_and_deposit_fee`
// plumbing was dead code. Keeping dead scaffolding around invites future
// regressions; we delete it entirely and let `ChargeMotra` be the single
// source of tx-fee truth.
//
// Wallets / explorers that previously queried `TransactionPaymentApi` must
// now query `MotraApi::estimate_fee(weight_ref_time)` for quotes — a MOTRA-
// denominated figure that matches the actual burn the sender will pay.
//
// Pallet index 5 is intentionally left unused in `construct_runtime!` below.
// Explicit index pins are added to every remaining pallet to prevent the
// drift-by-one cascade that `feedback_pallet_index_shift.md` warns about.

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
    /// Validator-emission treasury share (spec 202+). 15% of each era's
    /// validator-reserve emission is routed to `mat/trsy`, the rest goes
    /// to block-authoring validators pro-rata. Governance-tunable: change
    /// this value in a runtime upgrade to retune the validator↔treasury
    /// balance. Rounding residue always lands in treasury (safer sink).
    pub const TreasuryEmissionShare: Perbill = Perbill::from_percent(15);
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
    // Raised 16 → 64 in spec 203, then 64 → 256 in spec 212 (the network
    // hit 63/64 on 2026-04-29 when txseppe's 9-box HyperAI fleet asked to
    // join). 256 gives ~4× headroom over the spec-211 ceiling while keeping
    // sig-verify cost under one block budget (256 sr25519 verifies ≈ 26ms;
    // block budget is 6s). The paired `input_sanity::MAX_COMMITTEE_SIZE` and
    // `IntentSettlementMaxCommittee` below must track this — see
    // runtime/src/input_sanity.rs and the IntentSettlement parameter_types.
    type MaxCommitteeSize = ConstU32<256>;
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
    // Validator emission split knob (spec 202 onward). Governance can
    // retune the treasury share via runtime upgrade by changing the
    // `TreasuryEmissionShare` parameter_types value below — no code
    // change in the pallet needed.
    type TreasuryEmissionShare = TreasuryEmissionShare;
}

// ---------------------------------------------------------------------------
// Intent Settlement (Aegis Wave 2 W2.2)
// ---------------------------------------------------------------------------
//
// The `pallet_intent_settlement` pallet implements user-intent lifecycle,
// M-of-N committee attestation, Cardano-side settlement mirroring, and the
// per-account ADA credit ledger. Per user-confirmed Option 2 (2026-04-24)
// we do NOT wire `pallet_committee_governance`; instead the pallet's
// `CommitteeMembership` abstraction is satisfied by a READ-ONLY adapter
// over the existing `pallet_orinq_receipts` committee-set + threshold
// storage. The OrinqReceipts pallet remains the sole writer of committee
// membership; intent-settlement is a pure consumer.

/// Adapter exposing the on-chain `OrinqReceipts` committee set to
/// `pallet_intent_settlement`. Implements the full `IsCommitteeMember`
/// contract (membership predicate, size, threshold, and the
/// bidirectional `AccountId <-> [u8;32]` pubkey mapping).
///
/// For `AccountId = AccountId32` (this runtime's shape, derived from
/// `MultiSignature`) the pubkey IS the raw 32 bytes of the account, so
/// the mapping is injective and round-trips without registry storage.
pub struct OrinqCommitteeAdapter;

impl pallet_intent_settlement::IsCommitteeMember<AccountId> for OrinqCommitteeAdapter {
    fn is_member(who: &AccountId) -> bool {
        pallet_orinq_receipts::CommitteeMembers::<Runtime>::get().contains(who)
    }

    fn threshold() -> u32 {
        // OrinqReceipts threshold defaults to 1 for single-member bootstraps
        // (see pallet_orinq_receipts::AttestationThreshold docs). Clamp to
        // 1 so the intent-settlement M-of-N gate never reads as "0 sigs
        // required".
        pallet_orinq_receipts::AttestationThreshold::<Runtime>::get().max(1)
    }

    fn member_count() -> u32 {
        pallet_orinq_receipts::CommitteeMembers::<Runtime>::get().len() as u32
    }

    fn pubkey_of(who: &AccountId) -> [u8; 32] {
        // AccountId32 stores its pubkey as the inner `[u8; 32]`. `AsRef<[u8;32]>`
        // is implemented by `sp_runtime::AccountId32`, so this is a zero-copy view.
        let bytes: &[u8; 32] = who.as_ref();
        *bytes
    }

    fn account_of_pubkey(pubkey: &[u8; 32]) -> Option<AccountId> {
        // Reverse mapping: AccountId32::from([u8;32]) is infallible; we gate
        // the return on current committee membership so callers can't forge
        // a non-member account by supplying an arbitrary pubkey.
        let candidate = AccountId::from(*pubkey);
        if <Self as pallet_intent_settlement::IsCommitteeMember<AccountId>>::is_member(&candidate) {
            Some(candidate)
        } else {
            None
        }
    }
}

parameter_types! {
    /// Matches the widened MaxCommitteeSize=256 pinned in OrinqReceipts (raised
    /// 16 → 64 in spec 203, then 64 → 256 in spec 212). Keeping the
    /// intent-settlement cap in lockstep avoids an adapter mismatch where
    /// OrinqReceipts admits a member past intent-settlement's BoundedVec cap.
    pub const IntentSettlementMaxCommittee: u32 = 256;
    /// TTL-sweep bound per block; bounds the on_initialize cost.
    pub const IntentSettlementMaxExpirePerBlock: u32 = 64;
    /// Default intent TTL: 600 blocks ≈ 1h @ 6s. Matches spec v1 §3.3.
    pub const IntentSettlementDefaultIntentTTL: BlockNumber = 600;
    /// Default claim TTL: 28_800 blocks ≈ 48h @ 6s. Matches spec v1 §3.3.
    pub const IntentSettlementDefaultClaimTTL: BlockNumber = 28_800;
    /// Upper bound on `PendingBatches` index (keeper polls in chunks).
    pub const IntentSettlementMaxPendingBatches: u32 = 10_000;
    /// Default minimum committee-signer threshold for `settle_claim` and
    /// `credit_deposit` (the two intent-settlement extrinsics that take a
    /// `signatures: Vec<(CommitteePubkey, CommitteeSig)>` arg on-chain).
    ///
    /// Spec 205 (2026-04-26) bumps this 1 → 2 to match the Aegis 2-of-4
    /// signer expectation. The bump is a tightening: with default = 1 the
    /// pallet still required `caller_present` (the calling account must be
    /// in the signer set), so threshold-1 was effectively "caller's own
    /// sig only". Default = 2 forces a co-signer in addition to the caller.
    ///
    /// Storage semantics: the on-chain `MinSignerThreshold` storage value
    /// uses 0 as a sentinel meaning "fall back to this default" (see
    /// `pallet_intent_settlement::lib.rs` lines 280-282). Live preprod has
    /// the storage at 0, so the spec-205 upgrade takes effect immediately
    /// at the apply-block — no storage migration required.
    ///
    /// `request_voucher` is **unaffected** by this constant: that
    /// extrinsic does not have a `signatures` argument on-chain. Closing
    /// that gap is a separate pallet-code change, tracked as task #174.
    /// See `/tmp/minsigner-threshold-fix-report.md` for the diagnosis.
    ///
    /// Governance can still adjust at runtime via `set_min_signer_threshold`
    /// without a further code upgrade.
    pub const IntentSettlementDefaultMinSignerThreshold: u32 = 2;
    /// Spec 206 (Task #177): maximum number of `SettleBatchEntry` items in a
    /// single `settle_batch_atomic` call. Set to 256 to match the pallet's
    /// canonical `types::MAX_SETTLE_BATCH`. The bound must fit within the
    /// normal-class block budget alongside the M-of-N signature bundle —
    /// benchmark-verified at N ∈ {1, 8, 64, 256}.
    ///
    /// Spec 208 (Task #233 / B3, 2026-04-27): widened 256 → 1024. Empirical
    /// measurement on live spec-207 (block 0xef7f7113…, N=256) recorded
    /// `submit_batch_intents` proof_size = 1,327,104 B (12.66 % block /
    /// 16.88 % Normal). Linear extrapolation puts N=1024 at 50.16 % block /
    /// 66.88 % Normal — comfortable under the 75 % rule-of-thumb. N=2048
    /// would exceed 100 % block budget (133.54 % Normal). The pallet's
    /// `types::MAX_SETTLE_BATCH` constant is documentation-only and is
    /// not modified by this widening (the pallet uses the runtime's
    /// `<T as Config>::MaxSettleBatch` for the actual BoundedVec bound).
    pub const IntentSettlementMaxSettleBatch: u32 = 1024;
    /// Spec 207 (Task #210): maximum number of `SubmitIntentEntry` items in a
    /// single `submit_batch_intents` call (call_index=10). Canonical default
    /// `types::MAX_SUBMIT_BATCH = 256` — only constrained by per-block
    /// normal-class extrinsic budget plus PendingBatches index headroom.
    ///
    /// Spec 208 (Task #233 / B3, 2026-04-27): widened 256 → 1024. The pallet
    /// weight expression is exact and linear:
    ///   proof_size = 16,384 + N · 5,120 B
    ///   ref_time   = 50M + N · 5M ps
    /// At N=1024: proof_size = 5,259,264 B = 50.16 % of the 10 MiB max_block /
    /// 66.88 % of the 7.5 MiB Normal-class budget; ref_time = 5.17 B ps =
    /// 0.13 % of the 4 s block budget. submit_batch_intents is the
    /// proof_size-dominant call (the M-of-N committee batches dispatch as
    /// Operational and report proof_size 0 in spec-207).
    pub const IntentSettlementMaxSubmitBatch: u32 = 1024;
    /// Spec 207 (Task #211): maximum number of intents attested in a single
    /// `attest_batch_intents` call (call_index=11). Canonical default
    /// `types::MAX_ATTEST_BATCH = 256`. Collapses M*N per-epoch committee
    /// extrinsics into ONE batch call.
    ///
    /// Spec 208 (Task #233 / B3): widened 256 → 1024. Per-intent attestation
    /// is dominated by storage I/O, ~3M ref_time per entry; at 1024 entries
    /// base 50M + 1024 · 3M ≈ 3.12 B ref_time, ~0.08 % of the 4 s budget.
    /// Operational class so the proof_size budget is the full 10 MiB.
    pub const IntentSettlementMaxAttestBatch: u32 = 1024;
    /// Spec 207 (Task #212): maximum number of vouchers issued in a single
    /// `request_batch_vouchers` call (call_index=12). Canonical default
    /// `types::MAX_VOUCHER_BATCH = 256`.
    ///
    /// Spec 208 (Task #233 / B3): widened 256 → 1024. Voucher-batch is the
    /// ref_time-heaviest stage — base 50M + 1024 · 10M ≈ 10.3 B ref_time,
    /// still only ~0.26 % of the 4 s block budget. Operational class.
    pub const IntentSettlementMaxVoucherBatch: u32 = 1024;
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
    type SigVerifier = pallet_intent_settlement::Sr25519Verifier;
    type MaxSettleBatch = IntentSettlementMaxSettleBatch;
    type MaxSubmitBatch = IntentSettlementMaxSubmitBatch;
    type MaxAttestBatch = IntentSettlementMaxAttestBatch;
    type MaxVoucherBatch = IntentSettlementMaxVoucherBatch;
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
// IOG Partner Chains: Partner Chains Session — guarded for W-5 prevention
// ---------------------------------------------------------------------------
//
// W-5 prevention (spec-211, 2026-04-28): wrap ValidatorManagementSessionManager
// with a guard that REFUSES to end the session if `pallet_grandpa::PendingChange`
// has been stuck for more than `MAX_PENDING_CHANGE_STALL_BLOCKS` blocks.
//
// Rationale: when `should_end_session` returns true, partner-chains-session
// dispatches `SessionHandler.on_new_session` → pallet_grandpa.on_new_session
// → pallet_grandpa.schedule_change. If a previous PendingChange hasn't
// finalized, schedule_change returns Err(ChangePending) — but pallet_grandpa
// STILL overwrites `SetIdSession[current_set_id]` with the new session_index
// (substrate/frame/grandpa/src/lib.rs:622, unconditional after the if/else).
// Voters then dereference current_set_id → wrong session_index → wrong
// authorities → finality stalls. THIS is the v5→v6 reset trigger class.
//
// The fix: refuse to end the session at all while a stuck PendingChange
// exists. The committee transition is delayed (operator must resolve the
// finality stall, e.g. by sudo-clearing PendingChange), but no SetIdSession
// corruption occurs. Combined with the watchdog detection alert (#57)
// firing at 10 min, this gives operators a time-window to react before any
// state corruption and a hard guard if they miss the alert.

/// Threshold (blocks) above which a `pallet_grandpa::PendingChange` is
/// considered stuck. 100 blocks ≈ 10 min at 6s/block — same threshold
/// as the W-5 watchdog alert in `materios-watchdog`.
pub const MAX_PENDING_CHANGE_STALL_BLOCKS: BlockNumber = 100;

/// Mirror of `pallet_grandpa::StoredPendingChange` (which is `pub(super)`
/// in v38.0.0 so we cannot import it directly). Keeping the layout
/// in lock-step with substrate is asserted by the existing
/// `grandpa_pending_change_layout_compatibility` test in
/// `pallets/orinq-receipts/src/tests.rs`. If this fails to decode after
/// an SDK upgrade, inspect the new StoredPendingChange definition in
/// `substrate/frame/grandpa/src/lib.rs` and update both this struct and
/// the test fixture in lockstep.
#[derive(parity_scale_codec::Encode, parity_scale_codec::Decode)]
struct GrandpaPendingChangeMirror {
    scheduled_at: BlockNumber,
    delay: BlockNumber,
    next_authorities: sp_consensus_grandpa::AuthorityList,
    forced: Option<BlockNumber>,
}

/// Helper: returns true iff Grandpa::PendingChange has been waiting longer
/// than `MAX_PENDING_CHANGE_STALL_BLOCKS` at the given block height.
fn grandpa_pending_change_stuck(now: BlockNumber) -> bool {
    let pending_key =
        frame_support::storage::storage_prefix(b"Grandpa", b"PendingChange");
    if let Some(pending) =
        frame_support::storage::unhashed::get::<GrandpaPendingChangeMirror>(&pending_key)
    {
        let elapsed = now.saturating_sub(pending.scheduled_at);
        if elapsed > MAX_PENDING_CHANGE_STALL_BLOCKS {
            log::warn!(
                target: "materios::grandpa-guard",
                "W-5 GUARD: Grandpa::PendingChange stuck for {} blocks \
                 (scheduled_at={}, current={}, threshold={}). \
                 Resolve the finality stall (sudo-clear PendingChange or wait for \
                 a finalization that catches up the queue) before the next session \
                 can advance. See feedback_grandpa.md.",
                elapsed, pending.scheduled_at, now, MAX_PENDING_CHANGE_STALL_BLOCKS,
            );
            return true;
        }
    }
    false
}

/// Wrapper around `ValidatorManagementSessionManager` that refuses to end
/// the session if `pallet_grandpa::PendingChange` is stuck. See
/// `MAX_PENDING_CHANGE_STALL_BLOCKS` doc + the long comment above.
///
/// Bound to the concrete `Runtime` type (rather than generic `T`) because
/// the `BlockNumber = u32` concrete decode of `GrandpaPendingChangeMirror`
/// only makes sense at the runtime layer.
pub struct GuardedSessionManager;

impl pallet_partner_chains_session::ShouldEndSession<BlockNumber>
    for GuardedSessionManager
{
    fn should_end_session(n: BlockNumber) -> bool {
        if grandpa_pending_change_stuck(n) {
            return false;
        }
        ValidatorManagementSessionManager::<Runtime>::should_end_session(n)
    }
}

impl
    pallet_partner_chains_session::SessionManager<
        <Runtime as frame_system::Config>::AccountId,
        opaque::SessionKeys,
    > for GuardedSessionManager
{
    fn new_session_genesis(
        new_index: sp_staking::SessionIndex,
    ) -> Option<sp_std::vec::Vec<(<Runtime as frame_system::Config>::AccountId, opaque::SessionKeys)>> {
        ValidatorManagementSessionManager::<Runtime>::new_session_genesis(new_index)
    }
    fn new_session(
        new_index: sp_staking::SessionIndex,
    ) -> Option<sp_std::vec::Vec<(<Runtime as frame_system::Config>::AccountId, opaque::SessionKeys)>> {
        ValidatorManagementSessionManager::<Runtime>::new_session(new_index)
    }
    fn end_session(end_index: sp_staking::SessionIndex) {
        ValidatorManagementSessionManager::<Runtime>::end_session(end_index)
    }
    fn start_session(start_index: sp_staking::SessionIndex) {
        ValidatorManagementSessionManager::<Runtime>::start_session(start_index)
    }
}

impl pallet_partner_chains_session::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type ValidatorId = <Self as frame_system::Config>::AccountId;
    type ShouldEndSession = GuardedSessionManager;
    type NextSessionRotation = ();
    type SessionManager = GuardedSessionManager;
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

// Pallet indices are EXPLICITLY pinned (= N) to defend against index drift
// when pallets are added or removed. See feedback_pallet_index_shift.md: an
// off-by-one shift silently invalidates every consumer of the runtime
// metadata (explorers, wallets, SDK type generators). By pinning each
// index, removing a pallet leaves a gap at that index rather than shifting
// everything after it down by one.
//
// Pallet index 5 is reserved — previously `pallet_transaction_payment` —
// and intentionally left vacant. Removing `pallet_transaction_payment`
// entirely (HIGH #1, spec 202 / 2026-04-21) WITHOUT shifting subsequent
// indices keeps every downstream consumer stable across the 201→202
// upgrade. MOTRA burn-on-use via `ChargeMotra` SignedExtension is the sole
// tx-fee mechanism; there is no `TransactionPayment` pallet or RuntimeApi
// on this chain anymore.
construct_runtime! {
    pub enum Runtime {
        System: frame_system = 0,
        Timestamp: pallet_timestamp = 1,
        Aura: pallet_aura = 2,
        Grandpa: pallet_grandpa = 3,
        Balances: pallet_balances = 4,
        // [index 5 reserved — previously `pallet_transaction_payment`]
        Sudo: pallet_sudo = 6,
        Multisig: pallet_multisig = 7,
        Utility: pallet_utility = 8,
        // v5.1 tokenomics foundation
        Treasury: pallet_treasury = 9,
        Vesting: pallet_vesting = 10,
        OrinqReceipts: pallet_orinq_receipts = 11,
        Motra: pallet_motra = 12,
        // IOG Partner Chains pallets
        // Sidechain must come after Aura (reads current slot from it)
        Sidechain: pallet_sidechain = 13,
        SessionCommitteeManagement: pallet_session_validator_management = 14,
        BlockRewards: pallet_block_rewards = 15,
        // pallet_session stub (needed by pallet_grandpa for CurrentIndex)
        PalletSession: pallet_session = 16,
        // pallet_partner_chains_session must come last for correct initialization order
        Session: pallet_partner_chains_session = 17,
        NativeTokenManagement: pallet_native_token_management = 18,
        // Wave 2 W2.2 (spec 204): Aegis intent-settlement layer. Appended at
        // index 19 — all preceding indices remain pinned to defend metadata
        // stability for wallets / explorers / SDK type generators.
        IntentSettlement: pallet_intent_settlement = 19,
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

    // NOTE: `pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi`
    // is NOT implemented — the pallet was removed from the runtime at spec 202.
    // Wallets / explorers should query `MotraApi::estimate_fee` for MOTRA-
    // denominated fee quotes. The previous `query_info` / `query_fee_details`
    // / `query_weight_to_fee` / `query_length_to_fee` surface returned MATRA
    // figures that were never actually charged (NoOpCharge) — removing the
    // RPC eliminates the misleading quote.

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


