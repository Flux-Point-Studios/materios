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
    // 205 = Wave 3 Phase 2: integrate `pallet_tee_attestation` at index 20
    //        (TEE attestation primitive, ARM TrustZone via vendored Acurast
    //        verifier — see PR #17). Purely additive — no storage migrations,
    //        all maps start empty, the kill-switch `Disabled` defaults `true`
    //        at genesis via the pallet's `DefaultDisabled<T>` type-value.
    //        Sudo flips the switch via `set_disabled` post-deploy once Phase
    //        2.5 ships challenge-binding (security-review H-3 mitigation).
    //        Transaction version unchanged (purely additive call surface).
    // 206-215 = source-tree baseline diverged from deployed preprod during
    //        the spec-209..215 in-flight patch series. The deployed runtime
    //        on preprod is currently at `spec_version: 215, tx_version: 2`
    //        via `--wasm-runtime-overrides`. The source-tree baseline this
    //        PR branches from (origin/main) was 205. Bumping directly to
    //        216 below re-takes the lead from the deployed override chain
    //        — substrate refuses runtime upgrades whose version is <= the
    //        running version (the W-2 pitfall, see feedback_large_runtime
    //        _upgrade.md), so a 206 source-bump would be DOA on preprod.
    //        `tx_version` follows the deployed 2.
    // 216 = Phase 2.A: add `pallet_billing` at index 21 (prepaid MATRA
    //        balance + 402 billing — see PRs #19 + #20 + #21).
    //        `DebitsEnabled` defaults `false` at genesis — purely additive
    //        call surface, no behavior change until governance flips the
    //        kill-switch in Phase 2.B. `RequestIdRetentionBlocks` = 14_400
    //        (~1 day at 6s blocks) bounds idempotency-replay storage
    //        growth. Transaction version unchanged from deployed 2 (no
    //        existing extrinsic signature changed, only new ones added).
    // 217 = pallet-billing PR #20 security review L-2 (task #226): add
    //        `MaxPruneBatch = 256` Config constant + matching
    //        `PruneBatchTooLarge` error, and gate `prune_paid_requests`
    //        with `ensure!(ids.len() <= MaxPruneBatch)`. Closes a DoS
    //        lever where a malicious keeper could submit an unbounded
    //        Vec<(AccountId, H256)> whose linear-in-n declared weight
    //        exceeds the per-block normal-class budget. Behavior change
    //        is one-sided (existing legitimate keepers send batches <<
    //        256, so they're unaffected); only new failure path is the
    //        explicit reject above the cap. New `#[pallet::constant]`
    //        bumps runtime metadata → spec_version bump required even
    //        though the call signature itself is unchanged. tx_version
    //        stays at 2 — no existing extrinsic signature changed.
    //        NOTE: spec-217 was ALSO hot-deployed via wasm-runtime-
    //        override and accidentally reverted `MaxCommitteeSize`
    //        96 → 64 (see 218 below). The MaxPruneBatch landing here
    //        is the source-tree-correct version of the 217 bump.
    // 218 = (deployed via wasm-runtime-override) — restored
    //        `OrinqReceipts::MaxCommitteeSize` 64 → 96 (and
    //        `input_sanity::MAX_COMMITTEE_SIZE` in lockstep). Hotfix for
    //        the spec-217 cap regression.
    // 219 = C-deep / SCALE-canonical availability cert. Moves cert-hash
    //        canonicalisation from off-chain CBOR (Python `build_cert`,
    //        already retired in operator-kit PR #23) onto chain via a
    //        fixed-width 202-byte SCALE `Cert` struct (see
    //        `pallets/orinq-receipts/src/types.rs::Cert`).
    //        `attest_availability_cert` now requires `claimed_hash` to
    //        equal `Pallet::canonical_cert_hash(receipt_id)`; any mismatch
    //        increments `BadAttestStrikes<attester>` and, at threshold,
    //        triggers `auto_slash_for_bad_attest`. `BadAttestSlashThreshold`
    //        is seeded to 1 (aggressive flush) via `on_runtime_upgrade`;
    //        governance raises to 3 once the flush wave settles (~24-48h
    //        post-activation). Plus: pin `MaxCommitteeSize = 96` in source
    //        tree to match the live spec-218 hotfix and prevent a second
    //        96 → 64 regression — see the 217/218 comments above and
    //        `feedback_large_runtime_upgrade.md`. Extrinsic signature is
    //        type-stable (`(H256, [u8;32])` → `(H256, [u8;32])`, same
    //        call_index 3) so `transaction_version` stays at 2.
    // 220 = (deployed via wasm-runtime-override 2026-05-13) — settle_claim
    //        B+D L1 verification (task #78 mis-sec P0). Splits the legacy
    //        unsigned `settle_claim` into two phases:
    //          * `request_settle(claim_id, evidence)` — permissionless;
    //            anyone can post once they observe the matching Cardano
    //            `RequestVoucher` redeemer tx. Pins `SettlementEvidence`
    //            (cardano_tx_hash, observed_at_depth, observed_slot,
    //            mainchain_genesis_hash[32], policy_id_witness[32]).
    //          * `attest_settle(claim_id, signatures)` — committee posts
    //            M-of-N sigs over the canonical STCA payload (209-byte
    //            preimage). Pallet rebuilds the digest from chain-state-
    //            derived inputs at verify time. Closes the trust gap on
    //            the legacy unsigned `settle_claim` extrinsic. New Config
    //            items: `MinFinalityDepth = 15`, `SettlementRequestTtl =
    //            2400` (~4h @ 6s), `MainchainGenesisHash = preprod 162d29c4`.
    //        Legacy `settle_claim` returns `DeprecatedExtrinsic` after
    //        `SettleClaimCutoverBlock = upgrade_block + 50` (grace window
    //        for in-flight keepers to redeploy). This source bump catches
    //        main up to the live spec-220 WASM — the source tree at origin/
    //        main was at 219 with IS rev `1e4dc6c`; this PR bumps the IS
    //        pin to `6125ae4` which includes both #266 (settle B+D) and
    //        #267 (expire B+D).
    // 221 = (deployed via wasm-runtime-override 2026-05-14) — expire_policy
    //        B+D symmetric path (task #267 mis-sec P0 followup). Same
    //        shape as spec-220 settle B+D but for `expire_policy_mirror`:
    //          * `request_expire_policy(intent_id, tx_hash, evidence)`
    //            — permissionless observer posts once they see the
    //            Cardano `Expire` redeemer tx. Pins `ExpiryEvidence`.
    //          * `attest_expire_policy(intent_id, signatures)` — committee
    //            posts M-of-N sigs over the canonical EXPP payload
    //            (172-byte preimage).
    //        Legacy `expire_policy_mirror` returns `DeprecatedExtrinsic`
    //        after `PolicyExpireCutoverBlock = upgrade_block + 50`. Reuses
    //        the spec-220 Config items (`MinFinalityDepth`,
    //        `SettlementRequestTtl`, `MainchainGenesisHash`,
    //        `MateriosChainId`, `MaxCommittee`). New errors:
    //        `ExpiryRequestMissing`, `ExpiryRequestExpired`,
    //        `ExpiryRequestAlreadyExists`, `IntentNotEligibleForExpiry`,
    //        `ExpiryEvidenceMismatch`. Source-bump same as 220 — this
    //        version pinned only on chain via wasm-runtime-override; this
    //        PR catches main up.
    // 222 = MON Phase 1 — wire `pallet_oracle` into the runtime at index
    //        22. M-of-N price oracle: committee attestors sign the
    //        canonical PRIC payload (85-byte preimage, `blake2_256(b"PRIC"
    //        || materios_chain_id(32B) || pair_id(32B) || price(LE u64,
    //        8B) || decimals(u8, 1B) || slot_observed(LE u64, 8B))`) and
    //        the pallet aggregates to `Prices[pair_id]` once the per-pair
    //        threshold (`MinAttestorThreshold`) is crossed. Sudo-managed
    //        attestor registry in v1 via `register_attestor(pair_id,
    //        pubkey)`; v2 swaps to bonded permissionless. Config items:
    //        `MateriosChainId` (live preprod genesis `0e46e33f...`),
    //        `MinAttestorThreshold = 1` (Phase 1A single-publisher mode —
    //        Aegis publisher submits and the value lands directly in
    //        `Prices`; Phase 1B raises to ≥2 once a second publisher
    //        identity boots), `MaxAttestors = 16` (per-pair roster cap),
    //        `MaxStaleSlots = 60` (~6min @ 6s), `MaxFutureSlots = 10`
    //        (~1min anti-front-run tolerance). `AttestorRegistry` is the
    //        runtime-level `PalletOracleAttestorRegistry` adapter which
    //        reads from `pallet_oracle::Attestors` storage and maps
    //        `AccountId32 <-> [u8;32]` via `AsRef<[u8;32]>` (same zero-
    //        copy pattern as `OrinqCommitteeAdapter::pubkey_of`). Closes
    //        runtime side of task #268 (MON Phase 1) — see PRs #35 +
    //        #36 on materios-intent-settlement, design memo at
    //        `/home/deci/work/mon-phase1-aegis-extend-design.md`, and
    //        Aegis publisher rail PR #9 on aegis-publisher (`publisher/
    //        materios_rail.py` byte-pinned to the PRIC payload above).
    //        Purely additive — no existing extrinsic signature changed,
    //        `transaction_version` stays at 2.
    // 223 = MON Phase 1B — raise `OracleMinAttestorThreshold` from 1 to 2.
    //        Phase 1A shipped with M=1 single-publisher mode (live since
    //        spec-222 / block 202156). On 2026-05-15 a second standalone
    //        sr25519 attestor came up on Gemtek (ss58 `5DvG6sBxzRoSzgxMt6xu…`,
    //        pubkey `0x5207cdcb…c910`, registered at block 202344). Both
    //        attestors are now signing the same `(pair_id, slot_observed)`
    //        observations thanks to the `_SLOT_BUCKET = 10` floor in
    //        `materios_rail.py` (aegis-publisher PR #10, merged
    //        `f81f1b42…`). Raising the threshold to 2 turns on the real
    //        M-of-N aggregation gate: the pallet now demands ≥2 observations
    //        in the same `PendingAttestations[pair_id, slot_observed]`
    //        bundle before it writes `Prices[pair_id]` and emits
    //        `PriceUpdated`. The pallet recomputes the gate on every
    //        `submit_price` so no migration is needed — the threshold
    //        change takes effect at the next bundled submission post-
    //        upgrade.
    //        NO new Config items, NO new extrinsic, NO new storage. Pure
    //        constant retune. `transaction_version` stays at 2.
    // 224 = MON Phase 1C — raise `OracleMinAttestorThreshold` from 2 to 3.
    //        Third standalone sr25519 attestor came up on Node-3 alongside
    //        Node-2's Aegis publisher and Gemtek's attestor-2 (ss58
    //        `5FX4JQVhY…hPZL`, pubkey `0x98cde690…ce04`, registered at
    //        block ~202430). All three attestors run with the
    //        `_SLOT_BUCKET = 10` floor and tick every 60s — observations
    //        from the three independent processes resolve to the same
    //        `slot_observed` bucket within a ~60s window. Raising the
    //        threshold from 2 to 3 turns on full-quorum aggregation:
    //        every `Prices[pair_id]` update now carries the median of
    //        three independent observations.
    //        Same in-flight-safe semantics as spec-223 — the pallet
    //        rebuilds the gate on every `submit_price`, no migration.
    //        Pure constant retune. `transaction_version` stays at 2.
    // 225 = #84 mis-sec P1 — settle_claim bond + slash. New extrinsics on
    //        `pallet_intent_settlement` at IS rev `7334b61e` (post PR #38
    //        merge on materios-intent-settlement):
    //          * `post_settlement_bond(claim_id, amount)` — requester
    //            reserves `amount` via `Currency::reserve` while their
    //            `request_settle` evidence sits pending. Opt-in by
    //            default (`MinSettlementBond = 0`); production can raise
    //            via governance once a credible MATRA-denominated value
    //            surface lands.
    //          * `slash_bad_settlement_evidence(claim_id, fraud_proof)` —
    //            permissionless watcher posts a SCALE-encoded FRAU
    //            preimage proving the bonded `SettlementEvidence` was
    //            fraudulent. On verify, the bond is `slash_reserved`-d:
    //            `SlashWatcherShareBps / 10_000` to the watcher and the
    //            rest `repatriate_reserved`-d to the runtime treasury
    //            (`TreasuryPalletId = PalletId(*b"mat/trsy")`).
    //          * `release_settlement_bond(claim_id)` — gated by
    //            `BondReleaseDelayBlocks` (= 2 × `MinFinalityDepth`) and
    //            successful `attest_settle`. Returns the reserve to the
    //            original poster.
    //        Storage migration v2 → v3 chains on `OnRuntimeUpgrade`:
    //        widens existing `ClaimSettlementRequests` records with a
    //        new `bond_amount: u128` field (defaults to 0 for in-flight
    //        records that pre-date the upgrade, so the legacy
    //        permissionless `request_settle` flow keeps working
    //        unchanged). Bundled `BondMigrationProgress` cursor caps
    //        per-block migration work at `MAX_MIGRATE_REQUESTS = 50`.
    //        Watcher-share basis points clamp at the call site to
    //        `[0, 10_000]`; a misconfigured runtime can never pay out
    //        more than the bond.
    //        New `Config` items (4 new + 1 reuse):
    //          * `Currency` = `Balances` — reuses pallet_balances surface
    //            (same `ReservableCurrency<AccountId>` already used by
    //            the runtime treasury + attestor reserve pot).
    //          * `SlashWatcherShareBps = 5000` — 50% bounty per design
    //            memo §6 #9 starting point. Governance-tunable.
    //          * `BondReleaseDelayBlocks = 30` — 2 × `MinFinalityDepth`
    //            (= 2 × 15) so Cardano has had two finality windows to
    //            surface any reorg before the bond is returned.
    //          * `MinSettlementBond = 0` — opt-in default; production
    //            bumps via governance.
    //          * `SettlementTreasuryPalletId` = existing
    //            `TreasuryPalletId` (`PalletId(*b"mat/trsy")`). REUSE
    //            of the runtime treasury convention — slashed-bond
    //            destination matches every other slash flow in the
    //            runtime.
    //        Operational follow-ups queued before this WASM activates:
    //          * #295 — pre-fund `mat/trsy` (derived account
    //            `5EYCAeC2qY9TuwAccQS5Y6Q6FcFc7uM2cYKBGm4drbnGtaPv`)
    //            with `ExistentialDeposit` so `repatriate_reserved` can't
    //            stall on a non-existent destination at spec activation.
    //          * #296 — SDK/keeper UX guard against bonding TTL-expired
    //            `ClaimSettlementRequests`.
    //          * #297 — widen `BondMigrationProgress` cursor bound vs
    //            `MAX_MIGRATE_REQUESTS = 50` so a partial-migration
    //            cursor can't overflow `u32::MAX`.
    //        Pure additive — no existing extrinsic signature changed,
    //        `transaction_version` stays at 2.
    // 226 = #259 — pallet-perp-engine v0 runtime wire-up (PR-E). Sourced from
    //        `materios-intent-settlement` rev `c95e5edb` (post-PR-#41 PR-D
    //        merge tip; supersedes the spec-225 pin at rev `7334b61e`):
    //          - 8 permissionless / sudo extrinsics on `pallet_perp_engine`:
    //              * `governance_set_market(market_id, MarketConfig)` —
    //                sudo-only registration of a new market (call_index 0).
    //              * `open_position(market_id, direction, size_e8,
    //                leverage_bps)` — permissionless.
    //              * `close_position(market_id)` — permissionless;
    //                works at the cached mark even when the oracle is stale
    //                (per spec §5.5 "closes succeed on a stale feed").
    //              * `deposit_margin(amount_motra)` — MOTRA → pMATRA-USD
    //                conversion at the live MATRA/USD rate; pins
    //                `MarginAccount.weighted_deposit_rate_e18` for
    //                snapshot-rate withdraw accounting.
    //              * `withdraw_margin(amount_e18)` — gated by 24h
    //                `WithdrawDwellBlocks` AND post-withdraw margin-equity
    //                check; clamps MOTRA payout to the asymmetric
    //                snapshot-vs-live rate to bound volatile-collateral
    //                drawdown risk (cf. `feedback_u256_weighted_avg_volatile_
    //                collateral.md`).
    //              * `adjust_leverage(market_id, new_leverage_bps)` —
    //                permissionless re-leverage within the market's
    //                governance-set band.
    //              * `liquidate(market_id, who)` — permissionless,
    //                bond-gated. Slashes the FULL `KeeperBondMinimum`
    //                on a false trigger; on a valid liquidation pays
    //                `LiquidationFee` split keeper/treasury (per
    //                `MarketConfig.liquidation_fee_bps`). Returns
    //                `Ok(())` on punish so `with_storage_layer` does NOT
    //                roll back the slash writes — callers MUST scan
    //                `triggered_events` (Ok-return + emit-on-fail
    //                pattern per `feedback_substrate_ok_return_emit_on_
    //                fail_pattern.md`).
    //              * `settle_funding(market_id, epoch)` — permissionless,
    //                idempotent. Computes the trimmed-median premium
    //                index for the epoch, advances
    //                `CumulativeFundingIndex[market]`, and prunes the
    //                bounded `PremiumIndexSamples` ring.
    //          - 2 keeper bond extrinsics (PR-D, call_index 8/9):
    //              * `reserve_keeper_bond(market_id, amount)` — keeper
    //                reserves ≥ `KeeperBondMinimum` MOTRA via
    //                `Currency::reserve` before they can call
    //                `liquidate`. `ReservedKeeperBonds` bookkeeping
    //                map MUST stay ≤ actual `reserved_balance`.
    //              * `release_keeper_bond(market_id)` — withdraws the
    //                bond. Bond release is unconditional; the slash
    //                branch fires inside `liquidate` and pre-empts
    //                release.
    //          - `IntentKind::PerpAction(PerpActionKind)` variant landing
    //            on `pallet_intent_settlement::IntentKind` (PR-D,
    //            byte-pinned). Routes the perp surface (Open/Close/
    //            Liquidate) through the intent layer when an off-chain
    //            UX wants the intent-flow semantics. Expire-branch is
    //            `IntentNotEligibleForExpiry` — perp intents have no
    //            Cardano-side policy mirror to expire against, so they
    //            short-circuit the policy-expire path.
    //          - Storage maps registered: `Markets`, `Positions`,
    //            `MarginAccounts` (with snapshot-rate accounting),
    //            `CumulativeFundingIndex`, `MarkPriceCacheMap`,
    //            `PremiumIndexSamples`, `LastSettledFundingEpoch`,
    //            `ReservedKeeperBonds`, `BadDebtAccumulated`,
    //            `BadDebtWindowStart`.
    //          - Hooks: `on_initialize` iterates active markets, samples
    //            the premium index per market, and updates the cached
    //            mark price via the clamped EMA-basis trade-off (§5.2).
    //            Bounded by `MaxMarkets` so the hook's weight is
    //            constant in market-set size.
    //        16 new `Config` items wired (full set from the pallet
    //        Config trait at `pallets/perp-engine/src/lib.rs` line 145):
    //          * `Currency` = `Balances` — same `ReservableCurrency`
    //            surface used by every other reserve-pot pallet on this
    //            runtime.
    //          * `PriceOracle` = `PerpEngineOracleAdapter` — runtime-side
    //            adapter implementing `pallet_perp_engine::PriceOracle`
    //            on top of `pallet_oracle::Pallet`. Hashes the
    //            BoundedVec `OracleFeedId` into the 32-byte
    //            `pallet_oracle::PairId` via sha2_256, scales the
    //            `(price: u64, decimals: u8)` pair up to 1e18, and
    //            cross-checks freshness via
    //            `pallet_oracle::Pallet::is_price_fresh(pair_id,
    //            current_block, OracleMaxStaleSlots)`. Per design memo
    //            §6.1 "PRICE adapter" composition contract.
    //          * `PalletId = PerpEnginePalletId = PalletId(*b"perp/v0w")`
    //            — derives the sovereign account that holds MOTRA
    //            margin custody. Distinct from `mat/trsy` (treasury)
    //            and `mat/attr` (attestor reserve). The derived account
    //            (`5EYCAe…` style SS58) MUST be pre-funded with
    //            `ExistentialDeposit` at spec activation so the FIRST
    //            `Currency::transfer` from a fresh chain (`deposit_margin`
    //            or post-liquidate keeper payout via repatriate) cannot
    //            stall on a non-existent destination — same rationale
    //            as the spec-225 `mat/trsy` pre-fund (task #295). Done
    //            via sudo `balances.forceSetBalance` at ceremony time.
    //          * `MateriosChainId = [0e46e33f…]` — live preprod v6
    //            genesis hash. Reuses the same 32-byte value pinned on
    //            `pallet_oracle` (`OracleMateriosChainId`); the pallet
    //            Config types it as `Get<[u8; 32]>`. Defends future PR-B+
    //            committee-signed perp flows against cross-chain replay.
    //          * `MaxLeverageBps = 5_000` — 50× hard cap across ALL
    //            markets (per spec §10). Each market's
    //            `MarketConfig.max_leverage_bps` MUST be ≤ this value;
    //            governance enforces the bound in
    //            `governance_set_market`.
    //          * `MinLeverageBps = 100` — 1× minimum (per spec §10).
    //            Enforces `open_position` / `adjust_leverage` lower
    //            bound; rejects sub-1× over-collateralised opens which
    //            would only serve to grief storage.
    //          * `MaxMarkets = 32` — caps `Markets` cardinality so the
    //            `on_initialize` hook's per-block work is bounded. Spec
    //            §10 default; accommodates the v0 launch set of 3
    //            (ADA/BTC/ETH-PERP per spec §9.2) with growth headroom.
    //          * `MaxFundingSamplesPerEpoch = 600` — bounded ring buffer
    //            per (market, epoch) for `PremiumIndexSamples`. Spec
    //            §10 default (= `funding_epoch_blocks` = 1h @ 6s → 600).
    //          * `KeeperBondMinimum = 100 MATRA = 100 × 10^8` MOTRA
    //            base units (8 decimals). Spec §6.4 economic rationale:
    //            a $100-ballpark stake big enough to deter casual
    //            false-liquidate griefing, small enough to keep the
    //            keeper economy permissionless. Hard-slashed 100% on
    //            false trigger; half to `mat/trsy`, half burned via
    //            `Currency::slash_reserved`.
    //          * `FreshnessLimitBlocks = 3` — mark-cache freshness
    //            threshold. `on_initialize` updates the cache every
    //            block; 3 blocks (18s) of staleness suffices for the
    //            "open / liquidate paths reject stale" gate while not
    //            tripping on occasional block-author skips. Closes
    //            still succeed at the cached mark even when stale (per
    //            spec §5.5 collateral-trapped protection).
    //          * `MaxMarkBasisBps = 200` — 2% cap on the
    //            premium-index EMA basis added to the live oracle
    //            price (per spec §5.2 mark-manipulation guard against
    //            thin CLOB liquidity). The EMA basis is clamped at
    //            ±MaxMarkBasisBps × oracle_e18 before being written
    //            to `MarkPriceCache.mark_ema_basis_e18`.
    //          * `BadDebtCircuitBreakerThresholdE18 = 10_000 × 10^18`
    //            — $10_000 cumulative bad-debt over the rolling window
    //            auto-pauses the market (per spec §6.5). Governance
    //            tunes per market once mainnet volume materialises.
    //          * `BadDebtWindowBlocks = 14_400` — 24h rolling window
    //            (per spec §9.1; matches `WithdrawDwellBlocks`).
    //          * `MatraUsdFeedId = b"MATRA/USD"` — canonical Aegis MON
    //            Phase 1 publisher feed handle. The pallet hashes this
    //            BoundedVec into the 32-byte PairId for cross-pallet
    //            lookup via `PerpEngineOracleAdapter`. The 5-pair
    //            Aegis fleet has MATRA/USD running as one of its
    //            output rails (Phase 1D, task #293); confirm that
    //            feed is publishing fresh prices BEFORE the first
    //            `deposit_margin` / `withdraw_margin` exercise.
    //          * `WithdrawDwellBlocks = 14_400` — 24h dwell between
    //            `deposit_margin` and `withdraw_margin` on the same
    //            account (per spec §3.4 bridge-deposit-replay defence).
    //          * `WeightInfo = ()` — PR-E ships with default zero
    //            WeightInfo. PR-F runs `frame-benchmarking-cli` over
    //            the pallet's existing bench bodies and lands a real
    //            `weights.rs`; until then dispatch weights default to
    //            the pallet's tagged `#[pallet::call_index]` weights
    //            plus the default unit weight, which is conservative
    //            for the v0-pre-mainnet preprod environment.
    //        Operational follow-ups queued before this WASM activates:
    //          - Pre-fund the `perp/v0w` derived account (sovereign
    //            margin custody pot) with ≥ ExistentialDeposit via
    //            sudo `balances.forceSetBalance` at ceremony time.
    //            Same shape as the spec-225 `mat/trsy` pre-fund (#295).
    //          - Post-activation: governance calls `governance_set_market`
    //            registering ADA-PERP as the first market. The
    //            `MarketConfig.oracle_feed_id` MUST hash to a registered
    //            `pallet_oracle::PairId` with live attestor sigs (Phase
    //            1D's ADA/USD pair). Smoke-check: any signer can call
    //            `system.queryStorage('PerpEngine', 'Markets', '<id>')`
    //            and get the new MarketConfig.
    //          - Demo trade: `deposit_margin` 1 MATRA → `open_position`
    //            ADA-PERP 10× → `close_position`. Verifies the full
    //            oracle-mark + funding + margin-equity flow end-to-end.
    //        NO markets registered at genesis. NO pre_runtime_upgrade /
    //        post_runtime_upgrade migration — pallet starts empty (its
    //        on_initialize hook is a no-op until the first
    //        `governance_set_market` registers a market). Pure additive
    //        on the dispatch surface, `transaction_version` stays at 2.
    // 227 = perp-engine v0 polish + oracle SigVerifier wire-up
    // (companion to materios-intent-settlement PR #42 + #43, task #314 +
    // #316). Pallet-perp-engine: real `governance_set_market` body (14
    // validation gates + `MarketAlreadyExists` error + `MarketRegistered`
    // event, replaces under-specified `MarketSet`), sub-rate liquidation
    // fee floor-to-1-MOTRA when `fee_e18 > 0` (PR-C sec-review LOW 2).
    // Pallet-oracle: pluggable `SigVerifier` trait + `Sr25519Verifier`
    // production impl + `BenchAllowAnyVerifier` (cfg-gated). Runtime
    // adds `[pallet_oracle, Oracle]` + `[pallet_perp_engine, PerpEngine]`
    // to `define_benchmarks!` so frame-omni-bencher can build them.
    // Dispatch signatures unchanged → `transaction_version` stays at 2.
    spec_version: 227,
    impl_version: 1,
    apis: RUNTIME_API_VERSIONS,
    transaction_version: 2,
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
    // Raised 16 → 64 in spec 203 (original preprod cap had filled at the
    // 17th attestor on 2026-04-21). spec-217 accidentally regressed this
    // to 64 in the WASM (source had stayed at 64), ejecting 24 of 88
    // committee members. spec-218 hot-restored to 96 on chain via the
    // `wasm-runtime-overrides` chain; THIS source-tree edit lands the
    // matching code-tree value so future spec bumps do not silently
    // regress a SECOND time. Paired `input_sanity::MAX_COMMITTEE_SIZE`
    // must stay in lockstep — see runtime/src/input_sanity.rs.
    type MaxCommitteeSize = ConstU32<96>;
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
    /// Matches the widened MaxCommitteeSize=96 pinned in OrinqReceipts (spec
    /// 203 raised to 64, spec-218 hotfix lifted to 96 — see `runtime/src/lib.rs`
    /// spec_version log). Keeping the intent-settlement cap in lockstep avoids
    /// an adapter mismatch where OrinqReceipts admits a member but
    /// intent-settlement BoundedVec overflows.
    pub const IntentSettlementMaxCommittee: u32 = 96;
    /// TTL-sweep bound per block; bounds the on_initialize cost.
    pub const IntentSettlementMaxExpirePerBlock: u32 = 64;
    /// Default intent TTL: 600 blocks ≈ 1h @ 6s. Matches spec v1 §3.3.
    pub const IntentSettlementDefaultIntentTTL: BlockNumber = 600;
    /// Default claim TTL: 28_800 blocks ≈ 48h @ 6s. Matches spec v1 §3.3.
    pub const IntentSettlementDefaultClaimTTL: BlockNumber = 28_800;
    /// Upper bound on `PendingBatches` index (keeper polls in chunks).
    pub const IntentSettlementMaxPendingBatches: u32 = 10_000;
    /// Wave 2 interim M=1. Governance can bump via `set_min_signer_threshold`
    /// without a code upgrade once the multi-signer keeper rolls out.
    pub const IntentSettlementDefaultMinSignerThreshold: u32 = 1;
    /// Task #177: max claims in a single `settle_batch_atomic` call. The
    /// pallet canon is `MAX_SETTLE_BATCH = 256`; the bound must fit in the
    /// normal-class block budget alongside the M-of-N signature bundle.
    pub const IntentSettlementMaxSettleBatch: u32 = 256;
    /// Task #211: max intents per `attest_batch_intents` call.
    pub const IntentSettlementMaxAttestBatch: u32 = 256;
    /// Task #212: max vouchers per `request_batch_vouchers` call.
    pub const IntentSettlementMaxVoucherBatch: u32 = 256;
    /// Task #210: max intents per `submit_batch_intents` call. Bounded by the
    /// per-block normal-class extrinsic budget AND by `MaxPendingBatches`
    /// headroom, so 256 is the canonical cap.
    pub const IntentSettlementMaxSubmitBatch: u32 = 256;
    /// Task #73: 32-byte Materios chain identity (genesis hash). Bytes match
    /// the preprod genesis `0e46e33f…0849f7bf` (canonical reference:
    /// `feedback_cert_daemon_chain_id_must_be_set.md`). Pinning it here
    /// domain-separates committee-signed bundles across networks/resets.
    pub IntentSettlementMateriosChainId: sp_core::H256 = sp_core::H256([
        0x0e, 0x46, 0xe3, 0x3f, 0x63, 0x9a, 0x56, 0xcc,
        0x87, 0x80, 0xfd, 0x87, 0x1d, 0x9a, 0x15, 0xe1,
        0x6d, 0x99, 0xaf, 0x24, 0x85, 0x26, 0xf9, 0x07,
        0xcb, 0x56, 0x0c, 0xb4, 0x08, 0x49, 0xf7, 0xbf,
    ]);
    /// Task #73: Cardano preprod network magic. Production runtime SHOULD
    /// flip this to 764824073 for mainnet.
    pub const IntentSettlementNetworkMagic: u32 = 1;
    /// Task #73: 28-byte blake2b224 of the deployed `aegis_policy_v1` script.
    /// Placeholder zeroes here — production runtime SHOULD pin the real
    /// script hash from `aiken build` output. Domain-separates voucher
    /// signatures across script redeploys.
    pub const IntentSettlementAegisPolicyV1ScriptHash: [u8; 28] = [0u8; 28];
    /// Task #73: Settlement-protocol semver. Bump on any breaking pre-image
    /// change.
    pub const IntentSettlementSettlementVersion: u32 = 1;
    /// spec-220 (task #78 mis-sec P0): Cardano block depth that a
    /// `request_settle` / `request_expire_policy` evidence blob MUST claim
    /// before its `attest_*` counterpart is accepted. 15 Materios blocks
    /// of Cardano depth is well past the historical-reorg ceiling per
    /// design memo §4.4. Governance can retune via runtime upgrade.
    pub const IntentSettlementMinFinalityDepth: u32 = 15;
    /// spec-220 (task #78): TTL on a pending `request_settle` /
    /// `request_expire_policy` record. After this many Materios blocks the
    /// matching `attest_*` extrinsic rejects with
    /// `Error::ClaimSettlementRequestExpired` / `Error::ExpiryRequestExpired`
    /// and the storage entry is GC'd lazily on next touch. 2400 blocks @ 6s
    /// = 4 hours. Matches the design memo §3.5 + §13.7 baseline value.
    pub const IntentSettlementSettlementRequestTtl: u32 = 2400;
    /// spec-220 (task #78): Cardano preprod Shelley genesis hash pin. The
    /// pallet rejects any `SettlementEvidence` / `ExpiryEvidence` whose
    /// `mainchain_genesis_hash` ≠ this constant. Prevents preprod sig
    /// bundles from ever settling/expiring mainnet claims (and vice versa).
    /// Provenance: IOG canonical preprod config.json `ShelleyGenesisHash`
    /// field, verified against locally-fetched shelley-genesis.json via
    /// `blake2b-256(file_bytes) -> 162d29c4...bd86`.
    /// For mainnet flip: replace with mainnet `ShelleyGenesisHash`.
    pub const IntentSettlementMainchainGenesisHash: [u8; 32] = [
        0x16, 0x2d, 0x29, 0xc4, 0xe1, 0xcf, 0x6b, 0x8a,
        0x84, 0xf2, 0xd6, 0x92, 0xe6, 0x7a, 0x3a, 0xc6,
        0xbc, 0x78, 0x51, 0xbc, 0x3e, 0x6e, 0x4a, 0xfe,
        0x64, 0xd1, 0x57, 0x78, 0xbe, 0xd8, 0xbd, 0x86,
    ];
    /// spec-225 (task #84 mis-sec P1): basis-point share of a slashed
    /// settlement bond paid out to the watcher who proved the fraud.
    /// `5000` = 50% — design memo §6 #9 starting point. Pallet clamps
    /// at the call site to `[0, 10_000]` so a misconfigured runtime can
    /// never pay out more than the bond. Governance-tunable post-launch.
    pub const IntentSettlementSlashWatcherShareBps: u32 = 5000;
    /// spec-225 (task #84): minimum number of Materios blocks that must
    /// elapse between `attest_settle` landing and
    /// `release_settlement_bond` succeeding. Set to `2 * MinFinalityDepth`
    /// (= 2 × 15 = 30) so Cardano has had two finality windows to
    /// surface any reorg before the bond is returned to the original
    /// poster. Pallet doc-comment on `Config::BondReleaseDelayBlocks`
    /// (§4.2 of the design memo) names this exact ratio as the
    /// "production runtimes plumb" target.
    pub const IntentSettlementBondReleaseDelayBlocks: u32 = 30;
    /// spec-225 (task #84): minimum bond a requester must reserve via
    /// `post_settlement_bond` for the call to succeed. Defaulting to
    /// zero keeps the bond opt-in (matches design memo §5.2's
    /// "opt-in by default" property). Production runtimes bump this via
    /// governance once a credible MATRA-denominated value surface lands
    /// (e.g. post pallet-mm-rebate v0, task #257).
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
    // spec-220 (task #78) + spec-221 (task #267) Config items.
    type MinFinalityDepth = IntentSettlementMinFinalityDepth;
    type SettlementRequestTtl = IntentSettlementSettlementRequestTtl;
    type MainchainGenesisHash = IntentSettlementMainchainGenesisHash;
    // spec-225 (task #84 mis-sec P1) Config items — settle_claim bond +
    // slash. `Currency` reuses `Balances` (same `ReservableCurrency`
    // surface the treasury already uses); `SettlementTreasuryPalletId`
    // REUSES the runtime-level `TreasuryPalletId` so slashed-bond
    // residue lands in the same `mat/trsy` account as every other
    // treasury credit. Task #295 pre-funds that derived account with
    // `ExistentialDeposit` at spec activation so `repatriate_reserved`
    // can't stall on a non-existent destination.
    type Currency = Balances;
    type SlashWatcherShareBps = IntentSettlementSlashWatcherShareBps;
    type BondReleaseDelayBlocks = IntentSettlementBondReleaseDelayBlocks;
    type MinSettlementBond = IntentSettlementMinSettlementBond;
    type SettlementTreasuryPalletId = TreasuryPalletId;
    #[cfg(feature = "runtime-benchmarks")]
    type BenchmarkHelper = IntentSettlementBenchmarkHelper;
    type WeightInfo = pallet_intent_settlement::weights::SubstrateWeight<Runtime>;
}

/// Task #43: bench-only helper that bootstraps committee membership before
/// the `pallet_intent_settlement` benchmarks run their extrinsic call. We
/// reuse the OrinqReceipts committee membership store (since that's what
/// `OrinqCommitteeAdapter` reads from in production), and we lower the
/// attestation threshold to 1 so a single-signer benchmark bundle passes
/// the M-of-N gate. Only compiled under `runtime-benchmarks`.
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
            // Capacity is bounded by MaxCommitteeSize; the bench seeds a
            // single member so this is a no-overflow insert.
            let _ = members.try_insert(who.clone());
            pallet_orinq_receipts::CommitteeMembers::<Runtime>::put(members);
        }
        // Threshold defaults may be 0 (genesis) or higher; clamp to 1 so
        // the single-signer bundle satisfies the M-of-N gate.
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
// TEE Attestation (Wave 3 Phase 2)
// ---------------------------------------------------------------------------
//
// `pallet-tee-attestation` provides the TEE attestation primitive used by
// the cert-daemon's tier-1+ trust scoring. Phase 2 ships ARM TrustZone (via
// the vendored Acurast Android Key Attestation verifier) only; AMD SEV-SNP,
// Intel TDX, reproducible-build co-attestation and zk-VM execution proofs
// are typed but stubbed (`VerifyFailReason::NotImplemented`).
//
// Phase 2 deploys with the kill-switch ENABLED at genesis (`Disabled = true`
// via the pallet's `DefaultDisabled<T>`). Sudo flips it via `set_disabled`
// once Phase 2.5 binds `attestation_challenge` to the receipt's content
// hash (security-review H-3). This wiring PR does NOT activate the pallet —
// the runtime upgrade lands disabled, governance flips it post-deploy.
//
// Config trait surface (per pallets/tee-attestation/src/lib.rs L105-107) is
// minimal: the standard `RuntimeEvent` aggregator hookup. No bespoke
// parameters, no off-chain origin, no currency.

impl pallet_tee_attestation::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
}

// ---------------------------------------------------------------------------
// Billing (Phase 2.A — prepaid MATRA balance + 402 billing)
// ---------------------------------------------------------------------------
//
// `pallet-billing` (PRs #19 + #20) provides the on-chain home for the
// prepaid MATRA balance model that backs the gateway's 402 middleware:
// `topup` escrows from `Balances` into a per-account credit, governance
// sets per-endpoint prices, the gateway records paid requests via
// `record_paid_request` (idempotency-keyed by `(payer, request_id)`), and
// `execute_withdrawal` returns the unspent escrow.
//
// The pallet lands with `DebitsEnabled` defaulted `false`: every call
// surface is reachable but no MATRA actually moves on `record_paid_request`
// until governance flips the kill-switch in Phase 2.B. Gateway middleware
// already on `main` (PRs #43 + #44) calls `queryBillingBalance` /
// `queryEndpointPrice` against this pallet — without runtime wiring those
// reads return null and the middleware silently bypasses.
//
// `RequestIdRetentionBlocks = 14_400` (~1 day at 6s blocks) bounds the
// idempotency-replay storage. Long enough to absorb gateway retry storms
// + network reordering, short enough that misbehaving clients spamming
// unique request_ids cannot grow `PaidRequests` unboundedly — the
// `prune_paid_requests` extrinsic drops entries past this window.

parameter_types! {
    /// Phase 2.A — how long a `PaidRequests[(payer, request_id)]` entry is
    /// retained for idempotency replay protection. 14_400 blocks ≈ 1 day
    /// at 6s block time. Generous enough for client retries / network
    /// reordering; short enough that storage bloat is bounded if a
    /// misbehaving client spams unique request_ids.
    pub const BillingRequestIdRetentionBlocks: BlockNumber = 14_400;
    /// Maximum `(payer, request_id)` entries a single `prune_paid_requests`
    /// call may carry. Caps per-call declared weight so a keeper (honest
    /// or malicious) cannot submit a batch whose linear-in-`n` weight
    /// exceeds the per-block normal-class budget — PR #20 security review
    /// L-2, task #226. 256 is an order of magnitude above what production
    /// keeper scripts batch in practice and well inside one block's budget
    /// at the pallet's 5M ref_time / 256 proof_size per-entry rate.
    pub const BillingMaxPruneBatch: u32 = 256;
}

impl pallet_billing::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type MatraCurrency = Balances;
    // GovernanceOrigin gates `governance_set_endpoint_price` and the 2.B
    // kill-switch `governance_set_debits_enabled`. On preprod this is Sudo
    // (Alice) via `sudo.sudo(billing.governanceSetDebitsEnabled(true))`.
    // **Mainnet migration:** switch to `EitherOf<EnsureRoot, MultisigOrigin>`
    // (or a Council collective threshold) before mainnet launch — Sudo is
    // not an acceptable production governance origin for money flows.
    type GovernanceOrigin = EnsureRoot<AccountId>;
    type RequestIdRetentionBlocks = BillingRequestIdRetentionBlocks;
    type MaxPruneBatch = BillingMaxPruneBatch;
    type WeightInfo = pallet_billing::weights::SubstrateWeight;
}

// ---------------------------------------------------------------------------
// Oracle (MON Phase 1)
// ---------------------------------------------------------------------------
// Decentralized M-of-N price oracle. Sudo-registers attestor sr25519
// pubkeys per pair (Phase 1A: single Aegis publisher per pair; Phase 1B:
// ≥2). Each `submit_price` call signs over the canonical PRIC payload
// (85-byte preimage). The pallet aggregates observations and writes
// `Prices[pair_id]` once `MinAttestorThreshold` is crossed. Sister
// design at `/home/deci/work/mon-phase1-aegis-extend-design.md`.

parameter_types! {
    /// 32-byte materios chain identity — preprod v6 genesis hash. Pinned
    /// into every PRIC preimage so a price signed on preprod is structurally
    /// invalid post-reset / on mainnet. Same constant as
    /// `IntentSettlementMateriosChainId` but exposed as a raw `[u8; 32]` to
    /// match the oracle pallet's `Get<[u8; 32]>` Config bound (the IS
    /// pallet's variant types it as `Get<sp_core::H256>` — both encode the
    /// same 32 bytes).
    /// Provenance: live preprod chain `chain_getBlockHash(0)` at deploy time.
    ///   0x0e46e33f639a56cc8780fd871d9a15e16d99af248526f907cb560cb40849f7bf
    pub const OracleMateriosChainId: [u8; 32] = [
        0x0e, 0x46, 0xe3, 0x3f, 0x63, 0x9a, 0x56, 0xcc,
        0x87, 0x80, 0xfd, 0x87, 0x1d, 0x9a, 0x15, 0xe1,
        0x6d, 0x99, 0xaf, 0x24, 0x85, 0x26, 0xf9, 0x07,
        0xcb, 0x56, 0x0c, 0xb4, 0x08, 0x49, 0xf7, 0xbf,
    ];
    /// Per-pair attestor roster cap. 16 leaves comfortable headroom over
    /// the Phase 1A single-publisher mode while staying well inside one
    /// block's normal-class budget. The pallet enforces this bound on
    /// `Attestors[pair_id]` BoundedVec inserts via `register_attestor`.
    pub const OracleMaxAttestors: u32 = 16;
    /// Phase 1B (spec-223, 2026-05-15): M-of-N aggregation gate.
    /// `submit_price` accumulates observations into the
    /// `PendingAttestations[pair_id, slot_observed]` bundle until this
    /// many distinct attestor pubkeys have submitted; only then does the
    /// pallet aggregate and write `Prices[pair_id]`. Independent attestors
    /// (currently: Aegis publisher on Node-2 + standalone attestor on
    /// Gemtek) coordinate via the `_SLOT_BUCKET = 10` floor in
    /// `materios_rail.py` so observations within ~60s converge on the
    /// same `slot_observed`. Phase 1C raises to 3 once a third sr25519
    /// identity (peer operator) boots. The pallet rebuilds the gate on
    /// every `submit_price` — no migration needed when the threshold
    /// tightens.
    pub const OracleMinAttestorThreshold: u32 = 3;
    /// Reject observations older than `current_block - 60` (≈6min @ 6s).
    /// Phase 1A: Aegis publisher tick is 30s, so 60-block staleness is ≈12×
    /// the publish cadence — enough to ride out gateway hiccups but tight
    /// enough that stale prices can't accumulate. Governance tunes this
    /// per market when pull-oracle consumers (perp-engine #259, mm-rebate
    /// #257) start landing. Materios block counter is used in lieu of
    /// `slot_observed` semantics — the Aegis publisher rail substitutes
    /// `int(time.time())` for `slot_observed` per design memo §2 #4 so
    /// the threshold is wall-clock-equivalent.
    pub const OracleMaxStaleSlots: u64 = 60;
    /// Reject observations claiming `slot_observed > current_block + 10`
    /// (≈1min anti-front-run tolerance). Bounded above to keep a single
    /// misconfigured publisher from poisoning a feed with future-dated
    /// observations that pin to `Prices[pair_id]` for `MaxStaleSlots` of
    /// real time.
    pub const OracleMaxFutureSlots: u64 = 10;
}

/// Adapter exposing the on-chain `pallet_oracle::Attestors` storage to the
/// `IsAttestorFor<AccountId>` trait that `pallet_oracle::Config` requires.
///
/// For `AccountId = AccountId32` (this runtime's shape, derived from
/// `MultiSignature`) the sr25519 pubkey IS the raw 32 bytes of the account,
/// so the mapping is injective and round-trips without per-account registry
/// storage — same zero-copy pattern as `OrinqCommitteeAdapter::pubkey_of`.
///
/// `threshold_for` returns the runtime-level `OracleMinAttestorThreshold`
/// uniformly across pairs in Phase 1; v2 (per-pair tuning) extends this
/// to read from a `pallet_oracle::PairThreshold` storage map.
pub struct PalletOracleAttestorRegistry;

impl pallet_oracle::IsAttestorFor<AccountId> for PalletOracleAttestorRegistry {
    fn is_attestor(pair_id: &pallet_oracle::PairId, who: &AccountId) -> bool {
        // `pallet_oracle::Attestors[pair_id]` is a `BoundedVec<AttestorPubkey,
        // MaxAttestors>` of sr25519 32-byte pubkeys. AccountId32 ↔ pubkey
        // is the identity map for sr25519 on this runtime.
        let pubkey: pallet_oracle::AttestorPubkey = *<AccountId as AsRef<[u8; 32]>>::as_ref(who);
        pallet_oracle::Attestors::<Runtime>::get(pair_id).contains(&pubkey)
    }

    fn pubkey_of(who: &AccountId) -> pallet_oracle::AttestorPubkey {
        // Zero-copy view: AccountId32 stores its pubkey as inner `[u8; 32]`.
        *<AccountId as AsRef<[u8; 32]>>::as_ref(who)
    }

    fn threshold_for(_pair_id: &pallet_oracle::PairId) -> u32 {
        // Phase 1: uniform global threshold (`MinAttestorThreshold` Config
        // item). Phase 2 (v2 / mm-rebate consumer) replaces with per-pair
        // tuning sourced from a new `pallet_oracle::PairThreshold`
        // storage map. `.max(1)` defends against a misconfigured zero
        // genesis value: the pallet's aggregation gate is "≥ threshold"
        // and 0 would let a single attestor unilaterally write `Prices`
        // without satisfying the M-of-N intent of the design.
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
    // spec-227: pluggable sig verifier (pallet-oracle PR #42). Production
    // wires `Sr25519Verifier` — byte-exact equivalent of the previous
    // inline `sp_io::crypto::sr25519_verify` call. `BenchAllowAnyVerifier`
    // is cfg-gated behind `runtime-benchmarks` and cannot reach prod.
    type SigVerifier = pallet_oracle::Sr25519Verifier;
}

// ---------------------------------------------------------------------------
// Perp Engine (perp-engine v0 — PR-E, spec 226, task #259)
// ---------------------------------------------------------------------------
//
// Permissionless USD-quoted linear perpetual-futures primitive. Pull-based
// mark prices from `pallet-oracle`, pull-based funding, bond-gated
// permissionless liquidator pool with 100% slash on false trigger.
//
// All Config defaults are sourced from
// `/home/deci/work/perp-engine-v0-spec.md §10 parameter table` unless noted.
// The pallet's `Config` trait is the source of truth — see
// `pallets/perp-engine/src/lib.rs` line 145 (PR-D rev `c95e5edb`).

parameter_types! {
    /// PalletId for the perp-engine MOTRA margin-custody pot. All
    /// `deposit_margin` / `withdraw_margin` traffic and the post-
    /// liquidate keeper-payout splits route through this derived
    /// account. Bytes `b"perp/v0w"` are intentionally distinct from
    /// `mat/trsy` (treasury) and `mat/attr` (attestor reserve) so the
    /// account-store partitions cleanly.
    ///
    /// At spec-226 activation the derived account MUST be pre-funded
    /// with ≥ `ExistentialDeposit` via sudo `balances.forceSetBalance`
    /// (mirrors the spec-225 `mat/trsy` pre-fund, task #295) so the
    /// FIRST `Currency::transfer` from a chain that has never executed
    /// `deposit_margin` cannot stall on a non-existent destination.
    pub const PerpEnginePalletId: PalletId = PalletId(*b"perp/v0w");

    /// 32-byte materios chain identity — preprod v6 genesis hash. The
    /// pallet Config types this as `Get<[u8; 32]>`. Same bytes as
    /// `OracleMateriosChainId` so a future committee-signed perp flow
    /// can interlock with the oracle PRIC preimage scheme.
    pub const PerpEngineMateriosChainId: [u8; 32] = [
        0x0e, 0x46, 0xe3, 0x3f, 0x63, 0x9a, 0x56, 0xcc,
        0x87, 0x80, 0xfd, 0x87, 0x1d, 0x9a, 0x15, 0xe1,
        0x6d, 0x99, 0xaf, 0x24, 0x85, 0x26, 0xf9, 0x07,
        0xcb, 0x56, 0x0c, 0xb4, 0x08, 0x49, 0xf7, 0xbf,
    ];

    /// Hard cap on leverage across ALL markets, in basis points. 5_000 bps
    /// = 50× per spec §10. Each market's `MarketConfig.max_leverage_bps`
    /// MUST be ≤ this value; `governance_set_market` enforces the bound
    /// at registration time. Provides a runtime-level kill-switch for
    /// systemic over-leverage even if a misconfigured market slips
    /// through governance review.
    pub const PerpEngineMaxLeverageBps: u32 = 5_000;

    /// Floor on leverage in basis points. 100 bps = 1× per spec §10.
    /// `open_position` / `adjust_leverage` reject `leverage_bps <
    /// MinLeverageBps`. Rejects sub-1× over-collateralised opens which
    /// only serve to grief storage on the `Positions` map.
    pub const PerpEngineMinLeverageBps: u32 = 100;

    /// Cap on `Markets` cardinality. 32 markets accommodates the v0
    /// launch set of 3 (ADA-PERP, BTC-PERP, ETH-PERP per spec §9.2)
    /// with substantial headroom. Bounds the per-block work in
    /// `on_initialize` (mark-cache sweep + premium-index sample per
    /// active market) so the hook weight is constant in `Markets`
    /// cardinality and never exceeds the normal-class budget.
    pub const PerpEngineMaxMarkets: u32 = 32;

    /// Bounded ring-buffer size for `PremiumIndexSamples[(market, epoch)]`.
    /// 600 samples per epoch matches the canonical `funding_epoch_blocks
    /// = 600` (1h at 6s blocks) per spec §10 — exactly one sample per
    /// block. The pallet's `on_initialize` hook drops samples when the
    /// ring saturates.
    pub const PerpEngineMaxFundingSamplesPerEpoch: u32 = 600;

    /// Keeper bond minimum, in MOTRA base units (8 decimals — MOTRA is
    /// the on-chain token, MATRA is the human-readable unit). 100 MATRA
    /// × 10^8 = 10^10 base units. Per spec §6.4: large enough to deter
    /// casual false-liquidate griefing, small enough to keep the
    /// keeper economy permissionless. Slashed 100% on false trigger;
    /// half repatriated to `mat/trsy`, half burned via
    /// `Currency::slash_reserved`.
    pub const PerpEngineKeeperBondMinimum: Balance = 100u128 * 100_000_000u128;

    /// Mark-price cache freshness threshold, in blocks. `on_initialize`
    /// updates the cache every block; 3 blocks (≈18s) of staleness
    /// suffices for the "opens + liquidations reject stale" gate while
    /// not tripping on occasional block-author skips. Per spec §5.5
    /// closes succeed at the cached mark even when the gate fires —
    /// collateral-trapped protection takes precedence.
    pub const PerpEngineFreshnessLimitBlocks: u32 = 3;

    /// Cap on the premium-index EMA basis added to the live oracle
    /// price, in basis points. 200 bps = 2% per spec §5.2 — defends
    /// the mark price against manipulation via thin CLOB liquidity
    /// dragging the EMA off the oracle. Clamped symmetrically in
    /// `MarkPriceCache.mark_ema_basis_e18` so the cached mark stays
    /// within ±2% of the oracle price.
    pub const PerpEngineMaxMarkBasisBps: u32 = 200;

    /// Bad-debt circuit-breaker threshold, in 1e18-scaled pMATRA-USD.
    /// $10_000 = 10_000 × 10^18 per spec §6.5. When the rolling-window
    /// bad-debt sum exceeds this value the affected market auto-pauses
    /// — governance must explicitly clear the pause via runtime upgrade
    /// or a new `governance_set_market` row. Conservative default for
    /// v0 preprod; governance tunes per market once mainnet volume
    /// materialises.
    pub const PerpEngineBadDebtCircuitBreakerThresholdE18: u128 =
        10_000u128 * 1_000_000_000_000_000_000u128;

    /// Bad-debt rolling-window length, in blocks. 14_400 ≈ 24h at 6s
    /// blocks per spec §9.1. Matches `WithdrawDwellBlocks` so the
    /// time-domain semantics of "yesterday's bad debt" and "yesterday's
    /// deposit" are coherent. The window slides forward in
    /// `liquidate`'s bad-debt accumulator.
    pub const PerpEngineBadDebtWindowBlocks: u32 = 14_400;

    /// Withdraw-dwell window, in blocks. 14_400 ≈ 24h at 6s blocks per
    /// spec §3.4. A fresh `deposit_margin` must dwell this many blocks
    /// before the same account can `withdraw_margin` — defends against
    /// bridge-deposit-replay shapes where a brittle off-chain bridge
    /// re-credits a withdrawn deposit. Matches the spec-220
    /// `MinFinalityDepth × 1000`-equivalent intent-side dwell on
    /// intent-settlement.
    pub const PerpEngineWithdrawDwellBlocks: u32 = 14_400;

    /// MATRA/USD oracle feed handle. Hashed by the
    /// `PerpEngineOracleAdapter` into the 32-byte
    /// `pallet_oracle::PairId` for cross-pallet lookup. The Aegis
    /// publisher fleet on Node-2 publishes MATRA/USD as one of its
    /// five rails (Phase 1D, task #293); confirm that feed is
    /// publishing fresh prices BEFORE the first `deposit_margin` or
    /// `withdraw_margin` call on this runtime — both extrinsics fail
    /// with `OracleUnavailable` if the feed is stale or missing.
    ///
    /// 9 ASCII bytes — well inside `MAX_MARKET_ID_LEN = 16`. Wrapped
    /// in a `parameter_types!` accessor because `BoundedVec` does NOT
    /// have a const constructor; the closure runs once at runtime
    /// metadata bake time.
    pub PerpEngineMatraUsdFeedId: pallet_perp_engine::OracleFeedId =
        pallet_perp_engine::OracleFeedId::try_from(b"MATRA/USD".to_vec())
            .expect("9 bytes < MAX_MARKET_ID_LEN = 16; static literal");
}

/// Adapter implementing `pallet_perp_engine::PriceOracle` on top of
/// `pallet_oracle::Pallet<Runtime>`.
///
/// ## Type bridge
///
/// `pallet-perp-engine` types its feed handle as a bounded UTF-8 byte
/// string (`OracleFeedId = BoundedVec<u8, ConstU32<MAX_MARKET_ID_LEN=16>>`)
/// while `pallet-oracle` keys its storage by the canonical 32-byte
/// `PairId = [u8; 32]` (= `sha256(pair_string_utf8)`). The adapter is
/// the runtime-side bridge: hash the perp-engine handle to compute the
/// oracle PairId, then forward through `pallet_oracle::Pallet`.
///
/// This composition is the canonical "pallet-oracle as `PriceOracle`
/// adapter" shape per `materios-oracle-design.md §6.1`. Same pattern
/// `pallet-intent-settlement::IsCommitteeMember` uses to consume
/// `pallet-orinq-receipts` committee storage (`OrinqCommitteeAdapter`
/// above) and `pallet-oracle::IsAttestorFor` uses to consume the
/// AccountId32 → sr25519 pubkey identity map
/// (`PalletOracleAttestorRegistry` above).
///
/// ## Price-scale normalisation
///
/// `pallet-oracle` stores aggregated prices as `(price: u64, decimals:
/// u8)`. The perp-engine consumes prices at 1e18 scale. The adapter
/// scales the raw `u64` up to `u128` and multiplies by
/// `10^(18 - decimals)`. Decimals are bounded `[0, 18]` by the
/// pallet-oracle's `submit_price` validation (§oracle pallet line 12),
/// so the shift is always non-negative and the `u128` headroom is
/// `~10^18 × 10^18 = 10^36` — well clear of overflow even at
/// 18-decimal $1B-equivalent prices.
///
/// ## Freshness gate
///
/// `is_fresh` is fail-CLOSED on a missing or paused feed. We delegate to
/// `pallet_oracle::Pallet::is_price_fresh(pair_id, current_block,
/// OracleMaxStaleSlots)` so the same `MaxStaleSlots = 60` block tolerance
/// the oracle pallet enforces on `submit_price` applies uniformly to
/// downstream consumers (no separate per-consumer staleness config).
/// `current_block` is sourced from `frame_system::Pallet::block_number()`
/// at read time — the Aegis-publisher rail substitutes
/// `int(time.time())` for `slot_observed` per
/// `mon-phase1-aegis-extend-design.md §2 #4` so wall-clock-equivalent
/// staleness is the correct gate.
pub struct PerpEngineOracleAdapter;

impl pallet_perp_engine::PriceOracle for PerpEngineOracleAdapter {
    fn latest_price_e18(feed_id: &pallet_perp_engine::OracleFeedId) -> Option<u128> {
        // Hash the perp-engine BoundedVec handle to the canonical
        // 32-byte oracle PairId (`sha256(handle_bytes)`).
        let pair_id: pallet_oracle::PairId =
            sp_io::hashing::sha2_256(feed_id.as_slice());
        // `pallet_oracle::Pallet::get_price` returns `(u64 price, u8
        // decimals, SlotNumber)` or `None` when the feed has no
        // aggregated row yet.
        let (price_u64, decimals, _slot) =
            pallet_oracle::Pallet::<Runtime>::get_price(pair_id)?;
        // Scale `(price, decimals)` up to 1e18. Decimals are bounded
        // `[0, 18]` by the oracle pallet's `submit_price` validation
        // so the exponent is non-negative. Use `u128` throughout —
        // `10^18 × 10^18 = 10^36` is well inside `u128::MAX ≈ 3.4 × 10^38`.
        let shift = 18u32.saturating_sub(decimals as u32);
        let scale: u128 = 10u128.checked_pow(shift)?;
        (price_u64 as u128).checked_mul(scale)
    }

    fn price_age_blocks(feed_id: &pallet_perp_engine::OracleFeedId) -> u32 {
        // Compute age = current_block - last_update_block. Falls back
        // to `u32::MAX` (the no-feed sentinel per pallet-perp-engine
        // §PriceOracle docstring) whenever the feed has never been
        // published or the block-number conversion would underflow.
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
        // Fail-CLOSED on missing / paused / overflow paths via
        // `pallet_oracle::Pallet::is_price_fresh` semantics (returns
        // `false` whenever `Prices[pair_id]` is `None`).
        let pair_id: pallet_oracle::PairId =
            sp_io::hashing::sha2_256(feed_id.as_slice());
        // Materios block counter substitutes for `slot_observed` per
        // `materios_rail.py` design memo §2 #4 — the publisher rail
        // submits `int(time.time())` as `slot_observed`, and the
        // pallet treats it as a monotonic counter. Bridging to
        // block-number for the freshness gate is structurally
        // equivalent because both rails advance at the same wall-clock
        // tick.
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
        // Wave 3 Phase 2 (spec 205): TEE attestation primitive (ARM
        // TrustZone via vendored Acurast verifier — see PR #17). Appended
        // at index 20. Disabled at genesis via the pallet's
        // `DefaultDisabled<T>`; sudo flips the kill-switch via
        // `set_disabled` once Phase 2.5 ships challenge-binding.
        TeeAttestation: pallet_tee_attestation = 20,
        // Phase 2.A (spec 206): prepaid MATRA balance + 402 billing — see
        // PRs #19 (scaffold) + #20 (2.B-flip blockers). Appended at index
        // 21. `DebitsEnabled` defaults `false` via the pallet's
        // `DefaultDebitsDisabled<T>` type-value; governance flips it in
        // Phase 2.B. Until then every call surface is reachable but no
        // MATRA moves on `record_paid_request` — purely additive.
        Billing: pallet_billing = 21,
        // MON Phase 1 (spec 222): decentralized price oracle — M-of-N
        // attestor sigs over the canonical PRIC payload aggregated into
        // `Prices[pair_id]`. Appended at index 22. Sudo registers
        // attestor pubkeys per pair in Phase 1A; v2 swaps to bonded
        // permissionless registration. Closes runtime side of MON Phase 1
        // (task #268). Aegis publisher rail at
        // `aegis-publisher/publisher/materios_rail.py` is byte-pinned to
        // the PRIC preimage builder in `pallet_oracle::types`.
        Oracle: pallet_oracle = 22,
        // Perp Engine v0 (spec 226, task #259, PR-E): permissionless
        // USD-quoted linear perpetual-futures primitive. Appended at
        // index 23. Closes the runtime side of #259. Surface: open /
        // close / deposit_margin / withdraw_margin / adjust_leverage /
        // liquidate / settle_funding (all permissionless) + the two
        // bonded keeper extrinsics (reserve_keeper_bond /
        // release_keeper_bond, PR-D call_index 8/9) + sudo-only
        // governance_set_market. Reads pull-mark prices through the
        // runtime-side `PerpEngineOracleAdapter` over
        // `pallet_oracle::Pallet`. NO markets registered at genesis —
        // governance (sudo on preprod) calls `governance_set_market`
        // post-activation to register ADA-PERP as the first market. The
        // sovereign margin-custody pot at derived `PalletId(*b"perp/v0w")`
        // MUST be pre-funded with ≥ ExistentialDeposit at ceremony time
        // (same shape as the spec-225 `mat/trsy` pre-fund, task #295).
        PerpEngine: pallet_perp_engine = 23,
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
            get_preset::<RuntimeGenesisConfig>(id, |preset_id| {
                // The `development` preset exists only to satisfy
                // `frame-omni-bencher`'s default `--genesis-builder-preset=development`.
                // Pallet benchmarks seed their own storage in `dispatch_benchmark`,
                // so we return an empty JSON patch (`{}`) — the runtime fills in
                // defaults via `RuntimeGenesisConfig::default()`. Several IOG
                // partner-chains pallets ship `#[derive(DefaultNoBound)]` GenesisConfigs
                // whose serialized form omits a `_marker: PhantomData<T>` field
                // that the deserializer demands; serializing the default config
                // therefore round-trips into a deserialize error. Returning `{}`
                // sidesteps that by letting `build_state` apply each pallet's
                // genesis-config defaults in isolation.
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

/// `frame_system_benchmarking::Config` is a zero-method marker trait; we
/// implement it at crate root (rather than inside `dispatch_benchmark`) to
/// avoid the rustc-1.80+ `non_local_definitions` warning.
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


