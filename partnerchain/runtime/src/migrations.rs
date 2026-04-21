//! Runtime migrations (v5.1 Midnight-style fees, spec 201 → 202).
//!
//! One-shot sweep of stranded balances from the old 40/30/20/10 fee-router's
//! two PalletId-derived accounts into the treasury:
//!   * `mat/auth` — 40% author-pot share (fed by every signed tx pre-202)
//!   * `mat/attr` — 30% attestor-reserve share (fed by every signed tx + by
//!                  Component 8 slashing repatriation)
//!
//! After 202, the fee-router is deleted, so `mat/auth` never receives new
//! funds. `mat/attr` continues to receive slashed bonds (Component 8 routes
//! there). The sweep MUST only run once — subsequent upgrades leave
//! `mat/attr` alone so legitimate post-202 slashing receipts aren't stolen
//! by a future re-run.
//!
//! The one-shot gate is a StorageVersion on a dedicated pallet-agnostic
//! prefix. We deliberately avoid hanging the version off `pallet_balances`
//! or `pallet_treasury` (those pallets have their own storage-version
//! semantics and we don't want to overload them).
//!
//! Idempotency:
//!   * First call: version < V1 → sweep both pots → bump version to V1.
//!   * Any subsequent call: version == V1 → return immediately with 1 read.
//!
//! Test coverage:
//!   * `runtime::tests::treasury_drip_migration::
//!      migration_sweeps_author_and_attestor_pots_into_treasury`
//!   * `runtime::tests::treasury_drip_migration::migration_sweep_is_idempotent_on_second_call`
//!   * `runtime::tests::treasury_drip_migration::migration_with_empty_source_pots_is_noop`

use frame_support::{
    traits::{Get, OnRuntimeUpgrade},
    weights::Weight,
    PalletId,
};
use sp_runtime::traits::AccountIdConversion;

use crate::{AccountId, AttestorReservePalletId, Runtime, TreasuryPalletId};

/// Storage-version gate for the sweep migration. Incremented from V0 → V1 at
/// the end of the one-shot sweep. Plain u16 (not frame_support StorageVersion)
/// so we can compare and persist without a pallet storage binding — see
/// module docs on why we avoid introducing a new pallet here.
pub const SWEEP_MIGRATION_VERSION: u16 = 1;

/// The author-pot PalletId on spec ≤ 201. Duplicated here rather than
/// imported from `fee_router.rs` (which is deleted) so the migration
/// remains compilable long after the fee-router source is gone.
const AUTHOR_POT_ID: PalletId = PalletId(*b"mat/auth");

/// One-shot sweep of stranded fee-router balances into the treasury.
///
/// Implemented as `OnRuntimeUpgrade` so `frame-executive` runs it exactly
/// once at the 201 → 202 upgrade block, before any extrinsic of that block
/// executes. Idempotent on re-run (second pass short-circuits on the
/// storage-version read).
pub struct SweepFeeRouterPotsIntoTreasury;

impl SweepFeeRouterPotsIntoTreasury {
    /// Storage prefix for the migration's own version gate. Chosen to be a
    /// unique, human-readable key under `:migration:v5_1_sweep:`. Kept as
    /// plain storage rather than a pallet StorageVersion so we don't have
    /// to introduce a new pallet (pallet-index shift hazard — see
    /// feedback_pallet_index_shift.md).
    const VERSION_KEY: &'static [u8] = b":migration:v5_1_sweep:version";

    fn stored_version() -> u16 {
        frame_support::storage::unhashed::get::<u16>(Self::VERSION_KEY).unwrap_or(0)
    }

    fn set_version(v: u16) {
        frame_support::storage::unhashed::put::<u16>(Self::VERSION_KEY, &v);
    }

    fn author_pot() -> AccountId {
        AUTHOR_POT_ID.into_account_truncating()
    }

    fn attestor_pot() -> AccountId {
        AttestorReservePalletId::get().into_account_truncating()
    }

    fn treasury_pot() -> AccountId {
        TreasuryPalletId::get().into_account_truncating()
    }
}

impl OnRuntimeUpgrade for SweepFeeRouterPotsIntoTreasury {
    fn on_runtime_upgrade() -> Weight {
        if Self::stored_version() >= SWEEP_MIGRATION_VERSION {
            // Already swept. One read, no writes.
            return <<Runtime as frame_system::Config>::DbWeight as Get<frame_support::weights::RuntimeDbWeight>>::get().reads(1);
        }

        let author = Self::author_pot();
        let attestor = Self::attestor_pot();
        let treasury = Self::treasury_pot();

        let reads: u64 = 4; // version + 3 balances
        let mut writes: u64 = 0;

        // Sweep author pot. We use `transfer_all` semantics via
        // `pallet_balances::Pallet::force_set_balance` + manual credit to
        // avoid ED / account-reaping concerns — we're operating on PalletId
        // accounts that survive reaping by design. The net effect must be:
        //   pre_total_issuance == post_total_issuance (a transfer, not burn)
        //
        // Using `Currency::transfer` against KeepAlive would fail when the
        // source balance == its ExistentialDeposit. PalletId accounts don't
        // care about ED (they don't provide AccountInfo in a way that ED
        // gates), so AllowDeath is safe and correct here.
        use frame_support::traits::{
            Currency,
            ExistenceRequirement,
        };
        type Bal = pallet_balances::Pallet<Runtime>;

        let author_free = Bal::free_balance(&author);
        if author_free > 0 {
            // ExistenceRequirement::AllowDeath: PalletId accounts are
            // deterministic derivations; if they get reaped they come back
            // the moment any new credit arrives. We want to drain to zero.
            match <Bal as Currency<AccountId>>::transfer(
                &author,
                &treasury,
                author_free,
                ExistenceRequirement::AllowDeath,
            ) {
                Ok(()) => writes += 2, // debit + credit
                Err(e) => {
                    log::error!(
                        "migration: author pot transfer failed ({:?}); leaving funds in place",
                        e
                    );
                    // Don't halt the upgrade over this — the author pot is a
                    // PalletId account, not user funds, and a failed transfer
                    // means the funds stay where they are. The admin can
                    // sudo-transfer them later.
                }
            }
        }

        let attestor_free = Bal::free_balance(&attestor);
        if attestor_free > 0 {
            match <Bal as Currency<AccountId>>::transfer(
                &attestor,
                &treasury,
                attestor_free,
                ExistenceRequirement::AllowDeath,
            ) {
                Ok(()) => writes += 2,
                Err(e) => {
                    log::error!(
                        "migration: attestor pot transfer failed ({:?}); leaving funds in place",
                        e
                    );
                }
            }
        }

        // Bump the version gate so we never re-run the sweep. This is the
        // critical step for idempotency — even if the transfers above
        // partially failed, we've done our one-shot attempt and future
        // upgrades must not try again. Ops can always run a follow-up
        // sudo-transfer if a sweep was incomplete.
        Self::set_version(SWEEP_MIGRATION_VERSION);
        writes += 1;

        log::info!(
            "v5.1 migration: swept fee-router pots into treasury (author={}, attestor={})",
            author_free, attestor_free,
        );

        <<Runtime as frame_system::Config>::DbWeight as Get<frame_support::weights::RuntimeDbWeight>>::get().reads_writes(reads, writes)
    }
}
