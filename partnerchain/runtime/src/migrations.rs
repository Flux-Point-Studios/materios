//! One-shot sweep of stranded balances from the legacy fee-router's
//! PalletId-derived accounts (`mat/auth`, `mat/attr`) into the treasury.
//!
//! The sweep MUST only run once — subsequent upgrades leave `mat/attr`
//! alone so legitimate post-cutover slashing receipts aren't stolen by a
//! future re-run. The gate is a plain storage entry rather than a pallet
//! StorageVersion to avoid introducing a new pallet (pallet-index shift
//! hazard).

use frame_support::{
    traits::{Get, OnRuntimeUpgrade},
    weights::Weight,
    PalletId,
};
use sp_runtime::traits::AccountIdConversion;

use crate::{AccountId, AttestorReservePalletId, Runtime, TreasuryPalletId};

pub const SWEEP_MIGRATION_VERSION: u16 = 1;

/// The author-pot PalletId. Duplicated here so the migration remains
/// compilable after the fee-router source is gone.
const AUTHOR_POT_ID: PalletId = PalletId(*b"mat/auth");

/// One-shot sweep of stranded fee-router balances into the treasury.
/// Runs exactly once at upgrade; idempotent on re-run via the storage
/// version gate.
pub struct SweepFeeRouterPotsIntoTreasury;

impl SweepFeeRouterPotsIntoTreasury {
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
            return <<Runtime as frame_system::Config>::DbWeight as Get<frame_support::weights::RuntimeDbWeight>>::get().reads(1);
        }

        let author = Self::author_pot();
        let attestor = Self::attestor_pot();
        let treasury = Self::treasury_pot();

        let reads: u64 = 4;
        let mut writes: u64 = 0;

        // AllowDeath: PalletId accounts are deterministic derivations; they
        // come back the moment any new credit arrives. KeepAlive would
        // refuse to drain past ExistentialDeposit.
        use frame_support::traits::{
            Currency,
            ExistenceRequirement,
        };
        type Bal = pallet_balances::Pallet<Runtime>;

        let author_free = Bal::free_balance(&author);
        if author_free > 0 {
            match <Bal as Currency<AccountId>>::transfer(
                &author,
                &treasury,
                author_free,
                ExistenceRequirement::AllowDeath,
            ) {
                Ok(()) => writes += 2,
                Err(e) => {
                    log::error!(
                        "migration: author pot transfer failed ({:?}); leaving funds in place",
                        e
                    );
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

        // Bump the gate even on partial failure: we've done our one-shot
        // attempt and future upgrades must not retry. Ops can sudo-transfer
        // any residue.
        Self::set_version(SWEEP_MIGRATION_VERSION);
        writes += 1;

        log::info!(
            "v5.1 migration: swept fee-router pots into treasury (author={}, attestor={})",
            author_free, attestor_free,
        );

        <<Runtime as frame_system::Config>::DbWeight as Get<frame_support::weights::RuntimeDbWeight>>::get().reads_writes(reads, writes)
    }
}
