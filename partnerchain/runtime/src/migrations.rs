//! Runtime-upgrade migrations.
//!
//! `SweepFeeRouterPotsIntoTreasury` is a one-shot sweep of stranded balances
//! from the legacy fee-router's PalletId-derived accounts (`mat/auth`,
//! `mat/attr`) into the treasury. The sweep MUST only run once — subsequent
//! upgrades leave `mat/attr` alone so legitimate post-cutover slashing
//! receipts aren't stolen by a future re-run. The gate is a plain storage
//! entry rather than a pallet StorageVersion to avoid introducing a new
//! pallet (pallet-index shift hazard).
//!
//! `InitRootTimelock` stores the root-timelock delays on a chain that was
//! running before the pallet existed.

use frame_support::{
    traits::{Get, OnRuntimeUpgrade},
    weights::Weight,
    PalletId,
};
use pallet_root_timelock::DelayTable;
use sp_core::H256;
use sp_runtime::traits::AccountIdConversion;
#[cfg(feature = "try-runtime")]
use {
    crate::RootTimelockMaxDelay,
    alloc::vec::Vec,
    frame_support::ensure,
    parity_scale_codec::{Decode, Encode},
    sp_runtime::TryRuntimeError,
};

use crate::{
    AccountId, AttestorReservePalletId, BlockNumber, RootTimelockDefaultDelays, Runtime,
    TreasuryPalletId, TESTNET_TIMELOCK_DELAYS,
};

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

/// Genesis hash of the Materios preprod chain.
pub const PREPROD_GENESIS_HASH: H256 = H256([
    0x0e, 0x46, 0xe3, 0x3f, 0x63, 0x9a, 0x56, 0xcc, 0x87, 0x80, 0xfd, 0x87, 0x1d, 0x9a, 0x15, 0xe1,
    0x6d, 0x99, 0xaf, 0x24, 0x85, 0x26, 0xf9, 0x07, 0xcb, 0x56, 0x0c, 0xb4, 0x08, 0x49, 0xf7, 0xbf,
]);

/// Stores the root-timelock delays on a chain that was running before the
/// pallet existed: the testnet delays on preprod, the mainnet defaults on any
/// other chain. A chain whose genesis built the pallet already stores its
/// delays and is left alone, so this is a no-op on every later upgrade.
pub struct InitRootTimelock;

impl InitRootTimelock {
    fn delays_for_this_chain() -> DelayTable<BlockNumber> {
        if frame_system::BlockHash::<Runtime>::get(0) == PREPROD_GENESIS_HASH {
            TESTNET_TIMELOCK_DELAYS
        } else {
            RootTimelockDefaultDelays::get()
        }
    }
}

impl OnRuntimeUpgrade for InitRootTimelock {
    fn on_runtime_upgrade() -> Weight {
        let db: frame_support::weights::RuntimeDbWeight =
            <Runtime as frame_system::Config>::DbWeight::get();
        if pallet_root_timelock::Delays::<Runtime>::exists() {
            return db.reads(1);
        }
        let delays = Self::delays_for_this_chain();
        pallet_root_timelock::Delays::<Runtime>::put(delays);
        log::info!("root-timelock: stored delays {:?}", delays);
        db.reads_writes(2, 1)
    }

    #[cfg(feature = "try-runtime")]
    fn pre_upgrade() -> Result<Vec<u8>, TryRuntimeError> {
        Ok(pallet_root_timelock::Delays::<Runtime>::exists().encode())
    }

    #[cfg(feature = "try-runtime")]
    fn post_upgrade(state: Vec<u8>) -> Result<(), TryRuntimeError> {
        let existed =
            bool::decode(&mut &state[..]).map_err(|_| "pre_upgrade state does not decode")?;
        ensure!(
            pallet_root_timelock::Delays::<Runtime>::exists(),
            "delays are not stored"
        );
        let delays = pallet_root_timelock::Delays::<Runtime>::get();
        ensure!(
            delays.is_valid(RootTimelockMaxDelay::get()),
            "stored delays are invalid"
        );
        if !existed {
            ensure!(
                delays == Self::delays_for_this_chain(),
                "stored delays are not this chain's"
            );
            ensure!(
                pallet_root_timelock::Tasks::<Runtime>::iter()
                    .next()
                    .is_none(),
                "a task predates the pallet"
            );
            ensure!(
                pallet_root_timelock::Guardian::<Runtime>::get().is_none(),
                "a guardian predates the pallet"
            );
        }
        Ok(())
    }
}
