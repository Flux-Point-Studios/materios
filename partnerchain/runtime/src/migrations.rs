//! Runtime-level storage migrations, run by `Executive` before the pallets'
//! own `on_runtime_upgrade` hooks.
//!
//! `SweepFeeRouterPotsIntoTreasury` moves the legacy fee-router's stranded
//! `mat/auth` and `mat/attr` balances into the treasury exactly once; later
//! upgrades leave `mat/attr` alone so legitimate post-cutover slashing receipts
//! aren't stolen by a re-run. Its gate is a plain storage entry rather than a
//! pallet StorageVersion to avoid introducing a new pallet (pallet-index shift
//! hazard).
//!
//! `RemovePerpEngine` deletes the retired perp engine (formerly pallet index 23)
//! from state.
//!
//! `InitRootTimelock` stores the root-timelock delays on a chain that was
//! running before the pallet existed.

use alloc::vec::Vec;
use frame_support::{
    storage::unhashed,
    traits::{
        fungible::Inspect,
        tokens::{Fortitude, Preservation},
        Currency, ExistenceRequirement, Get, OnRuntimeUpgrade, ReservableCurrency,
    },
    weights::{constants::RocksDbWeight, RuntimeDbWeight, Weight},
    Blake2_128Concat, PalletId,
};
use pallet_root_timelock::DelayTable;
use sp_core::H256;
use sp_io::hashing::twox_128;
use sp_runtime::traits::AccountIdConversion;
#[cfg(feature = "try-runtime")]
use {
    crate::RootTimelockMaxDelay,
    frame_support::ensure,
    parity_scale_codec::{Decode, Encode},
    sp_runtime::TryRuntimeError,
};

use crate::{
    AccountId, AttestorReservePalletId, Balance, Balances, BlockNumber, RootTimelockDefaultDelays,
    Runtime, TreasuryPalletId, TESTNET_TIMELOCK_DELAYS,
};

/// `frame_system::Config::DbWeight` is `()` in this runtime, which prices
/// storage access at zero; migrations charge RocksDB costs instead.
pub(crate) fn db_weight() -> RuntimeDbWeight {
    RocksDbWeight::get()
}

/// Moves everything `pot` can transfer to the treasury and returns the amount
/// moved. That excludes frozen funds: any account can lock part of a pot's
/// balance (a vested transfer into it, say), and asking for the whole free
/// balance would then fail the transfer and strand all of it. AllowDeath
/// because a PalletId account is a deterministic derivation that reappears on
/// its next credit; KeepAlive would refuse to drain past the existential
/// deposit. A failed transfer is logged and moves nothing. Costs at most
/// `SWEEP_READS` and `SWEEP_WRITES`.
fn sweep_into_treasury(pot: &AccountId, name: &str) -> Balance {
    let movable = sweepable(pot);
    if movable == 0 {
        return 0;
    }
    let treasury: AccountId = TreasuryPalletId::get().into_account_truncating();
    match <Balances as Currency<AccountId>>::transfer(
        pot,
        &treasury,
        movable,
        ExistenceRequirement::AllowDeath,
    ) {
        Ok(()) => movable,
        Err(e) => {
            log::error!(
                "migration: {} pot transfer failed ({:?}); leaving funds in place",
                name,
                e
            );
            0
        }
    }
}

fn sweepable(pot: &AccountId) -> Balance {
    <Balances as Inspect<AccountId>>::reducible_balance(
        pot,
        Preservation::Expendable,
        Fortitude::Polite,
    )
}

/// The pot's balance read, then both accounts read and written, plus the
/// transfer, reap and endowment events.
const SWEEP_READS: u64 = 3;
const SWEEP_WRITES: u64 = 5;

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
        unhashed::get::<u16>(Self::VERSION_KEY).unwrap_or(0)
    }

    fn set_version(v: u16) {
        unhashed::put::<u16>(Self::VERSION_KEY, &v);
    }
}

impl OnRuntimeUpgrade for SweepFeeRouterPotsIntoTreasury {
    fn on_runtime_upgrade() -> Weight {
        if Self::stored_version() >= SWEEP_MIGRATION_VERSION {
            return db_weight().reads(1);
        }

        let author = sweep_into_treasury(&AUTHOR_POT_ID.into_account_truncating(), "author");
        let attestor = sweep_into_treasury(
            &AttestorReservePalletId::get().into_account_truncating(),
            "attestor",
        );

        // Bump the gate even on partial failure: we've done our one-shot
        // attempt and future upgrades must not retry. Ops can sudo-transfer
        // any residue.
        Self::set_version(SWEEP_MIGRATION_VERSION);

        log::info!(
            "v5.1 migration: swept fee-router pots into treasury (author={}, attestor={})",
            author,
            attestor,
        );

        db_weight().reads_writes(1 + 2 * SWEEP_READS, 2 * SWEEP_WRITES + 1)
    }
}

/// Upper bound on the perp-engine keys `RemovePerpEngine` visits in one
/// upgrade: the bond entries it releases plus the keys its prefix clear scans,
/// which include those released entries again. It keeps the upgrade block's
/// weight bounded whatever the state holds; keys past it are deleted by the
/// next upgrade that carries the migration.
pub const PERP_ENGINE_KEYS_PER_UPGRADE: u32 = 1_000;

const PERP_ENGINE_POT_ID: PalletId = PalletId(*b"perp/v0w");

fn perp_engine_prefix() -> [u8; 16] {
    twox_128(b"PerpEngine")
}

/// The perp engine's keeper bonds, keyed `(market id, keeper)`. Each amount
/// is an anonymous `Balances` reserve on the keeper, so it survives the pallet
/// unless released here.
#[frame_support::storage_alias]
type ReservedKeeperBonds = StorageDoubleMap<
    PerpEngine,
    Blake2_128Concat,
    Vec<u8>,
    Blake2_128Concat,
    AccountId,
    Balance,
    frame_support::storage::types::ValueQuery,
>;

#[cfg(any(test, feature = "try-runtime"))]
pub(crate) fn perp_engine_key_count() -> u32 {
    let prefix = perp_engine_prefix();
    let mut count = 0;
    let mut cursor = prefix.to_vec();
    while let Some(next) = sp_io::storage::next_key(&cursor) {
        if !next.starts_with(&prefix) {
            break;
        }
        count += 1;
        cursor = next;
    }
    count
}

/// Deletes the perp engine from state: every keeper bond goes back to its
/// keeper, the margin pot goes to the treasury, and every key under the
/// pallet prefix is removed. Margin accounts are USD-denominated claims on
/// the pot and are dropped with it. Each bond entry is deleted as it is
/// released, and the rest of the prefix is cleared only once no bond entry
/// is left, so a run cut short by the bound neither releases a bond twice nor
/// deletes one unreleased. Once the prefix is empty the migration costs one
/// read.
pub struct RemovePerpEngine;

impl OnRuntimeUpgrade for RemovePerpEngine {
    fn on_runtime_upgrade() -> Weight {
        let prefix = perp_engine_prefix();
        if !unhashed::contains_prefixed_key(&prefix) {
            return db_weight().reads(1);
        }

        let mut released: Balance = 0;
        let mut bonds: u32 = 0;
        for (_market, keeper, bond) in
            ReservedKeeperBonds::drain().take(PERP_ENGINE_KEYS_PER_UPGRADE as usize)
        {
            bonds += 1;
            let short = Balances::unreserve(&keeper, bond);
            if short > 0 {
                log::error!(
                    "migration: keeper {:?} held {} less in reserve than its perp-engine bond",
                    keeper,
                    short,
                );
            }
            released = released.saturating_add(bond.saturating_sub(short));
        }

        let swept = sweep_into_treasury(
            &PERP_ENGINE_POT_ID.into_account_truncating(),
            "perp-engine margin",
        );

        // The prefix clear runs only when the drain stopped short of the bound,
        // so no bond entry is left for it to delete unreleased, and its scan
        // spends what the drain left of the bound.
        let budget = PERP_ENGINE_KEYS_PER_UPGRADE - bonds;
        let (scanned, deleted) = if budget > 0 {
            let cleared = unhashed::clear_prefix(&prefix, Some(budget), None);
            (cleared.loops, cleared.unique)
        } else {
            (0, 0)
        };
        if unhashed::contains_prefixed_key(&prefix) {
            log::error!(
                "migration: perp-engine keys remain past the per-upgrade bound of {}; the next upgrade carrying RemovePerpEngine deletes them",
                PERP_ENGINE_KEYS_PER_UPGRADE,
            );
        }

        log::info!(
            "migration: removed the perp engine (released {} from {} keeper bonds, swept {} to the treasury, prefix clear scanned {} keys)",
            released, bonds, swept, scanned,
        );

        // Per bond: key lookup, value read and account read; value kill,
        // account write and the Unreserved event. Three further reads: the
        // prefix check, the drain's final lookup and the leftover check.
        let bonds = u64::from(bonds);
        db_weight().reads_writes(
            3 + 3 * bonds + SWEEP_READS + u64::from(scanned),
            3 * bonds + SWEEP_WRITES + u64::from(deleted),
        )
    }

    #[cfg(feature = "try-runtime")]
    fn pre_upgrade() -> Result<Vec<u8>, TryRuntimeError> {
        use alloc::collections::btree_map::BTreeMap;

        let mut bond_entries: u32 = 0;
        let mut bonds: BTreeMap<AccountId, Balance> = BTreeMap::new();
        for (_market, keeper, bond) in ReservedKeeperBonds::iter() {
            bond_entries += 1;
            let total = bonds.entry(keeper).or_default();
            *total = total.saturating_add(bond);
        }
        let keys = perp_engine_key_count();
        ensure!(
            keys + bond_entries <= PERP_ENGINE_KEYS_PER_UPGRADE,
            "perp-engine state exceeds what one upgrade deletes",
        );
        let mut reserved_after: Vec<(AccountId, Balance)> = Vec::with_capacity(bonds.len());
        for (keeper, bond) in bonds {
            let reserved = Balances::reserved_balance(&keeper);
            ensure!(
                reserved >= bond,
                "a keeper holds less in reserve than its bond"
            );
            reserved_after.push((keeper, reserved - bond));
        }

        let pot: AccountId = PERP_ENGINE_POT_ID.into_account_truncating();
        let movable = sweepable(&pot);
        let pot_after = Balances::free_balance(&pot) - movable;
        let treasury_after =
            Balances::free_balance(&TreasuryPalletId::get().into_account_truncating())
                .saturating_add(movable);

        log::info!(
            "RemovePerpEngine pre_upgrade: {} keys, {} bonded keepers, pot {} movable of {}",
            keys,
            reserved_after.len(),
            movable,
            movable + pot_after,
        );
        Ok((reserved_after, pot_after, treasury_after).encode())
    }

    #[cfg(feature = "try-runtime")]
    fn post_upgrade(state: Vec<u8>) -> Result<(), TryRuntimeError> {
        let (reserved_after, pot_after, treasury_after): (
            Vec<(AccountId, Balance)>,
            Balance,
            Balance,
        ) = Decode::decode(&mut &state[..])
            .map_err(|_| "RemovePerpEngine pre_upgrade state does not decode")?;

        ensure!(
            !unhashed::contains_prefixed_key(&perp_engine_prefix()),
            "perp-engine keys survived the upgrade",
        );
        for (keeper, reserved) in &reserved_after {
            ensure!(
                Balances::reserved_balance(keeper) == *reserved,
                "a keeper bond was not released exactly",
            );
        }
        ensure!(
            Balances::free_balance(&PERP_ENGINE_POT_ID.into_account_truncating()) == pot_after,
            "the perp-engine margin pot was not swept",
        );
        ensure!(
            Balances::free_balance(&TreasuryPalletId::get().into_account_truncating())
                == treasury_after,
            "the treasury did not receive exactly what the margin pot could move",
        );

        log::info!(
            "RemovePerpEngine post_upgrade: prefix empty, {} keepers released, pot swept",
            reserved_after.len(),
        );
        Ok(())
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
