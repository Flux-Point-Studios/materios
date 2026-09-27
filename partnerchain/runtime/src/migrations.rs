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

use alloc::vec::Vec;
use frame_support::{
    storage::unhashed,
    traits::{Currency, ExistenceRequirement, OnRuntimeUpgrade, ReservableCurrency},
    weights::{constants::RocksDbWeight, RuntimeDbWeight, Weight},
    Blake2_128Concat, PalletId,
};
use sp_io::hashing::twox_128;
use sp_runtime::traits::AccountIdConversion;

use crate::{AccountId, AttestorReservePalletId, Balance, Balances, TreasuryPalletId};

/// `frame_system::Config::DbWeight` is `()` in this runtime, which prices
/// storage access at zero; migrations charge RocksDB costs instead.
pub(crate) fn db_weight() -> RuntimeDbWeight {
    RocksDbWeight::get()
}

/// Moves `pot`'s whole free balance to the treasury, reaping `pot`, and
/// returns the amount moved. AllowDeath because a PalletId account is a
/// deterministic derivation that reappears on its next credit; KeepAlive would
/// refuse to drain past the existential deposit. A failed transfer is logged
/// and moves nothing. Costs at most `SWEEP_READS` and `SWEEP_WRITES`.
fn sweep_into_treasury(pot: &AccountId, name: &str) -> Balance {
    let free = Balances::free_balance(pot);
    if free == 0 {
        return 0;
    }
    let treasury: AccountId = TreasuryPalletId::get().into_account_truncating();
    match <Balances as Currency<AccountId>>::transfer(
        pot,
        &treasury,
        free,
        ExistenceRequirement::AllowDeath,
    ) {
        Ok(()) => free,
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
            "migration: removed the perp engine (released {} from {} keeper bonds, swept {} to the treasury, deleted {} further keys)",
            released, bonds, swept, deleted,
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
    fn pre_upgrade() -> Result<Vec<u8>, sp_runtime::TryRuntimeError> {
        use alloc::collections::btree_map::BTreeMap;
        use parity_scale_codec::Encode;

        let mut bond_entries: u32 = 0;
        let mut bonds: BTreeMap<AccountId, Balance> = BTreeMap::new();
        for (_market, keeper, bond) in ReservedKeeperBonds::iter() {
            bond_entries += 1;
            let total = bonds.entry(keeper).or_default();
            *total = total.saturating_add(bond);
        }
        let keys = perp_engine_key_count();
        frame_support::ensure!(
            keys + bond_entries <= PERP_ENGINE_KEYS_PER_UPGRADE,
            "perp-engine state exceeds what one upgrade deletes",
        );
        let mut reserved_after: Vec<(AccountId, Balance)> = Vec::with_capacity(bonds.len());
        for (keeper, bond) in bonds {
            let reserved = Balances::reserved_balance(&keeper);
            frame_support::ensure!(
                reserved >= bond,
                "a keeper holds less in reserve than its bond"
            );
            reserved_after.push((keeper, reserved - bond));
        }

        let pot = Balances::free_balance(&PERP_ENGINE_POT_ID.into_account_truncating());
        let treasury_after =
            Balances::free_balance(&TreasuryPalletId::get().into_account_truncating())
                .saturating_add(pot);

        log::info!(
            "RemovePerpEngine pre_upgrade: {} keys, {} bonded keepers, pot {}",
            keys,
            reserved_after.len(),
            pot,
        );
        Ok((reserved_after, treasury_after).encode())
    }

    #[cfg(feature = "try-runtime")]
    fn post_upgrade(state: Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
        use parity_scale_codec::Decode;

        let (reserved_after, treasury_after): (Vec<(AccountId, Balance)>, Balance) =
            Decode::decode(&mut &state[..])
                .map_err(|_| "RemovePerpEngine pre_upgrade state does not decode")?;

        frame_support::ensure!(
            !unhashed::contains_prefixed_key(&perp_engine_prefix()),
            "perp-engine keys survived the upgrade",
        );
        for (keeper, reserved) in &reserved_after {
            frame_support::ensure!(
                Balances::reserved_balance(keeper) == *reserved,
                "a keeper bond was not released exactly",
            );
        }
        frame_support::ensure!(
            Balances::free_balance(&PERP_ENGINE_POT_ID.into_account_truncating()) == 0,
            "the perp-engine margin pot was not swept",
        );
        frame_support::ensure!(
            Balances::free_balance(&TreasuryPalletId::get().into_account_truncating())
                == treasury_after,
            "the treasury did not receive exactly the margin pot",
        );

        log::info!(
            "RemovePerpEngine post_upgrade: prefix empty, {} keepers released, pot swept",
            reserved_after.len(),
        );
        Ok(())
    }
}
