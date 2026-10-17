use crate::{AccrualCheckpoint, Config, LastTouched, MotraBalances, Pallet};
use frame_support::{
    traits::{Get, OnNewAccount, StoredMap},
    weights::{constants::RocksDbWeight, RuntimeDbWeight, Weight},
};
use frame_system::pallet_prelude::BlockNumberFor;
use pallet_balances::AccountData;
use sp_runtime::{traits::Zero, DispatchError};

impl<T: Config> OnNewAccount<T::AccountId> for Pallet<T> {
    fn on_new_account(who: &T::AccountId) {
        // Reaping MATRA must not restart decay of an existing MOTRA balance.
        if !LastTouched::<T>::contains_key(who) {
            // Delegated MOTRA can predate System.Account and use the default zero clock.
            let last = if MotraBalances::<T>::get(who) == 0 {
                frame_system::Pallet::<T>::block_number()
            } else {
                BlockNumberFor::<T>::zero()
            };
            LastTouched::<T>::insert(who, last);
        }
    }
}

pub fn checkpoint_weight<T: Config>() -> Weight {
    let configured = T::DbWeight::get();
    let minimum = RocksDbWeight::get();
    // Some runtimes inherit FRAME's zero DbWeight default.
    RuntimeDbWeight {
        read: configured.read.max(minimum.read),
        write: configured.write.max(minimum.write),
    }
    .reads_writes(4, 1)
    .saturating_add(Weight::from_parts(0, 14_000))
}

/// Balances' system-account store, with a conservative MATRA holding checkpoint.
pub struct MatraAccountStore<T>(core::marker::PhantomData<T>);

impl<T> StoredMap<T::AccountId, AccountData<T::Balance>> for MatraAccountStore<T>
where
    T: Config<Balance = u128> + frame_system::Config<AccountData = AccountData<u128>>,
{
    fn get(who: &T::AccountId) -> AccountData<T::Balance> {
        frame_system::Pallet::<T>::get(who)
    }

    fn try_mutate_exists<R, E: From<DispatchError>>(
        who: &T::AccountId,
        f: impl FnOnce(&mut Option<AccountData<T::Balance>>) -> Result<R, E>,
    ) -> Result<R, E> {
        let mut balances = (0u128, 0u128);
        let result = frame_system::Pallet::<T>::try_mutate_exists(who, |account| {
            balances.0 = account.as_ref().map(|a| a.free).unwrap_or(0);
            let result = f(account)?;
            balances.1 = account.as_ref().map(|a| a.free).unwrap_or(0);
            Ok::<R, E>(result)
        })?;
        if balances.0 != balances.1 {
            let now = frame_system::Pallet::<T>::block_number();
            AccrualCheckpoint::<T>::mutate(who, |checkpoint| {
                *checkpoint = Some(match *checkpoint {
                    // First funding after an empty balance starts a new earning interval.
                    _ if balances.0 == 0 => (balances.1, now),
                    Some((held, since)) => (held.min(balances.1), since),
                    None => (balances.0.min(balances.1), now),
                });
            });
        }
        Ok(result)
    }
}
