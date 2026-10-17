use crate::{AccrualCheckpoint, Config};
use frame_support::{traits::StoredMap, weights::Weight};
use pallet_balances::AccountData;
use sp_runtime::DispatchError;

pub fn checkpoint_weight<T: Config>() -> Weight {
    <<T as Config>::WeightInfo as crate::weights::WeightInfo>::checkpoint()
}

pub fn reconciliation_weight<T: Config>() -> Weight {
    <<T as Config>::WeightInfo as crate::weights::WeightInfo>::reconcile()
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
