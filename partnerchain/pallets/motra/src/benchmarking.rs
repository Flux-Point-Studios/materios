#![cfg(feature = "runtime-benchmarks")]

use super::*;
use frame_benchmarking::v2::*;
use frame_system::pallet_prelude::BlockNumberFor;

#[benchmarks(where
    T: pallet_balances::Config<Balance = u128>
        + frame_system::Config<AccountData = pallet_balances::AccountData<u128>>
)]
mod benchmarks {
    use super::*;
    use frame_support::traits::StoredMap;

    #[benchmark]
    fn checkpoint() {
        let caller: T::AccountId = whitelisted_caller();
        frame_system::Pallet::<T>::set_block_number(100u32.into());
        frame_system::Account::<T>::mutate(&caller, |a| {
            a.providers = 1;
            a.data.free = u128::MAX - 2;
        });
        AccrualCheckpoint::<T>::insert(&caller, (u128::MAX - 2, BlockNumberFor::<T>::from(90u32)));
        LegacyAccrualStart::<T>::put(BlockNumberFor::<T>::from(80u32));

        #[block]
        {
            // A legacy repair can precede the requested mutation. Both visits share one DB key.
            for free in [u128::MAX - 1, u128::MAX - 3] {
                MatraAccountStore::<T>::try_mutate_exists(&caller, |a| {
                    a.as_mut().expect("existing account").free = free;
                    Ok::<_, sp_runtime::DispatchError>(())
                })
                .expect("free balance mutation");
            }
        }

        assert_eq!(
            AccrualCheckpoint::<T>::get(&caller),
            Some((u128::MAX - 3, 90u32.into()))
        );
        assert_eq!(LegacyAccrualStart::<T>::get(), Some(80u32.into()));
    }

    #[benchmark]
    fn initialize_delegatee_clock() {
        let caller: T::AccountId = whitelisted_caller();
        AccrualCheckpoint::<T>::insert(&caller, (u128::MAX, BlockNumberFor::<T>::from(90u32)));
        LastTouched::<T>::remove(&caller);
        let existing: T::AccountId = account("existing clock", 0, 0);
        LastTouched::<T>::insert(&existing, BlockNumberFor::<T>::from(80u32));

        #[block]
        {
            Pallet::<T>::initialize_delegatee_clock(&caller, 0);
        }

        assert_eq!(LastTouched::<T>::get(&caller), 90u32.into());
    }

    #[benchmark]
    fn set_delegatee() {
        let caller: T::AccountId = whitelisted_caller();
        #[extrinsic_call]
        _(frame_system::RawOrigin::Signed(caller.clone()), None);
    }

    #[benchmark]
    fn set_params() {
        let params = crate::types::MotraParams::default();
        #[extrinsic_call]
        _(frame_system::RawOrigin::Root, params);
    }

    #[benchmark]
    fn claim_motra() {
        let caller: T::AccountId = whitelisted_caller();
        #[extrinsic_call]
        _(frame_system::RawOrigin::Signed(caller));
    }

    impl_benchmark_test_suite!(Pallet, crate::tests::new_test_ext(), crate::tests::Test);
}
