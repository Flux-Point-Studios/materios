use super::*;
use frame_benchmarking::v2::*;
use frame_support::traits::Currency;
use frame_system::RawOrigin;

#[benchmarks(where T::MatraCurrency: Currency<T::AccountId, Balance = u128>)]
mod benchmarks {
    use super::*;

    fn funded<T: Config>() -> T::AccountId
    where
        T::MatraCurrency: Currency<T::AccountId, Balance = u128>,
    {
        let caller = account("payer", 0, 0);
        let _ = T::MatraCurrency::deposit_creating(&caller, 1_000_000);
        Balances::<T>::insert(&caller, 1_000_000);
        frame_system::Pallet::<T>::set_block_number(100u32.into());
        caller
    }

    #[benchmark]
    fn topup_self(m: Linear<0, 1>) {
        let caller = funded::<T>();
        #[extrinsic_call]
        topup_self(RawOrigin::Signed(caller.clone()), 10_000 * u128::from(m));
        assert_eq!(
            Balances::<T>::get(caller),
            1_000_000 + 10_000 * u128::from(m)
        );
    }

    #[benchmark]
    fn topup_for(m: Linear<0, 1>) {
        let caller = funded::<T>();
        let target: T::AccountId = account("target", 0, 0);
        Balances::<T>::insert(&target, 1_000_000);
        #[extrinsic_call]
        topup_for(
            RawOrigin::Signed(caller),
            target.clone(),
            10_000 * u128::from(m),
        );
        assert_eq!(
            Balances::<T>::get(target),
            1_000_000 + 10_000 * u128::from(m)
        );
    }

    #[benchmark]
    fn execute_withdrawal(m: Linear<0, 2>) {
        let caller = if m == 2 {
            account("new-payee", 0, 0)
        } else {
            funded::<T>()
        };
        frame_system::Pallet::<T>::set_block_number(100u32.into());
        PendingWithdrawals::<T>::insert(
            &caller,
            (
                10_000 * u128::from(m),
                frame_system::pallet_prelude::BlockNumberFor::<T>::from(100u32),
            ),
        );
        #[extrinsic_call]
        execute_withdrawal(RawOrigin::Signed(caller.clone()));
        assert!(!PendingWithdrawals::<T>::contains_key(caller));
    }

    impl_benchmark_test_suite!(
        Pallet,
        crate::tests::new_test_ext(),
        crate::tests::TestRuntime
    );
}
