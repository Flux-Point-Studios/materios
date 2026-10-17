#![cfg(feature = "runtime-benchmarks")]

use super::*;
use frame_benchmarking::v2::*;
use frame_support::weights::Weight;
use frame_system::pallet_prelude::BlockNumberFor;

#[benchmarks(where
    T: pallet_balances::Config<Balance = u128>
        + frame_system::Config<AccountData = pallet_balances::AccountData<u128>>
        + Send + Sync,
    <T as frame_system::Config>::RuntimeCall: sp_runtime::traits::Dispatchable<
        Info = frame_support::dispatch::DispatchInfo,
        PostInfo = frame_support::dispatch::PostDispatchInfo,
    >,
)]
mod benchmarks {
    use super::*;
    use frame_support::traits::StoredMap;

    fn dormant_payer<
        T: Config<Balance = u128>
            + frame_system::Config<AccountData = pallet_balances::AccountData<u128>>,
    >(
        elapsed: u32,
    ) -> T::AccountId {
        let caller: T::AccountId = account("dormant payer", 0, 0);
        let delegatee: T::AccountId = account("dormant delegatee", 0, 0);
        let balance = 1_000_000_000_000_000_000u128;
        frame_system::Pallet::<T>::set_block_number(elapsed.into());
        for who in [&caller, &delegatee] {
            frame_system::Account::<T>::mutate(who, |a| {
                a.providers = 1;
                a.data.free = balance;
            });
            AccrualCheckpoint::<T>::insert(who, (balance, BlockNumberFor::<T>::from(1u32)));
            LastTouched::<T>::insert(who, BlockNumberFor::<T>::from(0u32));
            MotraBalances::<T>::insert(who, balance);
        }
        Delegatees::<T>::insert(&caller, &delegatee);
        LegacyAccrualStart::<T>::put(BlockNumberFor::<T>::from(0u32));
        Params::<T>::mutate(|p| {
            p.decay_rate_per_block = sp_runtime::Perbill::from_parts(999_999_999);
            p.max_balance = u128::MAX;
            p.congestion_rate = 1_000;
            p.min_fee = 1_000;
            p.length_fee_per_byte = 1;
            p.generation_per_matra_per_block = 100_000;
        });
        caller
    }

    fn assert_delegatee_reconciled<T: Config>() {
        let delegatee: T::AccountId = account("dormant delegatee", 0, 0);
        assert_eq!(
            LastTouched::<T>::get(&delegatee),
            frame_system::Pallet::<T>::block_number()
        );
    }

    #[benchmark]
    fn checkpoint() {
        let caller: T::AccountId = whitelisted_caller();
        frame_system::Pallet::<T>::set_block_number(100u32.into());
        frame_system::Account::<T>::mutate(&caller, |a| {
            a.providers = 1;
            a.data.free = u128::MAX - 2;
        });
        AccrualCheckpoint::<T>::insert(&caller, (u128::MAX - 2, BlockNumberFor::<T>::from(90u32)));

        #[block]
        {
            // Reward and escrow payouts can change the same account twice in a dispatch.
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
    }

    #[benchmark]
    fn set_delegatee() {
        let caller = dormant_payer::<T>(u32::MAX);
        #[extrinsic_call]
        _(frame_system::RawOrigin::Signed(caller.clone()), None);
        assert_delegatee_reconciled::<T>();
    }

    #[benchmark]
    fn set_params() {
        let params = crate::types::MotraParams::default();
        #[extrinsic_call]
        _(frame_system::RawOrigin::Root, params);
    }

    #[benchmark]
    fn claim_motra() {
        let caller = dormant_payer::<T>(u32::MAX);
        #[extrinsic_call]
        _(frame_system::RawOrigin::Signed(caller));
        assert_delegatee_reconciled::<T>();
    }

    #[benchmark]
    fn reconcile() {
        let caller = dormant_payer::<T>(u32::MAX);
        #[block]
        {
            Pallet::<T>::reconcile(&caller).expect("reconciliation");
        }
        assert_eq!(LastTouched::<T>::get(&caller), u32::MAX.into());
        assert_delegatee_reconciled::<T>();
    }

    #[benchmark]
    fn reconcile_100k() {
        let caller = dormant_payer::<T>(100_000);
        #[block]
        {
            Pallet::<T>::reconcile(&caller).expect("reconciliation");
        }
        assert_eq!(LastTouched::<T>::get(&caller), 100_000u32.into());
        assert_delegatee_reconciled::<T>();
    }

    #[benchmark]
    fn reconcile_million() {
        let caller = dormant_payer::<T>(1_000_000);
        #[block]
        {
            Pallet::<T>::reconcile(&caller).expect("reconciliation");
        }
        assert_eq!(LastTouched::<T>::get(&caller), 1_000_000u32.into());
        assert_delegatee_reconciled::<T>();
    }

    #[benchmark]
    fn reconcile_legacy() {
        let caller = dormant_payer::<T>(u32::MAX);
        AccrualCheckpoint::<T>::remove(&caller);
        #[block]
        {
            Pallet::<T>::reconcile(&caller).expect("legacy reconciliation");
        }
        assert_delegatee_reconciled::<T>();
    }

    #[benchmark]
    fn fee_path() {
        use frame_support::dispatch::{DispatchInfo, PostDispatchInfo};
        use sp_runtime::traits::SignedExtension;
        let caller = dormant_payer::<T>(u32::MAX);
        let call = frame_system::Call::<T>::remark {
            remark: alloc::vec![],
        }
        .into();
        let info = DispatchInfo {
            weight: Weight::from_parts(1_000_000_000, 0),
            ..Default::default()
        };
        let post = PostDispatchInfo {
            actual_weight: Some(Weight::zero()),
            ..Default::default()
        };
        #[block]
        {
            let pre = crate::fee::ChargeMotra::<T>::new()
                .pre_dispatch(&caller, &call, &info, 100)
                .expect("fee pre-dispatch");
            crate::fee::ChargeMotra::<T>::post_dispatch(Some(pre), &info, &post, 100, &Ok(()))
                .expect("fee refund");
        }
        assert!(TotalBurned::<T>::get() > 0);
        assert_delegatee_reconciled::<T>();
    }

    impl_benchmark_test_suite!(Pallet, crate::tests::new_test_ext(), crate::tests::Test);
}
