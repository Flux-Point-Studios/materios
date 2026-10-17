use super::*;
use frame_support::weights::Weight;
use proptest::prelude::*;

fn seed(who: u64, matra: u128, stored: u128, rate: Perbill) {
    assert_ok!(Balances::force_set_balance(
        RuntimeOrigin::root(),
        who,
        matra
    ));
    pallet::Params::<Test>::mutate(|p| {
        p.decay_rate_per_block = rate;
        p.generation_per_matra_per_block = 100_000;
        p.max_balance = u128::MAX;
    });
    pallet::AccrualCheckpoint::<Test>::insert(who, (matra, 1));
    pallet::LastTouched::<Test>::insert(who, 1);
    pallet::MotraBalances::<Test>::insert(who, stored);
}

#[test]
fn decay_dormancy_does_not_exceed_equilibrium() {
    new_test_ext().execute_with(|| {
        seed(10, 1_000_000_000, 1_000, Perbill::from_parts(999_900_000));
        System::set_block_number(1_000_001);
        assert!(Motra::projected_balance(&10) <= 1_000_000_001_000);
        assert_eq!(Motra::reconcile(&10), Ok(Motra::projected_balance(&10)));
    });
}

#[test]
fn decay_u32_max_does_not_stop_at_the_old_cap_or_round_dust_up() {
    new_test_ext().execute_with(|| {
        seed(10, 0, 4_999, Perbill::from_parts(999_900_000));
        System::set_block_number(u64::from(u32::MAX) + 1);
        assert_eq!(Motra::reconcile(&10), Ok(0));
    });
}

#[test]
fn decay_matches_old_iteration_with_an_explicit_rounding_bound() {
    new_test_ext().execute_with(|| {
        for parts in [
            0,
            500_000_000,
            999_000_000,
            999_900_000,
            999_999_999,
            1_000_000_000,
        ] {
            let rate = Perbill::from_parts(parts);
            for stored in [1, 4_999, 1_000_000_000, 1_000_000_000_000_000_000] {
                for n in [0, 1, 2, 100, 100_000] {
                    System::set_block_number(1);
                    seed(10, 0, stored, rate);
                    System::set_block_number(n + 1);
                    let old = (0..n).fold(stored, |b, _| rate * b);
                    let projected = Motra::projected_balance(&10);
                    assert!(
                        old.abs_diff(projected) <= u128::from(n) + 2,
                        "rate={parts} stored={stored} n={n}: old={old}, new={projected}"
                    );
                }
            }
        }
    });
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn decay_dormant_generation_never_rewards_less_frequent_reconciliation(
        n in 0u64..2_000,
        matra in 1u128..1_000_000_000_000,
        parts in prop_oneof![Just(0), Just(999_900_000), Just(999_999_999), Just(1_000_000_000), 1u32..1_000_000_000],
    ) {
        new_test_ext().execute_with(|| {
            let rate = Perbill::from_parts(parts);
            seed(10, matra, 0, rate);
            seed(11, matra, 0, rate);
            for block in 2..=n + 1 {
                System::set_block_number(block);
                assert_ok!(Motra::reconcile(&10));
            }
            assert_ok!(Motra::reconcile(&11));
            let active = Motra::motra_balance(&10);
            let dormant = Motra::motra_balance(&11);
            assert!(dormant <= active, "n={n}, matra={matra}, r={parts}: {dormant} > {active}");
            // One unit per step covers nearest-integer error and conservative rounding;
            // four units also cover fixed-point error for per-block generation <= 1e18.
            assert!(active - dormant <= 4 * u128::from(n) + 2,
                "n={n}, matra={matra}, r={parts}: gap {}", active - dormant);
        });
    }

    #[test]
    fn decay_one_block_is_identical_to_the_existing_step(
        stored in 0u128..1_000_000_000_000_000_000,
        matra in 1u128..1_000_000_000_000,
        parts in 0u32..=1_000_000_000,
    ) {
        new_test_ext().execute_with(|| {
            let rate = Perbill::from_parts(parts);
            seed(10, matra, stored, rate);
            System::set_block_number(2);
            let expected = rate * stored + matra * 100_000 / 1_000_000;
            assert_eq!(Motra::projected_balance(&10), expected);
            assert_eq!(Motra::reconcile(&10), Ok(expected));
        });
    }
}

#[test]
fn decay_new_sponsorship_starts_at_credit_and_preserves_pending_generation() {
    new_test_ext().execute_with(|| {
        let rate = Perbill::from_parts(999_900_000);
        seed(10, 1_000_000_000, 0, rate);
        seed(11, 1_000_000, 0, rate);
        seed(12, 1_000_000, 0, rate);
        pallet::LastTouched::<Test>::remove(11);
        pallet::Delegatees::<Test>::insert(10, 11);
        System::set_block_number(200_001);
        let pending = Motra::projected_balance(&12);
        assert_ok!(Motra::reconcile(&10));
        let credited = Motra::motra_balance(&11);
        assert!(credited > 0);
        assert_eq!(Motra::projected_balance(&11), credited + pending);
        assert_eq!(Motra::last_touched(&11), 200_001);
        assert_eq!(Motra::reconcile(&11), Ok(credited + pending));
        System::set_block_number(200_002);
        assert_eq!(
            Motra::projected_balance(&11),
            rate * (credited + pending) + 100_000
        );
    });
}

#[test]
fn decay_fee_refunds_actual_weight_without_changing_length_or_minimum_fee() {
    use frame_support::dispatch::{DispatchInfo, Pays, PostDispatchInfo};
    use sp_runtime::traits::SignedExtension;
    new_test_ext().execute_with(|| {
        seed(10, 1, 1_000_000_000, Perbill::one());
        pallet::Params::<Test>::mutate(|p| p.congestion_rate = 1_000);
        let call = RuntimeCall::Motra(crate::Call::claim_motra {});
        let info = DispatchInfo {
            weight: Weight::from_parts(100_000_000, 0),
            ..Default::default()
        };
        let actual = Weight::from_parts(10_000_000, 0);
        let fee = Motra::compute_fee(actual, 100);
        let pre = crate::fee::ChargeMotra::<Test>::new()
            .pre_dispatch(&10, &call, &info, 100)
            .expect("pre-dispatch fee");
        let events_before_refund = System::events().len();
        assert_ok!(crate::fee::ChargeMotra::<Test>::post_dispatch(
            Some(pre),
            &info,
            &PostDispatchInfo {
                actual_weight: Some(actual),
                pays_fee: Pays::Yes
            },
            100,
            &Ok(()),
        ));
        assert_eq!(Motra::motra_balance(&10), 1_000_000_000 - fee);
        assert_eq!(Motra::total_burned(), fee);
        assert_eq!(
            System::events().len(),
            events_before_refund + 1,
            "refund must be observable alongside FeeBurned"
        );
    });
}

#[cfg(feature = "try-runtime")]
#[test]
fn decay_try_state_rejects_a_bypassed_balance_checkpoint() {
    new_test_ext().execute_with(|| {
        assert_ok!(Motra::try_state(System::block_number()));
        pallet::AccrualCheckpoint::<Test>::insert(3, (2, 1));
        assert!(Motra::try_state(System::block_number()).is_err());
    });
}

#[test]
fn decay_fee_refund_uses_paid_rate_and_records_only_the_credited_amount() {
    use frame_support::dispatch::{DispatchInfo, PostDispatchInfo};
    use sp_runtime::traits::SignedExtension;
    for saturated in [false, true] {
        new_test_ext().execute_with(|| {
            seed(10, 1, 1_000_000_000, Perbill::one());
            pallet::Params::<Test>::mutate(|p| p.congestion_rate = 1_000);
            let call = RuntimeCall::Motra(crate::Call::claim_motra {});
            let info = DispatchInfo {
                weight: Weight::from_parts(100_000_000, 0),
                ..Default::default()
            };
            let actual = Weight::from_parts(10_000_000, 0);
            let pre = crate::fee::ChargeMotra::<Test>::new()
                .pre_dispatch(&10, &call, &info, 10)
                .expect("fee");
            let burned = Motra::total_burned();
            pallet::Params::<Test>::mutate(|p| p.congestion_rate = 100_000);
            if saturated {
                pallet::MotraBalances::<Test>::insert(10, u128::MAX - 7);
            }
            let before = Motra::motra_balance(&10);
            assert_ok!(crate::fee::ChargeMotra::<Test>::post_dispatch(
                Some(pre),
                &info,
                &PostDispatchInfo {
                    actual_weight: Some(actual),
                    ..Default::default()
                },
                10,
                &Ok(()),
            ));
            let credited = Motra::motra_balance(&10) - before;
            assert_eq!(credited, if saturated { 7 } else { 90_000 });
            assert_eq!(burned - Motra::total_burned(), credited);
            assert_eq!(
                System::events().last().expect("refund event").event,
                RuntimeEvent::Motra(pallet::Event::FeeRefunded {
                    who: 10,
                    amount: credited
                })
            );
        });
    }
}

#[test]
fn decay_reconciliation_event_reports_its_accounts_decay() {
    new_test_ext().execute_with(|| {
        seed(10, 1_000, 100, Perbill::from_percent(50));
        seed(11, 0, 1_000, Perbill::from_percent(50));
        pallet::Delegatees::<Test>::insert(10, 11);
        pallet::TotalIssued::<Test>::put(1_100u128);
        System::set_block_number(2);
        assert_eq!(Motra::reconcile(&10), Ok(50));
        assert_eq!(Motra::total_issued(), 650);
        assert_eq!(
            System::events().last().expect("reconcile event").event,
            RuntimeEvent::Motra(pallet::Event::BalanceReconciled {
                account: 10,
                new_balance: 50,
                decayed: 50,
                generated: 100,
            })
        );
    });
}
