use crate::*;
use frame_support::{dispatch::GetDispatchInfo, traits::ReservableCurrency};
use pallet_balances::WeightInfo;
use proptest::prelude::*;
use sp_runtime::{traits::Dispatchable, BuildStorage};

type Base = pallet_balances::weights::SubstrateWeight<Runtime>;

fn base_weight(call: &pallet_balances::Call<Runtime>) -> Weight {
    use pallet_balances::Call::*;
    match call {
        transfer_allow_death { .. } => Base::transfer_allow_death(),
        transfer_keep_alive { .. } => Base::transfer_keep_alive(),
        force_transfer { .. } => Base::force_transfer(),
        transfer_all { .. } => Base::transfer_all(),
        force_unreserve { .. } => Base::force_unreserve(),
        upgrade_accounts { who } => Base::upgrade_accounts(who.len() as u32),
        force_set_balance { .. } => {
            Base::force_set_balance_creating().max(Base::force_set_balance_killing())
        }
        force_adjust_total_issuance { .. } => Base::force_adjust_total_issuance(),
        burn { keep_alive, .. } => {
            if *keep_alive {
                Base::burn_allow_death()
            } else {
                Base::burn_keep_alive()
            }
        }
        __Ignore(_, _) => unreachable!("uninhabited call"),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test]
    fn checkpoint_every_balances_call_covers_touched_storage(
        units in 1u128..1000,
        amount_kind in 0u8..5,
        recipient_exists in any::<bool>(),
        self_transfer in any::<bool>(),
        legacy in any::<bool>(),
        checkpoint_exists in any::<bool>(),
    ) {
        let sender = sp_keyring::Sr25519Keyring::Dave.to_account_id();
        let receiver = if self_transfer { sender.clone() } else {
            sp_keyring::Sr25519Keyring::Eve.to_account_id()
        };
        let ed = ExistentialDeposit::get();
        let free = (units + 2) * ed;
        let amount = match amount_kind {
            0 => 0,
            1 => ed,
            2 => free,
            3 => free - ed / 2,
            _ => u128::MAX,
        };
        for operation in 0..12 {
            let mut ext: sp_io::TestExternalities = frame_system::GenesisConfig::<Runtime>::default()
                .build_storage().expect("system genesis").into();
            ext.execute_with(|| {
                System::set_block_number(100);
                let mut accounts = vec![(sender.clone(), free)];
                if recipient_exists && receiver != sender {
                    accounts.push((receiver.clone(), 2 * ed));
                }
                for (who, balance) in accounts {
                    System::inc_providers(&who);
                    frame_system::Account::<Runtime>::mutate(&who, |a| {
                        a.data.free = balance;
                        if legacy {
                            a.data.flags = pallet_balances::ExtraFlags::old_logic();
                            a.data.reserved = ed;
                            a.providers = 0;
                            if amount_kind == 1 {
                                a.data.free = ed / 2;
                            }
                        }
                    });
                    if checkpoint_exists {
                        pallet_motra::AccrualCheckpoint::<Runtime>::insert(&who, (balance, 90));
                    }
                }
                pallet_balances::TotalIssuance::<Runtime>::put(10_000 * ed);
                pallet_motra::LegacyAccrualStart::<Runtime>::put(80);
                if !legacy && matches!(operation, 4 | 11) {
                    Balances::reserve(&sender, ed).expect("seed reserve");
                }
            });
            ext.commit_all().expect("commit fixture before observing writes");
            let (weight, base, before, after) = ext.execute_with(|| {
                let before = [Balances::free_balance(&sender), Balances::free_balance(&receiver)];
                let (weight, base) = if operation >= 10 {
                    use pallet_intent_settlement::WeightInfo as _;
                    type BondBase = pallet_intent_settlement::weights::SubstrateWeight<Runtime>;
                    type Bond = <Runtime as pallet_intent_settlement::Config>::WeightInfo;
                    if operation == 10 {
                        let _result = Balances::reserve(&sender, amount);
                        (Bond::post_settlement_bond(), BondBase::post_settlement_bond())
                    } else {
                        Balances::unreserve(&sender, amount);
                        (Bond::release_settlement_bond(), BondBase::release_settlement_bond())
                    }
                } else {
                    use pallet_balances::Call::*;
                    let call = match operation {
                        0 => transfer_allow_death { dest: receiver.clone().into(), value: amount },
                        1 => transfer_keep_alive { dest: receiver.clone().into(), value: amount },
                        2 => force_transfer { source: sender.clone().into(), dest: receiver.clone().into(), value: amount },
                        3 => transfer_all { dest: receiver.clone().into(), keep_alive: amount_kind % 2 == 0 },
                        4 => force_unreserve { who: sender.clone().into(), amount },
                        5 => upgrade_accounts { who: vec![sender.clone(), receiver.clone(), sender.clone()] },
                        6 => force_set_balance { who: sender.clone().into(), new_free: amount },
                        7 => force_adjust_total_issuance { direction: pallet_balances::AdjustmentDirection::Increase, delta: amount },
                        8 => burn { value: amount, keep_alive: true },
                        9 => burn { value: amount, keep_alive: false },
                        _ => unreachable!(),
                    };
                    let base = base_weight(&call);
                    let runtime_call = RuntimeCall::Balances(call);
                    let weight = runtime_call.get_dispatch_info().weight;
                    let origin = if matches!(operation, 2 | 4 | 6 | 7) {
                        RuntimeOrigin::root()
                    } else {
                        RuntimeOrigin::signed(sender.clone())
                    };
                    let _result = runtime_call.dispatch(origin);
                    (weight, base)
                };
                let after = [Balances::free_balance(&sender), Balances::free_balance(&receiver)];
                (weight, base, before, after)
            });
            let sender_key = pallet_motra::AccrualCheckpoint::<Runtime>::hashed_key_for(&sender);
            let touched: Vec<_> = ext.overlayed_changes().changes()
                .filter(|(key, _)| key.starts_with(&sender_key[..32]))
                .map(|(key, _)| key.clone()).collect();
            for (i, who) in [&sender, &receiver].into_iter().enumerate() {
                if before[i] != after[i] {
                    prop_assert!(touched.contains(&pallet_motra::AccrualCheckpoint::<Runtime>::hashed_key_for(who)),
                        "operation {} changed free balance without a checkpoint", operation);
                }
            }
            let required = base.saturating_add(pallet_motra::checkpoint_weight::<Runtime>()
                .saturating_mul(touched.len() as u64));
            prop_assert!(weight.all_gte(required),
                "operation {}: {:?} fails to cover {} checkpoint entries: {:?}",
                operation, weight, touched.len(), required);
            let account_bound = match operation {
                0..=3 => 2,
                5 => 3,
                7 => 0,
                _ => 1,
            };
            prop_assert!(weight.all_lte(base.saturating_add(
                pallet_motra::checkpoint_weight::<Runtime>().saturating_mul(account_bound))),
                "operation {} charges more than its {} account bound", operation, account_bound);
        }
    }
}
