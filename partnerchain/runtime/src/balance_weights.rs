use crate::Runtime;
use frame_support::weights::Weight;

pub struct WithMotra;

pub fn mutations(accounts: u64) -> Weight {
    pallet_motra::checkpoint_weight::<Runtime>().saturating_mul(accounts)
}

macro_rules! weights {
    ($pallet:ident, $base:ty, { $( $name:ident($($arg:ident: $ty:ty),*) => $accounts:expr; )* }) => {
        impl $pallet::weights::WeightInfo for WithMotra {
            $(fn $name($($arg: $ty),*) -> Weight {
                <$base as $pallet::weights::WeightInfo>::$name($($arg),*)
                    .saturating_add(mutations($accounts))
            })*
        }
    };
}

weights!(pallet_balances, pallet_balances::weights::SubstrateWeight<Runtime>, {
    transfer_allow_death() => 2;
    transfer_keep_alive() => 2;
    force_set_balance_creating() => 1;
    force_set_balance_killing() => 1;
    force_transfer() => 2;
    transfer_all() => 2;
    force_unreserve() => 1;
    upgrade_accounts(u: u32) => u64::from(u);
    force_adjust_total_issuance() => 0;
    burn_allow_death() => 1;
    burn_keep_alive() => 1;
});

weights!(pallet_vesting, pallet_vesting::weights::SubstrateWeight<Runtime>, {
    vest_locked(l: u32, s: u32) => 1;
    vest_unlocked(l: u32, s: u32) => 1;
    vest_other_locked(l: u32, s: u32) => 1;
    vest_other_unlocked(l: u32, s: u32) => 1;
    vested_transfer(l: u32, s: u32) => 3;
    force_vested_transfer(l: u32, s: u32) => 3;
    not_unlocking_merge_schedules(l: u32, s: u32) => 1;
    unlocking_merge_schedules(l: u32, s: u32) => 1;
    force_remove_vesting_schedule(l: u32, s: u32) => 1;
});

weights!(pallet_multisig, pallet_multisig::weights::SubstrateWeight<Runtime>, {
    as_multi_threshold_1(z: u32) => 0;
    as_multi_create(s: u32, z: u32) => 1;
    as_multi_approve(s: u32, z: u32) => 0;
    as_multi_complete(s: u32, z: u32) => 1;
    approve_as_multi_create(s: u32) => 1;
    approve_as_multi_approve(s: u32) => 0;
    cancel_as_multi(s: u32) => 1;
});

weights!(pallet_recovery, pallet_recovery::weights::SubstrateWeight<Runtime>, {
    as_recovered() => 0;
    set_recovered() => 0;
    create_recovery(n: u32) => 1;
    initiate_recovery() => 1;
    vouch_recovery(n: u32) => 0;
    claim_recovery(n: u32) => 0;
    close_recovery(n: u32) => 2;
    remove_recovery(n: u32) => 1;
    cancel_recovered() => 0;
});

weights!(pallet_treasury, pallet_treasury::weights::SubstrateWeight<Runtime>, {
    spend_local() => 0;
    remove_approval() => 0;
    on_initialize_proposals(p: u32) => 2 * u64::from(p) + 1;
    spend() => 0;
    payout() => 2;
    check_status() => 0;
    void_spend() => 0;
});

// Each slot was generated on this runtime, including the MOTRA checkpoints of
// any balance it moves.
weights!(pallet_intent_settlement, pallet_intent_settlement::weights::SubstrateWeight<Runtime>, {
    settle_batch_atomic(n: u32) => 0;
    post_settlement_bond() => 0;
    slash_bad_settlement_evidence() => 0;
    release_settlement_bond() => 0;
    request_settle() => 0;
    request_batch_settle(n: u32) => 0;
    supersede_settlement_request() => 0;
    submit_intent() => 0;
    request_credit_refund() => 0;
    submit_batch_intents(n: u32) => 0;
    attest_intent() => 0;
    attest_batch_intents(n: u32) => 0;
    request_voucher() => 0;
    request_batch_vouchers(n: u32) => 0;
    attest_settle() => 0;
    attest_batch_settle(n: u32) => 0;
    attest_expire_policy() => 0;
    expire_intents(n: u32) => 0;
    request_expire_policy() => 0;
});

weights!(pallet_billing, pallet_billing::weights::SubstrateWeight<Runtime>, {
    balance_mutations(accounts: u32) => u64::from(accounts);
    topup_self() => 0;
    topup_for() => 0;
    pay_request() => 0;
    governance_set_endpoint_price() => 0;
    governance_set_debits_enabled() => 0;
    request_withdrawal() => 0;
    execute_withdrawal() => 0;
    cancel_withdrawal() => 0;
    prune_paid_requests(n: u32) => 0;
});

impl pallet_motra::weights::WeightInfo for WithMotra {
    fn checkpoint() -> Weight {
        pallet_motra::weights::SubstrateWeight::<Runtime>::checkpoint()
    }

    fn reconcile() -> Weight {
        pallet_motra::weights::SubstrateWeight::<Runtime>::reconcile()
    }

    fn fee_path() -> Weight {
        pallet_motra::weights::SubstrateWeight::<Runtime>::fee_path()
    }

    fn set_delegatee() -> Weight {
        pallet_motra::weights::SubstrateWeight::<Runtime>::set_delegatee()
    }

    fn set_params() -> Weight {
        pallet_motra::weights::SubstrateWeight::<Runtime>::set_params()
    }

    fn claim_motra() -> Weight {
        pallet_motra::weights::SubstrateWeight::<Runtime>::claim_motra()
    }
}

impl pallet_orinq_receipts::weights::WeightInfo for WithMotra {
    fn attest_non_threshold(n: u32) -> Weight {
        pallet_orinq_receipts::weights::SubstrateWeight::<Runtime>::attest_non_threshold(n)
    }

    fn attest_threshold(n: u32) -> Weight {
        pallet_orinq_receipts::weights::SubstrateWeight::<Runtime>::attest_threshold(n)
    }

    fn attest_bad_hash() -> Weight {
        pallet_orinq_receipts::weights::SubstrateWeight::<Runtime>::attest_bad_hash()
    }

    fn submit_receipt() -> Weight {
        pallet_orinq_receipts::weights::SubstrateWeight::<Runtime>::submit_receipt()
            .saturating_add(crate::motra_duty::threshold_read())
    }

    fn set_availability_cert() -> Weight {
        pallet_orinq_receipts::weights::SubstrateWeight::<Runtime>::set_availability_cert()
    }

    fn bond() -> Weight {
        pallet_orinq_receipts::weights::SubstrateWeight::<Runtime>::bond()
    }

    fn unbond() -> Weight {
        pallet_orinq_receipts::weights::SubstrateWeight::<Runtime>::unbond()
    }

    fn slash_attestor() -> Weight {
        pallet_orinq_receipts::weights::SubstrateWeight::<Runtime>::slash_attestor()
    }

    fn expire_receipt_fee() -> Weight {
        pallet_orinq_receipts::weights::SubstrateWeight::<Runtime>::expire_receipt_fee()
    }

    fn balance_mutations(accounts: u32) -> Weight {
        mutations(u64::from(accounts))
    }
}
