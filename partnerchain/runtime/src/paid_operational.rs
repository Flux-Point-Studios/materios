//! The Operational-class calls a signer may pay for. Operational weight may
//! take the whole block beyond the Normal share, and a call that fails before
//! it runs keeps the weight it declared, so any other paid Operational call is
//! refused before payment. Wrappers carry their inner call's class and are
//! judged by the account their inner calls dispatch as.

use crate::{
    root_gate::{multisig_account, GuardianVeto, SudoRootGate},
    AccountId, OrinqCommitteeAdapter, RootTimelock, Runtime, RuntimeCall, System,
};
use frame_support::{
    dispatch::DispatchInfo,
    traits::{Contains, ContainsPair},
};
use pallet_intent_settlement::IsCommitteeMember;
use sp_runtime::traits::StaticLookup;

pub fn admits(who: &AccountId, call: &RuntimeCall) -> bool {
    use pallet_intent_settlement::Call as Settlement;
    match call {
        RuntimeCall::RootTimelock(
            pallet_root_timelock::Call::cancel { .. }
            | pallet_root_timelock::Call::fast_track { .. }
            | pallet_root_timelock::Call::cancel_all {}
            | pallet_root_timelock::Call::approve { .. },
        ) => GuardianVeto::contains(who, call),
        // Root's exempt calls, signed by the sudo key.
        RuntimeCall::Sudo(pallet_sudo::Call::sudo { .. }) => {
            SudoRootGate::contains(call) && holds_sudo_key(who, call)
        }
        // Anyone may enact a ready task; its call was scheduled through Root.
        RuntimeCall::RootTimelock(pallet_root_timelock::Call::enact { id, call }) => {
            RootTimelock::enactable(*id, call).is_ok()
        }
        RuntimeCall::System(frame_system::Call::apply_authorized_upgrade { code }) => {
            System::validate_authorized_upgrade(code).is_ok()
        }
        // Permissionless keepers and watchers, each of a bounded declared weight.
        RuntimeCall::IntentSettlement(
            Settlement::request_settle { .. }
            | Settlement::request_batch_settle { .. }
            | Settlement::request_expire_policy { .. }
            | Settlement::post_settlement_bond { .. }
            | Settlement::release_settlement_bond { .. }
            | Settlement::slash_bad_settlement_evidence { .. },
        ) => true,
        RuntimeCall::IntentSettlement(
            Settlement::attest_intent { .. }
            | Settlement::request_voucher { .. }
            | Settlement::settle_claim { .. }
            | Settlement::expire_policy_mirror { .. }
            | Settlement::credit_deposit { .. }
            | Settlement::settle_batch_atomic { .. }
            | Settlement::attest_batch_intents { .. }
            | Settlement::request_batch_vouchers { .. }
            | Settlement::attest_settle { .. }
            | Settlement::attest_batch_settle { .. }
            | Settlement::attest_expire_policy { .. }
            | Settlement::supersede_settlement_request { .. },
        ) => OrinqCommitteeAdapter::is_member(who),
        RuntimeCall::Utility(
            pallet_utility::Call::batch { calls }
            | pallet_utility::Call::batch_all { calls }
            | pallet_utility::Call::force_batch { calls },
        ) => !calls.is_empty() && calls.iter().all(|inner| admits(who, inner)),
        RuntimeCall::Utility(pallet_utility::Call::as_derivative { index, call }) => admits(
            &pallet_utility::Pallet::<Runtime>::derivative_account_id(who.clone(), *index),
            call,
        ),
        RuntimeCall::Multisig(pallet_multisig::Call::as_multi_threshold_1 {
            other_signatories,
            call,
        }) => multisig_account(who, other_signatories, 1)
            .is_some_and(|multisig| admits(&multisig, call)),
        RuntimeCall::Recovery(pallet_recovery::Call::as_recovered { account, call }) => {
            <Runtime as frame_system::Config>::Lookup::lookup(account.clone()).is_ok_and(
                |account| {
                    pallet_recovery::Proxy::<Runtime>::get(who).as_ref() == Some(&account)
                        && admits(&account, call)
                },
            )
        }
        _ => false,
    }
}

/// `CheckOnlySudoAccount`, which the runtime does not install as an
/// extension, is the SDK's public check that a signer holds the sudo key.
#[allow(deprecated)]
fn holds_sudo_key(who: &AccountId, call: &RuntimeCall) -> bool {
    use sp_runtime::traits::SignedExtension;
    pallet_sudo::CheckOnlySudoAccount::<Runtime>::new()
        .validate(who, call, &DispatchInfo::default(), 0)
        .is_ok()
}
