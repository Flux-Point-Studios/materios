//! Which Root calls the sudo key may dispatch at once, and how long every
//! other Root call waits in `RootTimelock`.
//!
//! Every signed path to Root goes through `pallet_sudo`: a multisig, a utility
//! batch and an account recovered through `pallet_recovery` all re-dispatch
//! their inner call under this filter, so gating `Sudo` gates them all. Root's
//! own dispatches bypass the filter, which is how `RootTimelock::enact` runs a
//! call once its delay has passed.

use crate::{IntentSettlementDefaultMinSignerThreshold, Runtime, RuntimeCall};
use core::slice;
use frame_support::traits::Contains;
use pallet_root_timelock::{CallClass, ClassifyCall, Delays};

/// `frame_system::Config::BaseCallFilter`.
pub struct SudoRootGate;

impl Contains<RuntimeCall> for SudoRootGate {
    fn contains(call: &RuntimeCall) -> bool {
        match call {
            RuntimeCall::Sudo(
                pallet_sudo::Call::sudo { call }
                | pallet_sudo::Call::sudo_unchecked_weight { call, .. },
            ) => runs_at_once(call),
            // `sudo_as`, `set_key` and `remove_key` are scheduled; Root may
            // call them after the delay.
            RuntimeCall::Sudo(_) => false,
            _ => true,
        }
    }
}

/// The calls the sudo key may dispatch as Root without waiting. None of them
/// can mint, move funds, or change who holds authority.
fn runs_at_once(call: &RuntimeCall) -> bool {
    match call {
        // Finality break-glass: forces the GRANDPA set the session already
        // selected at the next session boundary. It cannot choose that set.
        RuntimeCall::Grandpa(pallet_grandpa::Call::note_stalled { .. }) => true,
        // Kill-switches, in the stopping direction only.
        RuntimeCall::TeeAttestation(pallet_tee_attestation::Call::set_disabled {
            disabled: true,
        }) => true,
        RuntimeCall::Billing(pallet_billing::Call::governance_set_debits_enabled {
            enabled: false,
        }) => true,
        // Withdrawing a treasury spend before it pays out.
        RuntimeCall::Treasury(
            pallet_treasury::Call::remove_approval { .. }
            | pallet_treasury::Call::void_spend { .. },
        ) => true,
        RuntimeCall::RootTimelock(pallet_root_timelock::Call::schedule { .. }) => true,
        // Raising a delay only slows Root down. Lowering one is scheduled.
        RuntimeCall::RootTimelock(pallet_root_timelock::Call::set_delay { class, blocks }) => {
            *blocks >= Delays::<Runtime>::get().of(*class)
        }
        RuntimeCall::Utility(
            pallet_utility::Call::batch { calls }
            | pallet_utility::Call::batch_all { calls }
            | pallet_utility::Call::force_batch { calls },
        ) => calls.iter().all(runs_at_once),
        _ => false,
    }
}

/// The calls a wrapper dispatches in turn when it runs as Root.
struct Wrapped<'a> {
    calls: &'a [RuntimeCall],
    /// Whether they run under an origin the wrapper names instead of Root.
    under_another_origin: bool,
}

fn wrapped(call: &RuntimeCall) -> Option<Wrapped<'_>> {
    let (calls, under_another_origin) = match call {
        RuntimeCall::Sudo(
            pallet_sudo::Call::sudo { call }
            | pallet_sudo::Call::sudo_unchecked_weight { call, .. },
        )
        | RuntimeCall::Utility(pallet_utility::Call::with_weight { call, .. }) => {
            (slice::from_ref(call.as_ref()), false)
        }
        RuntimeCall::Sudo(pallet_sudo::Call::sudo_as { call, .. })
        | RuntimeCall::Utility(pallet_utility::Call::dispatch_as { call, .. }) => {
            (slice::from_ref(call.as_ref()), true)
        }
        RuntimeCall::Utility(
            pallet_utility::Call::batch { calls }
            | pallet_utility::Call::batch_all { calls }
            | pallet_utility::Call::force_batch { calls },
        ) => (calls.as_slice(), false),
        _ => return None,
    };
    Some(Wrapped {
        calls,
        under_another_origin,
    })
}

/// `pallet_root_timelock::Config::Classifier`. A wrapper waits the longest
/// class of the calls it carries, so a batch cannot hide a long call among
/// standard ones.
pub struct TimelockClassifier;

impl ClassifyCall<RuntimeCall> for TimelockClassifier {
    fn class_of(call: &RuntimeCall) -> CallClass {
        if let Some(wrapped) = wrapped(call) {
            let class = wrapped
                .calls
                .iter()
                .map(Self::class_of)
                .max()
                .unwrap_or(CallClass::Recovery);
            // Under another origin a recovery call is not a recovery call.
            return if wrapped.under_another_origin {
                class.max(CallClass::Standard)
            } else {
                class
            };
        }
        match call {
            // The committee and finality levers the chain is recovered with.
            // They can change who holds authority, so they wait the recovery
            // delay unless the guardian co-signs with `fast_track`.
            RuntimeCall::Grandpa(pallet_grandpa::Call::note_stalled { .. })
            | RuntimeCall::OrinqReceipts(
                pallet_orinq_receipts::Call::set_pinned_committee { .. }
                | pallet_orinq_receipts::Call::clear_pinned_committee {}
                | pallet_orinq_receipts::Call::set_break_glass_floor_enabled { .. }
                | pallet_orinq_receipts::Call::set_break_glass_aura_keys { .. }
                | pallet_orinq_receipts::Call::set_core_eviction_enabled { .. }
                | pallet_orinq_receipts::Call::set_contribution_window_enabled { .. }
                | pallet_orinq_receipts::Call::set_slack_invariant_enabled { .. }
                | pallet_orinq_receipts::Call::reset_candidate_liveness { .. },
            ) => CallClass::Recovery,
            // The Cardano scripts observed for native-token transfers into
            // this chain, and the signer floor for deposit attestations.
            RuntimeCall::NativeTokenManagement(
                pallet_native_token_management::Call::set_main_chain_scripts { .. },
            ) => CallClass::Long,
            RuntimeCall::IntentSettlement(
                pallet_intent_settlement::Call::set_min_signer_threshold { new_threshold },
            ) if lowers_min_signer_threshold(*new_threshold) => CallClass::Long,
            // Irreversible: no scheduled call could restore the key.
            RuntimeCall::Sudo(pallet_sudo::Call::remove_key {}) => CallClass::Long,
            RuntimeCall::RootTimelock(call) => call.class(),
            _ => CallClass::Standard,
        }
    }

    fn wraps_guardian_change(call: &RuntimeCall) -> bool {
        wrapped(call).is_some_and(|wrapped| {
            wrapped.calls.iter().any(|inner| {
                matches!(
                    inner,
                    RuntimeCall::RootTimelock(pallet_root_timelock::Call::set_guardian { .. })
                ) || Self::wraps_guardian_change(inner)
            })
        })
    }
}

/// Zero stands for the pallet default, as `set_min_signer_threshold` stores it.
fn lowers_min_signer_threshold(new_threshold: u32) -> bool {
    let effective = |v: u32| {
        if v == 0 {
            IntentSettlementDefaultMinSignerThreshold::get()
        } else {
            v
        }
    };
    effective(new_threshold)
        < effective(pallet_intent_settlement::MinSignerThreshold::<Runtime>::get())
}
