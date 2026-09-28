//! Which Root calls the sudo key may dispatch at once, and how long every
//! other Root call waits in `RootTimelock`.
//!
//! Every signed path to Root goes through `pallet_sudo`: a multisig, a utility
//! batch and an account recovered through `pallet_recovery` all re-dispatch
//! their inner call under this filter, so gating `Sudo` gates them all. Root's
//! own dispatches bypass the filter, which is how `RootTimelock::enact` runs a
//! call once its delay has passed.

use crate::{
    BlockNumber, IntentSettlementDefaultMinSignerThreshold, Runtime, RuntimeCall,
    RuntimeGenesisConfig, Sidechain,
};
use core::slice;
use frame_support::traits::Contains;
use pallet_root_timelock::{CallClass, ClassifyCall, Delays, Guardian};

/// The ceiling on [`max_exempt_stall_delay`]. The recorded recoveries used 30.
pub const MAX_EXEMPT_STALL_DELAY: BlockNumber = 100;

/// The longest `Grandpa.note_stalled` delay the sudo key may set without
/// waiting. The forced change it asks for is applied that many blocks after
/// the next session boundary, and GRANDPA refuses another forced change for
/// twice as long. While twice the delay fits in a session, neither outlasts
/// it, so the next rotation always goes through. A longer delay can hold a
/// change pending across boundaries, and every rotation is refused while one
/// is pending. A session is `slots_per_epoch` slots; the bound keeps twice the
/// delay inside half of them, so it holds with up to half the slots empty.
pub fn max_exempt_stall_delay() -> BlockNumber {
    MAX_EXEMPT_STALL_DELAY.min(Sidechain::slots_per_epoch().0 / 4)
}

/// Refuses a genesis in which nothing independent of the sudo key can veto
/// its timelock tasks: one that names no guardian without saying so, or one
/// whose guardian is the sudo key itself.
pub fn ensure_guarded_genesis(genesis: &RuntimeGenesisConfig) -> Result<(), &'static str> {
    genesis.root_timelock.ensure_guarded()?;
    match &genesis.root_timelock.guardian {
        Some(guardian) if genesis.sudo.key.as_ref() == Some(guardian) => {
            Err("the root-timelock guardian must not be the sudo key")
        }
        _ => Ok(()),
    }
}

/// `frame_system::Config::BaseCallFilter`.
pub struct SudoRootGate;

impl Contains<RuntimeCall> for SudoRootGate {
    fn contains(call: &RuntimeCall) -> bool {
        match call {
            RuntimeCall::Sudo(pallet_sudo::Call::sudo { call }) => runs_at_once(call),
            // `sudo_unchecked_weight` would let the key declare any weight
            // for an exempt call and fill blocks the guardian's veto needs.
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
        RuntimeCall::Grandpa(pallet_grandpa::Call::note_stalled { delay, .. }) => {
            *delay <= max_exempt_stall_delay()
        }
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
        // Withdrawing the pending guardian change keeps the guardian in
        // place. With no guardian nothing can veto the sudo key's tasks, so
        // its own veto gives it nothing new; it lets it withdraw an abandoned
        // task.
        RuntimeCall::RootTimelock(pallet_root_timelock::Call::cancel { id }) => {
            pallet_root_timelock::Pallet::<Runtime>::root_may_cancel(*id)
        }
        RuntimeCall::RootTimelock(pallet_root_timelock::Call::cancel_all {}) => {
            Guardian::<Runtime>::get().is_none()
        }
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
            // The committee and finality levers the chain is recovered with
            // that cannot fix who holds authority: they change how the
            // committee is drawn from the Cardano-registered candidates, or
            // force the GRANDPA set the session chose within one session.
            RuntimeCall::Grandpa(pallet_grandpa::Call::note_stalled { delay, .. })
                if *delay <= max_exempt_stall_delay() =>
            {
                CallClass::Recovery
            }
            RuntimeCall::OrinqReceipts(
                pallet_orinq_receipts::Call::clear_pinned_committee {}
                | pallet_orinq_receipts::Call::set_break_glass_floor_enabled { .. }
                | pallet_orinq_receipts::Call::set_core_eviction_enabled { .. }
                | pallet_orinq_receipts::Call::set_contribution_window_enabled { .. }
                | pallet_orinq_receipts::Call::set_slack_invariant_enabled { .. }
                | pallet_orinq_receipts::Call::reset_candidate_liveness { .. },
            ) => CallClass::Recovery,
            // The levers that can: a pin is installed verbatim, bypassing the
            // draw and every floor; the break-glass keys decide which draws
            // the floor accepts; a longer stall can freeze GRANDPA rotation;
            // a new sudo key is the defence against a stolen one, and with
            // the guardian's co-sign it lands before anything the stolen key
            // scheduled. Without a co-sign they wait as long as a mint does.
            RuntimeCall::Grandpa(pallet_grandpa::Call::note_stalled { .. })
            | RuntimeCall::OrinqReceipts(
                pallet_orinq_receipts::Call::set_pinned_committee { .. }
                | pallet_orinq_receipts::Call::set_break_glass_aura_keys { .. },
            )
            | RuntimeCall::Sudo(pallet_sudo::Call::set_key { .. }) => CallClass::AuthorityRecovery,
            // The Cardano scripts observed for native-token transfers into
            // this chain, and the signer floor for deposit attestations. The
            // long class binds these levers only: `set_code`, `set_storage`,
            // the attestation committee and the balance force calls reach
            // the same ends and wait the standard delay, which with the
            // guardian's veto is the bound against a stolen sudo key.
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
