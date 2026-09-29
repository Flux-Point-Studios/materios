//! Which Root calls the sudo key may dispatch at once, and how long every
//! other Root call waits in `RootTimelock`.
//!
//! Every signed path to Root goes through `pallet_sudo`: a multisig, a utility
//! batch and an account recovered through `pallet_recovery` all re-dispatch
//! their inner call under this filter, so gating `Sudo` gates them all. Root's
//! own dispatches bypass the filter, which is how `RootTimelock::enact` runs a
//! call once its delay has passed.

use crate::{
    AccountId, BlockNumber, IntentSettlementDefaultMinSignerThreshold, Runtime, RuntimeCall,
    RuntimeGenesisConfig, Sidechain,
};
use alloc::vec::Vec;
use core::slice;
use frame_support::{
    dispatch::GetDispatchInfo,
    traits::{Contains, ContainsPair},
    weights::{constants::RocksDbWeight, Weight},
};
use pallet_root_timelock::{CallClass, ClassifyCall, Guardian};
use sp_keyring::Sr25519Keyring;

/// The ceiling on [`max_exempt_stall_delay`]: the delay the recorded
/// recoveries and the recovery tooling use.
pub const MAX_EXEMPT_STALL_DELAY: BlockNumber = 30;

/// The longest `Grandpa.note_stalled` delay the sudo key may set without
/// waiting. The forced change it asks for is applied that many blocks after
/// the next session boundary, and GRANDPA refuses another forced change for
/// twice as long. While twice the delay fits in a session, neither outlasts
/// it, so the next rotation always goes through. A longer delay can hold a
/// change pending across boundaries, and every rotation is refused while one
/// is pending. A session is `slots_per_epoch` slots; the bound keeps twice the
/// delay inside a tenth of them, so it holds with up to nine tenths of the
/// slots empty.
pub fn max_exempt_stall_delay() -> BlockNumber {
    MAX_EXEMPT_STALL_DELAY.min(Sidechain::slots_per_epoch().0 / 20)
}

/// Refuses a genesis in which nothing independent of the sudo key can veto
/// its timelock tasks: one that names no guardian without saying so, one
/// that says so while it has a sudo key only its holders can sign for, one
/// whose guardian is the sudo key itself, and one whose guardian is a
/// well-known sr25519 development account (`//Alice` to `//Ferdie`, their
/// `//stash` accounts, `//One`, `//Two`), whose key anyone can derive, unless
/// its sudo key is one too, as on a development chain.
pub fn ensure_guarded_genesis(genesis: &RuntimeGenesisConfig) -> Result<(), &'static str> {
    genesis.root_timelock.ensure_guarded()?;
    let sudo = genesis.sudo.key.as_ref();
    let development = |who: &AccountId| {
        Sr25519Keyring::iter().any(|dev| AccountId::from(<[u8; 32]>::from(dev)) == *who)
    };
    let Some(guardian) = &genesis.root_timelock.guardian else {
        return if sudo.is_some_and(|key| !development(key)) {
            Err("root-timelock genesis is `unguarded` but its sudo key is not a development account; name a guardian")
        } else {
            Ok(())
        };
    };
    if sudo == Some(guardian) {
        Err("the root-timelock guardian must not be the sudo key")
    } else if development(guardian) && !sudo.is_some_and(development) {
        Err("the root-timelock guardian must not be a development account unless the sudo key is one too")
    } else {
        Ok(())
    }
}

/// `pallet_motra::Config::TakenFirst`: the guardian's veto and co-sign calls,
/// and a multisig guardian's `as_multi` wrapper around one, so the pool takes
/// them ahead of every fee-paying transaction. Only the current guardian's are
/// taken first, so a stolen sudo key cannot buy priority the veto needs, and a
/// wrapper's declared weight is bounded to the call it carries, so a
/// compromised guardian cannot use the priority to fill blocks.
pub struct GuardianVeto;

impl ContainsPair<AccountId, RuntimeCall> for GuardianVeto {
    fn contains(who: &AccountId, call: &RuntimeCall) -> bool {
        let Some(guardian) = Guardian::<Runtime>::get() else {
            return false;
        };
        match call {
            RuntimeCall::Multisig(pallet_multisig::Call::as_multi_threshold_1 {
                other_signatories,
                call,
            }) => {
                is_guardian_veto(call)
                    && multisig_account(who, other_signatories, 1) == Some(guardian)
            }
            RuntimeCall::Multisig(pallet_multisig::Call::as_multi {
                threshold,
                other_signatories,
                call,
                max_weight,
                ..
            }) => {
                is_guardian_veto(call)
                    && max_weight.all_lte(call.get_dispatch_info().weight)
                    && multisig_account(who, other_signatories, *threshold) == Some(guardian)
            }
            _ => is_guardian_veto(call) && *who == guardian,
        }
    }
}

/// The bare `RootTimelock` calls the guardian uses to veto a task or co-sign a
/// recovery. Each has a small, fixed weight, so no weight bound is needed to
/// take it first.
fn is_guardian_veto(call: &RuntimeCall) -> bool {
    matches!(
        call,
        RuntimeCall::RootTimelock(
            pallet_root_timelock::Call::cancel { .. }
                | pallet_root_timelock::Call::cancel_all {}
                | pallet_root_timelock::Call::fast_track { .. }
                | pallet_root_timelock::Call::approve { .. }
        )
    )
}

/// The account `pallet_multisig` derives for a call's signatories, or `None`
/// when they are not the well-formed set the pallet would accept (a zero
/// threshold, or the caller repeated among the others).
fn multisig_account(
    who: &AccountId,
    other_signatories: &[AccountId],
    threshold: u16,
) -> Option<AccountId> {
    if threshold == 0 {
        return None;
    }
    let mut signatories = Vec::with_capacity(other_signatories.len().saturating_add(1));
    signatories.extend_from_slice(other_signatories);
    signatories.push(who.clone());
    signatories.sort();
    signatories.dedup();
    (signatories.len() == other_signatories.len().saturating_add(1))
        .then(|| pallet_multisig::Pallet::<Runtime>::multi_account_id(&signatories, threshold))
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
        // Runs only the one call the guardian approved, and only one the
        // guardian could have fast-tracked.
        RuntimeCall::RootTimelock(pallet_root_timelock::Call::enact_approved { .. }) => true,
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

/// Every call a wrapper carries, at any depth, and the wrapper itself.
fn calls_in(call: &RuntimeCall) -> u64 {
    wrapped(call)
        .map_or(0, |wrapped| {
            wrapped
                .calls
                .iter()
                .map(calls_in)
                .fold(0, u64::saturating_add)
        })
        .saturating_add(1)
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
            // scheduled. Restarting what a kill-switch stopped joins them: a
            // stolen key may stop a service at once, and the guardian's
            // co-sign restarts it the same day. Without a co-sign they wait
            // as long as a mint does.
            RuntimeCall::Grandpa(pallet_grandpa::Call::note_stalled { .. })
            | RuntimeCall::OrinqReceipts(
                pallet_orinq_receipts::Call::set_pinned_committee { .. }
                | pallet_orinq_receipts::Call::set_break_glass_aura_keys { .. },
            )
            | RuntimeCall::Sudo(pallet_sudo::Call::set_key { .. })
            | RuntimeCall::TeeAttestation(pallet_tee_attestation::Call::set_disabled {
                disabled: false,
            })
            | RuntimeCall::Billing(pallet_billing::Call::governance_set_debits_enabled {
                enabled: true,
            }) => CallClass::AuthorityRecovery,
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

    /// Per call visited: at most one storage read, priced from `RocksDbWeight`
    /// whatever `frame_system::Config::DbWeight` says, and the step itself,
    /// priced as `pallet_utility` benchmarks one call of a batch.
    fn weight(call: &RuntimeCall) -> Weight {
        RocksDbWeight::get()
            .reads(1)
            .saturating_add(Weight::from_parts(5_000_000, 0))
            .saturating_mul(calls_in(call))
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
