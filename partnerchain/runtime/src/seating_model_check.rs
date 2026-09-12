//! Exhaustive reachability check over the composed seating gate (#515).
//!
//! `select_authorities` stacks four independently-armed predicates that can
//! REFUSE a draw, and a refusal means "keep the current committee for another
//! epoch". That is only safe while the current committee still finalizes. A
//! state where every candidate draw is refused is a ROTATION DEADLOCK: the
//! committee is frozen at whatever it was, and if that committee cannot carry
//! quorum, the chain cannot recover by rotating — which is the one mechanism
//! that would otherwise fix it. On mainnet there is no genesis reset, so the
//! exit is a manual lever (`set_pinned_committee`, `reset_candidate_liveness`,
//! `Grandpa::note_stalled`) or nothing.
//!
//! #505 proved this class is real and reachable: `SLACK_MARGIN = 1` made
//! growth unsatisfiable at n <= 5 and was caught only because someone thought
//! to ask "is growth REACHABLE" rather than "is growth SAFE". That was one
//! lever in isolation. This file asks the reachability question for the whole
//! composition, over every state, by brute force.
//!
//! WHAT THIS DOES AND DOES NOT COVER. Every verdict below is computed by
//! calling the REAL predicates from `committee_liveness` in the REAL order
//! `select_authorities` calls them — nothing here re-implements a rule, so the
//! check cannot drift from the runtime the way a transcribed model would. The
//! abstraction is in the INPUTS: all four predicates read a drawn committee
//! only through (size, live count, unproven count, break-glass present) and the
//! current committee only through (size, live count), so enumerating those
//! summaries and synthesising a witness committee for each is exhaustive over
//! the gate's behaviour.
//!
//! The POOL is modelled too, in the second half of this file, but separately and
//! for a specific reason: #534 was a pool bug — `filter_dead_permissioned` could
//! evict the last break-glass holder, after which the armed floor refused every
//! draw forever — and the gate-level model could not see it, because the gate
//! never learns which candidates were available to draw from. It was found by
//! reading the code. So `filtered_pool` below runs the REAL filters over a REAL
//! `AuthoritySelectionInputs` and asks the gate about what survived, which turns
//! "a filter removed the candidate the gate needed" from an assumption into an
//! assertion.

use crate::committee_liveness::{
    committee_covers_break_glass, grandpa_quorum_threshold, passes_growth_slack_invariant,
    passes_live_quorum_floor, CandidateLiveness,
};

/// Bound on committee size explored. `MAX_VALIDATORS` is 32; the interesting
/// structure (quorum's flat rungs at n ≡ 1 mod 3, the n <= 5 band where #505
/// bit) is all well below that, and the search is O(n^5), so this is the
/// largest bound that keeps the check a fast unit test rather than a nightly
/// job. Raised deliberately past the 16 of the Gate B1 enact proof.
const N_MAX: usize = 18;

const NOW: u32 = 1_000_000;
const WINDOW: u32 = 10_000;

/// How a single seat looks to the liveness lookups. These are the only three
/// shapes the predicates can distinguish: `live_member_count` keys on a recent
/// `last_authored`, `unproven_member_count` keys on its absence.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Seat {
    /// Authored inside the window.
    Live,
    /// Authored, but too long ago — a known-dead seat.
    Dead,
    /// Never authored: no evidence in either direction.
    Unproven,
}

impl Seat {
    fn liveness(self) -> CandidateLiveness {
        match self {
            Seat::Live => CandidateLiveness {
                first_selected: Some(0),
                last_authored: Some(NOW),
            },
            Seat::Dead => CandidateLiveness {
                first_selected: Some(0),
                last_authored: Some(NOW - WINDOW - 1),
            },
            Seat::Unproven => CandidateLiveness {
                first_selected: Some(0),
                last_authored: None,
            },
        }
    }
}

/// A drawn committee, described by the only four facts the gate can read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Draw {
    n: usize,
    live: usize,
    unproven: usize,
    /// Does the draw seat a holder of a break-glass Aura key?
    break_glass: bool,
}

/// The chain state a draw is judged against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Current {
    n: usize,
    live: usize,
}

impl Current {
    /// Is the chain finalizing right now? Below quorum it is not, and only a
    /// rotation can fix that.
    fn finalizing(self) -> bool {
        self.live >= grandpa_quorum_threshold(self.n)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Flags {
    slack: bool,
    break_glass: bool,
}

/// Break-glass key material. Index 0 is the FPS-held key; a draw that seats it
/// is built from keys starting at 0, one that does not starts at 1.
fn bg_keys() -> Vec<[u8; 32]> {
    vec![[0u8; 32]]
}

fn key(i: usize) -> Vec<u8> {
    let mut k = [0u8; 32];
    // Index 0 must equal the break-glass key exactly; others must not.
    k[31] = i as u8;
    k.to_vec()
}

/// Build a concrete witness committee realising `d`, and the lookup that
/// classifies its members. Returns `None` when the summary is not realisable.
fn witness(d: Draw) -> Option<(Vec<Vec<u8>>, Vec<Seat>)> {
    if d.live + d.unproven > d.n || d.n == 0 {
        return None;
    }
    let base = if d.break_glass { 0 } else { 1 };
    let keys: Vec<Vec<u8>> = (0..d.n).map(|i| key(base + i)).collect();
    let mut seats = vec![Seat::Dead; d.n];
    for s in seats.iter_mut().take(d.live) {
        *s = Seat::Live;
    }
    for s in seats.iter_mut().skip(d.live).take(d.unproven) {
        *s = Seat::Unproven;
    }
    Some((keys, seats))
}

/// The composed gate, in `select_authorities`' order. Returns true when the
/// draw would be ENACTED.
///
/// The three post-draw predicates are called exactly as the runtime calls them
/// (runtime/src/lib.rs: live-quorum floor, then growth-slack invariant, then
/// break-glass floor), each with the constants the runtime passes.
fn gate_accepts(d: Draw, c: Current, f: Flags) -> bool {
    let Some((keys, seats)) = witness(d) else {
        return false;
    };
    let lookup = |acct: [u8; 32]| -> CandidateLiveness {
        let idx = acct[31] as usize;
        let base = if d.break_glass { 0 } else { 1 };
        seats
            .get(idx.wrapping_sub(base))
            .copied()
            .unwrap_or(Seat::Dead)
            .liveness()
    };

    // 1. GRANDPA live-quorum floor (spec-230). Unconditional.
    if !passes_live_quorum_floor(&keys, NOW, WINDOW, lookup) {
        return false;
    }

    // 2. Growth-slack invariant (#505), gated on SlackInvariantEnabled.
    if f.slack
        && !passes_growth_slack_invariant(
            &keys,
            c.n,
            c.live,
            NOW,
            WINDOW,
            crate::UNPROVEN_SEAT_CREDIT,
            crate::SLACK_MARGIN,
            lookup,
        )
    {
        return false;
    }

    // 3. Break-glass floor (#490), gated on BreakGlassFloorEnabled.
    if f.break_glass && !committee_covers_break_glass(&keys, &bg_keys()) {
        return false;
    }

    true
}

/// What the candidate pool can actually offer. A draw cannot seat more live
/// members than exist, cannot exceed the pool, and cannot seat a break-glass
/// holder that has been filtered out of the pool.
#[derive(Clone, Copy, Debug)]
struct Pool {
    total: usize,
    live: usize,
    break_glass_available: bool,
}

fn feasible_draws(p: Pool) -> Vec<Draw> {
    let mut out = Vec::new();
    for n in 1..=p.total.min(N_MAX) {
        for live in 0..=n.min(p.live) {
            for unproven in 0..=(n - live) {
                for break_glass in [false, true] {
                    if break_glass && !p.break_glass_available {
                        continue;
                    }
                    // Seating the break-glass holder costs one of the n seats;
                    // with n == 0 there is nothing to seat it in.
                    out.push(Draw {
                        n,
                        live,
                        unproven,
                        break_glass,
                    });
                }
            }
        }
    }
    out
}

/// Does any offerable draw get through the gate?
fn any_draw_accepted(c: Current, f: Flags, p: Pool) -> bool {
    feasible_draws(p)
        .into_iter()
        .any(|d| gate_accepts(d, c, f))
}

// ---------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------

/// SAFETY. The composition must never enact a committee whose known-live
/// members cannot carry its own quorum. This is what the live-quorum floor is
/// for; the point of asserting it over the whole space is that a later lever
/// added ABOVE the floor could accept a draw the floor rejected, and the order
/// of the calls is the only thing preventing that today.
#[test]
fn composed_gate_never_enacts_a_sub_quorum_committee() {
    let mut checked = 0usize;
    for n in 1..=N_MAX {
        for live in 0..=n {
            for unproven in 0..=(n - live) {
                for break_glass in [false, true] {
                    let d = Draw {
                        n,
                        live,
                        unproven,
                        break_glass,
                    };
                    for cn in 1..=N_MAX {
                        for cl in 0..=cn {
                            let c = Current { n: cn, live: cl };
                            for slack in [false, true] {
                                for bg in [false, true] {
                                    let f = Flags {
                                        slack,
                                        break_glass: bg,
                                    };
                                    if gate_accepts(d, c, f) {
                                        assert!(
                                            d.live >= grandpa_quorum_threshold(d.n),
                                            "gate ENACTED a sub-quorum committee: {d:?} \
                                             (quorum {}) from {c:?} with {f:?}",
                                            grandpa_quorum_threshold(d.n),
                                        );
                                    }
                                    checked += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(checked > 100_000, "search collapsed to {checked} states");
}

/// LIVENESS, the #505 question generalised. A chain that is finalizing, whose
/// pool can still offer the committee it already has, must be able to rotate.
/// If every draw is refused, the committee is frozen — and a frozen committee
/// cannot shed a member that dies later, so today's healthy state becomes
/// tomorrow's halt with no lever having been touched.
#[test]
fn a_finalizing_chain_can_always_rotate() {
    for cn in 1..=N_MAX {
        for cl in 0..=cn {
            let c = Current { n: cn, live: cl };
            if !c.finalizing() {
                continue;
            }
            for slack in [false, true] {
                for bg in [false, true] {
                    let f = Flags {
                        slack,
                        break_glass: bg,
                    };
                    // The pool that always exists: the seats the chain is
                    // already running, break-glass holder included.
                    let p = Pool {
                        total: cn,
                        live: cl,
                        break_glass_available: true,
                    };
                    assert!(
                        any_draw_accepted(c, f, p),
                        "ROTATION DEADLOCK: finalizing chain {c:?} with {f:?} and pool \
                         {p:?} has NO acceptable draw — the committee is frozen"
                    );
                }
            }
        }
    }
}

/// THE ONE THAT BITES. When the break-glass floor is armed and the pool can no
/// longer offer a break-glass holder, every draw is refused — regardless of how
/// healthy the rest of the pool is. That state is absorbing under the gate
/// alone: rotation is frozen, and because `is_dead` keys on `last_authored`
/// which only a SEATED node can refresh, a filtered core cannot earn its way
/// back in. The exit is a manual lever, and this test exists to pin that the
/// dependency is real so the runbook cannot quietly stop mentioning it.
///
/// The two RUNTIME-CONTROLLED routes into this state are now closed (#534):
/// `filter_dead_permissioned` exempts break-glass holders from core eviction,
/// and `set_break_glass_aura_keys` refuses to empty the set while the floor is
/// armed. The state itself stays reachable — a Cardano permissioned-candidate
/// upsert that drops the holder is an L1 action no runtime check can prevent —
/// so the gate behaviour asserted here is deliberately unchanged, and the fixes
/// remove the ways to GET here rather than the consequence of being here.
#[test]
fn break_glass_floor_with_no_available_holder_freezes_rotation() {
    let c = Current { n: 5, live: 5 };
    let f = Flags {
        slack: true,
        break_glass: true,
    };
    let healthy_pool_without_bg = Pool {
        total: 16,
        live: 16,
        break_glass_available: false,
    };
    assert!(
        !any_draw_accepted(c, f, healthy_pool_without_bg),
        "expected the armed break-glass floor to refuse an all-external pool"
    );

    // Same pool, floor disarmed: rotation resumes. This is the discriminator —
    // without it the assertion above would also pass if the pool were simply
    // unusable for an unrelated reason.
    let disarmed = Flags {
        slack: true,
        break_glass: false,
    };
    assert!(
        any_draw_accepted(c, disarmed, healthy_pool_without_bg),
        "the pool must be otherwise perfectly rotatable — else the test above proves nothing"
    );

    // And with the holder back in the pool, the armed floor is satisfied.
    let with_bg = Pool {
        break_glass_available: true,
        ..healthy_pool_without_bg
    };
    assert!(
        any_draw_accepted(c, f, with_bg),
        "armed floor must accept a draw that seats the break-glass holder"
    );
}

/// The complete deadlock census. Every (state, flags, pool) combination where
/// the gate refuses everything is enumerated and reduced to the REASON. This is
/// a golden set: adding a lever that widens it fails here with the new states
/// named, which is the regression #505 did not have.
#[test]
fn deadlock_census_is_exactly_the_two_known_causes() {
    let mut no_bg_in_pool = 0usize;
    let mut pool_cannot_carry_quorum = 0usize;
    let mut unexplained: Vec<(Current, Flags, usize, usize, bool)> = Vec::new();

    for cn in 1..=N_MAX {
        for cl in 0..=cn {
            let c = Current { n: cn, live: cl };
            for total in 1..=N_MAX {
                for live in 0..=total {
                    for bg_avail in [false, true] {
                        let p = Pool {
                            total,
                            live,
                            break_glass_available: bg_avail,
                        };
                        for slack in [false, true] {
                            for bg in [false, true] {
                                let f = Flags {
                                    slack,
                                    break_glass: bg,
                                };
                                if any_draw_accepted(c, f, p) {
                                    continue;
                                }
                                // CAUSE 1: no pool subset can carry its own
                                // quorum. The smallest committee is n=1, whose
                                // quorum is 1, so this is exactly "no live
                                // candidate exists at all".
                                if p.live == 0 {
                                    pool_cannot_carry_quorum += 1;
                                    continue;
                                }
                                // CAUSE 2: the floor is armed and the pool
                                // cannot seat a break-glass holder.
                                if f.break_glass && !p.break_glass_available {
                                    no_bg_in_pool += 1;
                                    continue;
                                }
                                unexplained.push((c, f, total, live, bg_avail));
                            }
                        }
                    }
                }
            }
        }
    }

    assert!(
        unexplained.is_empty(),
        "NEW rotation-deadlock cause(s) found — {} state(s), first 5: {:?}",
        unexplained.len(),
        &unexplained[..unexplained.len().min(5)]
    );
    assert!(
        no_bg_in_pool > 0 && pool_cannot_carry_quorum > 0,
        "census found neither known cause ({no_bg_in_pool}, {pool_cannot_carry_quorum}) \
         — the search is not reaching the states it claims to"
    );
}

/// GROWTH REACHABILITY — the property #505 actually violated, and the one the
/// whole #407 ramp depends on.
///
/// "Can the chain rotate?" is too weak a question to catch it. The slack
/// invariant exempts `n <= n_current`, so a chain with a broken margin keeps
/// rotating to same-size committees forever and looks perfectly healthy — it
/// simply can never seat the extra validator, so it can never decentralize.
/// The failure is silent, has no wedge, and fires no watchdog.
///
/// So the question has to be asked about GROWTH specifically: given a healthy
/// chain and a pool with a live candidate to spare, is there an accepted draw
/// with `n > n_current`? Every rung, not just the n=5 one the compile-time
/// assert pins.
/// The floor below which growth is arithmetically impossible, and why.
///
/// `q(n) = n - floor((n-1)/3)` equals `n` for n <= 3: a committee of three or
/// fewer has ZERO slack, every seat must be live for the set to finalize. So a
/// draw of size <= 3 can never contain an unproven seat, and since a newcomer is
/// always unproven, a chain at n=1 or n=2 can never grow by seating one. That is
/// GRANDPA quorum arithmetic — no lever causes it and no lever can fix it. It is
/// pinned here so the scope of the growth test below is a stated fact rather
/// than a convenient starting index, and so that a future quorum-formula change
/// has to come past this assertion.
#[test]
fn quorum_leaves_no_slack_below_n4() {
    for n in 1..=3 {
        assert_eq!(
            grandpa_quorum_threshold(n),
            n,
            "q({n}) must equal {n} — a committee this small has no slack for an \
             unproven seat"
        );
    }
    assert!(
        grandpa_quorum_threshold(4) < 4,
        "n=4 must be the first size with slack, or the growth floor moves"
    );
}

#[test]
fn growth_is_reachable_from_every_healthy_rung() {
    // Starts at 3 because growing INTO n<=3 is arithmetically impossible for an
    // unproven newcomer — see `quorum_leaves_no_slack_below_n4`. Materios has
    // never run below n=4 and the break-glass floor keeps it there.
    for cn in 3..N_MAX {
        // A healthy chain: every seat live. This is the most favourable
        // possible starting point — if growth is unreachable HERE, the ramp is
        // dead no matter how good the candidate supply gets.
        let c = Current { n: cn, live: cn };
        for slack in [false, true] {
            for bg in [false, true] {
                let f = Flags {
                    slack,
                    break_glass: bg,
                };
                // The pool holds the current committee plus ONE NEWCOMER, and
                // the newcomer is UNPROVEN, not live. That is not a pessimistic
                // choice, it is the only possible one: liveness is
                // `LastAuthoredBlock`, which only a SEATED node can write, so a
                // first-time candidate is unproven by construction and stays
                // unproven until the seat it is being denied lets it author.
                // Modelling it as live would ask the gate a question that never
                // occurs in practice — and would have let #505 through here.
                let p = Pool {
                    total: cn + 1,
                    live: cn,
                    break_glass_available: true,
                };
                let grew = feasible_draws(p)
                    .into_iter()
                    .filter(|d| d.n > cn && d.unproven >= 1)
                    .any(|d| gate_accepts(d, c, f));
                assert!(
                    grew,
                    "GROWTH UNREACHABLE at n={cn} with {f:?}: a fully-live committee \
                     cannot seat ONE newcomer, because a newcomer is unproven and \
                     nothing here will credit it. The chain rotates forever at its \
                     current size and never decentralizes — silently, with no wedge \
                     and no watchdog. This is the #505 failure shape."
                );
            }
        }
    }
}

/// The same question for the ramp CLAMP half, which is where #505's margin
/// actually did its damage: `registered_pool_cap` decides how many external
/// seats are even offered, so a clamp stuck at the current count starves the
/// draw before any floor gets a say.
#[test]
fn the_ramp_clamp_offers_at_least_one_more_seat_from_every_healthy_rung() {
    use crate::committee_liveness::registered_pool_cap;
    // 4 FPS cores is the shipped permissioned pool; the externals are what ramp.
    const CORES: usize = 4;
    for ext_current in 0..(N_MAX - CORES) {
        let n_current = CORES + ext_current;
        let live_current = n_current; // fully healthy
        let cap = registered_pool_cap(
            ext_current + 1, // asking for exactly one more external seat
            CORES,
            ext_current,
            n_current,
            live_current,
            crate::SLACK_MARGIN,
            crate::MAX_VALIDATORS as usize,
        );
        assert!(
            cap > ext_current,
            "RAMP STARVED at n={n_current} ({ext_current} external, all live): the clamp \
             refuses to offer a {}th external seat, so the D-parameter can never rise. \
             cap={cap}",
            ext_current + 1,
        );
    }
}

/// The slack invariant must not be a deadlock cause on its own. #505 shipped a
/// margin that made it one; the constant is now 0 and a compile-time assert
/// guards it, but that assert only checks the n=5 rung. This checks every rung
/// against the real predicate: with the pool able to re-offer the current
/// committee, arming slack must never remove the last acceptable draw.
#[test]
fn arming_the_slack_invariant_never_removes_the_last_draw() {
    for cn in 1..=N_MAX {
        for cl in 0..=cn {
            let c = Current { n: cn, live: cl };
            for total in 1..=N_MAX {
                for live in 0..=total {
                    let p = Pool {
                        total,
                        live,
                        break_glass_available: true,
                    };
                    for bg in [false, true] {
                        let off = Flags {
                            slack: false,
                            break_glass: bg,
                        };
                        let on = Flags {
                            slack: true,
                            break_glass: bg,
                        };
                        if any_draw_accepted(c, off, p) {
                            assert!(
                                any_draw_accepted(c, on, p),
                                "arming the slack invariant froze rotation: {c:?} {p:?} bg={bg}"
                            );
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------
// Pool-filter layer (#534 follow-up)
//
// Everything above models the GATE: it enumerates draw summaries directly and
// asks which the four post-draw predicates accept. That is exhaustive over the
// gate — but #534 was a POOL bug, in `filter_dead_permissioned`, and the gate
// model could not see it because the gate never learns which candidates were
// available to draw from. It was found by reading the code, which is exactly
// the coverage gap worth closing.
//
// This layer runs the REAL filters over a REAL `AuthoritySelectionInputs`, then
// asks the gate about what SURVIVED. So a filter that removes the candidate the
// gate needs is now visible as a deadlock rather than as an assumption.
// ---------------------------------------------------------------------

use crate::committee_liveness::{filter_dead_permissioned, filter_dead_registered};
use authority_selection_inherents::authority_selection_inputs::AuthoritySelectionInputs;
use sidechain_domain::{
    AuraPublicKey, CandidateRegistrations, CrossChainPublicKey, CrossChainSignature, DParameter,
    EpochNonce, GrandpaPublicKey, MainchainPublicKey, MainchainSignature, McBlockNumber,
    McEpochNumber, McSlotNumber, McTxHash, McTxIndexInBlock, PermissionedCandidateData,
    RegistrationData, SidechainPublicKey, SidechainSignature, StakeDelegation, UtxoId, UtxoIndex,
    UtxoInfo,
};

/// Core-eviction thresholds, matching the runtime's `CORE_LIVENESS_*`.
const CORE_GRACE: u32 = 14_400;
const CORE_WINDOW: u32 = 100_800;
/// Registered thresholds, matching `LIVENESS_*`.
const REG_GRACE: u32 = 1_800;
const REG_WINDOW: u32 = 28_800;

fn perm_candidate(tag: u8) -> PermissionedCandidateData {
    PermissionedCandidateData {
        sidechain_public_key: SidechainPublicKey(alloc::vec![tag; 33]),
        aura_public_key: AuraPublicKey(pool_key(tag)),
        grandpa_public_key: GrandpaPublicKey(alloc::vec![tag; 32]),
    }
}

fn reg_candidate(tag: u8) -> CandidateRegistrations {
    let u = UtxoId { tx_hash: McTxHash([tag; 32]), index: UtxoIndex(0) };
    CandidateRegistrations {
        mainchain_pub_key: MainchainPublicKey([tag; 32]),
        registrations: alloc::vec![RegistrationData {
            registration_utxo: u,
            sidechain_signature: SidechainSignature(alloc::vec![0; 64]),
            mainchain_signature: MainchainSignature(alloc::vec![0; 64]),
            cross_chain_signature: CrossChainSignature(alloc::vec![]),
            sidechain_pub_key: SidechainPublicKey(alloc::vec![tag; 33]),
            cross_chain_pub_key: CrossChainPublicKey(alloc::vec![]),
            utxo_info: UtxoInfo {
                utxo_id: u,
                epoch_number: McEpochNumber(1),
                block_number: McBlockNumber(1),
                slot_number: McSlotNumber(1),
                tx_index_within_block: McTxIndexInBlock(0),
            },
            tx_inputs: alloc::vec![u],
            aura_pub_key: AuraPublicKey(pool_key(tag)),
            grandpa_pub_key: GrandpaPublicKey(alloc::vec![tag; 32]),
        }],
        stake_delegation: Some(StakeDelegation(1_000)),
    }
}

/// Distinct 32-byte key per tag. Byte 31 carries the tag so the lookup closure
/// can recover it from the liveness account.
fn pool_key(tag: u8) -> alloc::vec::Vec<u8> {
    let mut k = [0u8; 32];
    k[31] = tag;
    k.to_vec()
}

/// Liveness shapes for the POOL layer, calibrated to the filter thresholds
/// rather than the gate's.
///
/// `Seat::liveness()` is built for `WINDOW` (10_000), which sits far inside
/// `CORE_WINDOW` (100_800) — a "dead" seat by the gate's clock is comfortably
/// alive by the core filter's, so reusing it here would silently exercise
/// nothing. `Dead` is therefore pushed past the LONGER of the two windows.
///
/// `Unproven` also has to change meaning. To `is_dead`, a candidate selected
/// long ago that never authored is DEAD, not unproven — so the newcomer that
/// the gate calls unproven is, at the pool layer, one that was never selected
/// at all (`first_selected: None`, which the filters deliberately fail open on).
/// That is the real shape of a first-time candidate and the one #511 describes.
fn pool_liveness(seat: Seat, now: u32) -> CandidateLiveness {
    match seat {
        Seat::Live => CandidateLiveness {
            first_selected: Some(0),
            last_authored: Some(now),
        },
        Seat::Dead => CandidateLiveness {
            first_selected: Some(0),
            last_authored: Some(now - CORE_WINDOW.max(REG_WINDOW) - 1),
        },
        Seat::Unproven => CandidateLiveness {
            first_selected: None,
            last_authored: None,
        },
    }
}

/// One candidate's place in the pool: its tag, whether it is permissioned, its
/// liveness shape, and whether it holds a break-glass key.
#[derive(Clone, Copy, Debug)]
struct PoolMember {
    tag: u8,
    permissioned: bool,
    seat: Seat,
    break_glass: bool,
}

/// Run the REAL pool filters and report what survives.
///
/// Returns (permissioned survivors, registered survivors) as tags, which is
/// exactly what a draw could then be built from.
fn filtered_pool(members: &[PoolMember], now: u32) -> (Vec<u8>, Vec<u8>) {
    let inputs = AuthoritySelectionInputs {
        d_parameter: DParameter {
            num_permissioned_candidates: members.iter().filter(|m| m.permissioned).count() as u16,
            num_registered_candidates: members.iter().filter(|m| !m.permissioned).count() as u16,
        },
        permissioned_candidates: members
            .iter()
            .filter(|m| m.permissioned)
            .map(|m| perm_candidate(m.tag))
            .collect(),
        registered_candidates: members
            .iter()
            .filter(|m| !m.permissioned)
            .map(|m| reg_candidate(m.tag))
            .collect(),
        epoch_nonce: EpochNonce(alloc::vec![7; 32]),
    };

    let seats: alloc::collections::BTreeMap<u8, Seat> =
        members.iter().map(|m| (m.tag, m.seat)).collect();
    let lookup = |acct: [u8; 32]| -> CandidateLiveness {
        pool_liveness(seats.get(&acct[31]).copied().unwrap_or(Seat::Dead), now)
    };
    let bg: Vec<[u8; 32]> = members
        .iter()
        .filter(|m| m.break_glass)
        .map(|m| {
            let mut k = [0u8; 32];
            k[31] = m.tag;
            k
        })
        .collect();

    // The runtime's order: registered filter, then core eviction.
    let (inputs, _) = filter_dead_registered(inputs, now, REG_GRACE, REG_WINDOW, lookup);
    let (inputs, _) = filter_dead_permissioned(
        inputs,
        now,
        CORE_GRACE,
        CORE_WINDOW,
        crate::CORE_MAX_EVICTIONS_PER_SELECTION,
        &bg,
        lookup,
    );

    let perms = inputs
        .permissioned_candidates
        .iter()
        .map(|c| c.aura_public_key.0[31])
        .collect();
    let regs = inputs
        .registered_candidates
        .iter()
        .filter_map(|c| c.registrations.first())
        .map(|r| r.aura_pub_key.0[31])
        .collect();
    (perms, regs)
}

/// THE #534 INVARIANT, at the layer the bug actually lived in.
///
/// A pool's ONLY break-glass holder must be in the filtered pool, for every
/// liveness shape and every mix of other candidates. This is what the
/// gate-level model could not see: `committee_covers_break_glass` refuses a
/// draw with no holder, and before the fix `filter_dead_permissioned` could
/// remove the only one, so the two composed into a permanent refusal.
#[test]
fn the_filters_can_never_remove_a_break_glass_holder() {
    let now = 1_000_000;
    for holder_seat in [Seat::Live, Seat::Dead, Seat::Unproven] {
        for other_seat in [Seat::Live, Seat::Dead, Seat::Unproven] {
            for others in 0..4usize {
                for others_permissioned in [false, true] {
                    let mut members = alloc::vec![PoolMember {
                        tag: 1,
                        permissioned: true,
                        seat: holder_seat,
                        break_glass: true,
                    }];
                    for i in 0..others {
                        members.push(PoolMember {
                            tag: (10 + i) as u8,
                            permissioned: others_permissioned,
                            seat: other_seat,
                            break_glass: false,
                        });
                    }
                    let (perms, _regs) = filtered_pool(&members, now);
                    assert!(
                        perms.contains(&1u8),
                        "the break-glass holder was filtered OUT of the pool \
                         (holder={holder_seat:?}, {others} other {other_seat:?} \
                         candidates, permissioned={others_permissioned}). The armed floor \
                         would then refuse every draw, permanently."
                    );
                }
            }
        }
    }
}

/// Eviction still runs next to an exempt holder: a dead core that holds NO
/// break-glass key is evicted. Without this the test above would pass on a
/// build where eviction had simply stopped working.
#[test]
fn a_dead_non_holder_core_is_still_evicted() {
    let now = 1_000_000;
    let members = alloc::vec![
        PoolMember { tag: 1, permissioned: true, seat: Seat::Dead, break_glass: true },
        PoolMember { tag: 2, permissioned: true, seat: Seat::Dead, break_glass: false },
    ];
    let (perms, _) = filtered_pool(&members, now);
    assert!(perms.contains(&1u8), "holder must survive");
    assert!(
        !perms.contains(&2u8),
        "a dead core holding no break-glass key must still be evicted — the exemption \
         is not a blanket amnesty"
    );
}

/// The exemption is scoped to the LAST holder. With a second, live holder in
/// the pool the floor stays satisfiable, so a dead holder is shed like any
/// other dead core. This is the discriminator between the shipped rule and the
/// blanket amnesty the security review rejected: a blanket exemption keeps the
/// dead holder and this test fails.
#[test]
fn a_dead_holder_is_evicted_when_a_live_holder_shares_the_pool() {
    let now = 1_000_000;
    let members = alloc::vec![
        PoolMember { tag: 1, permissioned: true, seat: Seat::Dead, break_glass: true },
        PoolMember { tag: 2, permissioned: true, seat: Seat::Live, break_glass: true },
    ];
    let (perms, _) = filtered_pool(&members, now);
    assert!(
        !perms.contains(&1u8),
        "a dead holder with a live sibling holder must be evicted — the exemption covers \
         only the last holder"
    );
    assert!(perms.contains(&2u8), "the live holder must survive");
}

/// With two or more holders in the pool the exemption changes NOTHING: the
/// filtered pool is identical to the one produced with no break-glass keys at
/// all. This pins the live shape — four seeded keys, all permissioned — as a
/// behaviour-neutral upgrade, for every liveness assignment of the holders and
/// every liveness assignment of up to two non-holder cores. Each member's
/// liveness is enumerated independently: eviction is capped and ranked by
/// staleness, so a mixed pool (one live core beside one dead one) exercises
/// the ranking in a way uniform pools cannot.
#[test]
fn the_exemption_is_inert_with_two_or_more_holders_in_the_pool() {
    let now = 1_000_000;
    let seats = [Seat::Live, Seat::Dead, Seat::Unproven];
    let seat_of = |combo: usize, i: usize| seats[(combo / 3usize.pow(i as u32)) % 3];
    for n_holders in 2..=4usize {
        for holder_combo in 0..3usize.pow(n_holders as u32) {
            for n_others in 0..=2usize {
                for other_combo in 0..3usize.pow(n_others as u32) {
                    let mut with_keys = Vec::new();
                    for i in 0..n_holders {
                        with_keys.push(PoolMember {
                            tag: (1 + i) as u8,
                            permissioned: true,
                            seat: seat_of(holder_combo, i),
                            break_glass: true,
                        });
                    }
                    for i in 0..n_others {
                        with_keys.push(PoolMember {
                            tag: (10 + i) as u8,
                            permissioned: true,
                            seat: seat_of(other_combo, i),
                            break_glass: false,
                        });
                    }
                    let without_keys: Vec<PoolMember> = with_keys
                        .iter()
                        .map(|m| PoolMember { break_glass: false, ..*m })
                        .collect();
                    assert_eq!(
                        filtered_pool(&with_keys, now),
                        filtered_pool(&without_keys, now),
                        "with {n_holders} holders (liveness combo {holder_combo}) and {n_others} \
                         non-holders (liveness combo {other_combo}), the exemption changed the \
                         filtered pool"
                    );
                }
            }
        }
    }
}

/// FILTERING MUST NOT CREATE A DEADLOCK. The filters exist to shed dead weight,
/// so they must never take a state that could rotate and leave it unable to.
///
/// Formally: for every pool and every flag combination, if some draw from the
/// UNFILTERED pool is accepted, some draw from the FILTERED pool must be too.
/// A dead candidate cannot help satisfy the live-quorum floor anyway, so
/// removing one should never cost an acceptable draw — but "should" is the
/// assumption #534 violated, so it is checked rather than assumed.
#[test]
fn filtering_never_removes_the_last_acceptable_draw() {
    let now = 1_000_000;
    for n_perm in 1..=4usize {
        for n_reg in 0..=3usize {
            for perm_seat in [Seat::Live, Seat::Dead, Seat::Unproven] {
                for reg_seat in [Seat::Live, Seat::Dead, Seat::Unproven] {
                    let mut members = Vec::new();
                    for i in 0..n_perm {
                        members.push(PoolMember {
                            tag: (1 + i) as u8,
                            permissioned: true,
                            seat: perm_seat,
                            break_glass: i == 0,
                        });
                    }
                    for i in 0..n_reg {
                        members.push(PoolMember {
                            tag: (20 + i) as u8,
                            permissioned: false,
                            seat: reg_seat,
                            break_glass: false,
                        });
                    }

                    let live_before = members.iter().filter(|m| m.seat == Seat::Live).count();
                    let before = Pool {
                        total: members.len(),
                        live: live_before,
                        break_glass_available: true,
                    };

                    let (perms, regs) = filtered_pool(&members, now);
                    let surviving: Vec<&PoolMember> = members
                        .iter()
                        .filter(|m| {
                            if m.permissioned {
                                perms.contains(&m.tag)
                            } else {
                                regs.contains(&m.tag)
                            }
                        })
                        .collect();
                    let after = Pool {
                        total: surviving.len(),
                        live: surviving.iter().filter(|m| m.seat == Seat::Live).count(),
                        break_glass_available: surviving.iter().any(|m| m.break_glass),
                    };

                    for cn in 1..=6usize {
                        for cl in 0..=cn {
                            let c = Current { n: cn, live: cl };
                            for slack in [false, true] {
                                for bg in [false, true] {
                                    let f = Flags { slack, break_glass: bg };
                                    if any_draw_accepted(c, f, before)
                                        && !any_draw_accepted(c, f, after)
                                    {
                                        panic!(
                                            "FILTERING CREATED A DEADLOCK: {c:?} {f:?}\n  \
                                             pool before filtering: {before:?}\n  \
                                             pool after  filtering: {after:?}\n  \
                                             members: {n_perm} permissioned {perm_seat:?}, \
                                             {n_reg} registered {reg_seat:?}"
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
