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
//! the gate's behaviour. What is NOT modelled here is the candidate POOL: the
//! dead-registered filter, the core-eviction filter and the ramp clamp shape
//! which draws are *offered*, and they are covered by their own tests plus
//! `pool_supply` below, which bounds a draw by the live candidates that exist.

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
#[derive(Clone, Copy, PartialEq)]
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
