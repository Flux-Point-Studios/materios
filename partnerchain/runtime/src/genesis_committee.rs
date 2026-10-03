//! The genesis committee a chain spec declares, checked before the genesis
//! is built from it.

use crate::{RuntimeGenesisConfig, MAX_VALIDATORS};

/// Refuses a genesis whose committee the chain cannot run from.
///
/// The session pallet seats Aura and GRANDPA from the genesis committee, and
/// while Cardano's draw fails the live-quorum floor, as it does at block 1,
/// block 1 proposes that committee again for the next epoch. So genesis
/// refuses a committee that is empty, whose first rotation schedules an
/// empty GRANDPA set and halts the chain; Aura or GRANDPA authorities seeded
/// beside it; more seats than `MaxValidators`, which the pallet would cut
/// short; an authority listed twice or out of ascending cross-chain-key
/// order, Ariadne's order when every candidate gets a seat, so that one set
/// of authorities makes one genesis; and an Aura or GRANDPA key two authorities
/// share, which would author or vote twice.
pub fn ensure_runnable_genesis_committee(
    genesis: &RuntimeGenesisConfig,
) -> Result<(), &'static str> {
    let committee = &genesis.session_committee_management.initial_authorities;
    if committee.is_empty() {
        return Err("the genesis committee is empty, so its first rotation would schedule an empty GRANDPA set; list the authorities in sessionCommitteeManagement.initialAuthorities");
    }
    if !genesis.aura.authorities.is_empty() || !genesis.grandpa.authorities.is_empty() {
        return Err(
            "Aura and GRANDPA are seated from the genesis committee; leave aura and grandpa empty",
        );
    }
    if committee.len() > MAX_VALIDATORS as usize {
        return Err("the genesis committee has more seats than MaxValidators");
    }
    if !committee.windows(2).all(|pair| pair[0].0 < pair[1].0) {
        return Err("list each genesis authority once, in ascending cross-chain-key order");
    }
    let shares_a_key = committee.iter().enumerate().any(|(seat, (_, keys))| {
        committee[..seat]
            .iter()
            .any(|(_, earlier)| earlier.aura == keys.aura || earlier.grandpa == keys.grandpa)
    });
    if shares_a_key {
        return Err("two genesis authorities share an Aura or GRANDPA key");
    }
    Ok(())
}
