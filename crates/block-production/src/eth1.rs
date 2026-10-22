//! The eth1 data vote of an honest proposer, while deposits still come from the contract.

use axiom_types::{
    ChainConfig, Preset, Slot, accessors::CoreState, phase0::Eth1Data,
};

/// An execution block as deposit voting sees it: its time and the contract's tree.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Eth1Candidate {
    /// Block timestamp, in seconds.
    pub timestamp: u64,
    /// The deposit tree the block's state holds, and the block's hash.
    pub data: Eth1Data,
}

/// The vote rule of the phase0 honest validator.
///
/// # Overview
///
/// Proposers vote on a recent execution block, so the chain learns new deposits.
/// A vote counts once more than half the voting period's blocks cast it.
///
/// 1. Candidates are the blocks old enough to be final, and young enough to be fresh.
/// 2. Among the period's votes for candidates, the most cast wins.
/// 3. Ties go to the vote cast first.
/// 4. Without such votes, the latest candidate wins, or else the state's own data.
///
/// Electra stops the vote once the contract's deposits are all bridged.
/// See `get_eth1_vote` in the phase0 and Electra validator specs.
#[derive(Clone, Copy, Debug)]
pub struct Eth1Vote<'a> {
    /// The chain configuration.
    config: &'a ChainConfig,
}

impl<'a> Eth1Vote<'a> {
    /// The rule under a configuration's timing.
    #[must_use]
    pub const fn new(config: &'a ChainConfig) -> Self {
        Self { config }
    }

    /// The vote of a block at the state's slot, given the execution chain in height order.
    ///
    /// A closed bridge votes the state's data, which changes nothing.
    #[must_use]
    pub fn choose<S: CoreState>(
        self,
        state: &S,
        chain: &[Eth1Candidate],
        bridge_closed: bool,
    ) -> Eth1Data {
        let current = state.eth1_data();
        if bridge_closed {
            return current.clone();
        }
        let period_start = self.period_start(state);
        let considered: Vec<&Eth1Data> = chain
            .iter()
            .filter(|block| self.is_candidate(block, period_start))
            // A vote may never move the deposit count back.
            .filter(|block| block.data.deposit_count >= current.deposit_count)
            .map(|block| &block.data)
            .collect();
        let valid: Vec<&Eth1Data> = state
            .eth1_data_votes()
            .iter()
            .filter(|vote| considered.contains(vote))
            .collect();

        // The most cast vote, ties to the earliest: scan in cast order, replace only on more.
        let mut best: Option<(usize, &Eth1Data)> = None;
        for vote in &valid {
            let count = valid.iter().filter(|other| **other == *vote).count();
            if best.is_none_or(|(most, _)| count > most) {
                best = Some((count, vote));
            }
        }
        match best {
            Some((_, vote)) => vote.clone(),
            None => considered.last().map_or_else(|| current.clone(), |latest| (*latest).clone()),
        }
    }

    /// Start of the state's voting period, in seconds since the Unix epoch.
    ///
    /// See `voting_period_start_time` in the phase0 validator spec.
    fn period_start<S: CoreState>(self, state: &S) -> u64 {
        let period = S::Preset::EPOCHS_PER_ETH1_VOTING_PERIOD * S::Preset::SLOTS_PER_EPOCH;
        let start = Slot(state.slot().0 - state.slot().0 % period);
        state.genesis_time() + start.0 * self.config.slot_duration_ms / 1000
    }

    /// Whether a block lies between one and two follow distances before the period's start.
    ///
    /// See `is_candidate_block` in the phase0 validator spec.
    fn is_candidate(self, block: &Eth1Candidate, period_start: u64) -> bool {
        let distance = self.config.seconds_per_eth1_block * self.config.eth1_follow_distance;
        block.timestamp.saturating_add(distance) <= period_start
            && block.timestamp.saturating_add(2 * distance) >= period_start
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{Hash32, Minimal, Root, phase0};

    use super::*;

    /// Data voting for a deposit count, marked by a block hash byte.
    fn data(count: u64, hash: u8) -> Eth1Data {
        Eth1Data {
            deposit_root: Root::ZERO,
            deposit_count: count,
            block_hash: Hash32([hash; 32]),
        }
    }

    /// A state at slot 40 with genesis at time 1000, holding 4 deposits.
    fn state(votes: &[Eth1Data]) -> phase0::BeaconState<Minimal> {
        let mut state = phase0::BeaconState::<Minimal> {
            slot: Slot(40),
            genesis_time: 1000,
            eth1_data: data(4, 0),
            ..phase0::BeaconState::default()
        };
        for vote in votes {
            state.eth1_data_votes.push(vote.clone()).unwrap();
        }
        state
    }

    #[test]
    fn the_most_cast_candidate_vote_wins_and_ties_go_to_the_first() {
        // Fixture state: minimal periods are 4 epochs of 8 slots, so slot 40 starts at slot 32.
        // At 6 seconds a slot, the period starts at 1000 + 192 = 1192 seconds.
        // The follow distance is 16 blocks of 14 seconds, 224 seconds.
        // Candidates lie between 1192 - 448 = 744 and 1192 - 224 = 968.
        let config = ChainConfig::minimal();
        let chain = [
            Eth1Candidate { timestamp: 800, data: data(5, 1) },
            Eth1Candidate { timestamp: 900, data: data(6, 2) },
        ];
        // Votes: 2, 1, 2, 1 tie at two each; vote 2 was cast first.
        let votes = [data(6, 2), data(5, 1), data(6, 2), data(5, 1)];
        let vote = Eth1Vote::new(&config).choose(&state(&votes), &chain, false);
        assert_eq!(vote, data(6, 2));
    }

    #[test]
    fn without_valid_votes_the_latest_candidate_wins_unless_the_bridge_closed() {
        let config = ChainConfig::minimal();
        let chain = [
            Eth1Candidate { timestamp: 800, data: data(5, 1) },
            Eth1Candidate { timestamp: 900, data: data(6, 2) },
            // Mutation: this block moves the count back from 4 to 3, so it is no candidate.
            Eth1Candidate { timestamp: 950, data: data(3, 3) },
            // Too recent: 1000 lies past 968.
            Eth1Candidate { timestamp: 1000, data: data(7, 4) },
        ];
        let rule = Eth1Vote::new(&config);
        assert_eq!(rule.choose(&state(&[]), &chain, false), data(6, 2));
        // A closed bridge keeps the state's own data.
        assert_eq!(rule.choose(&state(&[]), &chain, true), data(4, 0));
        // No execution chain at all also keeps it.
        assert_eq!(rule.choose(&state(&[]), &[], false), data(4, 0));
    }
}
