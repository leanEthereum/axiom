//! Choosing the attestations of a block: a weighted maximum coverage over the credits left.

use std::{
    cmp::Reverse,
    collections::{BTreeMap, BinaryHeap},
};

use axiom_ssz::Ssz;
use axiom_types::{
    BlsSignature, CommitteeIndex, Epoch, ParticipationFlags, Root, Slot, ValidatorIndex,
    accessors::CoreState, phase0::AttestationData,
};

use crate::{
    Aggregate, AttestationPool, Bits, PoolError,
    packing::ledger::{FLAGS, Ledger},
};

/// One attestation of a block: a vote, the signers of each committee, and one signature.
///
/// Phase0 blocks carry one committee per attestation; Electra blocks carry several.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackedAttestation {
    /// The vote.
    pub data: AttestationData,
    /// The signers of each committee, in increasing committee order.
    pub committees: Vec<(CommitteeIndex, Bits)>,
    /// The aggregate signature of every signer.
    pub signature: BlsSignature,
    /// What the new credits pay, in the units of the ledger's rates.
    pub gain: u64,
}

impl PackedAttestation {
    /// The bits of every committee, back to back in committee order.
    ///
    /// See `compute_on_chain_aggregate` in the Electra validator spec.
    #[must_use]
    pub fn joined_bits(&self) -> Bits {
        let total = self.committees.iter().map(|(_, bits)| bits.len()).sum();
        let mut joined = Bits::zeros(total);
        let mut offset = 0;
        for (_, bits) in &self.committees {
            for position in bits.ones() {
                joined.set(offset + position);
            }
            offset += bits.len();
        }
        joined
    }

    /// The bits of the one committee a phase0 attestation names.
    ///
    /// # Errors
    ///
    /// Fails when the attestation spans no committee or several.
    pub const fn sole_committee_bits(&self) -> Result<&Bits, PoolError> {
        match self.committees.as_slice() {
            [(_, bits)] => Ok(bits),
            parts => Err(PoolError::CommitteeCount(parts.len())),
        }
    }
}

/// What a vote earns once included, as the fork of the block judges it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Eligibility {
    /// The credits the vote earns at this inclusion.
    pub flags: ParticipationFlags,
}

/// The seats of one committee: what each credit pays, and which seats hold it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Seats {
    /// The pay of each credit, per seat.
    rates: Vec<[u64; FLAGS]>,
    /// The seats holding each credit already, per credit.
    held: [Bits; FLAGS],
}

impl Seats {
    /// The seats of a committee, and the credits its members hold for an epoch.
    fn new<S: CoreState>(
        state: &S,
        ledger: &Ledger,
        members: &[ValidatorIndex],
        target: Epoch,
    ) -> Self {
        let mut held = [(); FLAGS].map(|()| Bits::zeros(members.len()));
        let mut rates = Vec::with_capacity(members.len());
        for (seat, member) in members.iter().enumerate() {
            rates.push(ledger.rates(state, *member));
            let credited = ledger.credited(target, *member);
            for (flag, bits) in held.iter_mut().enumerate() {
                if credited.has(flag) {
                    bits.set(seat);
                }
            }
        }
        Self { rates, held }
    }

    /// What signers would pay for the credits they earn and do not hold yet.
    fn gain(&self, signers: &Bits, flags: ParticipationFlags) -> u64 {
        let mut gain = 0;
        for (flag, held) in self.held.iter().enumerate() {
            if flags.has(flag) {
                gain += signers
                    .ones_outside(held)
                    .map(|seat| self.rates[seat][flag])
                    .sum::<u64>();
            }
        }
        gain
    }

    /// Records the credits signers earn.
    fn credit(&mut self, signers: &Bits, flags: ParticipationFlags) {
        for (flag, held) in self.held.iter_mut().enumerate() {
            if flags.has(flag) {
                held.union_with(signers);
            }
        }
    }
}

/// One committee's part of a candidate: the seats it fills and its stored aggregates.
#[derive(Clone, Debug)]
struct Part<'a> {
    /// The committee.
    committee: CommitteeIndex,
    /// Position of the committee's seats in the selection.
    seats: usize,
    /// The committee's aggregates for the vote.
    aggregates: &'a [Aggregate],
}

/// A vote the block may include, with the parts it can draw signers from.
#[derive(Clone, Debug)]
struct Candidate<'a> {
    /// The vote.
    data: &'a AttestationData,
    /// The credits the vote earns.
    flags: ParticipationFlags,
    /// The committees that signed it.
    parts: Vec<Part<'a>>,
}

/// A candidate picked for the block, with the aggregate taken from each paying committee.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Pick<'a> {
    /// Position of the candidate.
    candidate: usize,
    /// What the new credits pay.
    gain: u64,
    /// The aggregate of each committee, in increasing committee order.
    chosen: Vec<(CommitteeIndex, &'a Aggregate)>,
}

impl Pick<'_> {
    /// The block attestation the pick stands for.
    fn into_attestation(
        self,
        candidates: &[Candidate<'_>],
    ) -> Result<PackedAttestation, PoolError> {
        let signatures: Vec<BlsSignature> = self
            .chosen
            .iter()
            .map(|(_, aggregate)| aggregate.signature)
            .collect();
        Ok(PackedAttestation {
            data: candidates[self.candidate].data.clone(),
            committees: self
                .chosen
                .into_iter()
                .map(|(committee, aggregate)| (committee, aggregate.bits.clone()))
                .collect(),
            signature: Aggregate::sum(&signatures)?,
            gain: self.gain,
        })
    }
}

/// The candidates of one block and the seats they compete for.
#[derive(Clone, Debug)]
struct Selection<'a> {
    /// The votes, in slot then root order.
    candidates: Vec<Candidate<'a>>,
    /// The seats of every committee a candidate draws from.
    seats: Vec<Seats>,
}

impl<'a> Selection<'a> {
    /// The best aggregate of each part that still pays, and their total gain.
    fn best(&self, index: usize) -> (u64, Vec<(CommitteeIndex, usize, &'a Aggregate)>) {
        let candidate = &self.candidates[index];
        let mut total = 0;
        let mut chosen = Vec::new();
        for part in &candidate.parts {
            let seats = &self.seats[part.seats];
            let best = part
                .aggregates
                .iter()
                .map(|aggregate| (seats.gain(&aggregate.bits, candidate.flags), aggregate))
                .filter(|(gain, _)| *gain > 0)
                .max_by_key(|(gain, _)| *gain);
            if let Some((gain, aggregate)) = best {
                total += gain;
                chosen.push((part.committee, part.seats, aggregate));
            }
        }
        (total, chosen)
    }

    /// The gain of a candidate's best attestation now.
    fn gain(&self, index: usize) -> u64 {
        self.best(index).0
    }

    /// Takes a candidate's best attestation, crediting its signers.
    fn take(&mut self, index: usize) -> Pick<'a> {
        let (gain, chosen) = self.best(index);
        let flags = self.candidates[index].flags;
        for (_, seats, aggregate) in &chosen {
            self.seats[*seats].credit(&aggregate.bits, flags);
        }
        Pick {
            candidate: index,
            gain,
            chosen: chosen
                .into_iter()
                .map(|(committee, _, aggregate)| (committee, aggregate))
                .collect(),
        }
    }

    /// Greedy maximum coverage, recomputing a gain only when it may still be the largest.
    ///
    /// # Algorithm
    ///
    /// A gain never grows as credits are taken, since coverage is submodular.
    /// So a stale gain bounds the true one from above.
    /// The heap pops the largest bound and recomputes it.
    /// When the fresh gain still beats every other bound, it is the true maximum.
    /// See Minoux, Accelerated greedy algorithms, 1978.
    ///
    /// Ties order by candidate position, so the picks equal those of the plain greedy rule.
    fn lazy_greedy(&mut self, limit: usize) -> Vec<Pick<'a>> {
        let mut heap: BinaryHeap<(u64, Reverse<usize>)> = (0..self.candidates.len())
            .map(|index| (self.gain(index), Reverse(index)))
            .filter(|(gain, _)| *gain > 0)
            .collect();
        let mut picks = Vec::new();
        while picks.len() < limit {
            let Some((_, Reverse(index))) = heap.pop() else {
                break;
            };
            let fresh = (self.gain(index), Reverse(index));
            if fresh.0 == 0 {
                continue;
            }
            if heap.peek().is_some_and(|bound| fresh < *bound) {
                heap.push(fresh);
                continue;
            }
            picks.push(self.take(index));
            let left = self.gain(index);
            if left > 0 {
                heap.push((left, Reverse(index)));
            }
        }
        picks
    }

    /// Greedy maximum coverage, recomputing every gain each round.
    ///
    /// The reference the lazy rule must match pick for pick.
    #[cfg(test)]
    fn plain_greedy(&mut self, limit: usize) -> Vec<Pick<'a>> {
        let mut picks = Vec::new();
        while picks.len() < limit {
            let best = (0..self.candidates.len())
                .map(|index| (self.gain(index), Reverse(index)))
                .filter(|(gain, _)| *gain > 0)
                .max();
            let Some((_, Reverse(index))) = best else {
                break;
            };
            picks.push(self.take(index));
        }
        picks
    }
}

/// Picks the block's attestations from the pool, for the state at the block's slot.
///
/// # Overview
///
/// Each credit is a pair of a validator and a participation flag of one epoch.
/// A block attestation covers its signers' credits for the flags its vote earns.
/// The block holds a bounded number of attestations, and should earn the most.
/// That is weighted maximum coverage under a cardinality constraint.
///
/// # Algorithm
///
/// The greedy rule picks, each round, the attestation adding the most uncovered weight.
/// Coverage is submodular, so greedy reaches at least 1 - (1 - 1/k)^k of the optimum.
/// That bound exceeds 1 - 1/e, about 0.632, for every limit k.
/// See Nemhauser, Wolsey and Fisher, Mathematical Programming 14, 1978.
///
/// An Electra attestation joins one aggregate per committee of a vote.
/// Committees are disjoint sets of validators, so the gains of their parts add.
/// The best attestation for a vote then takes the best aggregate of each committee.
/// Each round thus finds the best set exactly, over that implicit family, and the bound holds.
///
/// Phase0 names one committee per vote, so each candidate has one part.
///
/// # Invariants
///
/// A candidate's target block is the state's own block at the target epoch's start.
/// Both branches then share every input to the target epoch's shuffling.
/// So a vote's bits name the same validators here as where it was signed.
#[derive(Debug)]
pub struct AttestationPacker<'a, S> {
    /// The state at the block's slot.
    state: &'a S,
    /// Credits held, and their pay.
    ledger: &'a Ledger,
}

impl<'a, S: CoreState> AttestationPacker<'a, S> {
    /// A packer for the state at the block's slot.
    #[must_use]
    pub const fn new(state: &'a S, ledger: &'a Ledger) -> Self {
        Self { state, ledger }
    }

    /// The attestations that earn the most, at most a limit of them, in the order picked.
    ///
    /// # Arguments
    ///
    /// - The pool holding the votes.
    /// - The fork's judgement of each vote: what it earns, or nothing when not includable.
    /// - The committee at a slot and index, under the state's shuffling.
    /// - The most attestations the block's body holds.
    ///
    /// # Errors
    ///
    /// Fails when the chosen signatures do not aggregate.
    pub fn pack(
        &self,
        pool: &'a AttestationPool,
        eligibility: impl Fn(&AttestationData) -> Option<Eligibility>,
        committee: impl Fn(Slot, CommitteeIndex) -> Option<Vec<ValidatorIndex>>,
        limit: usize,
    ) -> Result<Vec<PackedAttestation>, PoolError> {
        let mut selection = self.selection(pool, eligibility, committee);
        let picks = selection.lazy_greedy(limit);
        picks
            .into_iter()
            .map(|pick| pick.into_attestation(&selection.candidates))
            .collect()
    }

    /// The votes the block may include, with the seats of every committee involved.
    fn selection(
        &self,
        pool: &'a AttestationPool,
        eligibility: impl Fn(&AttestationData) -> Option<Eligibility>,
        committee: impl Fn(Slot, CommitteeIndex) -> Option<Vec<ValidatorIndex>>,
    ) -> Selection<'a> {
        let mut positions: BTreeMap<(Slot, CommitteeIndex), usize> = BTreeMap::new();
        let mut seats = Vec::new();
        let mut candidates = Vec::new();
        for group in pool.groups() {
            let data = &group.data;
            // Invariant: the target is on this state's chain, so the shuffling is shared.
            if self.state.block_root(data.target.epoch) != Some(data.target.root) {
                continue;
            }
            let Some(Eligibility { flags }) = eligibility(data) else {
                continue;
            };
            let mut parts = Vec::new();
            for (index, votes) in &group.committees {
                let key = (data.slot, *index);
                let position = match positions.get(&key) {
                    Some(position) => *position,
                    None => {
                        let Some(members) = committee(data.slot, *index) else {
                            continue;
                        };
                        let target = data.target.epoch;
                        seats.push(Seats::new(self.state, self.ledger, &members, target));
                        positions.insert(key, seats.len() - 1);
                        seats.len() - 1
                    }
                };
                // Bits of another length come from another shuffling, and never verify here.
                let size = seats[position].rates.len();
                let aggregates = votes.aggregates();
                if aggregates.iter().all(|vote| vote.bits.len() == size) {
                    parts.push(Part {
                        committee: *index,
                        seats: position,
                        aggregates,
                    });
                }
            }
            if !parts.is_empty() {
                candidates.push(Candidate { data, flags, parts });
            }
        }
        candidates.sort_by_cached_key(|candidate| Self::order(candidate.data));
        Selection { candidates, seats }
    }

    /// The deterministic order of candidates: by slot, then by data root.
    fn order(data: &AttestationData) -> (Slot, Root) {
        (data.slot, data.hash_tree_root())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use axiom_bls::Signature;
    use axiom_ssz::PersistentVector;
    use axiom_types::{
        Gwei, Minimal, altair,
        constants::{TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX},
        phase0::{Checkpoint, Validator},
    };
    use proptest::prelude::*;

    use super::*;
    use crate::{CommitteeAggregate, RewardRule};

    /// Root of every block of the fixture chain.
    const CHAIN: Root = Root([1; 32]);

    /// Members of each committee in the fixture.
    const SEATS: usize = 8;

    /// An Altair state at slot 17 of epoch 2, with 512 validators of 32 ETH.
    fn state() -> altair::BeaconState<Minimal> {
        let mut state = altair::BeaconState::<Minimal> {
            slot: Slot(17),
            block_roots: PersistentVector::repeat(&CHAIN),
            ..altair::BeaconState::default()
        };
        for _ in 0..512 {
            let validator = Validator {
                effective_balance: Gwei(32_000_000_000),
                exit_epoch: Epoch::FAR_FUTURE,
                withdrawable_epoch: Epoch::FAR_FUTURE,
                ..Validator::default()
            };
            state.validators.push(validator).unwrap();
            state.balances.push(Gwei(32_000_000_000)).unwrap();
            state
                .previous_epoch_participation
                .push(ParticipationFlags::default())
                .unwrap();
            state
                .current_epoch_participation
                .push(ParticipationFlags::default())
                .unwrap();
        }
        state
    }

    /// The ledger of the fixture, paying 1000 Gwei per increment.
    fn ledger(state: &altair::BeaconState<Minimal>) -> Ledger {
        Ledger {
            rule: RewardRule::ParticipationFlags {
                base_reward_per_increment: Gwei(1000),
            },
            current_epoch: Epoch(2),
            previous: state.previous_epoch_participation.iter().copied().collect(),
            current: state.current_epoch_participation.iter().copied().collect(),
        }
    }

    /// Committee c of slot s: 8 validators starting at 32 * (s % 8) + 8 * c, for c below 4.
    fn committee(slot: Slot, index: CommitteeIndex) -> Option<Vec<ValidatorIndex>> {
        (index.0 < 4).then(|| {
            let start = 32 * (slot.0 % 8) + 8 * index.0;
            (start..start + SEATS as u64).map(ValidatorIndex).collect()
        })
    }

    /// Every vote earns all three flags.
    fn all_flags(_: &AttestationData) -> Option<Eligibility> {
        let flags = [
            TIMELY_SOURCE_FLAG_INDEX,
            TIMELY_TARGET_FLAG_INDEX,
            TIMELY_HEAD_FLAG_INDEX,
        ]
        .into_iter()
        .fold(ParticipationFlags::default(), ParticipationFlags::with);
        Some(Eligibility { flags })
    }

    /// Electra-style data of a slot of epoch 2, voting for a head marked by a byte.
    fn data(slot: u64, head: u8) -> AttestationData {
        AttestationData {
            slot: Slot(slot),
            beacon_block_root: Root([head; 32]),
            target: Checkpoint {
                epoch: Epoch(2),
                root: CHAIN,
            },
            ..AttestationData::default()
        }
    }

    /// A vote of some seats of a committee, signed with the point at infinity.
    fn vote(data: AttestationData, committee: u64, seats: &[usize]) -> CommitteeAggregate {
        let mut bits = Bits::zeros(SEATS);
        for seat in seats {
            bits.set(*seat);
        }
        CommitteeAggregate {
            data,
            committee: CommitteeIndex(committee),
            aggregate: Aggregate {
                bits,
                signature: BlsSignature(Signature::INFINITY_BYTES),
            },
        }
    }

    /// The candidate, gain, and seats of each committee of every pick.
    type Shape = Vec<(usize, u64, Vec<(CommitteeIndex, Vec<usize>)>)>;

    fn shape(picks: &[Pick<'_>]) -> Shape {
        picks
            .iter()
            .map(|pick| {
                let parts = pick
                    .chosen
                    .iter()
                    .map(|(committee, aggregate)| (*committee, aggregate.bits.ones().collect()))
                    .collect();
                (pick.candidate, pick.gain, parts)
            })
            .collect()
    }

    /// A pool of random votes: up to 12 aggregates over 2 slots, 2 heads, and 4 committees.
    fn pool() -> impl Strategy<Value = AttestationPool> {
        let vote_parts = (
            16_u64..18,
            0_u8..2,
            0_u64..4,
            proptest::collection::btree_set(0..SEATS, 1..=SEATS),
        );
        proptest::collection::vec(vote_parts, 0..12).prop_map(|votes| {
            let mut pool = AttestationPool::default();
            for (slot, head, committee, seats) in votes {
                let seats: Vec<usize> = seats.into_iter().collect();
                pool.insert(vote(data(slot, head), committee, &seats))
                    .unwrap();
            }
            pool
        })
    }

    #[test]
    fn one_electra_attestation_spans_every_committee_of_a_vote() {
        // Fixture state: slot 16, one vote; committee 0 sends seats 0 to 2, committee 2 seat 5.
        let state = state();
        let ledger = ledger(&state);
        let mut pool = AttestationPool::default();
        pool.insert(vote(data(16, 7), 0, &[0, 1, 2])).unwrap();
        pool.insert(vote(data(16, 7), 2, &[5])).unwrap();

        let packed = AttestationPacker::new(&state, &ledger)
            .pack(&pool, all_flags, committee, 8)
            .unwrap();

        // One attestation spanning committees 0 then 2.
        assert_eq!(packed.len(), 1);
        let seats: Vec<(CommitteeIndex, Vec<usize>)> = packed[0]
            .committees
            .iter()
            .map(|(index, bits)| (*index, bits.ones().collect()))
            .collect();
        assert_eq!(
            seats,
            [
                (CommitteeIndex(0), vec![0, 1, 2]),
                (CommitteeIndex(2), vec![5])
            ]
        );
        // Four signers, each 32 increments at 1000 Gwei, earning weights 14 + 26 + 14 = 54.
        assert_eq!(packed[0].gain, 4 * 32_000 * 54);
        // Committee 2's seat 5 sits after committee 0's 8 seats, at 13.
        assert_eq!(
            packed[0].joined_bits().ones().collect::<Vec<_>>(),
            [0, 1, 2, 13]
        );
    }

    #[test]
    fn credits_already_held_pay_nothing() {
        // Fixture state: validator 0, seat 0 of committee 0 at slot 16, holds all three flags.
        let mut state = state();
        state.current_epoch_participation[0] = all_flags(&data(16, 0)).unwrap().flags;
        let ledger = ledger(&state);
        let mut pool = AttestationPool::default();
        pool.insert(vote(data(16, 7), 0, &[0])).unwrap();

        // The only vote adds nothing, so the block carries no attestation.
        let packed = AttestationPacker::new(&state, &ledger)
            .pack(&pool, all_flags, committee, 8)
            .unwrap();
        assert_eq!(packed, []);
    }

    #[test]
    fn a_vote_on_another_chain_is_left_out() {
        // Mutation: the vote's target root is not the state's block at epoch 2.
        let state = state();
        let ledger = ledger(&state);
        let mut other = data(16, 7);
        other.target.root = Root([9; 32]);
        let mut pool = AttestationPool::default();
        pool.insert(vote(other, 0, &[0, 1])).unwrap();

        let packed = AttestationPacker::new(&state, &ledger)
            .pack(&pool, all_flags, committee, 8)
            .unwrap();
        assert_eq!(packed, []);
    }

    proptest! {
        #[test]
        fn lazy_greedy_picks_exactly_what_plain_greedy_picks(pool in pool(), limit in 0_usize..6) {
            let state = state();
            let ledger = ledger(&state);
            let packer = AttestationPacker::new(&state, &ledger);

            let mut lazy = packer.selection(&pool, all_flags, committee);
            let mut plain = lazy.clone();
            prop_assert_eq!(shape(&lazy.lazy_greedy(limit)), shape(&plain.plain_greedy(limit)));
        }

        #[test]
        fn packed_attestations_are_valid_new_and_within_the_limit(
            pool in pool(),
            limit in 0_usize..6,
        ) {
            let state = state();
            let ledger = ledger(&state);
            let packed = AttestationPacker::new(&state, &ledger)
                .pack(&pool, all_flags, committee, limit)
                .unwrap();

            prop_assert!(packed.len() <= limit);
            let mut credited = BTreeSet::new();
            for attestation in &packed {
                let root = attestation.data.hash_tree_root();
                let group = pool
                    .groups()
                    .find(|group| group.data.hash_tree_root() == root)
                    .unwrap();
                // Committees appear once each, in increasing order.
                let committees: Vec<CommitteeIndex> =
                    attestation.committees.iter().map(|(index, _)| *index).collect();
                prop_assert!(committees.windows(2).all(|pair| pair[0] < pair[1]));
                let mut fresh = 0;
                for (index, bits) in &attestation.committees {
                    // Every part is a stored aggregate of its committee.
                    let stored = group.committees[index].aggregates();
                    prop_assert!(stored.iter().any(|aggregate| aggregate.bits == *bits));
                    // All three flags credit the same validators, so one credit each.
                    let members = committee(attestation.data.slot, *index).unwrap();
                    for seat in bits.ones() {
                        fresh += u64::from(credited.insert(members[seat]));
                    }
                }
                // No attestation is a duplicate: each pays for at least one new validator.
                prop_assert!(fresh > 0);
                prop_assert_eq!(attestation.gain, fresh * 32_000 * 54);
            }
        }

        #[test]
        fn a_larger_limit_never_earns_less(pool in pool(), limit in 0_usize..6) {
            let state = state();
            let ledger = ledger(&state);
            let packer = AttestationPacker::new(&state, &ledger);
            let earned = |limit| -> u64 {
                packer
                    .pack(&pool, all_flags, committee, limit)
                    .unwrap()
                    .iter()
                    .map(|attestation| attestation.gain)
                    .sum()
            };
            prop_assert!(earned(limit + 1) >= earned(limit));
        }
    }
}
