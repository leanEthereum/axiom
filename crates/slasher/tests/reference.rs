//! The slasher against a brute-force detector that compares every pair of votes.

use std::collections::BTreeSet;

use axiom_slasher::{Slasher, SlasherConfig, SlasherDatabase, Slashing};
use axiom_types::{
    BlsSignature, Epoch, Minimal, Root, ValidatorIndex,
    phase0::{AttestationData, Checkpoint},
    vote::{ConflictingVotes, IndexedVote},
};
use proptest::{collection::vec, prelude::*};

/// Validators in the generated histories.
const VALIDATORS: u64 = 12;

/// The latest target epoch generated, well inside the window.
const LAST_EPOCH: u64 = 20;

/// A small layout, so votes cross span, row, and record chunk boundaries.
///
/// The history of 64 epochs holds every generated vote.
const fn config() -> SlasherConfig {
    SlasherConfig {
        history_length: 64,
        chunk_size: 4,
        validator_chunk_size: 3,
        record_chunk_size: 5,
        prune_period: 1,
    }
}

/// A vote by some validators for a source, a target, and one of two heads.
fn vote(source: u64, span: u64, head: u8, signers: &BTreeSet<u64>) -> IndexedVote {
    let target = (source + span).min(LAST_EPOCH);
    IndexedVote {
        indices: signers.iter().copied().map(ValidatorIndex).collect(),
        data: AttestationData {
            beacon_block_root: Root([head; 32]),
            source: Checkpoint {
                epoch: Epoch(source),
                root: Root::ZERO,
            },
            target: Checkpoint {
                epoch: Epoch(target),
                root: Root::ZERO,
            },
            ..AttestationData::default()
        },
        signature: BlsSignature([head; 96]),
    }
}

fn votes() -> impl Strategy<Value = Vec<IndexedVote>> {
    let one = (
        0..LAST_EPOCH,
        0..4_u64,
        0..2_u8,
        proptest::collection::btree_set(0..VALIDATORS, 1..4),
    )
        .prop_map(|(source, span, head, signers)| vote(source, span, head, &signers));
    vec(one, 1..40)
}

/// Validators with two slashable votes among the given ones.
fn brute_force(votes: &[IndexedVote]) -> BTreeSet<ValidatorIndex> {
    let mut slashable = BTreeSet::new();
    for first in votes {
        for second in votes {
            if first.data.is_slashable_with(&second.data) {
                let common = ConflictingVotes {
                    first: first.clone(),
                    second: second.clone(),
                }
                .common_signers();
                slashable.extend(common);
            }
        }
    }
    slashable
}

proptest! {
    #[test]
    fn the_slasher_finds_exactly_the_slashable_validators(
        votes in votes(),
        splits in vec(any::<bool>(), 40),
    ) {
        let mut slasher = Slasher::<Minimal>::open(
            config(),
            SlasherDatabase::in_memory().expect("memory store"),
        )
        .expect("valid layout");
        let mut found = Vec::new();
        let mut epoch = Epoch(0);
        // Passes run at a random split of the arrivals, at the latest target seen so far.
        for (vote, split) in votes.iter().zip(splits.iter().chain(std::iter::repeat(&false))) {
            epoch = epoch.max(vote.data.target.epoch);
            slasher.accept_vote(vote.clone());
            if *split {
                found.extend(slasher.process(epoch).expect("pass succeeds").slashings);
            }
        }
        found.extend(slasher.process(epoch).expect("pass succeeds").slashings);

        // No false positive: every piece of evidence is slashable and made of received votes.
        let mut covered = BTreeSet::new();
        for slashing in found {
            let Slashing::Attester(evidence) = slashing else {
                panic!("only votes were given");
            };
            prop_assert!(evidence.first.data.is_slashable_with(&evidence.second.data));
            prop_assert!(votes.contains(&evidence.first));
            prop_assert!(votes.contains(&evidence.second));
            let common = evidence.common_signers();
            prop_assert!(!common.is_empty());
            covered.extend(common);
        }
        // Same findings: the validators condemned are exactly those with a slashable pair.
        prop_assert_eq!(covered, brute_force(&votes));
    }
}
