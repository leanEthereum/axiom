//! Votes of every fork's containers in, and every fork's slashing container out.
//!
//! The slasher works on fork-neutral votes.
//! The operation pool builds the container of the including block's fork from its evidence.

use std::ops::Range;

use axiom_operation_pool::{PoolError, PoolFork};
use axiom_slasher::{Slasher, SlasherConfig, SlasherDatabase, Slashing};
use axiom_ssz::{List, ProgressiveList};
use axiom_types::{
    BlsSignature, CommitteeIndex, Epoch, Minimal, Root, ValidatorIndex, altair, bellatrix, capella,
    deneb, electra, fulu, gloas,
    phase0::{self, AttestationData, Checkpoint},
    vote::{ConflictingVotes, IndexedVote},
};

/// Data of a vote from a source to a target, with a data index and a head named by one byte.
fn data(source: u64, target: u64, index: u64, head: u8) -> AttestationData {
    AttestationData {
        index: CommitteeIndex(index),
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
    }
}

/// The single piece of evidence the slasher finds in two votes.
fn evidence(first: IndexedVote, second: IndexedVote) -> ConflictingVotes {
    let database = SlasherDatabase::in_memory().expect("memory store");
    let mut slasher = Slasher::<Minimal>::open(SlasherConfig::default(), database).expect("valid");
    slasher.accept_vote(first);
    slasher.accept_vote(second);
    let mut slashings = slasher.process(Epoch(10)).expect("pass succeeds").slashings;
    assert_eq!(slashings.len(), 1);
    match slashings.remove(0) {
        Slashing::Attester(votes) => votes,
        Slashing::Proposer(_) => panic!("only votes were given"),
    }
}

fn indices(range: Range<u64>) -> Vec<ValidatorIndex> {
    range.map(ValidatorIndex).collect()
}

#[test]
fn phase0_votes_become_the_slashing_of_every_fork_before_electra() {
    // One committee of 3 votes (4, 9); two of its members also vote (5, 6) inside it.
    let outer = phase0::IndexedAttestation::<Minimal> {
        attesting_indices: List::try_from(indices(10..13)).expect("fits"),
        data: data(4, 9, 2, 0xa),
        signature: BlsSignature([0xa; 96]),
    };
    let inner = phase0::IndexedAttestation::<Minimal> {
        attesting_indices: List::try_from(indices(11..13)).expect("fits"),
        data: data(5, 6, 1, 0xb),
        signature: BlsSignature([0xb; 96]),
    };
    let votes = evidence(inner.indexed_vote(), outer.indexed_vote());
    // The surrounding vote comes first, as the spec's slashability check requires.
    let expected = phase0::AttesterSlashing {
        attestation_1: outer,
        attestation_2: inner,
    };
    assert_eq!(expected.conflicting_votes(), votes);
    assert_eq!(
        <phase0::BeaconState<Minimal> as PoolFork>::attester_slashing(&votes),
        Ok(expected.clone())
    );
    assert_eq!(
        <altair::BeaconState<Minimal> as PoolFork>::attester_slashing(&votes),
        Ok(expected.clone())
    );
    assert_eq!(
        <bellatrix::BeaconState<Minimal> as PoolFork>::attester_slashing(&votes),
        Ok(expected.clone())
    );
    assert_eq!(
        <capella::BeaconState<Minimal> as PoolFork>::attester_slashing(&votes),
        Ok(expected.clone())
    );
    assert_eq!(
        <deneb::BeaconState<Minimal> as PoolFork>::attester_slashing(&votes),
        Ok(expected)
    );
}

#[test]
fn electra_votes_spanning_committees_become_electra_and_fulu_slashings() {
    // A slot-wide aggregate of 3000 signers, beyond one committee's 2048, double votes.
    let first = electra::IndexedAttestation::<Minimal> {
        attesting_indices: List::try_from(indices(0..3000)).expect("fits a slot"),
        data: data(7, 8, 0, 0xa),
        signature: BlsSignature([0xa; 96]),
    };
    let second = electra::IndexedAttestation::<Minimal> {
        attesting_indices: List::try_from(indices(2999..3001)).expect("fits a slot"),
        data: data(7, 8, 0, 0xb),
        signature: BlsSignature([0xb; 96]),
    };
    let votes = evidence(first.indexed_vote(), second.indexed_vote());
    let expected = electra::AttesterSlashing {
        attestation_1: first,
        attestation_2: second,
    };
    assert_eq!(votes.common_signers(), [ValidatorIndex(2999)]);
    assert_eq!(
        <electra::BeaconState<Minimal> as PoolFork>::attester_slashing(&votes),
        Ok(expected.clone())
    );
    assert_eq!(
        <fulu::BeaconState<Minimal> as PoolFork>::attester_slashing(&votes),
        Ok(expected)
    );
    // A phase0 container holds one committee, so this evidence cannot go back in time.
    assert_eq!(
        <phase0::BeaconState<Minimal> as PoolFork>::attester_slashing(&votes),
        Err(PoolError::TooManySigners {
            count: 3000,
            limit: 2048
        })
    );
}

#[test]
fn gloas_votes_disagreeing_on_the_payload_are_a_double_vote() {
    // Same head and checkpoints, but data index 0 says no payload and index 1 says payload.
    let absent = gloas::IndexedAttestation {
        attesting_indices: ProgressiveList::from(indices(40..42)),
        data: data(2, 3, 0, 0xa),
        signature: BlsSignature([0xa; 96]),
    };
    let present = gloas::IndexedAttestation {
        attesting_indices: ProgressiveList::from(indices(41..43)),
        data: data(2, 3, 1, 0xa),
        signature: BlsSignature([0xb; 96]),
    };
    let votes = evidence(absent.indexed_vote(), present.indexed_vote());
    assert_eq!(
        <gloas::BeaconState<Minimal> as PoolFork>::attester_slashing(&votes),
        Ok(gloas::AttesterSlashing {
            attestation_1: absent,
            attestation_2: present,
        })
    );
}
