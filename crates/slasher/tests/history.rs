//! The slasher's history: the edges of its window, pruning, and restarts from disk.

use std::{
    fs,
    path::{Path, PathBuf},
    process,
};

use axiom_slasher::{
    ConfigError, Pass, Slasher, SlasherConfig, SlasherDatabase, SlasherError, Slashing,
};
use axiom_types::{
    BlsSignature, Epoch, Minimal, Root, Slot, ValidatorIndex,
    phase0::{
        AttestationData, BeaconBlockHeader, Checkpoint, ProposerSlashing, SignedBeaconBlockHeader,
    },
    vote::{ConflictingVotes, IndexedVote},
};

/// A window of 16 epochs in chunks of 4, over rows of 2 validators.
const fn config() -> SlasherConfig {
    SlasherConfig {
        history_length: 16,
        chunk_size: 4,
        validator_chunk_size: 2,
        record_chunk_size: 4,
        prune_period: 1,
    }
}

fn slasher() -> Slasher<Minimal> {
    Slasher::open(
        config(),
        SlasherDatabase::in_memory().expect("memory store"),
    )
    .expect("valid")
}

/// A vote of some validators from a source to a target, for a head named by one byte.
fn vote(signers: &[u64], source: u64, target: u64, head: u8) -> IndexedVote {
    IndexedVote {
        indices: signers.iter().copied().map(ValidatorIndex).collect(),
        data: AttestationData {
            slot: Slot(target * 8),
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

/// A header of validator 3 at a slot, for a parent named by one byte.
fn header(slot: u64, parent: u8) -> SignedBeaconBlockHeader {
    SignedBeaconBlockHeader {
        message: BeaconBlockHeader {
            slot: Slot(slot),
            proposer_index: ValidatorIndex(3),
            parent_root: Root([parent; 32]),
            ..BeaconBlockHeader::default()
        },
        signature: BlsSignature([parent; 96]),
    }
}

fn run<const N: usize>(
    slasher: &mut Slasher<Minimal>,
    epoch: u64,
    votes: [IndexedVote; N],
) -> Pass {
    for vote in votes {
        slasher.accept_vote(vote);
    }
    slasher.process(Epoch(epoch)).expect("pass succeeds")
}

/// A fresh directory under the build directory, deleted on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("axiom-slasher-{label}-{}", process::id()));
        fs::remove_dir_all(&path).ok();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).ok();
    }
}

#[test]
fn a_double_vote_is_found_with_both_votes() {
    // Validators 1 and 4 vote (2, 3) for head A; validator 4 then votes (2, 3) for head B.
    let mut slasher = slasher();
    let first = vote(&[1, 4], 2, 3, 0xa);
    let second = vote(&[4], 2, 3, 0xb);
    assert_eq!(run(&mut slasher, 3, [first.clone()]).slashings, []);
    let pass = run(&mut slasher, 3, [second.clone()]);
    assert_eq!(
        pass,
        Pass {
            slashings: vec![Slashing::Attester(ConflictingVotes { first, second })],
            votes: 1,
            ..Pass::default()
        }
    );
}

#[test]
fn a_repeated_vote_is_no_offence() {
    // The same vote arrives in a gossip aggregate and in a block.
    let mut slasher = slasher();
    let once = vote(&[0, 1], 4, 5, 0xa);
    run(&mut slasher, 5, [once.clone()]);
    let pass = run(&mut slasher, 5, [once]);
    assert_eq!(pass.slashings, []);
}

#[test]
fn surround_votes_are_found_in_both_directions_with_the_outer_vote_first() {
    // Validator 5 votes (6, 7), then (5, 8) which surrounds it.
    let mut slasher = slasher();
    let inner = vote(&[5], 6, 7, 0xa);
    let outer = vote(&[5], 5, 8, 0xb);
    run(&mut slasher, 8, [inner.clone()]);
    assert_eq!(
        run(&mut slasher, 8, [outer.clone()]).slashings,
        [Slashing::Attester(ConflictingVotes {
            first: outer,
            second: inner,
        })]
    );

    // Validator 6 votes (2, 9), then (4, 6) which it surrounds.
    let outer = vote(&[6], 2, 9, 0xc);
    let inner = vote(&[6], 4, 6, 0xd);
    run(&mut slasher, 9, [outer.clone()]);
    assert_eq!(
        run(&mut slasher, 9, [inner.clone()]).slashings,
        [Slashing::Attester(ConflictingVotes {
            first: outer,
            second: inner,
        })]
    );
}

#[test]
fn the_window_keeps_its_first_epoch_and_drops_the_one_before() {
    // At epoch 30 the window of 16 starts at epoch 15.
    let mut slasher = slasher();
    let pass = run(
        &mut slasher,
        30,
        [vote(&[0], 15, 30, 0xa), vote(&[1], 14, 30, 0xa)],
    );
    assert_eq!(
        pass,
        Pass {
            votes: 1,
            dropped: 1,
            pruned: 0,
            ..Pass::default()
        }
    );
    // Validator 0 then votes (16, 29), inside its first vote: found at the window's edge.
    let inner = vote(&[0], 16, 29, 0xb);
    assert_eq!(run(&mut slasher, 30, [inner]).slashings.len(), 1);
}

#[test]
fn a_vote_for_a_future_target_waits_for_its_epoch() {
    // At epoch 3 a vote with target 4 is deferred, then checked at epoch 4.
    let mut slasher = slasher();
    let early = run(&mut slasher, 3, [vote(&[2], 3, 4, 0xa)]);
    assert_eq!(early.deferred, 1);
    assert_eq!(slasher.queued(), 1);
    let due = run(&mut slasher, 4, [vote(&[2], 3, 4, 0xb)]);
    assert_eq!((due.votes, due.slashings.len()), (2, 1));
}

#[test]
fn reused_columns_forget_the_epochs_that_left_the_window() {
    // Fixture state: validator 0 votes (0, 15), setting the highest target of epochs 1 to 14.
    // Mutation: 33 epochs later those columns hold epochs 33 to 46.
    //
    //     epoch 1 and epoch 33 share column 1 of a 16-epoch window
    //
    // Without clearing, (33, 34) would look surrounded by a target 14 epochs ahead.
    let mut slasher = slasher();
    run(&mut slasher, 15, [vote(&[0], 0, 15, 0xa)]);
    let pass = run(&mut slasher, 34, [vote(&[0], 33, 34, 0xb)]);
    assert_eq!(pass.slashings, []);
    // Pruning deleted the old vote, its record chunk, and its counter.
    assert_eq!(pass.pruned, 4);
}

#[test]
fn double_proposals_are_found_once_per_pair() {
    // Proposer 3 signs two headers at slot 9, one of them twice, and one at slot 10.
    let mut slasher = slasher();
    let first = header(9, 1);
    let second = header(9, 2);
    for header in [first.clone(), first.clone(), header(10, 3), second.clone()] {
        slasher.accept_header(header);
    }
    let pass = slasher.process(Epoch(1)).expect("pass succeeds");
    assert_eq!(
        pass,
        Pass {
            slashings: vec![Slashing::Proposer(ProposerSlashing {
                signed_header_1: first,
                signed_header_2: second,
            })],
            headers: 4,
            ..Pass::default()
        }
    );
}

#[test]
fn a_restarted_slasher_remembers_votes_headers_and_its_epoch() {
    let directory = TempDir::new("restart");
    let first_vote = vote(&[7, 8, 300], 3, 4, 0xa);
    let first_header = header(33, 1);

    // Phase 1: record a vote and a header, then close the database.
    {
        let database = SlasherDatabase::open(&directory.0).expect("opens");
        let mut slasher = Slasher::<Minimal>::open(config(), database).expect("valid");
        slasher.accept_header(first_header.clone());
        run(&mut slasher, 5, [first_vote.clone()]);
    }

    // Phase 2: reopen; the epoch survives and a conflicting vote and header are found.
    let database = SlasherDatabase::open(&directory.0).expect("reopens");
    let mut slasher = Slasher::<Minimal>::open(config(), database).expect("valid");
    assert_eq!(slasher.epoch(), Some(Epoch(5)));
    let second_vote = vote(&[300], 3, 4, 0xb);
    let second_header = header(33, 2);
    slasher.accept_header(second_header.clone());
    // An earlier epoch is raised to the remembered one, so the window does not move back.
    let pass = run(&mut slasher, 2, [second_vote.clone()]);
    assert_eq!(
        pass.slashings,
        [
            Slashing::Proposer(ProposerSlashing {
                signed_header_1: first_header,
                signed_header_2: second_header,
            }),
            Slashing::Attester(ConflictingVotes {
                first: first_vote,
                second: second_vote,
            }),
        ]
    );
    assert_eq!(slasher.epoch(), Some(Epoch(5)));
}

#[test]
fn a_database_refuses_another_layout() {
    // History written with chunks of 4 epochs cannot be read with chunks of 8.
    let directory = TempDir::new("layout");
    let database = SlasherDatabase::open(&directory.0).expect("opens");
    drop(Slasher::<Minimal>::open(config(), database).expect("valid"));
    let wider = SlasherConfig {
        chunk_size: 8,
        ..config()
    };
    let reopened = SlasherDatabase::open(&directory.0).expect("reopens");
    assert!(matches!(
        Slasher::<Minimal>::open(wider, reopened),
        Err(SlasherError::GeometryMismatch { .. })
    ));
}

#[test]
fn an_invalid_layout_is_refused() {
    let zero = SlasherConfig {
        prune_period: 0,
        ..config()
    };
    let database = SlasherDatabase::in_memory().expect("memory store");
    assert!(matches!(
        Slasher::<Minimal>::open(zero, database),
        Err(SlasherError::Config(ConfigError::Zero {
            field: "prune period"
        }))
    ));
}
