//! Timings of the fork choice head on a mainnet-sized registry, after one slot of new votes.
//!
//! The registry defaults to one million validators, close to mainnet.
//! Set `AXIOM_BENCH_VALIDATORS` to change it, and `AXIOM_BENCH_BLOCKS` for a list of tree sizes.
//!
//! Each tree is a chain with a side block every eighth slot, all past the finalized anchor.
//! Every validator voted in the previous epoch, and one slot's committees vote anew per run.

use std::{env, hint::black_box};

use axiom_fork_choice::{BlockNode, ExecutionStatus, PayloadArrival, Store};
use axiom_ssz::Ssz;
use axiom_state_transition::{EpochCommittees, State, Verification};
use axiom_types::{
    BlsPubkey, BlsSignature, Bytes32, ChainConfig, CommitteeIndex, Epoch, ForkName, Gwei, Hash32,
    Mainnet, Preset, Root, Slot, ValidatorIndex, combined,
    fulu::{BeaconBlock, BeaconState, RandaoMixes, Validator},
    phase0::{AttestationData, Checkpoint},
    vote::{CommitteeVote, PayloadClaim},
};
use criterion::{BatchSize, Criterion};

/// Epoch the anchor state starts in, past genesis so the checkpoints are not trivial.
const START_EPOCH: Epoch = Epoch(10);

/// A list read from an environment variable, with a default.
fn sizes(variable: &str, default: &[usize]) -> Vec<usize> {
    env::var(variable).ok().map_or_else(
        || default.to_vec(),
        |value| {
            value
                .split(',')
                .filter_map(|size| size.parse().ok())
                .collect()
        },
    )
}

/// An active validator with a distinct key, at the maximum effective balance.
fn validator(index: usize) -> Validator {
    let mut pubkey = [0; 48];
    pubkey[..8].copy_from_slice(&(index as u64).to_le_bytes());
    Validator {
        pubkey: BlsPubkey(pubkey),
        withdrawal_credentials: Bytes32([1; 32]),
        effective_balance: Gwei(32_000_000_000),
        slashed: false,
        activation_eligibility_epoch: Epoch::GENESIS,
        activation_epoch: Epoch::GENESIS,
        exit_epoch: Epoch::FAR_FUTURE,
        withdrawable_epoch: Epoch::FAR_FUTURE,
    }
}

/// A Fulu state at the first slot of the start epoch, every validator active.
///
/// Its justified checkpoint is in the start epoch, so every block it seeds is viable.
fn anchor_state(count: usize) -> BeaconState<Mainnet> {
    let mut state = BeaconState::<Mainnet> {
        slot: START_EPOCH.start_slot::<Mainnet>(),
        validators: (0..count)
            .map(validator)
            .collect::<Vec<_>>()
            .try_into()
            .expect("the registry limit is 2^40"),
        balances: vec![Gwei(32_000_000_000); count]
            .try_into()
            .expect("the registry limit is 2^40"),
        randao_mixes: RandaoMixes::<Mainnet>::from_fn(|index| Bytes32([index as u8 ^ 0x5a; 32])),
        ..BeaconState::default()
    };
    state.current_justified_checkpoint.epoch = START_EPOCH;
    state
}

/// A distinct root for a block number.
fn root(number: usize) -> Root {
    let mut bytes = [0xbb; 32];
    bytes[..8].copy_from_slice(&(number as u64 + 1).to_le_bytes());
    Root(bytes)
}

/// A store anchored at the start epoch, with a tree of blocks and a full epoch of votes.
struct Fixture {
    /// The store, its scores current.
    store: Store<Mainnet>,
    /// The chain's tip, which the new votes support.
    tip: Root,
    /// The slot of the new votes.
    vote_slot: Slot,
    /// The committees of the new votes' epoch.
    committees: EpochCommittees,
}

impl Fixture {
    /// A store with a number of blocks past the anchor.
    fn new(
        base: &Store<Mainnet>,
        anchor_root: Root,
        anchor: &State<Mainnet>,
        blocks: usize,
    ) -> Self {
        let mut store = base.clone();
        let first = START_EPOCH.start_slot::<Mainnet>() + 1;

        // Fixture state: every eighth slot carries a side block beside the chain's block.
        let mut chain = vec![anchor_root];
        let mut main = Vec::new();
        let mut inserted = 0;
        let mut slot = first;
        while inserted < blocks {
            let parent = *chain.last().expect("the chain starts at the anchor");
            for side in 0..2 {
                if inserted == blocks || (side == 1 && !slot.0.is_multiple_of(8)) {
                    continue;
                }
                let block_root = root(inserted);
                let mut state = anchor.clone();
                if let combined::BeaconState::Fulu(beacon) = state.beacon_mut() {
                    beacon.slot = slot;
                }
                let node = BlockNode {
                    slot,
                    parent_root: parent,
                    proposer_index: ValidatorIndex(0),
                    parent_block_hash: Hash32::ZERO,
                    execution_block_hash: Hash32::ZERO,
                    status: ExecutionStatus::Valid,
                    payload: PayloadArrival::Embedded,
                };
                store.insert_validated_node(block_root, node, state);
                inserted += 1;
                if side == 0 {
                    chain.push(block_root);
                    main.push((slot, block_root));
                }
            }
            slot += 1;
        }
        let tip = *chain.last().expect("the chain starts at the anchor");
        let last_slot = slot - 1;
        let clock = store.slot_clock();
        store.on_tick(clock.slot_start_ms(last_slot + 1));

        // Every validator votes in the previous epoch for the chain's block of its slot.
        let epoch = last_slot.epoch::<Mainnet>();
        let previous = epoch - 1;
        let committees = EpochCommittees::compute(anchor.beacon(), previous);
        for offset in 0..Mainnet::SLOTS_PER_EPOCH {
            let vote_slot = Slot(previous.start_slot::<Mainnet>().0 + offset);
            let head = main
                .iter()
                .rev()
                .find(|(block_slot, _)| *block_slot <= vote_slot)
                .map_or(anchor_root, |(_, block_root)| *block_root);
            Self::vote(&mut store, &committees, vote_slot, head);
        }
        // The first head call weighs every vote once; later ones only see changes.
        store.head().expect("the justified state is stored");
        Self {
            store,
            tip,
            vote_slot: last_slot,
            committees: EpochCommittees::compute(anchor.beacon(), epoch),
        }
    }

    /// Every committee of a slot votes for a head block.
    fn vote(store: &mut Store<Mainnet>, committees: &EpochCommittees, slot: Slot, head: Root) {
        let epoch = slot.epoch::<Mainnet>();
        let target = Checkpoint {
            epoch,
            root: store
                .checkpoint_block(head, epoch)
                .expect("the head is in the store"),
        };
        for index in 0..committees.committees_per_slot() {
            let size = committees
                .committee(slot, CommitteeIndex(index))
                .map_or(0, <[ValidatorIndex]>::len);
            let vote = CommitteeVote {
                data: AttestationData {
                    slot,
                    index: CommitteeIndex(0),
                    beacon_block_root: head,
                    source: store.justified_checkpoint(),
                    target,
                },
                signature: BlsSignature::default(),
                committees: vec![CommitteeIndex(index)],
                bits: vec![true; size],
                payload: PayloadClaim::Silent,
            };
            store
                .on_attestation(&vote, true, Verification::Skip)
                .expect("the vote is well formed");
        }
    }
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    let count = sizes("AXIOM_BENCH_VALIDATORS", &[1_000_000])[0];

    // Fixture state: the anchor, hashed once for the store's commitment check.
    let config = ChainConfig::mainnet().with_forks_at_genesis(ForkName::Fulu);
    let beacon = anchor_state(count);
    let anchor_block = BeaconBlock::<Mainnet> {
        slot: beacon.slot,
        state_root: beacon.hash_tree_root(),
        ..BeaconBlock::default()
    };
    let anchor_root = anchor_block.hash_tree_root();
    let anchor = State::new(beacon);
    let base = Store::new(
        config,
        anchor.clone(),
        &combined::BeaconBlock::Fulu(anchor_block),
    )
    .expect("the anchor block commits to the state");

    {
        let mut group = criterion.benchmark_group(format!("head, {count} validators"));
        group.sample_size(10);
        for blocks in sizes("AXIOM_BENCH_BLOCKS", &[64, 256, 1024, 2048]) {
            let fixture = Fixture::new(&base, anchor_root, &anchor, blocks);
            group.bench_function(format!("{blocks} blocks, one slot of new votes"), |b| {
                b.iter_batched(
                    || {
                        let mut store = fixture.store.clone();
                        Fixture::vote(
                            &mut store,
                            &fixture.committees,
                            fixture.vote_slot,
                            fixture.tip,
                        );
                        store
                    },
                    |mut store| {
                        let head = store.head().expect("the justified state is stored");
                        black_box(head);
                        store
                    },
                    BatchSize::LargeInput,
                );
            });
        }
        group.finish();
    }
    criterion.final_summary();
}
