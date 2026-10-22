//! Timings of a mainnet-sized Fulu state: its root after a slot's edits, its clone, and an epoch.
//!
//! The registry size defaults to one million validators, close to mainnet.
//! Set `AXIOM_BENCH_VALIDATORS` to change it, and `AXIOM_BENCH_EPOCH_VALIDATORS` for the epoch.

use std::{env, hint::black_box};

use axiom_ssz::{Length, Ssz};
use axiom_state_transition::State;
use axiom_types::{
    BlsPubkey, Bytes32, ChainConfig, Epoch, ForkName, Gwei, Mainnet, ParticipationFlags, Preset,
    Root, Slot,
    fulu::{
        Balances, BeaconState, BlockRoots, EpochParticipation, InactivityScores, RandaoMixes,
        StateRoots, Validator, Validators,
    },
};
use criterion::{BatchSize, Criterion};

/// Epoch the fixture state starts in, past genesis so finality runs.
const START_EPOCH: Epoch = Epoch(10);

/// Members of a mainnet sync committee, each rewarded every slot.
const SYNC_COMMITTEE_SIZE: usize = 512;

/// Registry size read from an environment variable, with a default.
fn validator_count(variable: &str, default: usize) -> usize {
    env::var(variable)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

/// A cheap, deterministic stream of indices, so the edits spread over the registry.
struct Spread(u64);

impl Spread {
    /// The next index below a bound.
    const fn next_below(&mut self, bound: usize) -> usize {
        // Constants of Knuth's MMIX linear congruential generator.
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        ((self.0 >> 33) % bound as u64) as usize
    }
}

/// An active validator with a distinct key, at the maximum effective balance.
fn validator(index: usize) -> Validator {
    let mut pubkey = [0; 48];
    pubkey[..8].copy_from_slice(&(index as u64).to_le_bytes());
    let mut withdrawal_credentials = [0; 32];
    withdrawal_credentials[0] = 0x01;
    withdrawal_credentials[12..20].copy_from_slice(&(index as u64).to_le_bytes());
    Validator {
        pubkey: BlsPubkey(pubkey),
        withdrawal_credentials: Bytes32(withdrawal_credentials),
        effective_balance: Gwei(32_000_000_000),
        slashed: false,
        activation_eligibility_epoch: Epoch::GENESIS,
        activation_epoch: Epoch::GENESIS,
        exit_epoch: Epoch::FAR_FUTURE,
        withdrawable_epoch: Epoch::FAR_FUTURE,
    }
}

/// A Fulu state at the first slot of an epoch, with every validator active and attesting.
fn fixture(count: usize) -> BeaconState<Mainnet> {
    let slot = START_EPOCH.start_slot::<Mainnet>();
    let mut state = BeaconState::<Mainnet> {
        slot,
        validators: Validators::<Mainnet>::try_from((0..count).map(validator).collect::<Vec<_>>())
            .expect("the registry limit is 2^40"),
        balances: Balances::<Mainnet>::try_from(
            (0..count)
                .map(|index| Gwei(32_000_000_000 + index as u64 % 1_000_000))
                .collect::<Vec<_>>(),
        )
        .expect("the registry limit is 2^40"),
        previous_epoch_participation: EpochParticipation::<Mainnet>::try_from(vec![
            ParticipationFlags(0b111);
            count
        ])
        .expect("the registry limit is 2^40"),
        current_epoch_participation: EpochParticipation::<Mainnet>::try_from(vec![
            ParticipationFlags(0);
            count
        ])
        .expect("the registry limit is 2^40"),
        inactivity_scores: InactivityScores::<Mainnet>::try_from(vec![0; count])
            .expect("the registry limit is 2^40"),
        block_roots: BlockRoots::<Mainnet>::from_fn(|index| Root([index as u8; 32])),
        state_roots: StateRoots::<Mainnet>::from_fn(|index| Root([!(index as u8); 32])),
        randao_mixes: RandaoMixes::<Mainnet>::from_fn(|index| Bytes32([index as u8 ^ 0x5a; 32])),
        ..BeaconState::default()
    };
    state.fork.current_version = ChainConfig::mainnet().fork_version(ForkName::Fulu);
    state
}

/// The edits one slot with a full block makes to the large lists.
///
/// The slot's roots are recorded, the sync committee and the proposer are paid,
/// and a slot's worth of attesters set their flags, spread over the registry.
fn apply_slot_edits(state: &mut BeaconState<Mainnet>, spread: &mut Spread) {
    let count = state.validators.len();
    let ring = state.slot.0 as usize % <Mainnet as Preset>::SlotsPerHistoricalRoot::LEN;
    state.state_roots[ring] = Root([0xaa; 32]);
    state.block_roots[ring] = Root([0xbb; 32]);
    state.latest_block_header.state_root = Root([0xcc; 32]);
    state.slot = Slot(state.slot.0 + 1);

    for _ in 0..=SYNC_COMMITTEE_SIZE {
        let index = spread.next_below(count);
        state.balances[index] = Gwei(state.balances[index].0 + 1_000);
    }
    for _ in 0..count / 32 {
        let index = spread.next_below(count);
        state.current_epoch_participation[index] = ParticipationFlags(0b111);
    }
    let epoch = state.slot.epoch::<Mainnet>().0 as usize;
    state.randao_mixes[epoch % <Mainnet as Preset>::EpochsPerHistoricalVector::LEN] =
        Bytes32([0xdd; 32]);
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    let count = validator_count("AXIOM_BENCH_VALIDATORS", 1_000_000);
    let epoch_count = validator_count("AXIOM_BENCH_EPOCH_VALIDATORS", count);

    // Fixture state: a mainnet-sized registry, hashed once so any cache starts warm.
    let state = fixture(count);
    black_box(state.hash_tree_root());

    {
        let mut group = criterion.benchmark_group(format!("state, {count} validators"));
        group.sample_size(10);
        group.bench_function("clone", |b| {
            b.iter_with_large_drop(|| black_box(&state).clone());
        });
        group.bench_function("hash tree root, unchanged", |b| {
            b.iter(|| black_box(&state).hash_tree_root());
        });
        group.bench_function("hash tree root after one slot's edits", |b| {
            let mut spread = Spread(1);
            b.iter_batched(
                || {
                    let mut next = state.clone();
                    apply_slot_edits(&mut next, &mut spread);
                    next
                },
                |next| next.hash_tree_root(),
                BatchSize::LargeInput,
            );
        });
        group.bench_function("clone, one slot's edits, and hash tree root", |b| {
            let mut spread = Spread(2);
            b.iter_with_large_drop(|| {
                let mut next = state.clone();
                apply_slot_edits(&mut next, &mut spread);
                let root = next.hash_tree_root();
                (next, root)
            });
        });
        group.finish();
    }
    drop(state);

    // Fixture state: the same registry, wrapped with its caches, at an epoch's first slot.
    let config = ChainConfig::mainnet().with_forks_at_genesis(ForkName::Fulu);
    let wrapped = State::new(fixture(epoch_count));
    let target = (START_EPOCH + 1).start_slot::<Mainnet>();
    {
        let mut group = criterion.benchmark_group(format!("slots, {epoch_count} validators"));
        group.sample_size(10);
        group.bench_function("process slots across an epoch", |b| {
            b.iter_batched(
                || wrapped.clone(),
                |mut advanced| {
                    advanced
                        .process_slots(&config, target)
                        .expect("empty slots always apply");
                    advanced
                },
                BatchSize::LargeInput,
            );
        });
        group.finish();
    }

    criterion.final_summary();
}
