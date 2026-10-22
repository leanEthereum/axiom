//! Block and sync committee rewards, checked against the balances a real chain pays.
//!
//! The chain is the pyspec genesis with every validator voting, through every fork.
//! A reward the API reports must be exactly what the block's transition credits.

use axiom_ef_tests::{
    Case, Vectors,
    chain_builder::{ChainBuilder, PYSPEC_GENESIS, Participation},
};
use axiom_ssz::U256;
use axiom_state_transition::{
    ActiveBalance, KnownVerdict, State, Verification,
    altair::block::SyncRewardRates,
    phase0::epoch::{AttestationRewards, PendingParticipation},
    rewards::{BlockRewards, RewardsError, SignedGwei, SyncCommitteeReward},
};
use axiom_types::{
    ChainConfig, Epoch, ForkName, Gwei, Minimal, Preset, Slot, ValidatorIndex,
    accessors::CoreState, combined, phase0,
};

/// The fork schedule: Altair at epoch 1, then one fork per epoch up to Gloas at epoch 7.
fn every_fork() -> ChainConfig {
    let mut config = ChainConfig {
        terminal_total_difficulty: U256::from_u64(1000),
        ..ChainConfig::minimal()
    };
    for (epoch, fork) in (1..).zip(ForkName::ALL.into_iter().skip(1)) {
        config = config.with_fork_epoch(fork, Epoch(epoch));
    }
    config
}

/// A fully voting chain at the pyspec phase0 genesis, under a fork schedule.
fn builder(vectors: &Vectors, config: ChainConfig) -> ChainBuilder<Minimal> {
    let case = Case::new(vectors.consensus().join(PYSPEC_GENESIS));
    let bytes = case.ssz_bytes("state").expect("case has a genesis state");
    let genesis = combined::BeaconState::<Minimal>::decode_at(&bytes, &config)
        .expect("genesis decodes as phase0");
    ChainBuilder::new(config, genesis)
        .expect("pyspec genesis")
        .with_participation(Participation::Full)
}

/// A block's pre-state at its slot, and its post-state.
fn transition(
    parent: &State<Minimal>,
    block: &combined::SignedBeaconBlock<Minimal>,
    config: &ChainConfig,
) -> (State<Minimal>, State<Minimal>) {
    let mut pre = parent.clone();
    pre.process_slots(config, block.slot())
        .expect("slots advance");
    let mut post = pre.clone();
    post.state_transition(config, block, Verification::Skip, &KnownVerdict(true))
        .expect("the built block applies");
    (pre, post)
}

/// What a validator's balance gained across a block, negative for a loss.
fn gain(pre: &State<Minimal>, post: &State<Minimal>, index: ValidatorIndex) -> SignedGwei {
    let at = index.as_usize();
    SignedGwei::net(post.beacon().balances()[at], pre.beacon().balances()[at])
}

#[test]
fn block_and_sync_rewards_are_the_balance_changes_of_every_fork() {
    let Some(vectors) = Vectors::locate() else {
        return;
    };
    // Fixture state: 64 validators, all voting, forks one epoch apart from Altair to Gloas.
    let config = every_fork();
    let mut builder = builder(&vectors, config.clone());
    let mut checked = 0;
    // Slots 8 to 72 cover Altair through two Gloas epochs; phase0 has its own test.
    for _ in 1..=72 {
        let parent = builder.state().clone();
        let proposal = builder.propose().expect("the chain extends");
        let block = proposal.block();
        if block.fork_name() == ForkName::Phase0 {
            continue;
        }
        let (pre, post) = transition(&parent, block, &config);
        let rewards = BlockRewards::of_block(parent.clone(), block, &config).expect("rewards");
        let sync = SyncCommitteeReward::of_block(parent, block, &config).expect("sync rewards");

        // Every member signed, so each earns the participant rate; there are no slashings.
        let rates = SyncRewardRates::new::<Minimal>(ActiveBalance::of(pre.beacon()));
        let seats = Minimal::SYNC_COMMITTEE_SIZE;
        assert_eq!(rewards.sync_aggregate, rates.proposer * seats);
        assert_eq!(rewards.proposer_slashings, Gwei::ZERO);
        assert_eq!(rewards.attester_slashings, Gwei::ZERO);
        assert_eq!(
            rewards.total(),
            rewards.attestations + rewards.sync_aggregate
        );

        // Invariant: a non-proposing member's balance moves by its sync reward alone.
        // The proposer's moves by its block rewards plus its own sync reward, if it sits.
        let proposer = rewards.proposer_index;
        for reward in &sync {
            if reward.validator_index != proposer {
                assert_eq!(gain(&pre, &post, reward.validator_index), reward.reward);
            }
        }
        let own_sync = sync
            .iter()
            .find(|reward| reward.validator_index == proposer)
            .map_or(0, |reward| reward.reward.0);
        let expected = SignedGwei(SignedGwei::from(rewards.total()).0 + own_sync);
        assert_eq!(
            gain(&pre, &post, proposer),
            expected,
            "slot {}",
            block.slot()
        );

        // Every block includes the previous slot's votes, which pay its proposer.
        assert!(rewards.attestations > Gwei::ZERO, "slot {}", block.slot());
        checked += 1;
    }
    // Slot 0 has no block and slots 1 to 7 are phase0, so 65 of the 72 blocks count.
    assert_eq!(checked, 65);
}

#[test]
fn a_phase0_block_reports_the_inclusion_shares_its_epoch_pays_later() {
    let Some(vectors) = Vectors::locate() else {
        return;
    };
    // Fixture state: phase0 only, 64 validators, all voting for three epochs.
    let config = ChainConfig::minimal();
    let mut builder = builder(&vectors, config.clone());
    let mut reported = Gwei::ZERO;
    let mut last_parent = None;
    for slot in 1..=16_u64 {
        let parent = builder.state().clone();
        let proposal = builder.propose().expect("the chain extends");
        let block = proposal.block().clone();

        // A phase0 block pays nothing as it applies; the reward is deferred to the epoch.
        let rewards = BlockRewards::of_block(parent.clone(), &block, &config).expect("rewards");
        let (pre, post) = transition(&parent, &block, &config);
        assert_eq!(rewards.sync_aggregate, Gwei::ZERO);
        assert_eq!(
            gain(&pre, &post, rewards.proposer_index),
            SignedGwei::default()
        );

        // Timing: blocks at slots 9 to 16 first include the votes of epoch 1.
        if slot >= 9 {
            reported += rewards.attestations;
        }
        last_parent = Some(builder.state().clone());
    }

    // The transition ending epoch 2 pays epoch 1's proposers their inclusion shares.
    let mut state = last_parent.expect("sixteen blocks");
    state
        .process_slots(&config, Slot(23))
        .expect("slots advance");
    let mut typed = state
        .of_fork::<phase0::BeaconState<Minimal>>()
        .expect("a phase0 state");
    let total = ActiveBalance::of(typed.beacon());
    let participation = PendingParticipation::new(&mut typed, total).expect("participation");
    let shares = AttestationRewards::new(typed.beacon(), &participation)
        .inclusion_shares()
        .expect("inclusion shares")
        .proposers;
    let paid = shares
        .rewards
        .iter()
        .fold(Gwei::ZERO, |sum, share| sum + *share);
    assert_eq!(reported, paid);
    assert!(paid > Gwei::ZERO);
}

#[test]
fn a_phase0_block_has_no_sync_committee() {
    let Some(vectors) = Vectors::locate() else {
        return;
    };
    // Fixture state: the first phase0 block of the pyspec genesis.
    let config = ChainConfig::minimal();
    let mut builder = builder(&vectors, config.clone());
    let parent = builder.state().clone();
    let proposal = builder.propose().expect("the chain extends");
    assert_eq!(
        SyncCommitteeReward::of_block(parent, proposal.block(), &config),
        Err(RewardsError::NoSyncCommittee(ForkName::Phase0))
    );
}
