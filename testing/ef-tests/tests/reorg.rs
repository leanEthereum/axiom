//! Proposer reorgs: a late block with few votes is orphaned by the next proposer, a timely one is not.
//!
//! The chain starts at the pyspec phase0 genesis, whose 64 validators hold the pyspec test keys.
//! Minimal slots last six seconds, so the attestation deadline falls two seconds in.

use std::sync::Arc;

use axiom_block_production::{BuilderBoost, ProducedBlock, RandaoCheck};
use axiom_ef_tests::{
    Case, Vectors,
    chain_builder::{ChainBuilder, PYSPEC_GENESIS},
};
use axiom_fork_choice::{DataAvailability, PayloadStatus};
use axiom_node::{
    BlockOrder, Chain, ChainDatabase, ChainHandle, ExecutionLayer, ManualClock, ProposerReorgs,
    ProposerService,
};
use axiom_types::{
    BlsSignature, Bytes32, ChainConfig, ExecutionAddress, Minimal, Root, Slot, combined, phase0,
};
use tokio::runtime::Builder;

/// When a block arrives, and when the next proposer asks for its block, into their slots.
#[derive(Clone, Copy, Debug)]
struct Timing {
    /// Milliseconds into slot 2 that block 2 is imported.
    block_ms: u64,
    /// Milliseconds into slot 3 that the proposer produces.
    proposal_ms: u64,
}

/// A two-block chain whose second block arrives at a chosen time, and the votes around it.
struct Scenario {
    /// The chain, with blocks 1 and 2 and every vote of slots 1 and 2 for block 1.
    chain: Chain<Minimal>,
    /// Root of block 1, at slot 1.
    block_1: Root,
    /// Root of block 2, at slot 2.
    block_2: Root,
}

impl Scenario {
    /// Builds the chain, or nothing when the vectors are absent.
    ///
    /// Fixture state: blocks at slots 1 and 2, block 2 built on block 1.
    ///
    ///     slot 1: block 1 imported at the slot start, its committee votes for it
    ///     slot 2: block 2 imported at the chosen time, its committee votes for block 1
    ///
    /// The committee of slot 2 votes for block 1 whatever the timing.
    /// Only the arrival time of block 2 then differs between the timely and late cases.
    fn build(timing: Timing) -> Option<Self> {
        let case = Case::new(Vectors::locate()?.consensus().join(PYSPEC_GENESIS));
        let genesis: phase0::BeaconState<Minimal> =
            case.ssz("state").expect("the genesis vector decodes");
        let config = ChainConfig::minimal();
        let mut builder =
            ChainBuilder::new(config.clone(), genesis.clone()).expect("pyspec genesis");
        let database = ChainDatabase::in_memory(config.clone()).expect("an in-memory database");
        let mut chain =
            Chain::from_genesis(config, combined::BeaconState::Phase0(genesis), database)
                .expect("genesis anchors the chain");

        // Slot 1: block 1 on time, then the votes of its committee.
        let block_1 = builder.propose().expect("block 1").block().clone();
        chain
            .on_tick(chain.slot_start_ms(Slot(1)))
            .expect("the clock moves to slot 1");
        chain
            .import_block(&block_1, DataAvailability::Available, PayloadStatus::Valid)
            .expect("block 1 imports");
        let votes_1 = builder.committee_votes(Slot(1)).expect("slot 1 votes");

        // Slot 2: the committee votes for block 1 before block 2 is built on it.
        let votes_2 = builder.committee_votes(Slot(2)).expect("slot 2 votes");
        let block_2 = builder.propose().expect("block 2").block().clone();
        chain
            .on_tick(chain.slot_start_ms(Slot(2)))
            .expect("the clock moves to slot 2");
        for vote in &votes_1 {
            chain.on_vote(vote).expect("a slot 1 vote counts in slot 2");
        }
        // Timing: votes of slot 2 arrive in slot 2, so the chain holds them until slot 3.
        for vote in &votes_2 {
            chain.on_vote(vote).expect("a slot 2 vote is held");
        }
        chain
            .on_tick(chain.slot_start_ms(Slot(2)) + timing.block_ms)
            .expect("the clock moves to block 2's arrival");
        chain
            .import_block(&block_2, DataAvailability::Available, PayloadStatus::Valid)
            .expect("block 2 imports");
        Some(Self {
            chain,
            block_1: block_1.block_root(),
            block_2: block_2.block_root(),
        })
    }

    /// The parent of the block the slot 3 proposer produces.
    fn proposal_parent(self, timing: Timing, reorgs: ProposerReorgs) -> Root {
        let now = self.chain.slot_start_ms(Slot(3)) + timing.proposal_ms;
        let (chain, _thread) = ChainHandle::spawn(self.chain).expect("the chain thread starts");
        let proposer = ProposerService::new(
            chain,
            Arc::new(ExecutionLayer::disconnected()),
            Arc::new(ManualClock::at(now)),
            ExecutionAddress::ZERO,
            None,
        )
        .with_reorgs(reorgs);
        let order = BlockOrder {
            slot: Slot(3),
            randao_reveal: BlsSignature::default(),
            graffiti: Bytes32::default(),
            randao: RandaoCheck::Skip,
            boost: BuilderBoost::NEUTRAL,
        };
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime starts");
        let proposal = runtime
            .block_on(proposer.produce(order))
            .expect("the proposer produces a block");
        let ProducedBlock::Phase0(block) = proposal.block else {
            panic!("a phase0 chain produces phase0 blocks");
        };
        block.parent_root
    }
}

/// Block 2 three seconds into its slot, past the two second attestation deadline.
const LATE: Timing = Timing {
    block_ms: 3_000,
    proposal_ms: 0,
};

/// Block 2 half a second into its slot, before the attestation deadline.
const TIMELY: Timing = Timing {
    block_ms: 500,
    proposal_ms: 0,
};

#[test]
fn a_late_weak_block_is_orphaned_by_the_next_proposer() {
    let Some(scenario) = Scenario::build(LATE) else {
        return;
    };
    let (block_1, block_2) = (scenario.block_1, scenario.block_2);

    // Block 2 is the head: it is block 1's only child.
    assert_eq!(scenario.chain.head().root, block_2);

    // Threshold: block 2 holds no vote, under 20% of a committee.
    // Block 1 holds both committees' votes, 200% of one, over the 160% bound.
    // The proposer of slot 3 therefore builds on block 1.
    assert_eq!(
        scenario.proposal_parent(LATE, ProposerReorgs::Enabled),
        block_1
    );
}

#[test]
fn the_engine_is_kept_off_a_late_head_during_its_slot() {
    let Some(mut late) = Scenario::build(LATE) else {
        return;
    };
    let Some(mut timely) = Scenario::build(TIMELY) else {
        return;
    };

    // Still in slot 2, the votes of slot 2 are not counted, so weights are not checked.
    // A late block 2 points the engine at block 1; a timely one leaves it on block 2.
    let late_parent = late.chain.forkchoice_override().unwrap();
    assert_eq!(late_parent.map(|node| node.root), Some(late.block_1));
    assert_eq!(timely.chain.forkchoice_override().unwrap(), None);
}

#[test]
fn a_timely_block_is_built_on() {
    let Some(scenario) = Scenario::build(TIMELY) else {
        return;
    };
    let block_2 = scenario.block_2;

    // Same votes as the late case: only the arrival time differs, and it keeps block 2.
    assert_eq!(
        scenario.proposal_parent(TIMELY, ProposerReorgs::Enabled),
        block_2
    );
}

#[test]
fn a_late_proposer_does_not_reorg() {
    // Timing: the cutoff is one sixth of a slot, one second; the proposer asks 1.5 seconds in.
    // Its block would arrive too late to win the boost, so it builds on the head.
    let timing = Timing {
        proposal_ms: 1_500,
        ..LATE
    };
    let Some(scenario) = Scenario::build(timing) else {
        return;
    };
    let block_2 = scenario.block_2;
    assert_eq!(
        scenario.proposal_parent(timing, ProposerReorgs::Enabled),
        block_2
    );
}

#[test]
fn disabled_reorgs_always_build_on_the_head() {
    let Some(scenario) = Scenario::build(LATE) else {
        return;
    };
    let block_2 = scenario.block_2;
    assert_eq!(
        scenario.proposal_parent(LATE, ProposerReorgs::Disabled),
        block_2
    );
}
