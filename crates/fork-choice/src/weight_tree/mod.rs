//! LMD-GHOST weights kept current by vote changes, rather than recounted from every vote.
//!
//! # Overview
//!
//! The spec weighs a node by summing the stake of every vote for it or a descendant.
//! Recounting that for each head costs a pass over every validator and every block.
//!
//! The weight tree keeps those sums instead, and updates them by change:
//!
//! 1. Each validator's counted vote is remembered with the node and the stake it was credited.
//! 2. A changed vote debits its old node and credits its new one, directly.
//! 3. One pass over the blocks, children first, settles the changes into every ancestor.
//!
//! A head then costs the changed votes plus one pass over the blocks.
//! A new balance source, at most once an epoch, reweighs every vote once.
//!
//! Proposer boost never enters the stored sums.
//! The head walk adds it to the boosted chain, so no stale boost has to be undone.

mod balances;
mod node;

use std::{collections::HashMap, mem};

use axiom_types::{Gwei, Preset, Root, ValidatorIndex, combined::BeaconState, phase0::Checkpoint};
use balances::VoteWeights;
use node::Change;
pub(crate) use node::{PerNode, TreeNode};

use crate::{
    BlockNode, BlockTree, ExecutionStatus, NodePayload, PayloadArrival, Votes,
    committee_weight::CommitteeWeight, gloas::PayloadMark, tree_ghost::BlockMark,
    votes::ChangedVoters,
};

/// The stake credited for one validator's counted vote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Credit {
    /// Position of the block the vote names.
    node: usize,
    /// The node of that block the vote supports.
    payload: NodePayload,
    /// The stake credited, the vote's weight when it was applied.
    stake: Gwei,
}

/// The blocks of the store with the attestation scores of their nodes, kept current by change.
///
/// # Invariants
///
/// Blocks sit parents first, so a reverse pass sees every child before its parent.
/// After a refresh, each score is the stake of the counted votes for that node or a descendant.
/// That is the spec's attestation score, under the balance source of the refresh.
#[derive(Clone, Debug, Default)]
pub(crate) struct WeightTree {
    /// Blocks, parents first.
    nodes: Vec<TreeNode>,
    /// Position of each block.
    indices: HashMap<Root, usize>,
    /// What each validator's counted vote is credited with, by validator index.
    credits: Vec<Option<Credit>>,
    /// Validators whose counted vote names a block outside the tree, by that block.
    ///
    /// Such a vote counts nothing until its block enters the tree.
    parked: HashMap<Root, Vec<ValidatorIndex>>,
    /// Validators to credit again at the next refresh, since their block entered the tree.
    recheck: Vec<ValidatorIndex>,
    /// The checkpoint whose state weighs the votes, once a refresh ran.
    source: Option<Checkpoint>,
    /// Every validator's vote weight in that state.
    vote_weights: VoteWeights,
    /// The last block looked up by root while crediting, valid within one refresh.
    last_lookup: Option<(Root, usize)>,
    /// Scratch marks of the block-by-block head walk, kept between heads.
    block_marks: Vec<BlockMark>,
    /// Scratch marks of the Gloas head walk, kept between heads.
    payload_marks: Vec<PayloadMark>,
}

impl WeightTree {
    /// A tree holding only the anchor block.
    pub(crate) fn new(anchor_root: Root, anchor: &BlockNode) -> Self {
        let mut tree = Self::default();
        tree.insert(anchor_root, anchor, None);
        tree
    }

    /// Adds a block, given the variant of its parent it builds on.
    ///
    /// A block already in the tree is left as it is.
    pub(crate) fn insert(
        &mut self,
        root: Root,
        block: &BlockNode,
        parent_payload: Option<NodePayload>,
    ) {
        if self.indices.contains_key(&root) {
            return;
        }
        let parent = self.indices.get(&block.parent_root).copied();
        let parent_payload = parent_payload.unwrap_or(NodePayload::Full);
        if let Some(parent) = parent {
            *self.nodes[parent].children.get_mut(parent_payload) += 1;
        }
        self.indices.insert(root, self.nodes.len());
        self.nodes.push(TreeNode::new(
            root,
            parent,
            parent_payload,
            block.slot,
            block.payload,
            block.status == ExecutionStatus::Invalid,
        ));
        // Votes that named the block before it arrived count from now on.
        if let Some(validators) = self.parked.remove(&root) {
            self.recheck.extend(validators);
        }
    }

    /// Records that a block's payload envelope arrived and verified.
    pub(crate) fn reveal(&mut self, root: &Root) {
        if let Some(index) = self.indices.get(root)
            && self.nodes[*index].arrival == PayloadArrival::Awaited
        {
            self.nodes[*index].arrival = PayloadArrival::Revealed;
        }
    }

    /// Copies every block's validity from the block tree, after the engine judged payloads.
    pub(crate) fn sync_validity(&mut self, blocks: &BlockTree) {
        for node in &mut self.nodes {
            node.invalid = blocks
                .get(&node.root)
                .is_some_and(|block| block.status == ExecutionStatus::Invalid);
        }
    }

    /// Drops the blocks the block tree dropped, keeping the scores of the rest.
    ///
    /// The tree keeps one block's subtree, so no kept score ever held a dropped block's stake.
    /// A vote for a dropped block counts nothing, and waits in case the block returns.
    pub(crate) fn retain(&mut self, blocks: &BlockTree, votes: &Votes) {
        let mut positions = vec![None; self.nodes.len()];
        let mut kept = Vec::with_capacity(self.nodes.len());
        let mut dropped = Vec::new();
        for (old, mut node) in self.nodes.drain(..).enumerate() {
            if blocks.contains(&node.root) {
                positions[old] = Some(kept.len());
                node.parent = node.parent.and_then(|parent| positions[parent]);
                kept.push(node);
            } else {
                dropped.push((old, node.root));
            }
        }
        self.nodes = kept;
        self.indices = self
            .nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (node.root, index))
            .collect();

        let roots: HashMap<usize, Root> = dropped.into_iter().collect();
        for (validator, slot) in self.credits.iter_mut().enumerate() {
            let Some(credit) = slot else {
                continue;
            };
            match positions[credit.node] {
                Some(position) => credit.node = position,
                None => {
                    if let Some(root) = roots.get(&credit.node) {
                        self.parked
                            .entry(*root)
                            .or_default()
                            .push(ValidatorIndex::from(validator));
                    }
                    *slot = None;
                }
            }
        }
        // Validators whose vote moved on no longer wait for their old block.
        self.parked.retain(|root, validators| {
            validators.retain(|validator| {
                votes
                    .counted(*validator)
                    .is_some_and(|message| message.root == *root)
            });
            !validators.is_empty()
        });
    }

    /// Brings every score up to date with the votes, weighed in a checkpoint's state.
    ///
    /// A new balance source reweighs every vote; otherwise only the changed votes move.
    pub(crate) fn refresh<P: Preset>(
        &mut self,
        source: Checkpoint,
        state: &BeaconState<P>,
        votes: &mut Votes,
    ) {
        // Positions change between refreshes, so the lookup memo starts empty.
        self.last_lookup = None;
        let reweigh = self.source != Some(source);
        if reweigh {
            self.vote_weights = VoteWeights::of(state);
            self.source = Some(source);
        }
        match votes.take_changed() {
            ChangedVoters::Listed(_) if reweigh => self.credit_all(votes),
            ChangedVoters::All => self.credit_all(votes),
            ChangedVoters::Listed(changed) => {
                for validator in changed {
                    self.credit(validator, votes);
                }
            }
        }
        for validator in mem::take(&mut self.recheck) {
            self.credit(validator, votes);
        }
        self.settle();
    }

    /// The blocks, parents first.
    pub(crate) fn nodes(&self) -> &[TreeNode] {
        &self.nodes
    }

    /// Position of a block.
    pub(crate) fn index(&self, root: &Root) -> Option<usize> {
        self.indices.get(root).copied()
    }

    /// Attestation score of a node, nothing for a block outside the tree.
    pub(crate) fn score(&self, root: &Root, payload: NodePayload) -> Gwei {
        self.index(root)
            .map_or(Gwei::ZERO, |index| *self.nodes[index].scores.get(payload))
    }

    /// One slot's committee weight in the balance source of the last refresh.
    pub(crate) const fn committee(&self) -> CommitteeWeight {
        self.vote_weights.committee()
    }

    /// Lends out the scratch marks of the block-by-block head walk.
    pub(crate) fn take_block_marks(&mut self) -> Vec<BlockMark> {
        mem::take(&mut self.block_marks)
    }

    /// Takes back the scratch marks of the block-by-block head walk.
    pub(crate) fn return_block_marks(&mut self, marks: Vec<BlockMark>) {
        self.block_marks = marks;
    }

    /// Lends out the scratch marks of the Gloas head walk.
    pub(crate) fn take_payload_marks(&mut self) -> Vec<PayloadMark> {
        mem::take(&mut self.payload_marks)
    }

    /// Takes back the scratch marks of the Gloas head walk.
    pub(crate) fn return_payload_marks(&mut self, marks: Vec<PayloadMark>) {
        self.payload_marks = marks;
    }

    /// Credits every voter afresh.
    fn credit_all(&mut self, votes: &Votes) {
        for validator in votes.voters() {
            self.credit(validator, votes);
        }
    }

    /// Moves a validator's credit to the node its counted vote supports now.
    fn credit(&mut self, validator: ValidatorIndex, votes: &Votes) {
        let current = votes.counted(validator).and_then(|message| {
            // Why: a slot's committees mostly vote for one block, so the last lookup usually answers.
            let node = match self.last_lookup {
                Some((root, node)) if root == message.root => node,
                _ => {
                    let Some(node) = self.index(&message.root) else {
                        self.parked.entry(message.root).or_default().push(validator);
                        return None;
                    };
                    self.last_lookup = Some((message.root, node));
                    node
                }
            };
            let stake = self.vote_weights.of_validator(validator);
            let block = &self.nodes[node];
            (stake != Gwei::ZERO).then(|| Credit {
                node,
                payload: message.supported_payload(block.slot, block.arrival),
                stake,
            })
        });
        let previous = self.credits.get(validator.as_usize()).copied().flatten();
        if previous == current {
            return;
        }
        if let Some(previous) = previous {
            self.nodes[previous.node].change(previous.payload, Change::removing(previous.stake));
            self.credits[validator.as_usize()] = None;
        }
        if let Some(current) = current {
            self.nodes[current.node].change(current.payload, Change::adding(current.stake));
            // Invariant: only a recorded vote is credited, so the index is a committee member's.
            if self.credits.len() <= validator.as_usize() {
                self.credits.resize(validator.as_usize() + 1, None);
            }
            self.credits[validator.as_usize()] = Some(current);
        }
    }

    /// Settles every pending change into the scores, children before parents.
    fn settle(&mut self) {
        for index in (0..self.nodes.len()).rev() {
            let up = self.nodes[index].settle();
            if let Some(parent) = self.nodes[index].parent
                && up != Change::default()
            {
                let via = self.nodes[index].parent_payload;
                self.nodes[parent].change(via, up);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_ssz::Ssz;
    use axiom_state_transition::State;
    use axiom_types::{
        BlsPubkey, Bytes32, ChainConfig, Epoch, ForkName, Gwei, Hash32, Minimal, Preset, Root,
        Slot, ValidatorIndex, combined,
        phase0::{self, Checkpoint, RandaoMixes, Validator},
    };
    use proptest::prelude::*;

    use super::*;
    use crate::{LatestMessage, Store, Timeliness, VoteOrder, committee_weight::CommitteeWeight};

    /// Validators of the fixture registry.
    const VALIDATORS: u64 = 64;

    /// A block on a parent, one to five slots later, with its payload and voting source.
    #[derive(Clone, Copy, Debug)]
    struct NewBlock {
        parent: usize,
        gap: u64,
        payload: u8,
        builds_on_full: bool,
        source: u8,
        reweigh: u8,
        ptc_timely: bool,
    }

    /// One event the store goes through.
    #[derive(Clone, Debug)]
    enum Event {
        /// A block arrives.
        Block(NewBlock),
        /// Some validators vote for a block, some slots after it.
        Vote {
            first: u64,
            count: u64,
            block: usize,
            delay: u64,
            payload_present: bool,
        },
        /// Validators are proven equivocators.
        Equivocate { first: u64, count: u64 },
        /// A block takes the proposer boost, or the boost clears.
        Boost { block: Option<usize> },
        /// A block's payload turns out invalid.
        Invalidate { block: usize },
        /// A block's payload envelope arrives.
        Reveal { block: usize },
        /// The payload committee votes on a block.
        PayloadVote {
            block: usize,
            timely: bool,
            available: bool,
        },
        /// The clock moves on some slots.
        Tick { slots: u64 },
        /// A block's epoch becomes justified, so its state weighs the votes.
        Justify { block: usize },
        /// A block's epoch becomes finalized, and the store prunes.
        Finalize { block: usize },
    }

    fn event() -> impl Strategy<Value = Event> {
        let index = 0_usize..64;
        prop_oneof![
            4 => (index.clone(), 1_u64..6, 0_u8..3, any::<bool>(), 0_u8..3, 0_u8..4, any::<bool>())
                .prop_map(|(parent, gap, payload, builds_on_full, source, reweigh, ptc_timely)| {
                    Event::Block(NewBlock { parent, gap, payload, builds_on_full, source, reweigh, ptc_timely })
                }),
            4 => (0..VALIDATORS, 1_u64..24, index.clone(), 0_u64..3, any::<bool>()).prop_map(
                |(first, count, block, delay, payload_present)| Event::Vote {
                    first,
                    count,
                    block,
                    delay,
                    payload_present,
                }
            ),
            1 => (0..VALIDATORS, 1_u64..4).prop_map(|(first, count)| Event::Equivocate { first, count }),
            1 => proptest::option::of(index.clone()).prop_map(|block| Event::Boost { block }),
            1 => index.clone().prop_map(|block| Event::Invalidate { block }),
            1 => index.clone().prop_map(|block| Event::Reveal { block }),
            1 => (index.clone(), any::<bool>(), any::<bool>())
                .prop_map(|(block, timely, available)| Event::PayloadVote { block, timely, available }),
            1 => (0_u64..3).prop_map(|slots| Event::Tick { slots }),
            1 => index.clone().prop_map(|block| Event::Justify { block }),
            2 => index.prop_map(|block| Event::Finalize { block }),
        ]
    }

    /// An active validator with a distinct key and a balance between 16 and 32 ETH.
    fn validator(index: u64) -> Validator {
        let mut pubkey = [0; 48];
        pubkey[..8].copy_from_slice(&index.to_le_bytes());
        Validator {
            pubkey: BlsPubkey(pubkey),
            effective_balance: Gwei((16 + index % 17) * 1_000_000_000),
            exit_epoch: Epoch::FAR_FUTURE,
            withdrawable_epoch: Epoch::FAR_FUTURE,
            ..Validator::default()
        }
    }

    /// A phase0 state at a slot, with a justified checkpoint of an epoch.
    fn state(slot: Slot, justified: Epoch, reweigh: u8) -> State<Minimal> {
        let mut validators: Vec<Validator> = (0..VALIDATORS).map(validator).collect();
        // Mutation: some block states change effective balances, slash, or exit a validator.
        match reweigh {
            1 => validators[3].effective_balance = Gwei(31_000_000_000),
            2 => validators[5].slashed = true,
            3 => validators[7].exit_epoch = Epoch::GENESIS,
            _ => {}
        }
        let beacon = phase0::BeaconState::<Minimal> {
            slot,
            validators: validators.try_into().expect("64 validators fit"),
            randao_mixes: RandaoMixes::<Minimal>::from_fn(|index| Bytes32([index as u8; 32])),
            current_justified_checkpoint: Checkpoint {
                epoch: justified,
                root: Root::ZERO,
            },
            ..phase0::BeaconState::default()
        };
        State::new(beacon)
    }

    /// The store and the blocks it was given, in arrival order.
    struct Scenario {
        store: Store<Minimal>,
        roots: Vec<Root>,
        rule: ForkName,
        /// Blocks made so far, so every root stays distinct across prunes.
        made: u64,
    }

    impl Scenario {
        /// A store anchored at the first slot of epoch 1.
        fn new(rule: ForkName) -> Self {
            let anchor_slot = Epoch(1).start_slot::<Minimal>();
            let anchor = state(anchor_slot, Epoch(1), 0);
            let block = phase0::BeaconBlock::<Minimal> {
                slot: anchor_slot,
                state_root: anchor.hash_tree_root(),
                ..phase0::BeaconBlock::default()
            };
            let root = block.hash_tree_root();
            let config = ChainConfig::minimal().with_forks_at_genesis(rule);
            let store = Store::new(config, anchor, &combined::BeaconBlock::Phase0(block))
                .expect("the anchor commits to its state");
            Self {
                store,
                roots: vec![root],
                rule,
                made: 0,
            }
        }

        fn apply(&mut self, event: &Event) {
            let Self {
                store,
                roots,
                rule,
                made,
            } = self;
            match *event {
                Event::Block(block) => Self::add_block(store, roots, *rule, made, block),
                Event::Vote {
                    first,
                    count,
                    block,
                    delay,
                    payload_present,
                } => {
                    let root = roots[block % roots.len()];
                    let Some(node) = store.blocks.get(&root).copied() else {
                        return;
                    };
                    let order = if rule.separates_payloads() {
                        VoteOrder::BySlot
                    } else {
                        VoteOrder::ByEpoch
                    };
                    let voters =
                        (first..first + count).map(|index| ValidatorIndex(index % VALIDATORS));
                    let message = LatestMessage {
                        slot: node.slot + delay,
                        root,
                        payload_present,
                    };
                    store.votes.record::<Minimal>(voters, message, order);
                }
                Event::Equivocate { first, count } => {
                    store
                        .votes
                        .mark_equivocating((first..first + count).map(ValidatorIndex));
                }
                Event::Boost { block } => {
                    store.proposer_boost_root =
                        block.map_or(Root::ZERO, |block| roots[block % roots.len()]);
                }
                Event::Invalidate { block } => {
                    let root = roots[block % roots.len()];
                    let parent_hash = store
                        .blocks
                        .get(&root)
                        .and_then(|node| store.blocks.get(&node.parent_root))
                        .map(|parent| parent.execution_block_hash);
                    // The parent's payload is the latest valid one, so the block alone turns invalid.
                    if let Some(hash) = parent_hash {
                        store.invalidate_after(root, Some(hash));
                    }
                }
                Event::Reveal { block } => {
                    store.insert_validated_payload(roots[block % roots.len()]);
                }
                Event::PayloadVote {
                    block,
                    timely,
                    available,
                } => {
                    let seats: Vec<usize> = (0..=Minimal::PTC_SIZE as usize / 2).collect();
                    store
                        .ptc
                        .record(roots[block % roots.len()], &seats, timely, available);
                }
                Event::Tick { slots } => {
                    let clock = store.slot_clock();
                    let next = store.current_slot() + slots;
                    store.on_tick(clock.slot_start_ms(next) + 1);
                }
                Event::Justify { block } => {
                    let root = roots[block % roots.len()];
                    if let Some(node) = store.blocks.get(&root) {
                        let checkpoint = Checkpoint {
                            epoch: node.slot.epoch::<Minimal>(),
                            root,
                        };
                        let finalized = store.finalized_checkpoint();
                        store.checkpoints.update(checkpoint, finalized);
                    }
                }
                Event::Finalize { block } => Self::finalize(store, roots, block),
            }
        }

        fn finalize(store: &mut Store<Minimal>, roots: &mut Vec<Root>, block: usize) {
            let root = roots[block % roots.len()];
            let Some(node) = store.blocks.get(&root).copied() else {
                return;
            };
            let checkpoint = Checkpoint {
                epoch: node.slot.epoch::<Minimal>(),
                root,
            };
            // The block's epoch is justified first, if it is newer.
            let finalized = store.finalized_checkpoint();
            store.checkpoints.update(checkpoint, finalized);
            // Only an ancestor of the justified block may finalize.
            let justified = store.justified_checkpoint();
            if checkpoint.epoch > finalized.epoch && store.blocks.is_ancestor(justified.root, root)
            {
                store.checkpoints.update(justified, checkpoint);
                store.prune();
                roots.retain(|root| store.blocks.contains(root));
            }
        }

        fn add_block(
            store: &mut Store<Minimal>,
            roots: &mut Vec<Root>,
            rule: ForkName,
            made: &mut u64,
            block: NewBlock,
        ) {
            let NewBlock {
                parent,
                gap,
                payload,
                builds_on_full,
                source,
                reweigh,
                ptc_timely,
            } = block;
            let parent_root = roots[parent % roots.len()];
            let Some(parent_block) = store.blocks.get(&parent_root).copied() else {
                return;
            };
            let slot = parent_block.slot + gap;
            *made += 1;
            let number = *made;
            let mut bytes = [0x77; 32];
            bytes[..8].copy_from_slice(&number.to_le_bytes());
            let root = Root(bytes);
            let arrival = if rule.separates_payloads() {
                [
                    PayloadArrival::Embedded,
                    PayloadArrival::Awaited,
                    PayloadArrival::Revealed,
                ][usize::from(payload)]
            } else {
                PayloadArrival::Embedded
            };
            let node = BlockNode {
                slot,
                parent_root,
                proposer_index: ValidatorIndex(number % 4),
                parent_block_hash: if builds_on_full {
                    parent_block.execution_block_hash
                } else {
                    Hash32([0xee; 32])
                },
                execution_block_hash: Hash32(bytes),
                status: ExecutionStatus::Valid,
                payload: arrival,
            };
            let epoch = slot.epoch::<Minimal>();
            let source_epoch = [Epoch(1), Epoch::GENESIS, epoch][usize::from(source)];
            store.insert_validated_node(root, node, state(slot, source_epoch, reweigh));
            store.ptc.open::<Minimal>(root);
            store.block_timeliness.insert(
                root,
                Timeliness {
                    attestation: true,
                    ptc: ptc_timely,
                },
            );
            roots.push(root);
        }

        /// Checks the weight tree against the recount: scores, committee weight, head, and leaves.
        fn check(&mut self) -> Result<(), TestCaseError> {
            let store = &mut self.store;
            let tree_head = store.tree_head();
            prop_assert_eq!(&tree_head, &store.recounted_head());
            let tree_leaves = store.tree_leaves_and_weights();
            prop_assert_eq!(&tree_leaves, &store.recounted_leaves_and_weights());

            let ghost = store.ghost().expect("the justified state is stored");
            let recounted = ghost.attestation_scores();
            let committee = CommitteeWeight::of(ghost.balance_source());
            let store = ghost.store();
            prop_assert_eq!(store.weight_tree.committee(), committee);
            for (root, _) in store.blocks.iter() {
                prop_assert_eq!(
                    store.weight_tree.score(root, NodePayload::Pending),
                    recounted.get(root).copied().unwrap_or_default(),
                    "score of {}",
                    root
                );
            }
            Ok(())
        }
    }

    fn run(rule: ForkName, events: &[Event], check_every: bool) -> Result<(), TestCaseError> {
        let mut scenario = Scenario::new(rule);
        let clock = scenario.store.slot_clock();
        let start = scenario.store.current_slot();
        scenario.store.on_tick(clock.slot_start_ms(start + 1));
        for event in events {
            scenario.apply(event);
            if check_every {
                scenario.check()?;
            }
        }
        scenario.check()
    }

    #[test]
    fn a_pruned_block_that_returns_regains_its_votes() {
        // Fixture state: anchor at slot 8, chain a(13) then c(18), and side block b(9).
        let mut scenario = Scenario::new(ForkName::Fulu);
        let block = |parent, gap| {
            Event::Block(NewBlock {
                parent,
                gap,
                payload: 0,
                builds_on_full: true,
                source: 0,
                reweigh: 0,
                ptc_timely: true,
            })
        };
        scenario.apply(&block(0, 5));
        scenario.apply(&block(1, 5));
        scenario.apply(&block(0, 1));
        let side = scenario.roots[3];
        let side_node = scenario
            .store
            .blocks
            .get(&side)
            .copied()
            .expect("b is stored");

        // Validators 0 to 9 vote for b at slot 10; the tree credits them.
        scenario
            .store
            .on_tick(scenario.store.slot_clock().slot_start_ms(Slot(19)));
        scenario.apply(&Event::Vote {
            first: 0,
            count: 10,
            block: 3,
            delay: 1,
            payload_present: false,
        });
        scenario
            .check()
            .expect("the tree equals the recount before the prune");

        // Finalizing c in epoch 2 prunes the anchor, a, and b.
        // The new justified state reweighs every vote now, so the return alone must recredit b.
        scenario.apply(&Event::Finalize { block: 2 });
        assert!(!scenario.store.blocks.contains(&side));
        scenario
            .check()
            .expect("the tree equals the recount after the prune");

        // Mutation: b returns through a replayed history; its ten votes count again.
        scenario
            .store
            .insert_validated_node(side, side_node, state(Slot(9), Epoch(1), 0));
        scenario
            .check()
            .expect("the tree equals the recount after b returns");
        assert_ne!(
            scenario
                .store
                .weight_tree
                .score(&side, NodePayload::Pending),
            Gwei::ZERO
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn block_rule_heads_equal_the_recount(events in proptest::collection::vec(event(), 1..80)) {
            // Phase0 through Fulu weigh blocks; every step's head, leaves, and scores must agree.
            run(ForkName::Fulu, &events, true)?;
        }

        #[test]
        fn payload_rule_heads_equal_the_recount(events in proptest::collection::vec(event(), 1..80)) {
            // Gloas weighs each block's empty, full, and pending nodes apart.
            run(ForkName::Gloas, &events, true)?;
        }
    }
}
