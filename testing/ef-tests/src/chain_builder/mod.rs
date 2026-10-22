//! A builder of valid, fully signed chains across fork boundaries, for end-to-end tests.
//!
//! # Overview
//!
//! The builder starts from a genesis state whose validators hold the pyspec test keys.
//! It fills every slot with a block from the elected proposer, signed as the spec requires.
//!
//! The blocks carry no deposits or exits, and the eth1 vote repeats the state's.
//! They commit to blobs only when the caller supplies the commitments.
//! By default no one votes: no attestations, and an empty sync aggregate.
//! With full participation, every validator attests and every sync committee seat signs.
//!
//! The first Bellatrix block merges: its payload builds on the terminal proof-of-work block.
//! Each later block carries a stand-in payload on its parent's.
//! An engine serving the terminal block and its parent lets fork choice accept the merge.
//!
//! From Gloas on, each block bids for its own payload and the builder reveals it.
//! The next block then builds on that payload, so every Gloas block is full.

mod commitments;
mod draft;
mod error;
mod external;
mod keyring;
mod payload;
mod proposal;
mod votes;

use axiom_ssz::Ssz;
use axiom_state_transition::{
    KnownVerdict, State, TransitionError, Verification, gloas::EnvelopeError,
};
use axiom_types::{
    BlsSignature, ChainConfig, Hash32, KzgCommitment, Preset, Root, Slot,
    accessors::{CoreState, ForkState},
    combined,
    constants::{DOMAIN_BEACON_BUILDER, DOMAIN_BEACON_PROPOSER},
    gloas,
    phase0::SigningData,
};
pub use error::ChainBuilderError;
pub use external::{BlockAttestations, BlockInputs, UnsignedProposal};
pub use proposal::Proposal;
pub use votes::Participation;

use crate::chain_builder::{
    commitments::BlobCommitments, draft::Draft, keyring::Keyring, payload::PayloadParts,
};

/// The phase0 genesis of the minimal preset, under the consensus spec vectors' root.
///
/// It holds 64 active validators with the pyspec test keys, at the minimal genesis fork version.
/// See `initialize_beacon_state_from_eth1` in the phase0 beacon chain spec.
pub const PYSPEC_GENESIS: &str =
    "minimal/phase0/genesis/initialization/pyspec_tests/initialize_beacon_state_from_eth1";

/// A chain under construction: the state after its latest block, and the keys to extend it.
#[derive(Debug)]
pub struct ChainBuilder<P: Preset> {
    /// The fork schedule and timing the chain follows.
    config: ChainConfig,
    /// The state the chain starts from.
    genesis: combined::BeaconState<P>,
    /// The state after the latest block and, for Gloas, its envelope.
    state: State<P>,
    /// The validators' secret keys.
    keyring: Keyring,
    /// Who signs the votes each block carries.
    participation: Participation,
}

impl<P: Preset> ChainBuilder<P> {
    /// A builder at a genesis state whose validators hold the pyspec test keys.
    ///
    /// # Errors
    ///
    /// Fails when the genesis fork version differs from the configuration's.
    /// Fails when a validator's key is not the pyspec key of its index.
    pub fn new(
        config: ChainConfig,
        genesis: impl Into<combined::BeaconState<P>>,
    ) -> Result<Self, ChainBuilderError> {
        let genesis = genesis.into();
        let state_version = genesis.fork().current_version;
        let config_version = config.fork_version_at(genesis.current_epoch());
        if state_version != config_version {
            return Err(ChainBuilderError::ForkVersionMismatch {
                state: state_version,
                config: config_version,
            });
        }
        let validators = genesis.validators();
        let keyring = Keyring::pyspec(validators.len());
        for (index, validator) in validators.iter().enumerate() {
            if keyring.public_key(index) != Some(validator.pubkey.0) {
                return Err(ChainBuilderError::KeyMismatch {
                    index: index.into(),
                    secret: index as u64 + 1,
                });
            }
        }
        Ok(Self {
            config,
            state: State::new(genesis.clone()),
            genesis,
            keyring,
            participation: Participation::Silent,
        })
    }

    /// Has the validators vote as the participation says, from the next block on.
    #[must_use]
    pub const fn with_participation(mut self, participation: Participation) -> Self {
        self.participation = participation;
        self
    }

    /// The configuration the chain follows.
    #[must_use]
    pub const fn config(&self) -> &ChainConfig {
        &self.config
    }

    /// The state the chain starts from.
    #[must_use]
    pub const fn genesis(&self) -> &combined::BeaconState<P> {
        &self.genesis
    }

    /// The SSZ encoding of the genesis state, as a node reads it from a file.
    #[must_use]
    pub fn genesis_bytes(&self) -> Vec<u8> {
        self.genesis.encode()
    }

    /// The state after the latest block.
    #[must_use]
    pub const fn state(&self) -> &State<P> {
        &self.state
    }

    /// Hash of the terminal proof-of-work block, which the merge payload builds on.
    ///
    /// It is the configuration's hand-fixed terminal block hash, when set.
    #[must_use]
    pub fn terminal_block_hash(&self) -> Hash32 {
        PayloadParts::terminal_block_hash(&self.config)
    }

    /// Builds, signs, and applies the block of the next slot, with its envelope from Gloas on.
    ///
    /// # Errors
    ///
    /// Fails when the state cannot elect a proposer, or the built block or envelope is invalid.
    pub fn propose(&mut self) -> Result<Proposal<P>, ChainBuilderError> {
        let slot = self.state.beacon().slot() + 1;
        self.propose_at(slot)
    }

    /// Builds, signs, and applies the block of a later slot, leaving the slots between empty.
    ///
    /// # Algorithm
    ///
    /// 1. Advance a copy of the state to the slot, and read the proposer and inputs.
    /// 2. Apply the block once with a zero state root, to learn the true post-state root.
    /// 3. Sign the block with the true root, as the pyspec helpers do.
    /// 4. For Gloas, reveal the payload the bid committed to, signed by the proposer.
    ///
    /// Step 2 skips signatures, so the builder never verifies its own work.
    /// Consumers verify the blocks; the tests below do so with every signature checked.
    ///
    /// # Errors
    ///
    /// Fails when the slot is not after the latest block's.
    /// Fails when the state cannot elect a proposer, or the built block or envelope is invalid.
    pub fn propose_at(&mut self, slot: Slot) -> Result<Proposal<P>, ChainBuilderError> {
        self.propose_committing(slot, &[])
    }

    /// Builds the next block as the plain proposal does, committing to blobs the caller holds.
    ///
    /// The commitments go in the body in order, one per blob.
    /// Without an engine, nothing checks them against the payload's versioned hashes.
    ///
    /// # Errors
    ///
    /// Fails as the plain proposal does.
    /// Fails when the block's body holds no commitments, as before Deneb and from Gloas on.
    pub fn propose_with_blobs(
        &mut self,
        commitments: &[KzgCommitment],
    ) -> Result<Proposal<P>, ChainBuilderError> {
        let slot = self.state.beacon().slot() + 1;
        self.propose_committing(slot, commitments)
    }

    /// Builds the block of a slot, with the given commitments in its body.
    fn propose_committing(
        &mut self,
        slot: Slot,
        commitments: &[KzgCommitment],
    ) -> Result<Proposal<P>, ChainBuilderError> {
        let commitments = BlobCommitments(commitments);

        // Phase 1: the state at the slot, and what the block takes from it.
        let mut pre = self.state.clone();
        pre.process_slots(&self.config, slot)
            .map_err(|source| ChainBuilderError::Slots { slot, source })?;
        let draft = Draft::new(&pre, &self.config, &self.keyring, self.participation)?;

        // Phase 2: the post-state, and its root.
        // Why: the transition checks the claimed root last, and reports the one it computed.
        let mut post = pre.clone();
        let mut unrooted = draft.block(pre.beacon(), Root::ZERO)?;
        commitments.attach(&mut unrooted)?;
        let unrooted = combined::SignedBeaconBlock::from_parts(unrooted, BlsSignature::default());
        let outcome = post.state_transition(
            &self.config,
            &unrooted,
            Verification::Skip,
            &KnownVerdict(true),
        );
        let state_root = match outcome {
            Err(TransitionError::StateRootMismatch { computed, .. }) => computed,
            Err(source) => return Err(ChainBuilderError::Block { slot, source }),
            Ok(()) => return Err(ChainBuilderError::ZeroStateRoot(slot)),
        };

        // Phase 3: the block, signed over its header root.
        let mut block = draft.block(pre.beacon(), state_root)?;
        commitments.attach(&mut block)?;
        let epoch = slot.epoch::<P>();
        let block_signing_root = SigningData {
            object_root: block.hash_tree_root(),
            domain: pre.beacon().domain(DOMAIN_BEACON_PROPOSER, epoch),
        }
        .hash_tree_root();
        let signature = self
            .keyring
            .sign(draft.proposer_index, block_signing_root)?;
        let block = combined::SignedBeaconBlock::from_parts(block, signature);

        // Phase 4: the envelope, once payloads separate from blocks.
        let combined::SignedBeaconBlock::Gloas(gloas_block) = &block else {
            self.state = post;
            return Ok(Proposal::Coupled(block));
        };
        let envelope = self.reveal(&mut post, &draft, gloas_block)?;
        self.state = post;
        Ok(Proposal::Separated {
            block,
            envelope: Box::new(envelope),
        })
    }

    /// Builds the block of a slot around a proposer's reveal and the votes a caller collected.
    ///
    /// Nothing is signed and the chain does not move: the caller signs, then applies.
    /// From Gloas on, the self-built payload's envelope comes back unsigned too.
    ///
    /// # Errors
    ///
    /// Fails when the slot is not after the latest block's, the votes do not fit the block, or the block is invalid.
    pub fn produce(
        &self,
        slot: Slot,
        inputs: &BlockInputs<P>,
    ) -> Result<UnsignedProposal<P>, ChainBuilderError> {
        let mut pre = self.state.clone();
        pre.process_slots(&self.config, slot)
            .map_err(|source| ChainBuilderError::Slots { slot, source })?;
        let draft = Draft::new(&pre, &self.config, &self.keyring, Participation::Silent)?
            .with_reveal(inputs.randao_reveal);

        // The post-state root, learned from a dry run with a zero root, as for a built block.
        let mut post = pre.clone();
        let mut unrooted = draft.block(pre.beacon(), Root::ZERO)?;
        inputs.attach(&mut unrooted)?;
        let unrooted = combined::SignedBeaconBlock::from_parts(unrooted, BlsSignature::default());
        let outcome = post.state_transition(
            &self.config,
            &unrooted,
            Verification::Skip,
            &KnownVerdict(true),
        );
        let state_root = match outcome {
            Err(TransitionError::StateRootMismatch { computed, .. }) => computed,
            Err(source) => return Err(ChainBuilderError::Block { slot, source }),
            Ok(()) => return Err(ChainBuilderError::ZeroStateRoot(slot)),
        };
        let mut block = draft.block(pre.beacon(), state_root)?;
        inputs.attach(&mut block)?;

        // Once payloads separate, the self-built payload is revealed in an envelope.
        let combined::BeaconBlock::Gloas(gloas_block) = &block else {
            return Ok(UnsignedProposal {
                block,
                envelope: None,
            });
        };
        let fork = post.fork_name();
        let gloas_state =
            gloas::BeaconState::from_any(post.beacon()).ok_or(ChainBuilderError::Envelope {
                slot,
                source: EnvelopeError::WrongFork(fork),
            })?;
        let bid = &gloas_block.body.signed_execution_payload_bid.message;
        let envelope = draft.payload(bid.parent_block_hash).envelope(
            gloas_state.payload_expected_withdrawals.clone(),
            gloas_block.hash_tree_root(),
            gloas_block.parent_root,
        );
        Ok(UnsignedProposal {
            block,
            envelope: Some(envelope),
        })
    }

    /// Applies a block a proposer signed, and its envelope, with every signature checked.
    ///
    /// # Errors
    ///
    /// Fails when the block or the envelope is invalid; the chain then does not move.
    pub fn apply(
        &mut self,
        block: &combined::SignedBeaconBlock<P>,
        envelope: Option<&gloas::SignedExecutionPayloadEnvelope<P>>,
    ) -> Result<(), ChainBuilderError> {
        let slot = block.slot();
        let mut post = self.state.clone();
        post.state_transition(
            &self.config,
            block,
            Verification::Verify,
            &KnownVerdict(true),
        )
        .map_err(|source| ChainBuilderError::Block { slot, source })?;
        if let Some(envelope) = envelope {
            post.verify_execution_payload_envelope(
                &self.config,
                envelope,
                Verification::Verify,
                &KnownVerdict(true),
            )
            .map_err(|source| ChainBuilderError::Envelope { slot, source })?;
        }
        self.state = post;
        Ok(())
    }

    /// The proposer's envelope for its self-built bid, checked against the post-state.
    ///
    /// The withdrawals are those the block fixed in the state.
    /// The proposer signs as the builder, since the bid is self-built.
    /// The check skips the signature, like the block's dry run.
    /// See `verify_execution_payload_envelope` in the Gloas beacon chain spec.
    fn reveal(
        &self,
        post: &mut State<P>,
        draft: &Draft,
        block: &gloas::SignedBeaconBlock<P>,
    ) -> Result<gloas::SignedExecutionPayloadEnvelope<P>, ChainBuilderError> {
        let slot = draft.slot;
        let fork = post.fork_name();
        let gloas_state =
            gloas::BeaconState::from_any(post.beacon()).ok_or(ChainBuilderError::Envelope {
                slot,
                source: EnvelopeError::WrongFork(fork),
            })?;
        let bid = &block.message.body.signed_execution_payload_bid.message;
        let message = draft.payload(bid.parent_block_hash).envelope(
            gloas_state.payload_expected_withdrawals.clone(),
            block.message.hash_tree_root(),
            block.message.parent_root,
        );
        let domain = gloas_state.domain(DOMAIN_BEACON_BUILDER, slot.epoch::<P>());
        let signature = self.keyring.sign(
            draft.proposer_index,
            SigningData::signing_root(&message, domain),
        )?;
        let envelope = gloas::SignedExecutionPayloadEnvelope { message, signature };
        post.verify_execution_payload_envelope(
            &self.config,
            &envelope,
            Verification::Skip,
            &KnownVerdict(true),
        )
        .map_err(|source| ChainBuilderError::Envelope { slot, source })?;
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use axiom_fork_choice::{
        DataAvailability, ForkChoiceError, ForkChoiceNode, NodePayload, PayloadStatus, Store,
    };
    use axiom_ssz::U256;
    use axiom_types::{
        Epoch, ForkName, KzgCommitment, Minimal, Slot, ValidatorIndex, Version,
        bellatrix::PowBlock, constants::DOMAIN_RANDAO, phase0,
    };

    use super::*;
    use crate::{Case, Vectors};

    /// Blocks built: nine epochs of eight slots, the last two and a slot in Gloas.
    const BLOCKS: u64 = 72;

    /// The minimal configuration with Altair at epoch 1, and each later fork one epoch on.
    ///
    /// The terminal total difficulty is 1000, so a merge block's parent can sit at 999.
    fn schedule() -> ChainConfig {
        let mut config = ChainConfig {
            terminal_total_difficulty: U256::from_u64(1000),
            ..ChainConfig::minimal()
        };
        for (epoch, fork) in ForkName::ALL.into_iter().enumerate().skip(1) {
            config = config.with_fork_epoch(fork, Epoch(epoch as u64));
        }
        config
    }

    /// The terminal proof-of-work block at difficulty 1000, and its parent at 999.
    fn terminal_blocks(terminal_hash: Hash32) -> [PowBlock; 2] {
        let parent_hash = Hash32([0x7d; 32]);
        [
            PowBlock {
                block_hash: terminal_hash,
                parent_hash,
                total_difficulty: U256::from_u64(1000),
            },
            PowBlock {
                block_hash: parent_hash,
                parent_hash: Hash32::ZERO,
                total_difficulty: U256::from_u64(999),
            },
        ]
    }

    /// The pyspec genesis, or nothing when the vectors are absent.
    fn pyspec_genesis() -> Option<phase0::BeaconState<Minimal>> {
        let case = Case::new(Vectors::locate()?.consensus().join(PYSPEC_GENESIS));
        Some(case.ssz("state").expect("the genesis vector decodes"))
    }

    /// Start of a slot, in milliseconds since the Unix epoch.
    fn slot_start_ms(builder: &ChainBuilder<Minimal>, slot: Slot) -> u64 {
        builder.genesis().genesis_time() * 1000 + slot.0 * builder.config().slot_duration_ms
    }

    #[test]
    fn every_block_passes_the_state_transition_with_every_signature_checked() {
        let Some(genesis) = pyspec_genesis() else {
            return;
        };
        // Fixture state: 64 validators, all active at genesis, at slot 0.
        let active = genesis
            .validators
            .iter()
            .filter(|validator| validator.is_active_at(Epoch(0)))
            .count();
        assert_eq!((genesis.validators.len(), active), (64, 64));
        assert_eq!(genesis.slot, Slot(0));

        let config = schedule();
        let mut builder = ChainBuilder::<Minimal>::new(config.clone(), genesis.clone()).unwrap();
        let mut verifier = State::<Minimal>::new(genesis);

        // Slots 1 to 72, each block checked from scratch with signatures on.
        let mut forks = Vec::new();
        let mut envelopes = 0;
        for slot in 1..=BLOCKS {
            let proposal = builder.propose().unwrap();
            let block = proposal.block();
            assert_eq!(block.slot(), Slot(slot));
            forks.push(block.fork_name());
            verifier
                .state_transition(&config, block, Verification::Verify, &KnownVerdict(true))
                .unwrap();
            if let Some(envelope) = proposal.envelope() {
                verifier
                    .verify_execution_payload_envelope(
                        &config,
                        envelope,
                        Verification::Verify,
                        &KnownVerdict(true),
                    )
                    .unwrap();
                envelopes += 1;
            }
        }

        // Slot s belongs to epoch s / 8, whose fork is the epoch's index in fork order.
        // Phase0 holds slots 1 to 7, each later fork 8 slots, and Gloas slots 56 to 72.
        let expected = (1..=BLOCKS)
            .map(|slot| ForkName::ALL[(slot / 8).min(7) as usize])
            .collect::<Vec<_>>();
        assert_eq!(forks, expected);
        // Every Gloas block, 17 of them, came with its envelope.
        assert_eq!(envelopes, 17);
        // The verifier and the builder end at the same state.
        assert_eq!(verifier.hash_tree_root(), builder.state().hash_tree_root());
    }

    #[test]
    fn fork_choice_heads_the_last_block_with_its_payload_revealed() {
        let Some(genesis) = pyspec_genesis() else {
            return;
        };
        let config = schedule();
        let mut builder = ChainBuilder::<Minimal>::new(config.clone(), genesis).unwrap();

        // The store anchors at genesis, with the block whose state root is the genesis root.
        // The engine reported the terminal block and its parent, so the merge block passes.
        let anchor = combined::BeaconBlock::genesis(builder.genesis());
        let mut store = Store::new(config, State::new(builder.genesis().clone()), &anchor).unwrap();
        for block in terminal_blocks(builder.terminal_block_hash()) {
            store.on_pow_block(block);
        }

        // Each block arrives at the start of its slot, and each envelope right after it.
        let mut last_root = Root::ZERO;
        for _ in 0..BLOCKS {
            let proposal = builder.propose().unwrap();
            let block = proposal.block();
            store.on_tick(slot_start_ms(&builder, block.slot()));
            store
                .import_block(
                    block,
                    DataAvailability::Available,
                    Verification::Verify,
                    PayloadStatus::Valid,
                )
                .unwrap();
            if let Some(envelope) = proposal.envelope() {
                store
                    .on_execution_payload_envelope(
                        envelope,
                        DataAvailability::Available,
                        Verification::Verify,
                        PayloadStatus::Valid,
                    )
                    .unwrap();
            }
            last_root = block.block_root();
        }

        // At slot 72 the head is block 72, and its revealed payload outranks the empty branch.
        assert_eq!(
            store.head().unwrap(),
            ForkChoiceNode {
                root: last_root,
                payload: NodePayload::Full,
            }
        );
    }

    #[test]
    fn with_full_participation_every_fork_justifies_and_finalizes() {
        let Some(genesis) = pyspec_genesis() else {
            return;
        };
        let config = schedule();
        let mut builder = ChainBuilder::<Minimal>::new(config.clone(), genesis.clone())
            .unwrap()
            .with_participation(Participation::Full);
        let mut verifier = State::<Minimal>::new(genesis);

        // Slots 1 to 72, each block checked from scratch with signatures on.
        // Every block from Altair on carries 32 of 32 sync signatures and two committees' votes.
        let mut signers = Vec::new();
        for _ in 1..=BLOCKS {
            let proposal = builder.propose().unwrap();
            let block = proposal.block();
            verifier
                .state_transition(&config, block, Verification::Verify, &KnownVerdict(true))
                .unwrap();
            if let Some(envelope) = proposal.envelope() {
                verifier
                    .verify_execution_payload_envelope(
                        &config,
                        envelope,
                        Verification::Verify,
                        &KnownVerdict(true),
                    )
                    .unwrap();
            }
            signers.push(
                block
                    .sync_aggregate()
                    .map(|aggregate| aggregate.sync_committee_bits.count_ones()),
            );
        }

        // Phase0 slots 1 to 7 have no sync committee; every later block has all 32 seats.
        assert_eq!(signers[..7], [None; 7]);
        assert!(signers[7..].iter().all(|count| *count == Some(32)));

        // Justification starts at the end of epoch 2, and each epoch then justifies itself.
        // So slot 72, the start of epoch 9, has epoch 8 justified and epoch 7 finalized.
        let state = verifier.beacon();
        assert_eq!(state.current_justified_checkpoint().epoch, Epoch(8));
        assert_eq!(state.finalized_checkpoint().epoch, Epoch(7));
        assert_eq!(verifier.hash_tree_root(), builder.state().hash_tree_root());
    }

    #[test]
    fn blocks_commit_to_blobs_only_where_their_body_holds_commitments() {
        let Some(genesis) = pyspec_genesis() else {
            return;
        };
        let config = schedule();
        let mut builder = ChainBuilder::<Minimal>::new(config.clone(), genesis.clone()).unwrap();
        let mut verifier = State::<Minimal>::new(genesis);
        // The compressed point at infinity, a valid commitment to the zero blob.
        let mut infinity = [0; 48];
        infinity[0] = 0xc0;
        let commitments = [KzgCommitment(infinity); 2];

        // Slot 1 is phase0, whose body has no commitment list.
        assert_eq!(
            builder.propose_with_blobs(&commitments).unwrap_err(),
            ChainBuilderError::NoBlobCommitments {
                slot: Slot(1),
                fork: ForkName::Phase0,
            }
        );

        // Slots 1 to 31 cover phase0 to Capella, all without blobs.
        for _ in 1..32 {
            let proposal = builder.propose().unwrap();
            verifier
                .state_transition(
                    &config,
                    proposal.block(),
                    Verification::Verify,
                    &KnownVerdict(true),
                )
                .unwrap();
        }

        // Slot 32 opens Deneb, and 4097 commitments overflow the body's list of 4096.
        assert_eq!(
            builder
                .propose_with_blobs(&vec![KzgCommitment(infinity); 4097])
                .unwrap_err(),
            ChainBuilderError::TooManyCommitments {
                slot: Slot(32),
                count: 4097,
                limit: 4096,
            }
        );

        // Two commitments fit, and the block passes with every signature checked.
        let proposal = builder.propose_with_blobs(&commitments).unwrap();
        let block = proposal.block();
        assert_eq!(block.fork_name(), ForkName::Deneb);
        assert_eq!(block.message().blob_kzg_commitments(), commitments);
        verifier
            .state_transition(&config, block, Verification::Verify, &KnownVerdict(true))
            .unwrap();
        assert_eq!(verifier.hash_tree_root(), builder.state().hash_tree_root());
    }

    #[test]
    fn the_first_bellatrix_block_merges_on_the_terminal_block() {
        let Some(genesis) = pyspec_genesis() else {
            return;
        };
        let config = schedule();
        let mut builder = ChainBuilder::<Minimal>::new(config.clone(), genesis).unwrap();
        let anchor = combined::BeaconBlock::genesis(builder.genesis());
        let mut store = Store::new(config, State::new(builder.genesis().clone()), &anchor).unwrap();

        // Slots 1 to 15 are phase0 and Altair, with no payload.
        for _ in 1..16 {
            let proposal = builder.propose().unwrap();
            store.on_tick(slot_start_ms(&builder, proposal.block().slot()));
            store
                .import_block(
                    proposal.block(),
                    DataAvailability::Available,
                    Verification::Verify,
                    PayloadStatus::Valid,
                )
                .unwrap();
        }

        // Slot 16 opens Bellatrix, and its payload builds on the stand-in terminal block 0x7e.
        let merge = builder.propose().unwrap();
        let block = merge.block().message();
        assert_eq!(block.fork_name(), ForkName::Bellatrix);
        assert_eq!(
            block.execution_hashes().parent_block_hash,
            Hash32([0x7e; 32])
        );

        // Until the engine reports the terminal block, fork choice cannot accept the merge.
        store.on_tick(slot_start_ms(&builder, Slot(16)));
        let import = |store: &mut Store<Minimal>| {
            store.import_block(
                merge.block(),
                DataAvailability::Available,
                Verification::Verify,
                PayloadStatus::Valid,
            )
        };
        assert_eq!(
            import(&mut store),
            Err(ForkChoiceError::UnknownPowBlock(Hash32([0x7e; 32])))
        );
        for block in terminal_blocks(builder.terminal_block_hash()) {
            store.on_pow_block(block);
        }
        assert_eq!(import(&mut store), Ok(()));
    }

    #[test]
    fn a_validator_without_its_pyspec_key_is_refused() {
        let Some(mut genesis) = pyspec_genesis() else {
            return;
        };
        // Mutation: validator 3 takes the key of validator 4, whose secret is 5.
        genesis.validators[3].pubkey = genesis.validators[4].pubkey;

        let outcome = ChainBuilder::<Minimal>::new(schedule(), genesis);

        // Validator 3 should hold the secret 4.
        assert_eq!(
            outcome.unwrap_err(),
            ChainBuilderError::KeyMismatch {
                index: ValidatorIndex(3),
                secret: 4,
            }
        );
    }

    #[test]
    fn a_genesis_of_another_fork_version_is_refused() {
        let Some(genesis) = pyspec_genesis() else {
            return;
        };
        // Mutation: the configuration expects the mainnet genesis version 0x00000000.
        let mut config = schedule();
        config.genesis_fork_version = Version([0, 0, 0, 0]);

        let outcome = ChainBuilder::<Minimal>::new(config, genesis);

        // The minimal genesis signs with 0x00000001.
        assert_eq!(
            outcome.unwrap_err(),
            ChainBuilderError::ForkVersionMismatch {
                state: Version([0, 0, 0, 1]),
                config: Version([0, 0, 0, 0]),
            }
        );
    }

    #[test]
    fn a_produced_block_signed_by_its_proposer_matches_a_built_one() {
        let Some(genesis) = pyspec_genesis() else {
            return;
        };
        // Fixture state: two builders from one genesis, one building, one producing for a signer.
        let config = schedule();
        let mut built = ChainBuilder::<Minimal>::new(config.clone(), genesis.clone()).unwrap();
        let mut produced = ChainBuilder::<Minimal>::new(config, genesis).unwrap();

        // Slots 1 to 64 run phase0 to Gloas; the signer is the keyring, as a validator client would be.
        for slot in 1..=64 {
            let slot = Slot(slot);
            let mut pre = produced.state().clone();
            pre.process_slots(produced.config(), slot).unwrap();
            let proposer = pre.beacon_proposer_index().unwrap();
            let epoch = slot.epoch::<Minimal>();
            let reveal = produced
                .keyring
                .sign(
                    proposer,
                    SigningData::signing_root(&epoch, pre.beacon().domain(DOMAIN_RANDAO, epoch)),
                )
                .unwrap();
            let inputs = BlockInputs {
                randao_reveal: reveal,
                attestations: BlockAttestations::None,
                sync_aggregate: None,
            };
            let unsigned = produced.produce(slot, &inputs).unwrap();
            let root = SigningData {
                object_root: unsigned.block.hash_tree_root(),
                domain: pre.beacon().domain(DOMAIN_BEACON_PROPOSER, epoch),
            }
            .hash_tree_root();
            let signature = produced.keyring.sign(proposer, root).unwrap();
            let block = combined::SignedBeaconBlock::from_parts(unsigned.block, signature);
            let envelope = unsigned.envelope.map(|message| {
                let domain = pre.beacon().domain(DOMAIN_BEACON_BUILDER, epoch);
                let signature = produced
                    .keyring
                    .sign(proposer, SigningData::signing_root(&message, domain))
                    .unwrap();
                gloas::SignedExecutionPayloadEnvelope { message, signature }
            });

            // Applying with every signature checked lands on the same block as building.
            produced.apply(&block, envelope.as_ref()).unwrap();
            let expected = built.propose().unwrap();
            assert_eq!(&block, expected.block());
            assert_eq!(envelope.as_ref(), expected.envelope());
        }
        assert_eq!(
            produced.state().hash_tree_root(),
            built.state().hash_tree_root()
        );
    }
}
