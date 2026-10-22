//! A builder of valid, fully signed chains across fork boundaries, for end-to-end tests.
//!
//! # Overview
//!
//! The builder starts from a genesis state whose validators hold the pyspec test keys.
//! It fills every slot with a block from the elected proposer, signed as the spec requires.
//!
//! The blocks carry no attestations, deposits, exits, or blobs.
//! The sync aggregate is empty, and the eth1 vote repeats the state's.
//! Bellatrix stays before the merge; from Capella on, each block carries a stand-in payload.
//!
//! From Gloas on, each block bids for its own payload and the builder reveals it.
//! The next block then builds on that payload, so every Gloas block is full.

mod draft;
mod error;
mod keyring;
mod payload;
mod proposal;

use axiom_ssz::Ssz;
use axiom_state_transition::{
    KnownVerdict, State, TransitionError, Verification, gloas::EnvelopeError,
};
use axiom_types::{
    BlsSignature, ChainConfig, Preset, Root,
    accessors::{CoreState, ForkState},
    combined,
    constants::{DOMAIN_BEACON_BUILDER, DOMAIN_BEACON_PROPOSER},
    gloas,
    phase0::SigningData,
};
pub use error::ChainBuilderError;
pub use proposal::Proposal;

use crate::chain_builder::{draft::Draft, keyring::Keyring};

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
        })
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

    /// Builds, signs, and applies the block of the next slot, with its envelope from Gloas on.
    ///
    /// # Algorithm
    ///
    /// 1. Advance a copy of the state to the next slot, and read the proposer and inputs.
    /// 2. Apply the block once with a zero state root, to learn the true post-state root.
    /// 3. Sign the block with the true root, as the pyspec helpers do.
    /// 4. For Gloas, reveal the payload the bid committed to, signed by the proposer.
    ///
    /// Step 2 skips signatures, so the builder never verifies its own work.
    /// Consumers verify the blocks; the tests below do so with every signature checked.
    ///
    /// # Errors
    ///
    /// Fails when the state cannot elect a proposer, or the built block or envelope is invalid.
    pub fn propose(&mut self) -> Result<Proposal<P>, ChainBuilderError> {
        let slot = self.state.beacon().slot() + 1;

        // Phase 1: the state at the slot, and what the block takes from it.
        let mut pre = self.state.clone();
        pre.process_slots(&self.config, slot)
            .map_err(|source| ChainBuilderError::Slots { slot, source })?;
        let draft = Draft::new(&pre, &self.config, &self.keyring)?;

        // Phase 2: the post-state, and its root.
        // Why: the transition checks the claimed root last, and reports the one it computed.
        let mut post = pre.clone();
        let unrooted = combined::SignedBeaconBlock::from_parts(
            draft.block(pre.beacon(), Root::ZERO)?,
            BlsSignature::default(),
        );
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
        let block = draft.block(pre.beacon(), state_root)?;
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
    use axiom_fork_choice::{DataAvailability, ForkChoiceNode, NodePayload, PayloadStatus, Store};
    use axiom_types::{Epoch, ForkName, Minimal, Slot, ValidatorIndex, Version, phase0};

    use super::*;
    use crate::{Case, Vectors};

    /// Blocks built: nine epochs of eight slots, the last two and a slot in Gloas.
    const BLOCKS: u64 = 72;

    /// The minimal configuration with Altair at epoch 1, and each later fork one epoch on.
    fn schedule() -> ChainConfig {
        let mut config = ChainConfig::minimal();
        for (epoch, fork) in ForkName::ALL.into_iter().enumerate().skip(1) {
            config = config.with_fork_epoch(fork, Epoch(epoch as u64));
        }
        config
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
        let anchor = combined::BeaconBlock::genesis(builder.genesis());
        let mut store = Store::new(config, State::new(builder.genesis().clone()), &anchor).unwrap();

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
}
