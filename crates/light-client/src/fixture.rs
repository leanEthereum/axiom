//! A hand-built chain for tests: blocks, their post-states, and real sync committee signatures.

use axiom_bls::{SecretKey, Signature};
use axiom_ssz::{PersistentVector, Root, Ssz};
use axiom_types::{
    BlsPubkey, BlsSignature, ChainConfig, Domain, ForkName, Hash32, Minimal, Slot,
    accessors::CoreState,
    altair::{self, SigningData, SyncAggregate, SyncCommittee},
    bellatrix, capella,
    combined::{BeaconState, SignedBeaconBlock},
    constants::DOMAIN_SYNC_COMMITTEE,
    deneb, electra, fulu, gloas, phase0,
    phase0::{BeaconBlockHeader, Checkpoint},
};

use crate::{
    Header, LightClientError, PostState,
    combined::{
        Format, LightClientBootstrap, LightClientHeader, LightClientStore, LightClientUpdate,
    },
};

/// The genesis validators root every signature of the fixture commits to.
pub(crate) const GENESIS_VALIDATORS_ROOT: Root = Root([0x42; 32]);

/// Members of a minimal sync committee.
const COMMITTEE_SIZE: usize = 32;

/// A chain configuration and a sync committee whose secret keys the tests hold.
pub(crate) struct Chain {
    /// The fork schedule.
    pub(crate) config: ChainConfig,
    /// Secret keys of the current committee, by seat.
    keys: Vec<SecretKey>,
    /// The current sync committee of every state.
    pub(crate) current: SyncCommittee<Minimal>,
    /// The next sync committee of every state: the current one, seats reversed.
    pub(crate) next: SyncCommittee<Minimal>,
}

impl Chain {
    /// A chain with every fork up to the given one active from genesis.
    pub(crate) fn new(last: ForkName) -> Self {
        Self::with_config(ChainConfig::minimal().with_forks_at_genesis(last))
    }

    /// A chain with a given fork schedule.
    pub(crate) fn with_config(config: ChainConfig) -> Self {
        // Secret scalars 1 through 32, big-endian.
        let keys: Vec<SecretKey> = (1..=COMMITTEE_SIZE as u8)
            .map(|scalar| {
                let mut bytes = [0; 32];
                bytes[31] = scalar;
                SecretKey::from_bytes(&bytes).unwrap()
            })
            .collect();
        let pubkeys: Vec<BlsPubkey> = keys
            .iter()
            .map(|key| BlsPubkey(key.public_key().to_bytes()))
            .collect();
        let current = SyncCommittee {
            pubkeys: PersistentVector::from_fn(|seat| pubkeys[seat]),
            aggregate_pubkey: BlsPubkey::default(),
        };
        let next = SyncCommittee {
            pubkeys: PersistentVector::from_fn(|seat| pubkeys[COMMITTEE_SIZE - 1 - seat]),
            aggregate_pubkey: BlsPubkey::default(),
        };
        Self {
            config,
            keys,
            current,
            next,
        }
    }

    /// A block at a slot and its post-state, which finalizes a checkpoint.
    pub(crate) fn block(
        &self,
        slot: Slot,
        parent_root: Root,
        finalized: Checkpoint,
        aggregate: SyncAggregate<Minimal>,
    ) -> (BeaconState<Minimal>, SignedBeaconBlock<Minimal>) {
        // Each block commits to an execution block hash of its slot, so headers differ.
        let hash = Hash32([slot.0 as u8; 32]);
        let committees = (self.current.clone(), self.next.clone());
        match self.config.fork_at(slot.epoch::<Minimal>()) {
            ForkName::Phase0 => {
                let mut block = phase0::SignedBeaconBlock::<Minimal>::default();
                (block.message.slot, block.message.parent_root) = (slot, parent_root);
                let mut state = phase0::BeaconState::<Minimal>::default();
                block.message.state_root = seal(&mut state, block.message.header(), finalized);
                (state.into(), SignedBeaconBlock::Phase0(block))
            }
            ForkName::Altair => {
                let mut block = altair::SignedBeaconBlock::<Minimal>::default();
                (block.message.slot, block.message.parent_root) = (slot, parent_root);
                block.message.body.sync_aggregate = aggregate;
                let mut state = altair::BeaconState::<Minimal>::default();
                (state.current_sync_committee, state.next_sync_committee) = committees;
                block.message.state_root = seal(&mut state, block.message.header(), finalized);
                (state.into(), SignedBeaconBlock::Altair(block))
            }
            ForkName::Bellatrix => {
                let mut block = bellatrix::SignedBeaconBlock::<Minimal>::default();
                (block.message.slot, block.message.parent_root) = (slot, parent_root);
                block.message.body.sync_aggregate = aggregate;
                block.message.body.execution_payload.block_hash = hash;
                let mut state = bellatrix::BeaconState::<Minimal>::default();
                (state.current_sync_committee, state.next_sync_committee) = committees;
                block.message.state_root = seal(&mut state, block.message.header(), finalized);
                (state.into(), SignedBeaconBlock::Bellatrix(block))
            }
            ForkName::Capella => {
                let mut block = capella::SignedBeaconBlock::<Minimal>::default();
                (block.message.slot, block.message.parent_root) = (slot, parent_root);
                block.message.body.sync_aggregate = aggregate;
                block.message.body.execution_payload.block_hash = hash;
                let mut state = capella::BeaconState::<Minimal>::default();
                (state.current_sync_committee, state.next_sync_committee) = committees;
                block.message.state_root = seal(&mut state, block.message.header(), finalized);
                (state.into(), SignedBeaconBlock::Capella(block))
            }
            ForkName::Deneb => {
                let mut block = deneb::SignedBeaconBlock::<Minimal>::default();
                (block.message.slot, block.message.parent_root) = (slot, parent_root);
                block.message.body.sync_aggregate = aggregate;
                block.message.body.execution_payload.block_hash = hash;
                let mut state = deneb::BeaconState::<Minimal>::default();
                (state.current_sync_committee, state.next_sync_committee) = committees;
                block.message.state_root = seal(&mut state, block.message.header(), finalized);
                (state.into(), SignedBeaconBlock::Deneb(block))
            }
            ForkName::Electra => {
                let mut block = electra::SignedBeaconBlock::<Minimal>::default();
                (block.message.slot, block.message.parent_root) = (slot, parent_root);
                block.message.body.sync_aggregate = aggregate;
                block.message.body.execution_payload.block_hash = hash;
                let mut state = electra::BeaconState::<Minimal>::default();
                (state.current_sync_committee, state.next_sync_committee) = committees;
                block.message.state_root = seal(&mut state, block.message.header(), finalized);
                (state.into(), SignedBeaconBlock::Electra(block))
            }
            ForkName::Fulu => {
                let mut block = electra::SignedBeaconBlock::<Minimal>::default();
                (block.message.slot, block.message.parent_root) = (slot, parent_root);
                block.message.body.sync_aggregate = aggregate;
                block.message.body.execution_payload.block_hash = hash;
                let mut state = fulu::BeaconState::<Minimal>::default();
                (state.current_sync_committee, state.next_sync_committee) = committees;
                block.message.state_root = seal(&mut state, block.message.header(), finalized);
                (state.into(), SignedBeaconBlock::Fulu(block))
            }
            ForkName::Gloas => {
                let mut block = gloas::SignedBeaconBlock::<Minimal>::default();
                (block.message.slot, block.message.parent_root) = (slot, parent_root);
                block.message.body.sync_aggregate = aggregate;
                let bid = &mut block.message.body.signed_execution_payload_bid.message;
                bid.parent_block_hash = hash;
                let mut state = gloas::BeaconState::<Minimal>::default();
                (state.current_sync_committee, state.next_sync_committee) = committees;
                block.message.state_root = seal(&mut state, block.message.header(), finalized);
                (state.into(), SignedBeaconBlock::Gloas(block))
            }
        }
    }

    /// The current committee's signature over a block, by its first seats.
    ///
    /// The committee signs in the fork of the slot before the signature slot.
    pub(crate) fn sign(
        &self,
        attested: &SignedBeaconBlock<Minimal>,
        signature_slot: Slot,
        signers: usize,
    ) -> SyncAggregate<Minimal> {
        let header = LightClientHeader::of_block(attested);
        let epoch = signature_slot.saturating_sub(1).epoch::<Minimal>();
        let domain = Domain::compute(
            DOMAIN_SYNC_COMMITTEE,
            self.config.fork_version_at(epoch),
            GENESIS_VALIDATORS_ROOT,
        );
        let message = SigningData::signing_root(Header::<Minimal>::beacon(&header), domain);
        let signatures: Vec<Signature> = self.keys[..signers]
            .iter()
            .map(|key| key.sign(&message.0))
            .collect();
        let mut aggregate = SyncAggregate::<Minimal>::default();
        for seat in 0..signers {
            aggregate.sync_committee_bits.set(seat, true);
        }
        // Without signers the signature bytes stay zero: nothing reads them below the minimum.
        if signers > 0 {
            aggregate.sync_committee_signature =
                BlsSignature(Signature::aggregate(&signatures).unwrap().to_bytes());
        }
        aggregate
    }

    /// Four blocks: a bootstrap block, a finalized one, an attested one, and its signing child.
    ///
    /// The attested state finalizes the finalized block, or the genesis checkpoint at slot 0.
    pub(crate) fn line(&self, slots: [u64; 4], signers: usize) -> Line {
        let [bootstrap, finalized, attested, signature] = slots.map(Slot);
        let empty = SyncAggregate::default;
        let bootstrap = self.block(bootstrap, Root::ZERO, Checkpoint::default(), empty());
        let (finalized, checkpoint) = if finalized == Slot::GENESIS {
            let genesis = self.block(finalized, Root::ZERO, Checkpoint::default(), empty());
            (genesis, Checkpoint::default())
        } else {
            let block = self.block(
                finalized,
                bootstrap.1.block_root(),
                Checkpoint::default(),
                empty(),
            );
            let checkpoint = Checkpoint {
                epoch: finalized.epoch::<Minimal>(),
                root: block.1.block_root(),
            };
            (block, checkpoint)
        };
        let attested = self.block(attested, finalized.1.block_root(), checkpoint, empty());
        let aggregate = self.sign(&attested.1, signature, signers);
        let signature = self.block(signature, attested.1.block_root(), checkpoint, aggregate);
        Line {
            bootstrap,
            finalized,
            attested,
            signature,
        }
    }
}

/// A block and its post-state.
pub(crate) type Pair = (BeaconState<Minimal>, SignedBeaconBlock<Minimal>);

/// The four blocks of a light client scenario, oldest first.
pub(crate) struct Line {
    /// The block a store bootstraps from.
    pub(crate) bootstrap: Pair,
    /// The block the attested state finalizes.
    pub(crate) finalized: Pair,
    /// The block the sync committee signs.
    pub(crate) attested: Pair,
    /// The child carrying the signature.
    pub(crate) signature: Pair,
}

impl Line {
    /// The update the signature block yields, with the finalized block at hand.
    pub(crate) fn update(&self, config: &ChainConfig) -> LightClientUpdate<Minimal> {
        self.update_with(config, Some(&self.finalized.1)).unwrap()
    }

    /// The update the signature block yields, with or without a finalized block.
    pub(crate) fn update_with(
        &self,
        config: &ChainConfig,
        finalized: Option<&SignedBeaconBlock<Minimal>>,
    ) -> Result<LightClientUpdate<Minimal>, LightClientError> {
        let signature = PostState::new(&self.signature.0, &self.signature.1)?;
        let attested = PostState::new(&self.attested.0, &self.attested.1)?;
        LightClientUpdate::create(config, &signature, &attested, finalized)
    }

    /// A store of a format, bootstrapped from the bootstrap block.
    pub(crate) fn store(&self, config: &ChainConfig, format: Format) -> LightClientStore<Minimal> {
        let (state, block) = &self.bootstrap;
        let bootstrap = LightClientBootstrap::create(&PostState::new(state, block).unwrap());
        LightClientStore::initialize(format, config, block.block_root(), bootstrap.unwrap())
            .unwrap()
    }
}

/// Puts a state at its block: slot, latest header, and finality, then returns its root.
fn seal<S: CoreState<Preset = Minimal> + Ssz>(
    state: &mut S,
    header: BeaconBlockHeader,
    finalized: Checkpoint,
) -> Root {
    *state.slot_mut() = header.slot;
    *state.latest_block_header_mut() = header;
    *state.finalized_checkpoint_mut() = finalized;
    state.hash_tree_root()
}
