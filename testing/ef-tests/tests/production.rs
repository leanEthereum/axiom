//! Blocks produced from the operation pool, for every fork, signed and checked from scratch.
//!
//! The chain starts at the pyspec genesis, whose validators hold the pyspec test keys.
//! Every validator attests and every sync committee seat signs, through the pools.
//! Each produced block is signed and applied with every signature checked.

use std::{collections::BTreeSet, mem};

use axiom_block_production::{
    BlockProducer, ExecutionChoice, GloasBid, LocalBuild, LocalPayload, ParentPayload,
    PayloadRequest, ProducedBlock, ProposalRequest, RandaoCheck, RevealedRequests,
};
use axiom_bls::SecretKey;
use axiom_das::BlockColumns;
use axiom_ef_tests::{Case, Vectors, chain_builder::PYSPEC_GENESIS};
use axiom_gossip::BlockBlobs;
use axiom_kzg::Kzg;
use axiom_operation_pool::{Aggregate, CommitteeAggregate, OperationPool, SyncPool};
use axiom_ssz::{ByteList, List, ProgressiveList, Ssz, U256};
use axiom_state_transition::{KnownVerdict, State, Verification};
use axiom_types::{
    BlsPubkey, BlsSignature, Bytes32, ChainConfig, CommitteeIndex, Epoch, ForkName, Hash32,
    KzgCommitment, KzgProof, Minimal, Preset, Root, Slot, ValidatorIndex,
    accessors::CoreState,
    altair::SyncCommitteeMessage,
    bellatrix, capella, combined,
    constants::{
        DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_BUILDER, DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO,
        DOMAIN_SYNC_COMMITTEE,
    },
    deneb::{self, Blob},
    electra, fulu, gloas,
    phase0::{
        self, AttestationData, BeaconBlockHeader, Checkpoint, ProposerSlashing,
        SignedBeaconBlockHeader, SigningData,
    },
    vote::{ConflictingVotes, IndexedVote},
};

/// Blocks produced: nine epochs of eight slots, the last two and a slot in Gloas.
const BLOCKS: u64 = 72;

/// Gas limit of every stand-in payload.
const GAS_LIMIT: u64 = 30_000_000;

/// The terminal proof-of-work block the merge payload builds on.
const TERMINAL: Hash32 = Hash32([0x7e; 32]);

/// The minimal configuration with Altair at epoch 1, and each later fork one epoch on.
fn schedule() -> ChainConfig {
    let mut config = ChainConfig {
        terminal_total_difficulty: U256::from_u64(1000),
        terminal_block_hash: TERMINAL,
        ..ChainConfig::minimal()
    };
    // Fixture state: one fork per epoch from Altair to Gloas.
    // Hstar stays in the far future.
    // Its envelopes need a pipeline this harness drives for Gloas only.
    for (epoch, fork) in ForkName::ALL
        .into_iter()
        .enumerate()
        .skip(1)
        .take_while(|(_, fork)| *fork != ForkName::Hstar)
    {
        config = config.with_fork_epoch(fork, Epoch(epoch as u64));
    }
    config
}

/// The pyspec genesis, or nothing when the vectors are absent.
fn pyspec_genesis() -> Option<phase0::BeaconState<Minimal>> {
    let case = Case::new(Vectors::locate()?.consensus().join(PYSPEC_GENESIS));
    Some(case.ssz("state").expect("the genesis vector decodes"))
}

/// The pyspec secret key of a validator: its index plus one.
fn key(index: ValidatorIndex) -> SecretKey {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&(index.0 + 1).to_be_bytes());
    SecretKey::from_bytes(&bytes).expect("small nonzero scalars are valid keys")
}

/// A validator's signature over a root.
fn sign(index: ValidatorIndex, root: Root) -> BlsSignature {
    BlsSignature(key(index).sign(&root.0).to_bytes())
}

/// The point at infinity: the commitment and every proof of the zero blob.
const fn infinity_point() -> [u8; 48] {
    let mut point = [0; 48];
    point[0] = 0xc0;
    point
}

/// A chain built by producing blocks from its own pools.
struct Chain {
    /// The fork schedule.
    config: ChainConfig,
    /// The state after the latest block.
    state: State<Minimal>,
    /// Operations waiting for a block.
    pool: OperationPool<Minimal>,
    /// Blobs each block from Deneb on carries.
    blobs: usize,
    /// Hash of the latest execution payload, or the terminal block before the merge.
    payload_hash: Hash32,
    /// Validators and committees that voted for the latest block, whose votes wait in the pool.
    voters: (usize, usize),
    /// Whether payloads from Bellatrix to Fulu come from a builder, revealed after signing.
    builder: bool,
}

/// What one produced block carried.
#[derive(Debug)]
struct Produced {
    /// The fork of the block.
    fork: ForkName,
    /// Committees spanned by each attestation.
    committees: Vec<usize>,
    /// Validators the attestations name.
    attesters: usize,
    /// Validators and committees that voted for the parent block.
    parent_voters: (usize, usize),
    /// Sync committee seats that signed.
    sync_signers: Option<usize>,
    /// Attester slashings.
    attester_slashings: usize,
    /// Blob sidecars or columns built from the block's blobs.
    sidecars: usize,
    /// Whether the block was produced blinded.
    blinded: bool,
}

impl Chain {
    fn new(genesis: phase0::BeaconState<Minimal>, blobs: usize) -> Self {
        Self {
            config: schedule(),
            state: State::new(genesis),
            pool: OperationPool::default(),
            blobs,
            payload_hash: TERMINAL,
            voters: (0, 0),
            builder: false,
        }
    }

    /// Root of the latest block, whose header waits for its state root until the next slot.
    fn head_root(&self) -> Root {
        let mut header = self.state.beacon().latest_block_header().clone();
        if header.state_root == Root::ZERO {
            header.state_root = self.state.hash_tree_root();
        }
        header.hash_tree_root()
    }

    /// The state at a slot, without a block.
    fn advanced(&self, slot: Slot) -> State<Minimal> {
        let mut state = self.state.clone();
        state
            .process_slots(&self.config, slot)
            .expect("the chain advances through empty slots");
        state
    }

    /// Every sync committee seat signs the head, as the committee of the next slot.
    fn sign_sync(&mut self, slot: Slot) {
        let advanced = self.advanced(slot);
        if advanced.fork_name() == ForkName::Phase0 {
            return;
        }
        let voted = Slot(slot.0 - 1);
        let root = self.head_root();
        let domain = advanced
            .beacon()
            .domain(DOMAIN_SYNC_COMMITTEE, voted.epoch::<Minimal>());
        let signing_root = SigningData::signing_root(&root, domain);
        let members: BTreeSet<ValidatorIndex> = (0..advanced.beacon().validators().len())
            .map(ValidatorIndex::from)
            .collect();
        for validator in members {
            let Some(seats) = sync_seats(&advanced, validator) else {
                continue;
            };
            let message = SyncCommitteeMessage {
                slot: voted,
                beacon_block_root: root,
                validator_index: validator,
                signature: sign(validator, signing_root),
            };
            self.pool
                .sync_mut()
                .insert_message(&message, &seats)
                .expect("a seat message joins the pool");
        }
    }

    /// Every member of every committee of the head's slot votes for the head, one by one.
    ///
    /// # Returns
    ///
    /// The voters and their committees, fewer once a slashed validator has exited.
    fn attest(&mut self) -> (usize, usize) {
        let slot = self.state.beacon().slot();
        let head = self.head_root();
        let epoch = slot.epoch::<Minimal>();
        let beacon = self.state.beacon();
        let source = beacon.current_justified_checkpoint();
        // The target is the head itself when the head opens the epoch.
        let target_root = if slot == epoch.start_slot::<Minimal>() {
            head
        } else {
            beacon
                .block_root(epoch)
                .expect("the epoch start is in the state history")
        };
        let domain = beacon.domain(DOMAIN_BEACON_ATTESTER, epoch);
        let electra_style = self.state.fork_name() >= ForkName::Electra;
        let committees = self
            .state
            .committees(epoch)
            .expect("the head epoch committees are cached");
        let mut voters = 0;
        for index in 0..committees.committees_per_slot() {
            let committee_index = CommitteeIndex(index);
            let members = committees
                .committee(slot, committee_index)
                .expect("every committee of the slot exists")
                .to_vec();
            let data = AttestationData {
                slot,
                // From Electra the data names no committee; in Gloas zero signals the slot's block.
                index: if electra_style {
                    CommitteeIndex(0)
                } else {
                    committee_index
                },
                beacon_block_root: head,
                source,
                target: Checkpoint {
                    epoch,
                    root: target_root,
                },
            };
            let signing_root = SigningData::signing_root(&data, domain);
            for (seat, member) in members.iter().enumerate() {
                let single = electra::SingleAttestation {
                    committee_index,
                    attester_index: *member,
                    data: data.clone(),
                    signature: sign(*member, signing_root),
                };
                let vote = CommitteeAggregate::single(&single, &members)
                    .expect("the attester sits in its committee");
                assert_eq!(vote.aggregate.bits.ones().collect::<Vec<_>>(), [seat]);
                self.pool
                    .attestations_mut()
                    .insert(vote)
                    .expect("a fresh vote joins the pool");
                voters += 1;
            }
        }
        (voters, committees.committees_per_slot() as usize)
    }

    /// The payload the stand-in engine builds for a slot, as the producer asks for it.
    fn execution(
        &self,
        producer: &BlockProducer<'_, Minimal>,
        slot: Slot,
    ) -> (
        ExecutionChoice<Minimal>,
        Option<combined::ExecutionPayload<Minimal>>,
    ) {
        let fork = self.config.fork_at(slot.epoch::<Minimal>());
        if fork < ForkName::Bellatrix {
            return (ExecutionChoice::PreMerge, None);
        }
        let parent = if fork == ForkName::Gloas {
            ParentPayload::Full(RevealedRequests::Gloas(gloas::ExecutionRequests::default()))
        } else {
            ParentPayload::Empty
        };
        let request = producer
            .payload_request(&self.state, slot, &parent)
            .expect("the payload request is computable");
        let build = LocalBuild {
            payload: self.payload(fork, &request),
            value: U256::from_u64(1_000),
        };
        if fork == ForkName::Gloas {
            let choice = ExecutionChoice::Gloas {
                parent,
                bid: GloasBid::SelfBuild(Box::new(build)),
            };
            return (choice, None);
        }
        if !self.builder {
            return (ExecutionChoice::Local(build), None);
        }
        let (bid, payload) = builder_bid(build);
        (ExecutionChoice::Builder(bid), Some(payload))
    }

    /// The stand-in engine's payload of a fork, on the latest payload.
    fn payload(&self, fork: ForkName, request: &PayloadRequest) -> LocalPayload<Minimal> {
        let slot = request.slot;
        let parent_hash = self.payload_hash;
        let block_hash = Hash32(Root::sha256(&slot.0.to_le_bytes()).0);
        let blobs = self.blobs;
        let commitments = vec![KzgCommitment(infinity_point()); blobs];
        let blob_list = vec![Blob::<Minimal>::default(); blobs];
        match fork {
            ForkName::Bellatrix => LocalPayload::Bellatrix(bellatrix::ExecutionPayload {
                parent_hash,
                prev_randao: request.prev_randao,
                block_number: slot.0,
                gas_limit: GAS_LIMIT,
                timestamp: request.timestamp,
                block_hash,
                transactions: transactions(slot),
                ..bellatrix::ExecutionPayload::default()
            }),
            ForkName::Capella => LocalPayload::Capella(capella::ExecutionPayload {
                parent_hash,
                prev_randao: request.prev_randao,
                block_number: slot.0,
                gas_limit: GAS_LIMIT,
                timestamp: request.timestamp,
                block_hash,
                transactions: transactions(slot),
                withdrawals: List::try_from(request.withdrawals.clone())
                    .expect("the list fits its bound"),
                ..capella::ExecutionPayload::default()
            }),
            ForkName::Gloas => LocalPayload::Gloas {
                payload: gloas::ExecutionPayload {
                    parent_hash,
                    prev_randao: request.prev_randao,
                    block_number: slot.0,
                    gas_limit: GAS_LIMIT,
                    timestamp: request.timestamp,
                    block_hash,
                    withdrawals: ProgressiveList::from(request.withdrawals.clone()),
                    slot_number: slot.0,
                    ..gloas::ExecutionPayload::default()
                },
                blobs: fulu_bundle(&commitments, &blob_list),
                requests: gloas::ExecutionRequests::default(),
            },
            fork => {
                let payload = deneb::ExecutionPayload {
                    parent_hash,
                    prev_randao: request.prev_randao,
                    block_number: slot.0,
                    gas_limit: GAS_LIMIT,
                    timestamp: request.timestamp,
                    block_hash,
                    transactions: transactions(slot),
                    withdrawals: List::try_from(request.withdrawals.clone())
                        .expect("the list fits its bound"),
                    ..deneb::ExecutionPayload::default()
                };
                let deneb_blobs = deneb::BlobsBundle {
                    commitments: List::try_from(commitments.clone())
                        .expect("the list fits its bound"),
                    proofs: List::try_from(vec![KzgProof(infinity_point()); blobs])
                        .expect("the list fits its bound"),
                    blobs: List::try_from(blob_list.clone()).expect("the list fits its bound"),
                };
                match fork {
                    ForkName::Deneb => LocalPayload::Deneb {
                        payload,
                        blobs: deneb_blobs,
                    },
                    ForkName::Electra => LocalPayload::Electra {
                        payload,
                        blobs: deneb_blobs,
                        requests: electra::ExecutionRequests::default(),
                    },
                    _ => LocalPayload::Fulu {
                        payload,
                        blobs: fulu_bundle(&commitments, &blob_list),
                        requests: electra::ExecutionRequests::default(),
                    },
                }
            }
        }
    }

    /// Produces, signs, and applies the block of a slot, checking every signature.
    fn propose(&mut self, slot: Slot) -> Option<Produced> {
        self.sign_sync(slot);
        let advanced = self.advanced(slot);
        let proposer = advanced
            .beacon_proposer_index()
            .expect("the slot has a proposer");
        // A slashed proposer cannot propose, so its slot stays empty.
        if advanced.beacon().validators()[proposer.as_usize()].slashed {
            return None;
        }
        let epoch = slot.epoch::<Minimal>();
        let reveal_root =
            SigningData::signing_root(&epoch, advanced.beacon().domain(DOMAIN_RANDAO, epoch));
        let producer = BlockProducer::new(&self.config, &self.pool);
        let request = ProposalRequest {
            slot,
            randao_reveal: sign(proposer, reveal_root),
            randao: RandaoCheck::Verify,
            graffiti: Bytes32([0x61; 32]),
            eth1_chain: Vec::new(),
            deposits: Vec::new(),
            execution: ExecutionChoice::PreMerge,
        };
        let (execution, revealed) = self.execution(&producer, slot);
        let request = ProposalRequest {
            execution,
            ..request
        };
        let proposal = producer
            .produce(&self.state, request)
            .expect("the producer builds the block");
        let produced = proposal.block;
        let fork = produced.fork_name();
        assert_eq!(produced.slot(), slot);
        assert_eq!(produced.is_blinded(), revealed.is_some());

        let signed = self.sign_and_apply(&advanced, proposer, &produced, revealed);
        let block = signed.message();
        let sidecars = Self::sidecars(&produced, &signed);
        let hashes = block.execution_hashes();
        if hashes.block_hash != Hash32::ZERO {
            self.payload_hash = hashes.block_hash;
        }
        // Votes on this block wait in the pool for the next one.
        self.pool.on_slot(slot);
        let voters = self.attest();
        let previous_voters = mem::replace(&mut self.voters, voters);

        let committees: Vec<usize> = block
            .committee_votes()
            .iter()
            .map(|vote| vote.committees.len())
            .collect();
        let attesters = block
            .committee_votes()
            .iter()
            .map(|vote| vote.bits.iter().filter(|bit| **bit).count())
            .sum();
        Some(Produced {
            fork,
            committees,
            attesters,
            parent_voters: previous_voters,
            sync_signers: signed
                .sync_aggregate()
                .map(|aggregate| aggregate.sync_committee_bits.count_ones()),
            attester_slashings: block.conflicting_votes().len(),
            sidecars,
            blinded: produced.is_blinded(),
        })
    }

    /// Signs a produced block as its proposer, then applies it with every signature checked.
    ///
    /// A blinded block is signed first, then unblinded with the payload its builder reveals.
    fn sign_and_apply(
        &mut self,
        advanced: &State<Minimal>,
        proposer: ValidatorIndex,
        produced: &ProducedBlock<Minimal>,
        revealed: Option<combined::ExecutionPayload<Minimal>>,
    ) -> combined::SignedBeaconBlock<Minimal> {
        let epoch = produced.slot().epoch::<Minimal>();
        // The validator signs the block root in the proposer domain, blinded or not.
        let domain = advanced.beacon().domain(DOMAIN_BEACON_PROPOSER, epoch);
        let signing_root = SigningData {
            object_root: produced.block_root(),
            domain,
        }
        .hash_tree_root();
        let signature = sign(proposer, signing_root);
        let signed = match (produced, revealed) {
            // The builder reveals the payload; the full block keeps the signed root.
            (ProducedBlock::Blinded(blinded), Some(payload)) => {
                let signed =
                    combined::SignedBlindedBeaconBlock::from_parts(blinded.clone(), signature);
                let full = signed
                    .unblind(payload)
                    .expect("the revealed payload matches the header");
                assert_eq!(full.block_root(), produced.block_root());
                full
            }
            _ => combined::SignedBeaconBlock::from_parts(
                produced.block().expect("a full block"),
                signature,
            ),
        };
        let block = signed.message();
        assert_eq!(block.proposer_index(), proposer);
        self.state
            .state_transition(
                &self.config,
                &signed,
                Verification::Verify,
                &KnownVerdict(true),
            )
            .expect("the produced block is valid with every signature");
        if let ProducedBlock::GloasContents(contents) = produced {
            let domain = advanced.beacon().domain(DOMAIN_BEACON_BUILDER, epoch);
            let envelope = gloas::SignedExecutionPayloadEnvelope {
                signature: sign(
                    proposer,
                    SigningData::signing_root(&contents.execution_payload_envelope, domain),
                ),
                message: contents.execution_payload_envelope.clone(),
            };
            self.state
                .verify_execution_payload_envelope(
                    &self.config,
                    &envelope,
                    Verification::Verify,
                    &KnownVerdict(true),
                )
                .expect("the envelope is valid with every signature");
        }
        signed
    }

    /// The blob sidecars or columns a published block's blobs make, proofs checked.
    fn sidecars(
        produced: &ProducedBlock<Minimal>,
        signed: &combined::SignedBeaconBlock<Minimal>,
    ) -> usize {
        let kzg = Kzg::mainnet();
        match (produced, signed) {
            (ProducedBlock::Deneb(contents), combined::SignedBeaconBlock::Deneb(block)) => {
                BlockBlobs::deneb(block)
                    .sidecars(&contents.blobs, &contents.kzg_proofs, kzg)
                    .expect("the zero blob proofs verify")
                    .len()
            }
            (ProducedBlock::Electra(contents), combined::SignedBeaconBlock::Electra(block)) => {
                BlockBlobs::electra(block)
                    .sidecars(&contents.blobs, &contents.kzg_proofs, kzg)
                    .expect("the zero blob proofs verify")
                    .len()
            }
            (ProducedBlock::Fulu(contents), combined::SignedBeaconBlock::Fulu(block)) => {
                BlockColumns::new(block)
                    .sidecars(&contents.blobs, &contents.kzg_proofs, kzg)
                    .expect("the zero blob proofs verify")
                    .len()
            }
            _ => 0,
        }
    }
}

/// The seats a validator holds in the sync committee of a state.
fn sync_seats(state: &State<Minimal>, validator: ValidatorIndex) -> Option<Vec<usize>> {
    match state.beacon() {
        combined::BeaconState::Phase0(_) => None,
        combined::BeaconState::Altair(beacon) => SyncPool::<Minimal>::seats(beacon, validator).ok(),
        combined::BeaconState::Bellatrix(beacon) => {
            SyncPool::<Minimal>::seats(beacon, validator).ok()
        }
        combined::BeaconState::Capella(beacon) => {
            SyncPool::<Minimal>::seats(beacon, validator).ok()
        }
        combined::BeaconState::Deneb(beacon) => SyncPool::<Minimal>::seats(beacon, validator).ok(),
        combined::BeaconState::Electra(beacon) => {
            SyncPool::<Minimal>::seats(beacon, validator).ok()
        }
        combined::BeaconState::Fulu(beacon) => SyncPool::<Minimal>::seats(beacon, validator).ok(),
        combined::BeaconState::Gloas(beacon) => SyncPool::<Minimal>::seats(beacon, validator).ok(),
        combined::BeaconState::Hstar(beacon) => SyncPool::<Minimal>::seats(beacon, validator).ok(),
    }
}

/// A Fulu blobs bundle of zero blobs, with every cell proof at infinity.
fn fulu_bundle(
    commitments: &[KzgCommitment],
    blobs: &[Blob<Minimal>],
) -> fulu::BlobsBundle<Minimal> {
    let cells = Minimal::CELLS_PER_EXT_BLOB as usize;
    fulu::BlobsBundle {
        commitments: List::try_from(commitments.to_vec()).expect("the list fits its bound"),
        proofs: List::try_from(vec![KzgProof(infinity_point()); blobs.len() * cells])
            .expect("the list fits its bound"),
        blobs: List::try_from(blobs.to_vec()).expect("the list fits its bound"),
    }
}

/// A proposer slashing of a validator: two headers it signed for one slot.
fn double_proposal(state: &State<Minimal>, proposer: ValidatorIndex) -> ProposerSlashing {
    let header = |root: u8| {
        let message = BeaconBlockHeader {
            slot: Slot(1),
            proposer_index: proposer,
            body_root: Root([root; 32]),
            ..BeaconBlockHeader::default()
        };
        let domain = state.beacon().domain(DOMAIN_BEACON_PROPOSER, Epoch(0));
        SignedBeaconBlockHeader {
            signature: sign(proposer, SigningData::signing_root(&message, domain)),
            message,
        }
    };
    ProposerSlashing {
        signed_header_1: header(1),
        signed_header_2: header(2),
    }
}

/// Two votes of some validators for two targets of one epoch, each signed by all of them.
fn double_vote(state: &State<Minimal>, validators: &[ValidatorIndex]) -> ConflictingVotes {
    let epoch = state.beacon().current_epoch();
    let vote = |root: u8| {
        let data = AttestationData {
            slot: epoch.start_slot::<Minimal>(),
            target: Checkpoint {
                epoch,
                root: Root([root; 32]),
            },
            ..AttestationData::default()
        };
        let domain = state.beacon().domain(DOMAIN_BEACON_ATTESTER, epoch);
        let signing_root = SigningData::signing_root(&data, domain);
        let signatures: Vec<BlsSignature> = validators
            .iter()
            .map(|validator| sign(*validator, signing_root))
            .collect();
        IndexedVote {
            indices: validators.to_vec(),
            data,
            signature: Aggregate::sum(&signatures).expect("signatures are points"),
        }
    };
    ConflictingVotes {
        first: vote(1),
        second: vote(2),
    }
}

#[test]
fn produced_blocks_of_every_fork_pass_the_transition_with_every_signature_checked() {
    let Some(genesis) = pyspec_genesis() else {
        return;
    };
    // Fixture state: 64 validators; minimal epochs of 8 slots have 2 committees of 4 per slot.
    // Every block from Deneb on carries one zero blob, whose commitment and proofs are at infinity.
    let mut chain = Chain::new(genesis, 1);
    let mut produced = Vec::new();
    for slot in 1..=BLOCKS {
        // Mutation: validator 9 signs two blocks for slot 1, evidence the slot 50 block carries.
        if slot == 50 {
            let slashing = double_proposal(&chain.state, ValidatorIndex(9));
            let state = chain.state.beacon();
            chain
                .pool
                .slashings_mut()
                .insert_proposer(state, slashing)
                .unwrap();
        }
        // Mutation: validators 20 and 21 vote twice in epoch 5, under Electra.
        if slot == 43 {
            let votes = double_vote(&chain.state, &[ValidatorIndex(20), ValidatorIndex(21)]);
            let state = chain.state.beacon();
            chain
                .pool
                .slashings_mut()
                .insert_attester(state, votes)
                .unwrap();
        }
        produced.extend(chain.propose(Slot(slot)).map(|block| (slot, block)));
    }

    // The three slashed validators are slashed in the final state.
    let validators = chain.state.beacon().validators();
    for index in [9, 20, 21] {
        assert!(validators[index].slashed, "validator {index}");
    }
    // Some slots of slashed proposers stayed empty; every other slot has its block.
    assert!(produced.len() >= 65);
    for (slot, block) in &produced {
        let slot = *slot;
        let fork = ForkName::ALL[(slot / 8).min(7) as usize];
        assert_eq!(block.fork, fork, "slot {slot}");
        // From slot 2 on, every vote for the slot before is in, when that slot had a block.
        if slot >= 2 && produced.iter().any(|(earlier, _)| *earlier == slot - 1) {
            // Phase0 names one committee per attestation; Electra joins both in one.
            // Slot 40 opens Electra: of Deneb's slot 39 votes, only committee 0's data has index 0.
            let (attesters, committees) = match slot {
                40 => (4, vec![1]),
                _ if fork >= ForkName::Electra => {
                    (block.parent_voters.0, vec![block.parent_voters.1])
                }
                _ => (block.parent_voters.0, vec![1; block.parent_voters.1]),
            };
            assert_eq!(block.attesters, attesters, "slot {slot}");
            assert_eq!(block.committees, committees, "slot {slot}");
        }
        // Every block from Altair on carries all 32 sync committee signatures.
        let signers = if fork == ForkName::Phase0 {
            None
        } else {
            Some(32)
        };
        assert_eq!(block.sync_signers, signers, "slot {slot}");
        // Deneb and Electra make one blob sidecar, Fulu all 128 columns, others none.
        let sidecars = match fork {
            ForkName::Deneb | ForkName::Electra => 1,
            ForkName::Fulu => 128,
            _ => 0,
        };
        assert_eq!(block.sidecars, sidecars, "slot {slot}");
    }
    // Electra's on-chain aggregation joined both committees of a slot in one attestation.
    let joined = produced
        .iter()
        .filter(|(_, block)| block.fork >= ForkName::Electra && block.committees == [2])
        .count();
    assert!(
        joined >= 30,
        "{joined} Electra blocks joined two committees"
    );
    // The attester slashing went in exactly once.
    let attester_slashings: usize = produced
        .iter()
        .map(|(_, block)| block.attester_slashings)
        .sum();
    assert_eq!(attester_slashings, 1);

    // Full participation through the pools justifies and finalizes as fast as the protocol allows.
    // At slot 72, the start of epoch 9, epoch 8 is justified and epoch 7 finalized.
    let state = chain.state.beacon();
    assert_eq!(state.current_justified_checkpoint().epoch, Epoch(8));
    assert_eq!(state.finalized_checkpoint().epoch, Epoch(7));
}

/// A builder's bid on a payload, unsigned, and the payload it reveals.
fn builder_bid(
    build: LocalBuild<Minimal>,
) -> (
    combined::SignedBuilderBid<Minimal>,
    combined::ExecutionPayload<Minimal>,
) {
    let value = build.value;
    let pubkey = BlsPubkey::default();
    let signature = BlsSignature::default();
    match build.payload {
        LocalPayload::Bellatrix(payload) => {
            let message = bellatrix::BuilderBid {
                header: (&payload).into(),
                value,
                pubkey,
            };
            (
                combined::SignedBuilderBid::Bellatrix(bellatrix::SignedBuilderBid {
                    message,
                    signature,
                }),
                combined::ExecutionPayload::Bellatrix(payload),
            )
        }
        LocalPayload::Capella(payload) => {
            let message = capella::BuilderBid {
                header: (&payload).into(),
                value,
                pubkey,
            };
            (
                combined::SignedBuilderBid::Capella(capella::SignedBuilderBid {
                    message,
                    signature,
                }),
                combined::ExecutionPayload::Capella(payload),
            )
        }
        LocalPayload::Deneb { payload, blobs } => {
            let message = deneb::BuilderBid {
                header: (&payload).into(),
                blob_kzg_commitments: blobs.commitments,
                value,
                pubkey,
            };
            (
                combined::SignedBuilderBid::Deneb(deneb::SignedBuilderBid { message, signature }),
                combined::ExecutionPayload::Deneb(payload),
            )
        }
        LocalPayload::Electra {
            payload,
            blobs,
            requests,
        } => {
            let message = electra::BuilderBid {
                header: (&payload).into(),
                blob_kzg_commitments: blobs.commitments,
                execution_requests: requests,
                value,
                pubkey,
            };
            (
                combined::SignedBuilderBid::Electra(electra::SignedBuilderBid {
                    message,
                    signature,
                }),
                combined::ExecutionPayload::Electra(payload),
            )
        }
        LocalPayload::Fulu {
            payload,
            blobs,
            requests,
        } => {
            let message = electra::BuilderBid {
                header: (&payload).into(),
                blob_kzg_commitments: blobs.commitments,
                execution_requests: requests,
                value,
                pubkey,
            };
            (
                combined::SignedBuilderBid::Fulu(electra::SignedBuilderBid { message, signature }),
                combined::ExecutionPayload::Fulu(payload),
            )
        }
        LocalPayload::Gloas { .. } | LocalPayload::Hstar { .. } => {
            unreachable!("bids from Gloas on come through the protocol")
        }
    }
}

#[test]
fn blinded_blocks_on_builder_payloads_unblind_into_valid_blocks() {
    let Some(genesis) = pyspec_genesis() else {
        return;
    };
    // Fixture state: the same chain, with every payload from Bellatrix to Fulu from a builder.
    // A blinded block carries no blob, so the blocks carry none.
    let mut chain = Chain::new(genesis, 0);
    chain.builder = true;
    let mut blinded = Vec::new();
    for slot in 1_u64..56 {
        let block = chain.propose(Slot(slot)).unwrap();
        blinded.push((block.fork, block.blinded));
    }

    // Slots 16 to 55 are Bellatrix to Fulu, all blinded; each unblinded block passed the transition.
    let expected: Vec<(ForkName, bool)> = (1_u64..56)
        .map(|slot| {
            let fork = ForkName::ALL[(slot / 8) as usize];
            (fork, slot >= 16)
        })
        .collect();
    assert_eq!(blinded, expected);
}

/// One stand-in transaction naming the slot, so payloads differ from their empty stand-ins.
fn transactions(slot: Slot) -> bellatrix::Transactions<Minimal> {
    let transaction =
        ByteList::try_from(slot.0.to_le_bytes().to_vec()).expect("eight bytes fit a transaction");
    List::try_from(vec![transaction]).expect("the list fits its bound")
}
