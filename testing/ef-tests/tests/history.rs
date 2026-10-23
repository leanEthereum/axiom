//! The chain's history across every fork: archive replay, backfill, and resumed backfill.
//!
//! The chains come from the builder at the pyspec genesis: 64 validators, minimal preset.

use std::{
    env, fs,
    net::{SocketAddr, TcpListener},
    ops::RangeInclusive,
    path::{Path, PathBuf},
    process,
    sync::Arc,
    time::Duration,
};

use axiom_ef_tests::{
    Case, Vectors,
    chain_builder::{ChainBuilder, PYSPEC_GENESIS, Participation, Proposal},
};
use axiom_execution::{CAPABILITIES, JwtSecret, mock::MockEngine};
use axiom_fork_choice::PayloadStatus;
use axiom_http::{Client, ClientConfig, Endpoint, Method, Request, Response, StatusCode};
use axiom_json::{Data, Json};
use axiom_node::{
    AnchorSource, Chain, ChainDatabase, ChainError, CheckpointServer, EngineConfig, HistorySegment,
    HistorySettings, HistoryStart, ManualClock, NetworkSettings, Node, NodeConfig, NodeError,
    PortMappingSettings, Reconstruction, SegmentContext, SegmentError, SnapshotInterval,
    StorageMode, WeakSubjectivity, WeakSubjectivityError,
};
use axiom_p2p::Multiaddr;
use axiom_ssz::{Ssz, U256};
use axiom_state_transition::State;
use axiom_types::{
    BlsSignature, ChainConfig, Epoch, ForkName, Hash32, Minimal, Root, Slot, accessors::CoreState,
    bellatrix::PowBlock, combined, deneb, electra, fulu, phase0::Checkpoint,
};
use tokio::{
    runtime::Builder,
    sync::oneshot,
    task::{self, JoinHandle},
    time,
};

/// The terminal total difficulty of the multi-fork chain.
const TERMINAL_TOTAL_DIFFICULTY: u64 = 1000;

/// The parent of the terminal proof-of-work block, the stand-in hash the builder uses.
const TERMINAL_PARENT: Hash32 = Hash32([0x7d; 32]);

/// A scratch directory, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let path = env::temp_dir().join(format!("axiom-history-{name}-{}", process::id()));
        let _fresh = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("temporary directory is writable");
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.0);
    }
}

/// Altair at epoch 1, then one fork per epoch, Gloas at epoch 7.
fn every_fork() -> ChainConfig {
    let mut config = ChainConfig {
        terminal_total_difficulty: U256::from_u64(TERMINAL_TOTAL_DIFFICULTY),
        ..ChainConfig::minimal()
    };
    for (epoch, fork) in (1..).zip(ForkName::ALL.into_iter().skip(1)) {
        config = config.with_fork_epoch(fork, Epoch(epoch));
    }
    config
}

/// A builder at the pyspec genesis where every validator votes.
fn builder(vectors: &Vectors) -> ChainBuilder<Minimal> {
    let config = every_fork();
    let genesis_case = Case::new(vectors.consensus().join(PYSPEC_GENESIS));
    let bytes = genesis_case
        .ssz_bytes("state")
        .expect("case has a genesis state");
    let genesis = combined::BeaconState::<Minimal>::decode_at(&bytes, &config)
        .expect("genesis decodes as phase0");
    ChainBuilder::new(config, genesis)
        .expect("pyspec genesis")
        .with_participation(Participation::Full)
}

/// A built chain: the proposals and the state at every slot, empty slots included.
struct BuiltChain {
    /// The proposals, in slot order.
    proposals: Vec<Proposal<Minimal>>,
    /// The state at each slot, from genesis to the last proposal.
    states: Vec<State<Minimal>>,
    /// The root of the genesis block, which the state implies.
    genesis_root: Root,
}

impl BuiltChain {
    /// Proposes up to a slot, leaving some slots empty.
    fn build(builder: &mut ChainBuilder<Minimal>, last: u64, empty: &[u64]) -> Self {
        let config = builder.config().clone();
        let mut states = vec![builder.state().clone()];
        let mut proposals = Vec::new();
        for slot in 1..=last {
            if empty.contains(&slot) {
                let mut state = states.last().expect("genesis").clone();
                state
                    .process_slots(&config, Slot(slot))
                    .expect("empty slot runs");
                states.push(state);
                continue;
            }
            proposals.push(
                builder
                    .propose_at(Slot(slot))
                    .expect("each block extends the chain"),
            );
            states.push(builder.state().clone());
        }
        let genesis_root = combined::BeaconBlock::genesis(builder.genesis()).hash_tree_root();
        Self {
            proposals,
            states,
            genesis_root,
        }
    }

    /// The root of the canonical block at a slot, the genesis block at slot 0.
    fn root_at(&self, slot: u64) -> Root {
        if slot == 0 {
            self.genesis_root
        } else {
            self.block_at(slot).block_root()
        }
    }

    /// The block proposed at a slot.
    fn block_at(&self, slot: u64) -> &combined::SignedBeaconBlock<Minimal> {
        self.proposals
            .iter()
            .map(Proposal::block)
            .find(|block| block.slot() == Slot(slot))
            .expect("a block at the slot")
    }
}

/// Milliseconds at the start of a slot.
fn slot_start_ms(genesis: &combined::BeaconState<Minimal>, slot: u64) -> u64 {
    (genesis.genesis_time() + 6 * slot) * 1000
}

/// Feeds a built chain to a chain, slot by slot, every payload valid.
fn import(
    chain: &mut Chain<Minimal>,
    built: &BuiltChain,
    genesis: &combined::BeaconState<Minimal>,
) {
    for proposal in &built.proposals {
        let block = proposal.block();
        chain
            .on_tick(slot_start_ms(genesis, block.slot().0))
            .expect("tick");
        chain
            .submit_block(Arc::new(block.clone()), PayloadStatus::Valid)
            .expect("block imports");
        if let Some(envelope) = proposal.envelope() {
            chain
                .submit_envelope(Arc::new(envelope.clone()), PayloadStatus::Valid)
                .expect("envelope imports");
        }
    }
}

/// Tells a chain of the terminal proof-of-work block at 1000 and its parent at 999.
fn known_pow_chain(chain: &mut Chain<Minimal>, terminal: Hash32) {
    chain.on_pow_block(PowBlock {
        block_hash: terminal,
        parent_hash: TERMINAL_PARENT,
        total_difficulty: U256::from_u64(TERMINAL_TOTAL_DIFFICULTY),
    });
    chain.on_pow_block(PowBlock {
        block_hash: TERMINAL_PARENT,
        parent_hash: Hash32::ZERO,
        total_difficulty: U256::from_u64(TERMINAL_TOTAL_DIFFICULTY - 1),
    });
}

#[test]
fn an_archive_rebuilds_the_state_at_every_slot_through_every_fork() {
    let Some(vectors) = Vectors::locate() else {
        return;
    };
    // Fixture state: 72 slots, phase0 at 0 through Gloas at 7, with slots 20 and 43 empty.
    // Every validator votes, so slot 72 finalizes epoch 7, the Gloas block at slot 56.
    let mut builder = builder(&vectors);
    let config = builder.config().clone();
    let genesis = builder.genesis().clone();
    let terminal = builder.terminal_block_hash();
    let built = BuiltChain::build(&mut builder, 72, &[20, 43]);
    let scratch = Scratch::new("archive");
    let interval = SnapshotInterval::new(8).expect("eight slots");

    // An archive snapshots every 8 slots; a pruned database keeps the finalized anchor only.
    let archive = ChainDatabase::open(&scratch.0, config.clone())
        .unwrap()
        .with_mode(StorageMode::Archive(interval));
    let mut chain = Chain::from_genesis(config.clone(), genesis.clone(), archive).unwrap();
    known_pow_chain(&mut chain, terminal);
    import(&mut chain, &built, &genesis);
    let pruned = ChainDatabase::in_memory(config.clone()).unwrap();
    let mut pruned = Chain::from_genesis(config.clone(), genesis.clone(), pruned).unwrap();
    known_pow_chain(&mut pruned, terminal);
    import(&mut pruned, &built, &genesis);

    let head = chain.head();
    assert_eq!(head.slot, Slot(72));
    assert_eq!(head.finalized.epoch, Epoch(7));

    // Every slot's state, finalized or not, empty or not, is the state the builder reached.
    for (slot, expected) in (0..).zip(&built.states) {
        let rebuilt = chain
            .state_at_slot(Slot(slot))
            .unwrap()
            .expect("archive has every slot");
        assert_eq!(
            rebuilt.hash_tree_root(),
            expected.hash_tree_root(),
            "slot {slot}"
        );
        // The same state is found by its root.
        let by_root = chain
            .state_by_root(expected.hash_tree_root())
            .unwrap()
            .expect("archive indexes every root");
        assert_eq!(by_root.beacon().slot(), Slot(slot), "slot {slot}");
    }
    // Past the head there is no state yet.
    assert!(chain.state_at_slot(Slot(73)).unwrap().is_none());

    // The pruned chain has no state before its finalized block at 56, and every state after.
    assert!(pruned.state_at_slot(Slot(55)).unwrap().is_none());
    for slot in 56..=72 {
        let state = pruned
            .state_at_slot(Slot(slot))
            .unwrap()
            .expect("held since finality");
        assert_eq!(
            state.hash_tree_root(),
            built.states[slot as usize].hash_tree_root(),
            "slot {slot}"
        );
    }

    // Light client data settled by finality survives a restart.
    let settled: Vec<_> = chain
        .light_client()
        .settled_updates()
        .map(|(period, update)| (period, update.clone()))
        .collect();
    let mut bootstraps: Vec<_> = chain
        .light_client()
        .bootstraps()
        .map(|(root, bootstrap)| (*root, bootstrap.clone()))
        .collect();
    bootstraps.sort_by_key(|(root, _)| *root);
    assert_ne!(settled, []);
    assert_ne!(bootstraps, []);
    drop(chain);

    // A restart resumes at the finalized block, and replay still reaches every finalized slot.
    let archive = ChainDatabase::open(&scratch.0, config.clone())
        .unwrap()
        .with_mode(StorageMode::Archive(interval));
    let mut resumed = Chain::resume(config, archive).unwrap();
    for slot in 0..=56 {
        let rebuilt = resumed
            .state_at_slot(Slot(slot))
            .unwrap()
            .expect("finalized slot");
        assert_eq!(
            rebuilt.hash_tree_root(),
            built.states[slot as usize].hash_tree_root(),
            "slot {slot}"
        );
    }
    let restored: Vec<_> = resumed
        .light_client()
        .settled_updates()
        .map(|(period, update)| (period, update.clone()))
        .collect();
    let mut restored_bootstraps: Vec<_> = resumed
        .light_client()
        .bootstraps()
        .map(|(root, bootstrap)| (*root, bootstrap.clone()))
        .collect();
    restored_bootstraps.sort_by_key(|(root, _)| *root);
    assert_eq!(restored, settled);
    assert_eq!(restored_bootstraps, bootstraps);
}

#[test]
fn a_backfill_segment_must_link_to_the_stored_history_and_be_signed() {
    let Some(vectors) = Vectors::locate() else {
        return;
    };
    // Fixture state: a checkpoint at block 24, the first Capella block, and the blocks below it.
    let mut builder = builder(&vectors);
    let config = builder.config().clone();
    let built = BuiltChain::build(&mut builder, 24, &[]);
    let anchor = built.block_at(24).clone();
    let database = ChainDatabase::in_memory(config.clone()).unwrap();
    let mut chain = Chain::from_anchor(
        config.clone(),
        built.states[24].beacon().clone(),
        &anchor,
        database,
    )
    .unwrap();
    let start = chain.database().history_start().unwrap().expect("anchored");
    assert_eq!(
        start,
        HistoryStart {
            slot: Slot(24),
            parent_root: anchor.parent_root(),
        }
    );
    let segment = |slots: RangeInclusive<u64>, tamper: Option<u64>| {
        let blocks = slots
            .map(|slot| {
                let block = built.block_at(slot).clone();
                if tamper == Some(slot) {
                    let message = block.message();
                    combined::SignedBeaconBlock::from_parts(message, BlsSignature::default())
                } else {
                    block
                }
            })
            .collect();
        HistorySegment::new(blocks, Vec::new(), Vec::new(), Vec::new())
    };
    let verify = |chain: &Chain<Minimal>, segment: HistorySegment<Minimal>, start| {
        let keys = chain.proposer_keys(segment.proposers());
        let context = SegmentContext {
            config: &config,
            genesis_validators_root: chain.genesis_validators_root(),
            keys: &keys,
            sampled: &[],
            retained: true,
        };
        segment.verify(start, &context)
    };

    // Mutation: block 23 is missing, so block 22 is not the parent block 24 names.
    let error = verify(&chain, segment(16..=22, None), start).unwrap_err();
    assert!(
        matches!(error, SegmentError::BrokenLink { slot: Slot(22), .. }),
        "{error}"
    );
    // Mutation: block 20 carries the empty signature, so the batch of signatures fails.
    let error = verify(&chain, segment(16..=23, Some(20)), start).unwrap_err();
    assert!(matches!(error, SegmentError::Signature(_)), "{error}");

    // Blocks 16 to 23 link and verify, and storing them moves the start to block 16.
    let verified = verify(&chain, segment(16..=23, None), start).unwrap();
    let moved = chain.import_history(&verified).unwrap();
    assert_eq!(
        moved,
        HistoryStart {
            slot: Slot(16),
            parent_root: built.block_at(16).parent_root(),
        }
    );
    for slot in 16..=24 {
        assert_eq!(
            chain.canonical_root(Slot(slot)).unwrap(),
            Some(built.block_at(slot).block_root()),
            "slot {slot}"
        );
    }
    // A segment checked against the old start no longer fits.
    let stale = verify(&chain, segment(16..=23, None), start).unwrap();
    assert!(chain.import_history(&stale).is_err());

    // The rest, down to genesis: the genesis block itself carries no signature.
    let mut blocks: Vec<_> = vec![combined::SignedBeaconBlock::from_parts(
        combined::BeaconBlock::genesis(builder.genesis()),
        BlsSignature::default(),
    )];
    blocks.extend((1..=15).map(|slot| built.block_at(slot).clone()));
    let rest = HistorySegment::new(blocks, Vec::new(), Vec::new(), Vec::new());
    let verified = verify(&chain, rest, moved).unwrap();
    let start = chain.import_history(&verified).unwrap();
    assert!(start.reaches_genesis());
    assert_eq!(chain.backfill_target().unwrap(), None);
}

#[test]
fn a_weak_subjectivity_checkpoint_the_anchor_contradicts_is_refused() {
    let Some(vectors) = Vectors::locate() else {
        return;
    };
    // Fixture state: a checkpoint at block 24, whose state lists the block roots of slots 0 to 23.
    let mut builder = builder(&vectors);
    let config = builder.config().clone();
    let built = BuiltChain::build(&mut builder, 24, &[]);
    let anchored = || {
        let database = ChainDatabase::in_memory(config.clone()).unwrap();
        Chain::from_anchor(
            config.clone(),
            built.states[24].beacon().clone(),
            built.block_at(24),
            database,
        )
        .unwrap()
    };
    let trusted = |epoch, root| {
        WeakSubjectivity(Checkpoint {
            epoch: Epoch(epoch),
            root,
        })
    };

    // Block 8 starts epoch 1, and the anchor state proves it.
    assert!(
        anchored()
            .with_weak_subjectivity(trusted(1, built.root_at(8)))
            .is_ok()
    );

    // Mutation: the operator trusts another root at epoch 1.
    let error = anchored()
        .with_weak_subjectivity(trusted(1, Root([9; 32])))
        .unwrap_err();
    let ChainError::WeakSubjectivity(error) = error else {
        panic!("expected a weak subjectivity error, got {error}");
    };
    assert_eq!(
        error,
        WeakSubjectivityError::Conflict {
            epoch: Epoch(1),
            expected: Root([9; 32]),
            actual: built.root_at(8),
        }
    );

    // A checkpoint past the anchor waits for finality to reach it.
    assert!(
        anchored()
            .with_weak_subjectivity(trusted(5, Root([9; 32])))
            .is_ok()
    );
}

/// A node in the test's runtime, with a client for its API.
struct TestNode {
    /// The beacon API client.
    client: Client,
    /// Stops the node.
    stop: oneshot::Sender<()>,
    /// The node's task.
    task: JoinHandle<Result<(), NodeError>>,
}

impl TestNode {
    /// Starts a node whose API listens on an address, with the clock at a time.
    async fn start(now_ms: u64, chain: ChainConfig, config: NodeConfig, api: SocketAddr) -> Self {
        let (stop, stopped) = oneshot::channel::<()>();
        let task = task::spawn(Node::<Minimal>::run(
            chain,
            config,
            Arc::new(ManualClock::at(now_ms)),
            async move {
                let _stopped = stopped.await;
            },
        ));
        let client = Client::new(
            Endpoint::parse(&format!("http://{api}")).expect("a socket address is a valid URL"),
            ClientConfig::default(),
        );
        for _ in 0..500 {
            if client
                .send(&Request::new(Method::Get, "/eth/v1/node/health"))
                .await
                .is_ok()
            {
                break;
            }
            time::sleep(Duration::from_millis(10)).await;
        }
        Self { client, stop, task }
    }

    /// Publishes each block, then its envelope if it has one.
    async fn publish(&self, proposals: &[Proposal<Minimal>]) {
        for proposal in proposals {
            let block = proposal.block();
            let request = Request::new(Method::Post, "/eth/v2/beacon/blocks")
                .with_header("eth-consensus-version", block.fork_name().to_string())
                .with_body("application/octet-stream", Self::contents(block));
            let response = self.client.send(&request).await.expect("node answers");
            assert_eq!(
                response.status,
                StatusCode::OK,
                "slot {}: {}",
                block.slot(),
                text(&response)
            );
            if let Some(envelope) = proposal.envelope() {
                let request =
                    Request::new(Method::Post, "/eth/v1/beacon/execution_payload_envelopes")
                        .with_header("eth-consensus-version", "gloas")
                        .with_header("eth-blob-data-included", "false")
                        .with_body("application/octet-stream", envelope.encode());
                let response = self.client.send(&request).await.expect("node answers");
                assert_eq!(
                    response.status,
                    StatusCode::OK,
                    "envelope: {}",
                    text(&response)
                );
            }
        }
    }

    /// A block as the publish route takes it: its contents from Deneb to Fulu, alone otherwise.
    fn contents(block: &combined::SignedBeaconBlock<Minimal>) -> Vec<u8> {
        match block {
            combined::SignedBeaconBlock::Deneb(signed) => deneb::SignedBlockContents {
                signed_block: signed.clone(),
                ..Default::default()
            }
            .encode(),
            combined::SignedBeaconBlock::Electra(signed) => electra::SignedBlockContents {
                signed_block: signed.clone(),
                ..Default::default()
            }
            .encode(),
            combined::SignedBeaconBlock::Fulu(signed) => fulu::SignedBlockContents {
                signed_block: signed.clone(),
                ..Default::default()
            }
            .encode(),
            other => other.encode(),
        }
    }

    /// The root of the canonical block at a slot, if the node serves one.
    async fn root_at(&self, slot: u64) -> Option<Root> {
        let path = format!("/eth/v1/beacon/blocks/{slot}/root");
        let response = self
            .client
            .send(&Request::new(Method::Get, &path))
            .await
            .ok()?;
        if response.status != StatusCode::OK {
            return None;
        }
        let json = Json::parse(&response.body).ok()?;
        let text = json.get("data")?.get("root")?.as_str()?.to_owned();
        let bytes = <[u8; 32]>::from_data(&text).ok()?;
        Some(Root(bytes))
    }

    /// Waits up to a minute for the genesis block, then checks every block up to the anchor at 48.
    async fn serves_up_to_anchor(&self, built: &BuiltChain) {
        for _ in 0..3000 {
            if self.root_at(0).await.is_some() {
                break;
            }
            time::sleep(Duration::from_millis(20)).await;
        }
        for slot in 0..=48 {
            assert_eq!(
                self.root_at(slot).await,
                Some(built.root_at(slot)),
                "slot {slot}"
            );
        }
    }

    /// Stops the node and checks it shut down cleanly.
    async fn stop(self) {
        self.stop.send(()).expect("node still running");
        self.task
            .await
            .expect("node task completes")
            .expect("node shuts down cleanly");
    }
}

/// A response body as text, for failure messages.
fn text(response: &Response) -> String {
    String::from_utf8_lossy(&response.body).into_owned()
}

/// A free local TCP port, released for the node to bind.
fn free_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("a local port is free")
}

/// A mock engine that calls every payload valid and knows the terminal proof-of-work blocks.
async fn valid_engine(terminal: Hash32, secret_file: &Path) -> (MockEngine, EngineConfig) {
    let secret = JwtSecret::new([0x42; 32]);
    fs::write(secret_file, "42".repeat(32)).expect("temporary directory is writable");
    let mock = MockEngine::start(secret)
        .await
        .expect("a loopback port is free");
    let valid = Json::parse(r#"{"status":"VALID","latestValidHash":null,"validationError":null}"#)
        .expect("valid JSON");
    let updated = Json::from([("payloadStatus", valid.clone()), ("payloadId", Json::Null)]);
    for method in CAPABILITIES {
        if method.starts_with("engine_newPayload") {
            mock.reply(method, valid.clone());
        } else if method.starts_with("engine_forkchoiceUpdated") {
            mock.reply(method, updated.clone());
        }
    }
    mock.reply("eth_getBlockByHash", Json::Null);
    mock.serve_pow_block(&PowBlock {
        block_hash: terminal,
        parent_hash: TERMINAL_PARENT,
        total_difficulty: U256::from_u64(TERMINAL_TOTAL_DIFFICULTY),
    });
    mock.serve_pow_block(&PowBlock {
        block_hash: TERMINAL_PARENT,
        parent_hash: Hash32::ZERO,
        total_difficulty: U256::from_u64(TERMINAL_TOTAL_DIFFICULTY - 1),
    });
    let config = EngineConfig {
        url: mock.url().to_owned(),
        jwt_secret: secret_file.to_path_buf(),
        timeout_multiplier: 1,
    };
    (mock, config)
}

/// A database checkpoint-synced at block 48 and backfilled down to block 41, then closed.
fn interrupt_backfill(directory: &Path, config: &ChainConfig, built: &BuiltChain) {
    let database = ChainDatabase::open(&directory.join("chain"), config.clone())
        .expect("a fresh directory opens");
    let mut chain = Chain::from_anchor(
        config.clone(),
        built.states[48].beacon().clone(),
        built.block_at(48),
        database,
    )
    .expect("block 48 commits to its state");
    let blocks = (41..=47).map(|slot| built.block_at(slot).clone()).collect();
    let segment = HistorySegment::new(blocks, Vec::new(), Vec::new(), Vec::new());
    let keys = chain.proposer_keys(segment.proposers());
    let start = chain
        .database()
        .history_start()
        .expect("the database reads")
        .expect("the anchor starts the history");
    let context = SegmentContext {
        config,
        genesis_validators_root: chain.genesis_validators_root(),
        keys: &keys,
        sampled: &[],
        retained: false,
    };
    let verified = segment
        .verify(start, &context)
        .expect("blocks 41 to 47 link to block 48");
    let start = chain.import_history(&verified).expect("the segment stores");
    assert_eq!(start.slot, Slot(41));
}

#[test]
fn a_checkpoint_synced_node_backfills_to_genesis_and_resumes_after_a_restart() {
    let Some(vectors) = Vectors::locate() else {
        return;
    };
    // Fixture state: 64 slots through every fork, every validator voting.
    // At slot 64 epoch 6 is finalized: the Fulu block at slot 48 is the checkpoint.
    let mut builder = builder(&vectors);
    let config = builder.config().clone();
    let genesis = builder.genesis().clone();
    let terminal = builder.terminal_block_hash();
    let built = BuiltChain::build(&mut builder, 64, &[]);
    let scratch = Scratch::new("backfill");
    let genesis_path = scratch.0.join("genesis.ssz");
    fs::write(&genesis_path, genesis.encode()).unwrap();
    // Timing: the clock stands at slot 65, so every block is in the past.
    let now_ms = slot_start_ms(&genesis, 65);

    // Phase 0: node C's database, checkpoint-synced at block 48 and backfilled down to 41.
    // Then the process stops, as if killed in the middle of backfill.
    let c_directory = scratch.0.join("c");
    interrupt_backfill(&c_directory, &config, &built);

    let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let settings = |listen_address, boot_nodes| NetworkSettings {
            listen_address,
            quic_port: None,
            target_peers: 64,
            port_mapping: PortMappingSettings::default(),
            boot_nodes,
            custody_group_count: 4,
            discovery: None,
            subscribe_all_subnets: false,
            backfill_rate_limiting: false,
        };

        // Node A holds the whole chain from genesis, published over its API.
        let (engine, engine_config) = valid_engine(terminal, &scratch.0.join("jwt.hex")).await;
        let (a_p2p, a_api) = (free_address(), free_address());
        let a = TestNode::start(
            now_ms,
            config.clone(),
            NodeConfig {
                anchor: Some(AnchorSource::Genesis(genesis_path.clone().into())),
                http_address: Some(a_api),
                engine: Some(engine_config),
                network: Some(settings(a_p2p, Vec::new())),
                ..NodeConfig::default()
            },
            a_api,
        )
        .await;
        a.publish(&built.proposals).await;
        let boot: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", a_p2p.port())
            .parse()
            .unwrap();

        // Node B downloads A's finalized checkpoint, then backfills every block to genesis.
        // As an archive with the genesis state, it then rebuilds the states below block 48.
        let b_api = free_address();
        let b = TestNode::start(
            now_ms,
            config.clone(),
            NodeConfig {
                data_dir: Some(scratch.0.join("b")),
                anchor: Some(AnchorSource::Url {
                    url: format!("http://{a_api}"),
                    timeout: CheckpointServer::DEFAULT_TIMEOUT,
                }),
                http_address: Some(b_api),
                network: Some(settings(free_address(), vec![boot.clone()])),
                history: HistorySettings {
                    mode: StorageMode::Archive(SnapshotInterval::new(8).unwrap()),
                    genesis: Some(genesis_path.clone().into()),
                    ..HistorySettings::default()
                },
                ..NodeConfig::default()
            },
            b_api,
        )
        .await;
        // Backfill verifies 48 signatures, so it gets a minute rather than seconds.
        b.serves_up_to_anchor(&built).await;

        // Node C resumes its interrupted backfill from block 41, in the default pruned mode.
        // The serving window of 272 epochs reaches back past genesis, so it too goes all the way.
        let c_api = free_address();
        let c = TestNode::start(
            now_ms,
            config.clone(),
            NodeConfig {
                data_dir: Some(c_directory.clone()),
                http_address: Some(c_api),
                network: Some(settings(free_address(), vec![boot])),
                ..NodeConfig::default()
            },
            c_api,
        )
        .await;
        c.serves_up_to_anchor(&built).await;

        // Rebuilding runs in short steps after backfill; give it a few seconds to finish.
        time::sleep(Duration::from_secs(3)).await;
        b.stop().await;
        c.stop().await;
        a.stop().await;
        engine.stop().await;
    });

    rebuilt_archive_replays(&scratch.0.join("b"), &config, &built);
}

/// Checks a reopened archive: the rebuild reached the anchor, and every state below it replays.
fn rebuilt_archive_replays(directory: &Path, config: &ChainConfig, built: &BuiltChain) {
    let interval = SnapshotInterval::new(8).expect("eight slots");
    let database = ChainDatabase::<Minimal>::open(&directory.join("chain"), config.clone())
        .expect("the stopped node released its database")
        .with_mode(StorageMode::Archive(interval));
    let cursor = database
        .reconstruction()
        .expect("the database reads")
        .expect("a rebuild was due");
    assert_eq!(cursor.reached, cursor.target);
    assert_eq!(cursor.target, Slot(48));
    let mut chain = Chain::resume(config.clone(), database).expect("the archive resumes");
    let step = chain
        .reconstruct_history(8)
        .expect("a finished rebuild steps cleanly");
    assert_eq!(step, Reconstruction::Done);
    for slot in 0..=48 {
        let state = chain
            .state_at_slot(Slot(slot))
            .expect("replay succeeds")
            .expect("archived slot");
        assert_eq!(
            state.hash_tree_root(),
            built.states[slot as usize].hash_tree_root(),
            "slot {slot}"
        );
    }
}
