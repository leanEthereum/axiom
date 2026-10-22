//! Whole nodes, started from a spec genesis state.
//! The tests drive them through the beacon API and the network.

use std::{
    env, fs,
    net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket},
    path::PathBuf,
    process,
    sync::Arc,
    time::Duration,
};

use axiom_discv5::Enr;
use axiom_ef_tests::{
    Case, Vectors,
    chain_builder::{ChainBuilder, PYSPEC_GENESIS, Proposal},
};
use axiom_http::{Client, ClientConfig, Endpoint, Method, Request, Response, StatusCode};
use axiom_json::Json;
use axiom_node::{
    AnchorSource, DiscoverySettings, ManualClock, NetworkSettings, Node, NodeConfig, NodeError,
};
use axiom_p2p::Multiaddr;
use axiom_ssz::Ssz;
use axiom_state_transition::{KnownVerdict, State, Verification};
use axiom_types::{
    ChainConfig, Epoch, ForkName, Minimal,
    accessors::CoreState,
    combined,
    fulu::{BeaconState, SignedBeaconBlock, SignedBlockContents},
};
use tokio::{
    runtime::Builder,
    sync::oneshot,
    task::{self, JoinHandle},
    time,
};

/// The fork choice case whose genesis and two blocks the nodes are fed.
///
/// Block 1 at slot 1 and block 2 at slot 2, with no votes and no blobs.
const CASE: &str = "minimal/fulu/fork_choice/get_head/pyspec_tests/chain_no_attestations";

/// The two blocks of the case, in the order they extend the chain.
const BLOCKS: [&str; 2] = [
    "block_0x74accc6cc86aa84d9b90602053aee7738f063e0fe5855192d08e5a1a6778fe36",
    "block_0x8b932df328b89fd55311a65e4d5bf43288fb22f2e31a59da1bdd5714ac11452e",
];

/// A case with two branches from genesis: a long one and a short, heavier one.
const FORK_CASE: &str =
    "minimal/fulu/fork_choice/get_head/pyspec_tests/shorter_chain_but_heavier_weight";

/// The long branch, slots 1 to 3.
const FORK_LONG: [&str; 3] = [
    "block_0x74accc6cc86aa84d9b90602053aee7738f063e0fe5855192d08e5a1a6778fe36",
    "block_0x8b932df328b89fd55311a65e4d5bf43288fb22f2e31a59da1bdd5714ac11452e",
    "block_0x0b5c1cb7cc0a47d47d3d6fbabbfd71845588478817b6eb8a64f2991bde80b24d",
];

/// The short branch, one block.
const FORK_SHORT: &str = "block_0xd732ef4e56577b5a756d9af8926eb3c9d5efb3f4a0b80436f3215f7d2d3af6fe";

/// The head after both blocks.
const HEAD: &str = "0x8b932df328b89fd55311a65e4d5bf43288fb22f2e31a59da1bdd5714ac11452e";

/// The case, its genesis written as the plain SSZ file a node reads, and the clock at slot 2.
struct Fixture {
    /// The vector case.
    case: Case,
    /// A scratch directory, removed at the end.
    directory: PathBuf,
    /// The genesis file.
    genesis: PathBuf,
    /// Milliseconds at the start of the slot the clock stands at.
    ///
    /// ```text
    ///     slot:   0        1        2
    ///     time:   0 s      6 s      12 s
    /// ```
    ///
    /// The clock stands at slot 2, when both blocks are timely.
    now_ms: u64,
}

impl Fixture {
    /// The main case with the clock at slot 2, or nothing when the vectors are not downloaded.
    fn load(name: &str) -> Option<Self> {
        Self::load_case(name, CASE, 2)
    }

    /// A case with the clock at the start of a slot.
    fn load_case(name: &str, case: &str, slot: u64) -> Option<Self> {
        let case = Case::new(Vectors::locate()?.consensus().join(case));
        let directory = env::temp_dir().join(format!("axiom-{name}-{}", process::id()));
        fs::create_dir_all(&directory).expect("temporary directory is writable");
        let genesis = directory.join("genesis.ssz");
        let bytes = case
            .ssz_bytes("anchor_state")
            .expect("case has an anchor state");
        fs::write(&genesis, &bytes).expect("temporary directory is writable");
        let genesis_time = BeaconState::<Minimal>::decode(&bytes)
            .expect("anchor state decodes")
            .genesis_time;
        Some(Self {
            case,
            directory,
            genesis,
            // Minimal slots last six seconds.
            now_ms: (genesis_time + 6 * slot) * 1000,
        })
    }

    /// A signed block of the case, wrapped as the publish route takes it.
    fn contents(&self, name: &str) -> SignedBlockContents<Minimal> {
        SignedBlockContents {
            signed_block: self
                .case
                .ssz::<SignedBeaconBlock<Minimal>>(name)
                .expect("case has the block"),
            ..SignedBlockContents::default()
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // A leftover temporary directory is harmless.
        let _ignored = fs::remove_dir_all(&self.directory);
    }
}

/// A node running in the test's runtime, with a client for its API.
struct TestNode {
    /// The beacon API client.
    client: Client,
    /// Stops the node.
    stop: oneshot::Sender<()>,
    /// The node's task.
    task: JoinHandle<Result<(), NodeError>>,
}

impl TestNode {
    /// Starts a node from the fixture's genesis, with its API on a free port.
    async fn start(fixture: &Fixture, network: Option<NetworkSettings>) -> Self {
        let address = free_address();
        let config = NodeConfig {
            anchor: Some(AnchorSource::Genesis(fixture.genesis.clone())),
            http_address: Some(address),
            network,
            ..NodeConfig::default()
        };
        Self::start_with(fixture.now_ms, fulu(), config, address).await
    }

    /// Starts a node with a full configuration whose API listens on an address.
    ///
    /// # Arguments
    ///
    /// - `now_ms`: the time the node's clock stands at.
    /// - `chain_config`: the fork schedule the node follows.
    async fn start_with(
        now_ms: u64,
        chain_config: ChainConfig,
        config: NodeConfig,
        address: SocketAddr,
    ) -> Self {
        let (stop, stopped) = oneshot::channel::<()>();
        let task = task::spawn(Node::<Minimal>::run(
            chain_config,
            config,
            Arc::new(ManualClock::at(now_ms)),
            async move {
                let _stopped = stopped.await;
            },
        ));
        let client = Client::new(
            Endpoint::parse(&format!("http://{address}")).expect("a socket address is a valid URL"),
            ClientConfig::default(),
        );

        // Wait for the API to answer.
        for _ in 0..200 {
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

    /// Publishes a block of any fork over the API, in the format the fork's route takes.
    ///
    /// A Fulu block travels in its block contents; every other fork's block travels alone.
    async fn publish_any(&self, block: &combined::SignedBeaconBlock<Minimal>) -> Response {
        let body = match block {
            combined::SignedBeaconBlock::Fulu(signed) => SignedBlockContents {
                signed_block: signed.clone(),
                ..SignedBlockContents::default()
            }
            .encode(),
            other => other.encode(),
        };
        let request = Request::new(Method::Post, "/eth/v2/beacon/blocks")
            .with_header("eth-consensus-version", block.fork_name().to_string())
            .with_body("application/octet-stream", body);
        self.client.send(&request).await.expect("node answers")
    }

    /// Publishes each block, then its envelope if it has one, checking every answer.
    async fn publish_chain(&self, proposals: &[Proposal<Minimal>]) {
        for (slot, proposal) in (1..).zip(proposals) {
            let response = self.publish_any(proposal.block()).await;
            assert_eq!(
                response.status,
                StatusCode::OK,
                "slot {slot}: {}",
                body_text(&response)
            );
            if let Some(response) = self.publish_envelope(proposal).await {
                let message = body_text(&response);
                assert_eq!(
                    response.status,
                    StatusCode::OK,
                    "envelope {slot}: {message}"
                );
            }
        }
    }

    /// Publishes a Gloas payload envelope over the API.
    async fn publish_envelope(&self, proposal: &Proposal<Minimal>) -> Option<Response> {
        let envelope = proposal.envelope()?;
        let request = Request::new(Method::Post, "/eth/v1/beacon/execution_payload_envelope")
            .with_body("application/octet-stream", envelope.encode());
        Some(self.client.send(&request).await.expect("node answers"))
    }

    /// Publishes a block over the API.
    async fn publish(&self, contents: &SignedBlockContents<Minimal>) -> Response {
        let request = Request::new(Method::Post, "/eth/v2/beacon/blocks")
            .with_body("application/octet-stream", contents.encode());
        self.client.send(&request).await.expect("node answers")
    }

    /// A JSON route's parsed body, or why the route did not answer with one.
    async fn json(&self, path: &str) -> Result<Json, String> {
        let response = self
            .client
            .send(&Request::new(Method::Get, path))
            .await
            .map_err(|error| format!("{path}: {error}"))?;
        if response.status != StatusCode::OK {
            return Err(format!(
                "{path}: {}: {}",
                response.status,
                body_text(&response)
            ));
        }
        Json::parse(&response.body).map_err(|error| format!("{path}: {error}"))
    }

    /// The head block's root, as the header route reports it.
    async fn head_root(&self) -> Option<String> {
        let header = self.json("/eth/v1/beacon/headers/head").await.ok()?;
        header.get("data")?.get("root")?.as_str().map(str::to_owned)
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

/// The Fulu chain the fork choice cases run on: every fork up to Fulu at genesis.
fn fulu() -> ChainConfig {
    ChainConfig::minimal().with_forks_at_genesis(ForkName::Fulu)
}

/// A free local TCP port, released for the node to bind.
fn free_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("a local port is free")
}

/// A free local UDP port, released for discovery to bind.
fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .and_then(|socket| socket.local_addr())
        .expect("a local port is free")
        .port()
}

/// Waits until a node reports a head, or gives up after about ten seconds.
async fn wait_for_head(node: &TestNode, expected: &str) -> Option<String> {
    wait_for_head_within(node, expected, 500).await
}

/// Waits until a node reports a head, polling every 20 milliseconds a number of times.
async fn wait_for_head_within(node: &TestNode, expected: &str, attempts: u32) -> Option<String> {
    let mut head = None;
    for _ in 0..attempts {
        head = node.head_root().await;
        if head.as_deref() == Some(expected) {
            break;
        }
        time::sleep(Duration::from_millis(20)).await;
    }
    head
}

/// A response body as text, for failure messages.
fn body_text(response: &Response) -> String {
    String::from_utf8_lossy(&response.body).into_owned()
}

#[test]
fn a_node_imports_published_blocks_and_reports_its_head() {
    let Some(fixture) = Fixture::load("api") else {
        return;
    };
    let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let node = TestNode::start(&fixture, None).await;

        // Two slots behind the clock, the node reports that it is syncing.
        let health = node
            .client
            .send(&Request::new(Method::Get, "/eth/v1/node/health"))
            .await
            .unwrap();
        assert_eq!(health.status, StatusCode::PARTIAL_CONTENT);

        // Publish both blocks, each without blobs.
        for name in BLOCKS {
            let response = node.publish(&fixture.contents(name)).await;
            assert_eq!(response.status, StatusCode::OK, "{}", body_text(&response));
        }

        // The head is the second block, at slot 2, and canonical.
        let header = node.json("/eth/v1/beacon/headers/head").await.unwrap();
        let data = header.get("data").unwrap();
        assert_eq!(data.get("root").and_then(Json::as_str), Some(HEAD));
        assert_eq!(data.get("canonical").and_then(Json::as_bool), Some(true));
        let slot = data
            .get("header")
            .and_then(|header| header.get("message"))
            .and_then(|message| message.get("slot"));
        assert_eq!(slot.and_then(Json::as_str), Some("2"));

        // The node is now in sync.
        let syncing = node.json("/eth/v1/node/syncing").await.unwrap();
        let data = syncing.get("data").unwrap();
        assert_eq!(data.get("head_slot").and_then(Json::as_str), Some("2"));
        assert_eq!(data.get("is_syncing").and_then(Json::as_bool), Some(false));

        // A block by slot is the canonical one; slot 3 is still empty.
        let by_slot = node.json("/eth/v1/beacon/blocks/2/root").await.unwrap();
        let root = by_slot.get("data").and_then(|data| data.get("root"));
        assert_eq!(root.and_then(Json::as_str), Some(HEAD));
        let missing = node
            .client
            .send(&Request::new(Method::Get, "/eth/v1/beacon/blocks/3/root"))
            .await
            .unwrap();
        assert_eq!(missing.status, StatusCode::NOT_FOUND);

        node.stop().await;
    });
}

#[test]
fn a_node_range_syncs_from_a_peer_over_noise() {
    let Some(fixture) = Fixture::load("sync") else {
        return;
    };
    let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        // Fixture state: node A holds both blocks; node B knows only genesis.
        //
        //     A: genesis -> 1 -> 2        B: genesis
        //     B dials A, the status handshake shows A ahead, B fetches slots 1 and 2.
        let a_address = free_address();
        let settings = |listen_address, boot_nodes| NetworkSettings {
            listen_address,
            boot_nodes,
            custody_group_count: 4,
            discovery: None,
        };
        let a = TestNode::start(&fixture, Some(settings(a_address, Vec::new()))).await;
        for name in BLOCKS {
            assert_eq!(
                a.publish(&fixture.contents(name)).await.status,
                StatusCode::OK
            );
        }
        assert_eq!(a.head_root().await.as_deref(), Some(HEAD));

        let boot: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", a_address.port())
            .parse()
            .unwrap();
        let b = TestNode::start(&fixture, Some(settings(free_address(), vec![boot]))).await;

        // Wait for B to reach A's head, over real TCP and Noise.
        let mut head = None;
        for _ in 0..500 {
            head = b.head_root().await;
            if head.as_deref() == Some(HEAD) {
                break;
            }
            time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            head.as_deref(),
            Some(HEAD),
            "node B never synced to node A's head"
        );

        b.stop().await;
        a.stop().await;
    });
}

#[test]
fn a_node_finds_its_peer_through_discovery() {
    let Some(fixture) = Fixture::load("discovery") else {
        return;
    };
    let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        // Fixture state: A announces 127.0.0.1 in its record and holds both blocks.
        // B knows only A's record, not its TCP address.
        //
        // 1. B runs a discv5 lookup and finds A's record.
        // 2. B dials A over TCP.
        // 3. The two nodes exchange status.
        // 4. B range-syncs from A.
        let discovery = |boot_enrs| DiscoverySettings {
            udp_port: free_udp_port(),
            enr_address: Some(Ipv4Addr::LOCALHOST),
            boot_enrs,
        };
        let settings = |boot_enrs| NetworkSettings {
            listen_address: free_address(),
            boot_nodes: Vec::new(),
            custody_group_count: 4,
            discovery: Some(discovery(boot_enrs)),
        };
        let a = TestNode::start(&fixture, Some(settings(Vec::new()))).await;
        for name in BLOCKS {
            assert_eq!(
                a.publish(&fixture.contents(name)).await.status,
                StatusCode::OK
            );
        }

        // A's record, as its identity route reports it.
        let identity = a.json("/eth/v1/node/identity").await.unwrap();
        let enr: Enr = identity
            .get("data")
            .and_then(|data| data.get("enr"))
            .and_then(Json::as_str)
            .expect("a node with discovery has a record")
            .parse()
            .expect("the record parses");

        let b = TestNode::start(&fixture, Some(settings(vec![enr]))).await;
        let head = wait_for_head(&b, HEAD).await;
        assert_eq!(head.as_deref(), Some(HEAD), "node B never found node A");

        b.stop().await;
        a.stop().await;
    });
}

#[test]
fn a_node_starts_from_a_checkpoint_and_builds_on_it() {
    let Some(fixture) = Fixture::load("checkpoint") else {
        return;
    };

    // Fixture state: block 1 and its post-state, a checkpoint in the middle of epoch 0.
    //
    // Block 1 builds on genesis and gives state 1.
    // The checkpoint is block 1 with state 1, at slot 1.
    // Block 2 builds on block 1, and is published after the node starts.
    let genesis =
        BeaconState::<Minimal>::decode(&fixture.case.ssz_bytes("anchor_state").unwrap()).unwrap();
    let anchor = fixture
        .case
        .ssz::<SignedBeaconBlock<Minimal>>(BLOCKS[0])
        .unwrap();
    let mut state = State::new(genesis);
    state
        .state_transition(&fulu(), &anchor, Verification::Verify, &KnownVerdict(true))
        .unwrap();
    let state_path = fixture.directory.join("checkpoint_state.ssz");
    let block_path = fixture.directory.join("checkpoint_block.ssz");
    fs::write(&state_path, state.beacon().encode()).unwrap();
    fs::write(&block_path, anchor.encode()).unwrap();

    let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let address = free_address();
        let config = NodeConfig {
            anchor: Some(AnchorSource::Checkpoint {
                state: state_path,
                block: block_path,
            }),
            http_address: Some(address),
            ..NodeConfig::default()
        };
        let node = TestNode::start_with(fixture.now_ms, fulu(), config, address).await;

        // A child of the mid-epoch anchor imports and becomes the head.
        let response = node.publish(&fixture.contents(BLOCKS[1])).await;
        assert_eq!(response.status, StatusCode::OK, "{}", body_text(&response));
        assert_eq!(node.head_root().await.as_deref(), Some(HEAD));

        // The anchor is served exactly as given, signature included.
        let root = anchor.message.hash_tree_root();
        let request = Request::new(Method::Get, &format!("/eth/v2/beacon/blocks/{root}"))
            .with_header("accept", "application/octet-stream");
        let served = node.client.send(&request).await.unwrap();
        assert_eq!(
            SignedBeaconBlock::<Minimal>::decode(&served.body).unwrap(),
            anchor
        );
        node.stop().await;
    });
}

#[test]
fn a_node_on_a_dead_branch_rewinds_and_syncs_the_peer_chain() {
    let Some(fixture) = Fixture::load_case("fork", FORK_CASE, 3) else {
        return;
    };
    let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        // Fixture state: two branches from genesis; A holds the long one, B only the short one.
        //
        // Each branch lists its blocks by slot, each the parent of the next.
        //
        //     A: genesis, 1 (0x74ac), 2 (0x8b93), 3 (0x0b5c)
        //     B: genesis, 1 (0xd732)
        //
        // B starts first and cannot reach A yet, so it holds its branch before they meet.
        // Then B asks for slots 2 and 3, whose parent it does not know.
        // It must rewind to finality and fetch the whole long branch, without blaming A.
        let a_address = free_address();
        let settings = |listen_address, boot_nodes| NetworkSettings {
            listen_address,
            boot_nodes,
            custody_group_count: 4,
            discovery: None,
        };
        let boot: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", a_address.port()).parse().unwrap();
        let b = TestNode::start(&fixture, Some(settings(free_address(), vec![boot]))).await;
        assert_eq!(b.publish(&fixture.contents(FORK_SHORT)).await.status, StatusCode::OK);

        let a = TestNode::start(&fixture, Some(settings(a_address, Vec::new()))).await;
        for name in FORK_LONG {
            assert_eq!(a.publish(&fixture.contents(name)).await.status, StatusCode::OK);
        }

        // B redials its boot node at its next upkeep, one slot later, and ends up holding A's tip.
        let tip = "/eth/v1/beacon/blocks/0x0b5c1cb7cc0a47d47d3d6fbabbfd71845588478817b6eb8a64f2991bde80b24d/root";
        let mut found = false;
        for _ in 0..1000 {
            if b.json(tip).await.is_ok() {
                found = true;
                break;
            }
            time::sleep(Duration::from_millis(20)).await;
        }
        assert!(found, "node B never fetched the long branch");

        b.stop().await;
        a.stop().await;
    });
}

/// The fork schedule of the multi-fork chain: Altair at epoch 1, then one fork per epoch.
///
/// Gloas starts at epoch 7, the last fork, so the chain ends with payloads in envelopes.
fn every_fork() -> ChainConfig {
    let mut config = ChainConfig::minimal();
    for (epoch, fork) in (1..).zip(ForkName::ALL.into_iter().skip(1)) {
        config = config.with_fork_epoch(fork, Epoch(epoch));
    }
    config
}

/// Slots of the multi-fork chain: every slot of the eight forks' epochs, and one more Gloas epoch.
const EVERY_FORK_SLOTS: u64 = 9 * 8;

#[test]
fn a_node_syncs_from_genesis_through_every_fork() {
    let Some(vectors) = Vectors::locate() else {
        return;
    };
    // Fixture state: the pyspec phase0 genesis, 64 validators with the test keys.
    // Forks follow each other an epoch apart, phase0 at 0 through Gloas at 7.
    let config = every_fork();
    let genesis_case = Case::new(vectors.consensus().join(PYSPEC_GENESIS));
    let genesis_bytes = genesis_case
        .ssz_bytes("state")
        .expect("case has a genesis state");
    let genesis = combined::BeaconState::<Minimal>::decode_at(&genesis_bytes, &config)
        .expect("genesis decodes as phase0");
    let genesis_time = genesis.genesis_time();
    let mut builder = ChainBuilder::new(config.clone(), genesis).expect("pyspec genesis");

    // Every slot from 1 to 72 gets a block; Gloas blocks also get their envelope.
    let proposals: Vec<Proposal<Minimal>> = (0..EVERY_FORK_SLOTS)
        .map(|_| builder.propose().expect("each block extends the chain"))
        .collect();
    let forks: Vec<ForkName> = proposals.iter().map(|p| p.block().fork_name()).collect();
    assert_eq!(forks.first(), Some(&ForkName::Phase0));
    assert_eq!(forks.last(), Some(&ForkName::Gloas));
    let tip = proposals.last().expect("72 blocks").block().block_root();
    let tip = format!("{tip}");

    let directory = env::temp_dir().join(format!("axiom-every-fork-{}", process::id()));
    fs::create_dir_all(&directory).expect("temporary directory is writable");
    let genesis_path = directory.join("genesis.ssz");
    fs::write(&genesis_path, &genesis_bytes).expect("temporary directory is writable");
    // The clock stands at slot 73, so every block is in the past.
    let now_ms = (genesis_time + 6 * (EVERY_FORK_SLOTS + 1)) * 1000;

    let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let settings = |listen_address, boot_nodes| NetworkSettings {
            listen_address,
            boot_nodes,
            custody_group_count: 4,
            discovery: None,
        };
        let node_config = |network| NodeConfig {
            anchor: Some(AnchorSource::Genesis(genesis_path.clone())),
            network: Some(network),
            ..NodeConfig::default()
        };

        // Node A takes every block and envelope over its API, fork after fork.
        let a_address = free_address();
        let a_api = free_address();
        let a = TestNode::start_with(
            now_ms,
            config.clone(),
            NodeConfig {
                http_address: Some(a_api),
                ..node_config(settings(a_address, Vec::new()))
            },
            a_api,
        )
        .await;
        a.publish_chain(&proposals).await;
        assert_eq!(a.head_root().await.as_deref(), Some(tip.as_str()));

        // Node B knows only genesis, and range-syncs every fork from A.
        // A Gloas block builds on its parent's payload, so B must import each envelope in turn.
        let boot: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", a_address.port())
            .parse()
            .unwrap();
        let b_api = free_address();
        let b = TestNode::start_with(
            now_ms,
            config.clone(),
            NodeConfig {
                http_address: Some(b_api),
                ..node_config(settings(free_address(), vec![boot]))
            },
            b_api,
        )
        .await;
        // Sync verifies every signature of 72 blocks, so it gets a minute rather than seconds.
        let head = wait_for_head_within(&b, &tip, 3000).await;
        assert_eq!(
            head.as_deref(),
            Some(tip.as_str()),
            "node B never reached the Gloas tip"
        );

        // B serves each fork's blocks back by slot, the first slot of each fork included.
        for fork in ForkName::ALL {
            let slot = config.fork_epoch(fork).start_slot::<Minimal>().0.max(1);
            let expected = format!("{}", proposals[(slot - 1) as usize].block().block_root());
            let root = b
                .json(&format!("/eth/v1/beacon/blocks/{slot}/root"))
                .await
                .expect("B holds the block");
            let root = root.get("data").and_then(|data| data.get("root"));
            assert_eq!(
                root.and_then(Json::as_str),
                Some(expected.as_str()),
                "{fork}"
            );
        }

        b.stop().await;
        a.stop().await;
    });
    let _ignored = fs::remove_dir_all(&directory);
}
