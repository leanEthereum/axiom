//! Whole nodes, started from a spec genesis state and driven through the beacon API and the network.

use std::{
    env, fs,
    net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket},
    path::PathBuf,
    process,
    sync::Arc,
    time::Duration,
};

use axiom_discv5::Enr;
use axiom_ef_tests::{Case, Vectors, config_of};
use axiom_http::{Client, ClientConfig, Endpoint, Method, Request, Response, StatusCode};
use axiom_json::Json;
use axiom_node::{
    AnchorSource, DiscoverySettings, ManualClock, NetworkSettings, Node, NodeConfig, NodeError,
};
use axiom_p2p::Multiaddr;
use axiom_ssz::Ssz;
use axiom_state_transition::{KnownVerdict, State, Verification};
use axiom_types::{BeaconState, Minimal, SignedBeaconBlock, SignedBlockContents};
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
    /// Milliseconds at the start of slot 2, when both blocks are timely.
    ///
    ///     slot:   0        1        2
    ///     time:   0 s      6 s      12 s   <- clock
    now_ms: u64,
}

impl Fixture {
    /// The fixture, or nothing when the vectors are not downloaded.
    fn load(name: &str) -> Option<Self> {
        let case = Case::new(Vectors::locate()?.consensus().join(CASE));
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
            now_ms: (genesis_time + 12) * 1000,
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
        Self::start_with(fixture, config, address).await
    }

    /// Starts a node with a full configuration whose API listens on an address.
    async fn start_with(fixture: &Fixture, config: NodeConfig, address: SocketAddr) -> Self {
        let (stop, stopped) = oneshot::channel::<()>();
        let task = task::spawn(Node::<Minimal>::run(
            config_of::<Minimal>(),
            config,
            Arc::new(ManualClock::at(fixture.now_ms)),
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
    let mut head = None;
    for _ in 0..500 {
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
        //     B ──discv5 lookup──> A's record ──TCP dial──> A ──status──> range sync
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
fn a_node_starts_from_a_checkpoint() {
    let Some(fixture) = Fixture::load("checkpoint") else {
        return;
    };

    // Fixture state: block 2 and its post-state, computed by running both blocks on genesis.
    //
    //     genesis ──block 1──> state 1 ──block 2──> state 2      checkpoint = (block 2, state 2)
    let genesis =
        BeaconState::<Minimal>::decode(&fixture.case.ssz_bytes("anchor_state").unwrap()).unwrap();
    let mut state = State::new(genesis);
    let mut last = None;
    for name in BLOCKS {
        let block = fixture
            .case
            .ssz::<SignedBeaconBlock<Minimal>>(name)
            .unwrap();
        state
            .state_transition(
                &config_of::<Minimal>(),
                &block,
                Verification::Verify,
                &KnownVerdict(true),
            )
            .unwrap();
        last = Some(block);
    }
    let block = last.unwrap();
    let state_path = fixture.directory.join("checkpoint_state.ssz");
    let block_path = fixture.directory.join("checkpoint_block.ssz");
    fs::write(&state_path, state.beacon().encode()).unwrap();
    fs::write(&block_path, block.encode()).unwrap();

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
        let node = TestNode::start_with(&fixture, config, address).await;

        // The checkpoint block is the head, with no block before it to replay.
        assert_eq!(node.head_root().await.as_deref(), Some(HEAD));
        node.stop().await;
    });
}
