//! Whole nodes, started from a spec genesis state.
//! The tests drive them through the beacon API and the network.

use std::{
    env, fs,
    net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket},
    path::{Path, PathBuf},
    process,
    sync::Arc,
    time::Duration,
};

use axiom_discv5::Enr;
use axiom_ef_tests::{
    Case, Vectors,
    chain_builder::{ChainBuilder, PYSPEC_GENESIS, Participation, Proposal},
};
use axiom_execution::{CAPABILITIES, JsonCodec, JwtSecret, mock::MockEngine};
use axiom_fork_choice::bellatrix::SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY;
use axiom_http::{Client, ClientConfig, Endpoint, Method, Request, Response, StatusCode};
use axiom_json::Json;
use axiom_kzg::{Blob as KzgBlob, Kzg};
use axiom_light_client::{
    Header,
    combined::{
        Format, LightClientBootstrap, LightClientFinalityUpdate, LightClientOptimisticUpdate,
        LightClientStore, LightClientUpdate,
    },
};
use axiom_node::{
    AnchorSource, DiscoverySettings, EngineConfig, ManualClock, NetworkSettings, Node, NodeConfig,
    NodeError,
};
use axiom_p2p::Multiaddr;
use axiom_ssz::{Ssz, U256};
use axiom_state_transition::{KnownVerdict, State, Verification};
use axiom_types::{
    ChainConfig, Epoch, ForkName, Hash32, KzgCommitment, KzgProof, Minimal, Slot,
    accessors::CoreState,
    bellatrix::PowBlock,
    combined,
    deneb::{self, Blob},
    electra,
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

/// Blobs with their commitments and one opening proof per blob, as a proposer holds them.
#[derive(Clone, Debug, Default)]
struct BlobBundle {
    /// The blobs.
    blobs: Vec<Blob<Minimal>>,
    /// The commitment to each blob.
    commitments: Vec<KzgCommitment>,
    /// The proof that opens each commitment to its blob.
    proofs: Vec<KzgProof>,
}

impl BlobBundle {
    /// One blob per seed, whose first two field elements are the seed and its successor.
    fn from_seeds(seeds: &[u8]) -> Self {
        let kzg = Kzg::mainnet();
        let mut bundle = Self::default();
        for &seed in seeds {
            let mut bytes = Blob::<Minimal>::default().as_ref().to_vec();
            bytes[31] = seed;
            bytes[63] = seed + 1;
            let blob = KzgBlob::from_bytes(&bytes).expect("small elements are canonical");
            let commitment = kzg.blob_to_kzg_commitment(&blob);
            let proof = kzg
                .compute_blob_kzg_proof(&blob, &commitment)
                .expect("a computed commitment is a point");
            bundle
                .blobs
                .push(Blob::<Minimal>::try_from(bytes.as_slice()).expect("a blob's size"));
            bundle.commitments.push(KzgCommitment(commitment.0));
            bundle.proofs.push(KzgProof(proof.0));
        }
        bundle
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

    /// Publishes a block of any fork over the API, without blobs.
    async fn publish_any(&self, block: &combined::SignedBeaconBlock<Minimal>) -> Response {
        self.publish_with_blobs(block, &BlobBundle::default()).await
    }

    /// Publishes a block of any fork over the API, in the format the fork's route takes.
    ///
    /// From Deneb to Fulu a block travels in its block contents, with the bundle's blobs.
    /// Every other fork's block travels alone.
    async fn publish_with_blobs(
        &self,
        block: &combined::SignedBeaconBlock<Minimal>,
        bundle: &BlobBundle,
    ) -> Response {
        let body = match block {
            combined::SignedBeaconBlock::Deneb(signed) => deneb::SignedBlockContents {
                signed_block: signed.clone(),
                kzg_proofs: bundle
                    .proofs
                    .clone()
                    .try_into()
                    .expect("the proofs fit the list"),
                blobs: bundle
                    .blobs
                    .clone()
                    .try_into()
                    .expect("the blobs fit the list"),
            }
            .encode(),
            combined::SignedBeaconBlock::Electra(signed) => electra::SignedBlockContents {
                signed_block: signed.clone(),
                kzg_proofs: bundle
                    .proofs
                    .clone()
                    .try_into()
                    .expect("the proofs fit the list"),
                blobs: bundle
                    .blobs
                    .clone()
                    .try_into()
                    .expect("the blobs fit the list"),
            }
            .encode(),
            combined::SignedBeaconBlock::Fulu(signed) => SignedBlockContents {
                signed_block: signed.clone(),
                kzg_proofs: bundle
                    .proofs
                    .clone()
                    .try_into()
                    .expect("the proofs fit the list"),
                blobs: bundle
                    .blobs
                    .clone()
                    .try_into()
                    .expect("the blobs fit the list"),
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

    /// An SSZ route's answer, or why the route did not answer.
    async fn ssz_body(&self, path: &str) -> Result<Response, String> {
        let request =
            Request::new(Method::Get, path).with_header("accept", "application/octet-stream");
        let response = self
            .client
            .send(&request)
            .await
            .map_err(|error| format!("{path}: {error}"))?;
        if response.status != StatusCode::OK {
            return Err(format!(
                "{path}: {}: {}",
                response.status,
                body_text(&response)
            ));
        }
        Ok(response)
    }

    /// An SSZ route's body and the fork it is tagged with, or why the route did not answer.
    async fn ssz(&self, path: &str) -> Result<(Vec<u8>, ForkName), String> {
        let response = self.ssz_body(path).await?;
        let fork = response
            .headers
            .get("eth-consensus-version")
            .and_then(ForkName::from_name)
            .ok_or_else(|| format!("{path}: no fork tag"))?;
        Ok((response.body, fork))
    }

    /// The latest optimistic update, as its attested and signature slots.
    async fn optimistic_slots(&self) -> (Slot, Slot) {
        let (bytes, fork) = self
            .ssz("/eth/v1/beacon/light_client/optimistic_update")
            .await
            .expect("the node serves an optimistic update");
        let LightClientOptimisticUpdate::Altair(update) =
            LightClientOptimisticUpdate::<Minimal>::decode(&bytes, fork)
                .expect("the update decodes")
        else {
            panic!("an Altair chain serves Altair updates");
        };
        (update.attested_header.beacon.slot, update.signature_slot)
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

/// A response's status, and the message of the error body the API sends with it.
fn api_error(response: &Response) -> (StatusCode, Option<String>) {
    let message = Json::parse(&response.body).ok().and_then(|body| {
        body.get("message")
            .and_then(Json::as_str)
            .map(str::to_owned)
    });
    (response.status, message)
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

/// The terminal total difficulty of the multi-fork chain.
///
/// The terminal block sits exactly on it, and its parent one short.
const TERMINAL_TOTAL_DIFFICULTY: u64 = 1000;

/// The parent of the terminal proof-of-work block, a stand-in hash.
const TERMINAL_PARENT: Hash32 = Hash32([0x7d; 32]);

/// The fork schedule of the multi-fork chain: Altair at epoch 1, then one fork per epoch.
///
/// Gloas starts at epoch 7, the last fork, so the chain ends with payloads in envelopes.
/// The merge happens with the first Bellatrix block, at slot 16.
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

/// Slots of the multi-fork chain: every slot of the eight forks' epochs, and one more Gloas epoch.
const EVERY_FORK_SLOTS: u64 = 9 * 8;

/// Slot of the merge block: the first slot of Bellatrix, at epoch 2.
const MERGE_SLOT: u64 = 16;

/// A builder of the multi-fork chain at the pyspec phase0 genesis.
fn every_fork_builder(vectors: &Vectors) -> ChainBuilder<Minimal> {
    let config = every_fork();
    let genesis_case = Case::new(vectors.consensus().join(PYSPEC_GENESIS));
    let genesis_bytes = genesis_case
        .ssz_bytes("state")
        .expect("case has a genesis state");
    let genesis = combined::BeaconState::<Minimal>::decode_at(&genesis_bytes, &config)
        .expect("genesis decodes as phase0");
    ChainBuilder::new(config, genesis).expect("pyspec genesis")
}

/// A scratch directory holding a builder's genesis file, and that file's path.
fn write_genesis(name: &str, builder: &ChainBuilder<Minimal>) -> (PathBuf, PathBuf) {
    let directory = env::temp_dir().join(format!("axiom-{name}-{}", process::id()));
    fs::create_dir_all(&directory).expect("temporary directory is writable");
    let genesis_path = directory.join("genesis.ssz");
    fs::write(&genesis_path, builder.genesis_bytes()).expect("temporary directory is writable");
    (directory, genesis_path)
}

/// Milliseconds at the start of a slot of a builder's chain.
fn slot_start_ms(builder: &ChainBuilder<Minimal>, slot: u64) -> u64 {
    (builder.genesis().genesis_time() + 6 * slot) * 1000
}

/// A mock engine that calls every payload valid, and the node configuration that reaches it.
///
/// It knows two proof-of-work blocks: the terminal one, and its parent one short of the threshold.
/// Every other block is unknown to it.
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
    };
    (mock, config)
}

/// The hashes a mock engine was asked to look up, in order.
fn pow_lookups(engine: &MockEngine) -> Vec<Json> {
    engine
        .calls()
        .into_iter()
        .filter(|call| call.method == "eth_getBlockByHash")
        .map(|call| call.params[0].clone())
        .collect()
}

#[test]
fn a_node_syncs_from_genesis_through_every_fork() {
    let Some(vectors) = Vectors::locate() else {
        return;
    };
    // Fixture state: the pyspec phase0 genesis, 64 validators with the test keys.
    // Forks follow each other an epoch apart, phase0 at 0 through Gloas at 7.
    let mut builder = every_fork_builder(&vectors);
    let config = builder.config().clone();
    let terminal = builder.terminal_block_hash();

    // Every slot from 1 to 72 gets a block; Gloas blocks also get their envelope.
    let proposals: Vec<Proposal<Minimal>> = (0..EVERY_FORK_SLOTS)
        .map(|_| builder.propose().expect("each block extends the chain"))
        .collect();
    let forks: Vec<ForkName> = proposals.iter().map(|p| p.block().fork_name()).collect();
    assert_eq!(forks.first(), Some(&ForkName::Phase0));
    assert_eq!(forks.last(), Some(&ForkName::Gloas));
    let tip = proposals.last().expect("72 blocks").block().block_root();
    let tip = format!("{tip}");

    let (directory, genesis_path) = write_genesis("every-fork", &builder);
    // The clock stands at slot 73, so every block is in the past.
    let now_ms = slot_start_ms(&builder, EVERY_FORK_SLOTS + 1);

    let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        // Each node has its own engine, which calls every payload valid.
        // Both engines know the terminal block at difficulty 1000 and its parent at 999.
        let (a_engine, a_engine_config) =
            valid_engine(terminal, &directory.join("a-jwt.hex")).await;
        let (b_engine, b_engine_config) =
            valid_engine(terminal, &directory.join("b-jwt.hex")).await;
        let settings = |listen_address, boot_nodes| NetworkSettings {
            listen_address,
            boot_nodes,
            custody_group_count: 4,
            discovery: None,
        };
        let node_config = |network, engine| NodeConfig {
            anchor: Some(AnchorSource::Genesis(genesis_path.clone())),
            network: Some(network),
            engine: Some(engine),
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
                ..node_config(settings(a_address, Vec::new()), a_engine_config)
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
                ..node_config(settings(free_address(), vec![boot]), b_engine_config)
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

        // Before importing the merge block of slot 16, B asked its engine for the terminal block.
        // The terminal block at 1000 led to its parent at 999, and nothing else was looked up.
        let expected = vec![terminal.to_json(), TERMINAL_PARENT.to_json()];
        assert_eq!(pow_lookups(&b_engine), expected);
        // Every payload came back valid, so B's head is fully verified.
        let syncing = b.json("/eth/v1/node/syncing").await.unwrap();
        let optimistic = syncing
            .get("data")
            .and_then(|data| data.get("is_optimistic"));
        assert_eq!(optimistic.and_then(Json::as_bool), Some(false));

        b.stop().await;
        a.stop().await;
        b_engine.stop().await;
        a_engine.stop().await;
    });
    let _ignored = fs::remove_dir_all(&directory);
}

#[test]
fn a_node_without_an_engine_imports_an_old_merge_block_optimistically() {
    let Some(vectors) = Vectors::locate() else {
        return;
    };
    // Fixture state: the multi-fork chain up to its merge block, at slot 16.
    let mut builder = every_fork_builder(&vectors);
    let config = builder.config().clone();
    let proposals: Vec<Proposal<Minimal>> = (0..MERGE_SLOT)
        .map(|_| builder.propose().expect("each block extends the chain"))
        .collect();
    let merge = proposals.last().expect("16 blocks").block();
    assert_eq!(merge.fork_name(), ForkName::Bellatrix);
    let merge_root = format!("{}", merge.block_root());

    // Timing: the clock stands at slot 144, 128 slots after the merge block.
    // An unvalidated merge block may import only once that old.
    let (directory, genesis_path) = write_genesis("old-merge", &builder);
    let now_ms = slot_start_ms(&builder, MERGE_SLOT + SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY);

    let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let address = free_address();
        let node_config = NodeConfig {
            anchor: Some(AnchorSource::Genesis(genesis_path.clone())),
            http_address: Some(address),
            ..NodeConfig::default()
        };
        let node = TestNode::start_with(now_ms, config, node_config, address).await;

        // No engine knows the terminal block, yet the merge block imports and becomes the head.
        node.publish_chain(&proposals).await;
        assert_eq!(node.head_root().await.as_deref(), Some(merge_root.as_str()));

        // Its payload was never validated, so the node follows the chain optimistically.
        let syncing = node.json("/eth/v1/node/syncing").await.unwrap();
        let optimistic = syncing
            .get("data")
            .and_then(|data| data.get("is_optimistic"));
        assert_eq!(optimistic.and_then(Json::as_bool), Some(true));
        node.stop().await;
    });
    let _ignored = fs::remove_dir_all(&directory);
}

/// Slot the light client chain's clock stands at, the start of epoch 11.
///
/// Its canonical blocks fill slots 1 to 87, so slot 88 is still empty.
const LIGHT_CLIENT_NOW: u64 = 88;

/// Splits the body of the updates route into its updates.
///
/// Each chunk is an 8-byte little-endian length, a fork digest, then the update.
fn update_chunks(mut body: &[u8]) -> Vec<LightClientUpdate<Minimal>> {
    let mut updates = Vec::new();
    while !body.is_empty() {
        let (length, rest) = body.split_at(8);
        let length =
            u64::from_le_bytes(length.try_into().expect("eight bytes make a length")) as usize;
        let (chunk, rest) = rest.split_at(length);
        // Every block of this chain is Altair's, so the digest only needs to be present.
        updates.push(
            LightClientUpdate::decode(&chunk[4..], ForkName::Altair).expect("each chunk decodes"),
        );
        body = rest;
    }
    updates
}

#[test]
fn a_node_serves_light_client_data_that_follows_its_canonical_chain() {
    let Some(vectors) = Vectors::locate() else {
        return;
    };
    // Fixture state: the pyspec phase0 genesis, with Altair from epoch 1 and no later fork.
    // Every validator attests and every sync committee seat signs, so the chain finalizes.
    let config = ChainConfig::minimal().with_fork_epoch(ForkName::Altair, Epoch(1));
    let genesis_bytes = Case::new(vectors.consensus().join(PYSPEC_GENESIS))
        .ssz_bytes("state")
        .expect("case has a genesis state");
    let genesis = combined::BeaconState::<Minimal>::decode_at(&genesis_bytes, &config).unwrap();
    let genesis_time = genesis.genesis_time();
    let genesis_validators_root = genesis.genesis_validators_root();

    // Branch a: full votes on slots 1 to 85, then two blocks only the sync committee signs.
    //
    //     a: 1 .. 85 (full), 86 and 87 (sync signatures, no attestations)
    //     b: 1 .. 85 (the same blocks), then 88, skipping 86 and 87
    //
    // Blocks 86 and 87 add no fork choice weight, so b's timely block at 88 takes the head.
    let full = |config: &ChainConfig| {
        ChainBuilder::<Minimal>::new(config.clone(), genesis.clone())
            .unwrap()
            .with_participation(Participation::Full)
    };
    let mut a_builder = full(&config);
    let mut a: Vec<Proposal<Minimal>> = (1..=85).map(|_| a_builder.propose().unwrap()).collect();
    let mut a_builder = a_builder.with_participation(Participation::SyncOnly);
    a.extend((86..=87).map(|_| a_builder.propose().unwrap()));
    let mut b_builder = full(&config);
    let b_shared: Vec<Proposal<Minimal>> = (1..=85).map(|_| b_builder.propose().unwrap()).collect();
    assert_eq!(b_shared.last(), a.get(84));
    let b_tip = b_builder.propose_at(Slot(LIGHT_CLIENT_NOW)).unwrap();

    let directory = env::temp_dir().join(format!("axiom-light-client-{}", process::id()));
    fs::create_dir_all(&directory).expect("temporary directory is writable");
    let genesis_path = directory.join("genesis.ssz");
    fs::write(&genesis_path, &genesis_bytes).expect("temporary directory is writable");
    let now_ms = (genesis_time + 6 * LIGHT_CLIENT_NOW) * 1000;

    let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let address = free_address();
        let node_config = NodeConfig {
            anchor: Some(AnchorSource::Genesis(genesis_path.clone())),
            http_address: Some(address),
            ..NodeConfig::default()
        };
        let node = TestNode::start_with(now_ms, config.clone(), node_config, address).await;
        node.publish_chain(&a).await;

        // The head is block 87, which signs for block 86.
        assert_eq!(node.optimistic_slots().await, (Slot(86), Slot(87)));

        // Two periods of 64 slots have a best update each.
        // Period 0's earliest update with finality attests 32, when epoch 2 finalized.
        // Period 1's earliest whose finalized header is in period 1 attests 80, finalizing slot 64.
        let response = node
            .ssz_body("/eth/v1/beacon/light_client/updates?start_period=0&count=2")
            .await
            .unwrap();
        let updates = update_chunks(&response.body);
        let attested: Vec<Slot> = updates
            .iter()
            .map(LightClientUpdate::context_slot)
            .collect();
        assert_eq!(attested, [Slot(32), Slot(80)]);

        // A light client trusts block 8, the first Altair epoch boundary, and fetches its bootstrap.
        let trusted = a[7].block().block_root();
        let (bytes, fork) = node
            .ssz(&format!("/eth/v1/beacon/light_client/bootstrap/{trusted}"))
            .await
            .unwrap();
        assert_eq!(fork, ForkName::Altair);
        let bootstrap = LightClientBootstrap::decode(&bytes, fork).unwrap();
        let mut store =
            LightClientStore::initialize(Format::Altair, &config, trusted, bootstrap).unwrap();

        // Both updates verify against the committees the bootstrap and period 0 prove.
        // The client then trusts slot 64 as finalized, and slot 80 as its optimistic head.
        for update in updates {
            store
                .process_update(
                    &config,
                    update,
                    Slot(LIGHT_CLIENT_NOW),
                    genesis_validators_root,
                )
                .unwrap();
        }
        assert_eq!(store.finalized_header().beacon().slot, Slot(64));
        assert_eq!(store.optimistic_header().beacon().slot, Slot(80));

        // The finality update of the head proves slot 64 too.
        let (bytes, fork) = node
            .ssz("/eth/v1/beacon/light_client/finality_update")
            .await
            .unwrap();
        let LightClientFinalityUpdate::Altair(finality) =
            LightClientFinalityUpdate::<Minimal>::decode(&bytes, fork).unwrap()
        else {
            panic!("an Altair chain serves Altair updates");
        };
        assert_eq!(
            (
                finality.attested_header.beacon.slot,
                finality.finalized_header.beacon.slot
            ),
            (Slot(86), Slot(64))
        );

        // Branch b's block at 88 arrives on time, and its proposer boost takes the head.
        let response = node.publish_any(b_tip.block()).await;
        assert_eq!(response.status, StatusCode::OK, "{}", body_text(&response));
        let b_root = format!("{}", b_tip.block().block_root());
        assert_eq!(node.head_root().await, Some(b_root));

        // Blocks 86 and 87 are orphaned, so their newer updates are no longer served.
        // Block 88 signs for block 85, the head's parent.
        assert_eq!(node.optimistic_slots().await, (Slot(85), Slot(88)));

        node.stop().await;
    });
    let _ignored = fs::remove_dir_all(&directory);
}

/// Publishes two blocks with blobs to node A, and checks node B range-syncs blocks and blobs.
///
/// The genesis is the anchor of a fork choice case of the fork, with every fork up to it active.
fn publish_blobs_and_sync(fork: ForkName) {
    let Some(vectors) = Vectors::locate() else {
        return;
    };
    let config = ChainConfig::minimal().with_forks_at_genesis(fork);
    let case = Case::new(vectors.consensus().join(format!(
        "minimal/{fork}/fork_choice/get_head/pyspec_tests/chain_no_attestations"
    )));
    let genesis_bytes = case
        .ssz_bytes("anchor_state")
        .expect("case has an anchor state");
    let genesis = combined::BeaconState::<Minimal>::decode_at(&genesis_bytes, &config)
        .expect("anchor state decodes in its fork");
    let genesis_time = genesis.genesis_time();
    let mut builder = ChainBuilder::new(config.clone(), genesis).expect("pyspec keys");

    // Fixture state: block 1 commits to 2 blobs, block 2 to 1 blob.
    let bundles = [
        BlobBundle::from_seeds(&[1, 3]),
        BlobBundle::from_seeds(&[5]),
    ];
    let blocks: Vec<combined::SignedBeaconBlock<Minimal>> = bundles
        .iter()
        .map(|bundle| {
            builder
                .propose_with_blobs(&bundle.commitments)
                .expect("each block extends the chain")
                .block()
                .clone()
        })
        .collect();
    assert!(blocks.iter().all(|block| block.fork_name() == fork));
    let tip = format!("{}", blocks[1].block_root());

    let directory = env::temp_dir().join(format!("axiom-blobs-{fork}-{}", process::id()));
    fs::create_dir_all(&directory).expect("temporary directory is writable");
    let genesis_path = directory.join("genesis.ssz");
    fs::write(&genesis_path, &genesis_bytes).expect("temporary directory is writable");
    // The clock stands at slot 3, so both blocks are in the past.
    let now_ms = (genesis_time + 6 * 3) * 1000;

    let runtime = Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime starts");
    runtime.block_on(async {
        let start = |listen_address, boot_nodes| {
            let api = free_address();
            let network = NetworkSettings {
                listen_address,
                boot_nodes,
                custody_group_count: 4,
                discovery: None,
            };
            let node_config = NodeConfig {
                anchor: Some(AnchorSource::Genesis(genesis_path.clone())),
                http_address: Some(api),
                network: Some(network),
                ..NodeConfig::default()
            };
            TestNode::start_with(now_ms, config.clone(), node_config, api)
        };
        let a_address = free_address();
        let a = start(a_address, Vec::new()).await;

        // Mutation: block 1 carries the proofs of its 2 blobs swapped.
        // The batch check fails, so nothing is broadcast or imported.
        let mut swapped = bundles[0].clone();
        swapped.proofs.swap(0, 1);
        let response = a.publish_with_blobs(&blocks[0], &swapped).await;
        let root = blocks[0].block_root();
        let message = format!("blob data: blob proofs of block {root} do not verify");
        assert_eq!(
            api_error(&response),
            (StatusCode::BAD_REQUEST, Some(message))
        );

        // Mutation: block 1 travels with its first blob only, 1 of 2.
        let mut short = bundles[0].clone();
        short.blobs.pop();
        short.proofs.pop();
        let response = a.publish_with_blobs(&blocks[0], &short).await;
        let message = format!("blob data: block {root} commits to 2 blobs, but 1 are offered");
        assert_eq!(
            api_error(&response),
            (StatusCode::BAD_REQUEST, Some(message))
        );

        // Each block imports at once with its blobs, so A's head is block 2.
        for (block, bundle) in blocks.iter().zip(&bundles) {
            let response = a.publish_with_blobs(block, bundle).await;
            assert_eq!(response.status, StatusCode::OK, "{}", body_text(&response));
        }
        assert_eq!(a.head_root().await.as_deref(), Some(tip.as_str()));

        // Node B knows only genesis and range-syncs from A.
        // Both blocks are inside the retention window, so B imports each only with its blobs.
        // Reaching the tip shows A served all 3 sidecars and B verified them.
        let boot: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", a_address.port())
            .parse()
            .expect("a TCP address is a multiaddress");
        let b = start(free_address(), vec![boot]).await;
        let head = wait_for_head(&b, &tip).await;
        assert_eq!(
            head.as_deref(),
            Some(tip.as_str()),
            "node B never synced the {fork} blocks with their blobs"
        );

        b.stop().await;
        a.stop().await;
    });
    let _ignored = fs::remove_dir_all(&directory);
}

#[test]
fn a_node_publishes_deneb_blobs_and_a_peer_syncs_them() {
    publish_blobs_and_sync(ForkName::Deneb);
}

#[test]
fn a_node_publishes_electra_blobs_and_a_peer_syncs_them() {
    publish_blobs_and_sync(ForkName::Electra);
}
