//! A whole node, started from a spec genesis state and driven through its beacon API.

use std::{env, fs, net::TcpListener, process, sync::Arc, time::Duration};

use axiom_ef_tests::{Case, Vectors, config_of};
use axiom_http::{Client, ClientConfig, Endpoint, Method, Request, Response, StatusCode};
use axiom_json::Json;
use axiom_node::{ManualClock, Node, NodeConfig};
use axiom_ssz::Ssz;
use axiom_types::{BeaconState, Minimal, SignedBeaconBlock, SignedBlockContents};
use tokio::{runtime::Builder, sync::oneshot, task, time};

/// The fork choice case whose genesis and two blocks the node is fed.
///
/// Block 1 at slot 1 and block 2 at slot 2, with no votes.
const CASE: &str = "minimal/fulu/fork_choice/get_head/pyspec_tests/chain_no_attestations";

/// The two blocks of the case, in the order they extend the chain.
const BLOCKS: [&str; 2] = [
    "block_0x74accc6cc86aa84d9b90602053aee7738f063e0fe5855192d08e5a1a6778fe36",
    "block_0x8b932df328b89fd55311a65e4d5bf43288fb22f2e31a59da1bdd5714ac11452e",
];

/// The head after both blocks.
const HEAD: &str = "0x8b932df328b89fd55311a65e4d5bf43288fb22f2e31a59da1bdd5714ac11452e";

#[test]
fn a_node_imports_published_blocks_and_reports_its_head() {
    let Some(vectors) = Vectors::locate() else {
        // Without downloaded vectors there is no genesis to start from.
        return;
    };
    let case = Case::new(vectors.consensus().join(CASE));

    // Fixture state: the case's genesis written as the plain SSZ file a node reads.
    let directory = env::temp_dir().join(format!("axiom-node-{}", process::id()));
    fs::create_dir_all(&directory).unwrap();
    let genesis_path = directory.join("genesis.ssz");
    fs::write(&genesis_path, case.ssz_bytes("anchor_state").unwrap()).unwrap();
    let genesis_time = BeaconState::<Minimal>::decode(&case.ssz_bytes("anchor_state").unwrap())
        .unwrap()
        .genesis_time;

    // The clock stands at the start of slot 2, when both blocks are timely.
    //
    //     slot:   0        1        2
    //     time:   0 s      6 s      12 s   <- clock
    let clock = ManualClock::at((genesis_time + 12) * 1000);

    // Pick a free port, then hand it to the node.
    let address = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let config = NodeConfig {
        genesis_state: Some(genesis_path),
        http_address: Some(address),
        ..NodeConfig::default()
    };

    let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let (stop, stopped) = oneshot::channel::<()>();
        let node = task::spawn(Node::<Minimal>::run(
            config_of::<Minimal>(),
            config,
            Arc::new(clock),
            async move {
                let _stopped = stopped.await;
            },
        ));
        let client = Client::new(
            Endpoint::parse(&format!("http://{address}")).unwrap(),
            ClientConfig::default(),
        );

        // Wait for the API to come up.
        let mut health = None;
        for _ in 0..100 {
            if let Ok(response) = client
                .send(&Request::new(Method::Get, "/eth/v1/node/health"))
                .await
            {
                health = Some(response.status);
                break;
            }
            time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            health,
            Some(StatusCode::PARTIAL_CONTENT),
            "two slots behind is syncing"
        );

        // Publish both blocks, each without blobs.
        for name in BLOCKS {
            let contents = SignedBlockContents::<Minimal> {
                signed_block: case.ssz::<SignedBeaconBlock<Minimal>>(name).unwrap(),
                ..SignedBlockContents::default()
            };
            let request = Request::new(Method::Post, "/eth/v2/beacon/blocks")
                .with_body("application/octet-stream", contents.encode());
            let response = client.send(&request).await.unwrap();
            assert_eq!(response.status, StatusCode::OK, "{}", body_text(&response));
        }

        // The head is the second block, at slot 2, and the node is in sync.
        let header = json(&client, "/eth/v1/beacon/headers/head").await;
        let data = header.get("data").unwrap();
        assert_eq!(data.get("root").and_then(Json::as_str), Some(HEAD));
        assert_eq!(data.get("canonical").and_then(Json::as_bool), Some(true));
        let slot = data
            .get("header")
            .and_then(|header| header.get("message"))
            .and_then(|message| message.get("slot"));
        assert_eq!(slot.and_then(Json::as_str), Some("2"));

        let syncing = json(&client, "/eth/v1/node/syncing").await;
        let data = syncing.get("data").unwrap();
        assert_eq!(data.get("head_slot").and_then(Json::as_str), Some("2"));
        assert_eq!(data.get("is_syncing").and_then(Json::as_bool), Some(false));

        // A block by slot is the canonical one; slot 3 is still empty.
        let by_slot = json(&client, "/eth/v1/beacon/blocks/2/root").await;
        assert_eq!(
            by_slot
                .get("data")
                .and_then(|data| data.get("root"))
                .and_then(Json::as_str),
            Some(HEAD)
        );
        let missing = client
            .send(&Request::new(Method::Get, "/eth/v1/beacon/blocks/3/root"))
            .await
            .unwrap();
        assert_eq!(missing.status, StatusCode::NOT_FOUND);

        // Shutdown drains every service and returns cleanly.
        stop.send(()).unwrap();
        node.await.unwrap().unwrap();
    });
    fs::remove_dir_all(&directory).unwrap();
}

/// A JSON route's parsed body, which must be a success.
async fn json(client: &Client, path: &str) -> Json {
    let response = client.send(&Request::new(Method::Get, path)).await.unwrap();
    assert_eq!(
        response.status,
        StatusCode::OK,
        "{path}: {}",
        body_text(&response)
    );
    Json::parse(&response.body).unwrap()
}

/// A response body as text, for failure messages.
fn body_text(response: &Response) -> String {
    String::from_utf8_lossy(&response.body).into_owned()
}
