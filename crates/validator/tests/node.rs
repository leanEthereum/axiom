//! A validator client running its duties against a real in-process Axiom node.
//!
//! The node is the full service, reached only through its HTTP API.
//! It keeps the chain, the fork choice, and the operation pools, and it builds every block.
//! The client holds all 64 pyspec keys, so the chain finalizes only if every duty works.
//!
//! No execution engine runs, so the chain stays before the merge.
//! Point AXIOM_VECTORS at the vectors root, which defaults to the workspace's testing/vectors.

use std::{env, fs, net::TcpListener, path::PathBuf, process, sync::Arc, time::Duration};

use axiom_bls::SecretKey;
use axiom_ef_tests::{Case, Vectors, chain_builder::PYSPEC_GENESIS};
use axiom_http::{Client, ClientConfig, Endpoint, Method, Request, StatusCode};
use axiom_json::Json;
use axiom_node::{AnchorSource, Clock, Node, NodeConfig, SystemClock};
use axiom_ssz::Ssz;
use axiom_types::{ChainConfig, Epoch, ForkName, Minimal, Root, Slot, SlotClock, phase0};
use axiom_validator::{
    beacon::{BeaconClient, BeaconNodes},
    duties::{ClientSettings, DutyContext, SlotTimer, ValidatorClient},
    protection::SlashingDatabase,
    signing::{Bls, LocalKey, SigningContext, SigningGuard, ValidatorSigner},
    validators::{DEFAULT_GAS_LIMIT, ProposerDefaults, ValidatorStore},
};
use tokio::{runtime::Builder, sync::oneshot, task, time};

/// Slots the run covers: phase0 in epoch 0, Altair in epoch 1, then Bellatrix before the merge.
const SLOTS: u64 = 40;

/// Length of a slot, long enough for the node to import and the client to sign 64 duties.
const SLOT_MS: u64 = 2_000;

/// The real clock, shifted so that the chain's genesis is a moment ago.
#[derive(Debug)]
struct ShiftedClock {
    /// Milliseconds to subtract from the system clock.
    offset_ms: u64,
}

impl Clock for ShiftedClock {
    fn now_ms(&self) -> u64 {
        SystemClock.now_ms() - self.offset_ms
    }
}

/// The minimal configuration with Altair at epoch 1 and Bellatrix at epoch 2.
///
/// The terminal total difficulty is out of reach, so the chain never merges.
fn schedule() -> ChainConfig {
    ChainConfig {
        slot_duration_ms: SLOT_MS,
        ..ChainConfig::minimal()
    }
    .with_fork_epoch(ForkName::Altair, Epoch(1))
    .with_fork_epoch(ForkName::Bellatrix, Epoch(2))
}

/// The pyspec key of a validator: the secret is its index plus one.
fn pyspec_key(index: u64) -> LocalKey<Bls> {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&(index + 1).to_be_bytes());
    LocalKey::new(SecretKey::from_bytes(&bytes).expect("small scalars are keys"))
        .expect("BLS keys are stateless")
}

/// A decimal string member of a JSON object.
fn number(value: &Json, name: &str) -> u64 {
    value
        .get(name)
        .and_then(Json::as_str)
        .and_then(|text| text.parse().ok())
        .unwrap_or_else(|| panic!("{name} is a decimal string"))
}

/// The data member of a GET route's JSON reply, which must succeed.
async fn data(client: &Client, path: &str) -> Json {
    let response = client
        .send(&Request::new(Method::Get, path))
        .await
        .expect("the node answers");
    assert_eq!(response.status, StatusCode::OK, "{path}");
    let json = Json::parse(&response.body).expect("the reply is JSON");
    json.get("data").cloned().expect("the reply has data")
}

/// The duties of a client holding the pyspec keys of the first validators, with one node.
fn duty_context(
    config: Arc<ChainConfig>,
    genesis_validators_root: Root,
    validators: u64,
    url: &str,
    timer: SlotTimer,
) -> DutyContext<Minimal> {
    let context = SigningContext::new(Arc::clone(&config), genesis_validators_root);
    let protection = Arc::new(
        SlashingDatabase::in_memory(genesis_validators_root).expect("a memory database opens"),
    );
    let store = Arc::new(ValidatorStore::new(
        SigningGuard::new(context, protection),
        ProposerDefaults {
            gas_limit: DEFAULT_GAS_LIMIT,
            ..ProposerDefaults::default()
        },
    ));
    for index in 0..validators {
        store
            .add(ValidatorSigner::Local(pyspec_key(index)), true)
            .expect("each key registers");
    }
    let client_config = ClientConfig {
        request_timeout: Duration::from_secs(5),
        ..ClientConfig::default()
    };
    let nodes = Arc::new(
        BeaconNodes::new(vec![
            BeaconClient::new(url, client_config).expect("a loopback URL"),
        ])
        .expect("one node"),
    );
    let settings = ClientSettings {
        doppelganger_epochs: 0,
        ..ClientSettings::default()
    };
    DutyContext::new(store, nodes, config, timer, settings)
}

#[test]
fn a_validator_client_finalizes_a_chain_on_an_axiom_node() {
    let Some(vectors) = Vectors::locate() else {
        return;
    };
    let genesis: phase0::BeaconState<Minimal> = Case::new(vectors.consensus().join(PYSPEC_GENESIS))
        .ssz("state")
        .expect("the genesis vector decodes");
    Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("the runtime starts")
        .block_on(run(genesis));
}

/// Runs the node and the client until the last slot, then reads the chain back over the API.
async fn run(genesis: phase0::BeaconState<Minimal>) {
    // Fixture state: 64 validators with the pyspec keys, Altair at epoch 1, Bellatrix at epoch 2.
    let config = Arc::new(schedule());
    let validators = genesis.validators.len() as u64;
    let genesis_ms = genesis.genesis_time * 1000;
    let genesis_validators_root = genesis.genesis_validators_root;
    let directory: PathBuf = env::temp_dir().join(format!("axiom-vc-node-{}", process::id()));
    fs::create_dir_all(&directory).expect("the temporary directory is writable");
    let genesis_path = directory.join("genesis.ssz");
    fs::write(&genesis_path, genesis.encode()).expect("the temporary directory is writable");

    // Timing: genesis was half a slot ago, so slot 1 starts in half a slot.
    // The node and the client read the same clock.
    let offset_ms = SystemClock.now_ms() - genesis_ms - SLOT_MS / 2;
    let clock = Arc::new(ShiftedClock { offset_ms });

    // The node, with its API on a free loopback port and no peers.
    let address = TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("a loopback port is free");
    let node_config = NodeConfig {
        anchor: Some(AnchorSource::Genesis(genesis_path)),
        http_address: Some(address),
        ..NodeConfig::default()
    };
    let (stop_node, node_stopped) = oneshot::channel::<()>();
    let node = task::spawn(Node::<Minimal>::run(
        (*config).clone(),
        node_config,
        Arc::clone(&clock) as Arc<dyn Clock>,
        async move {
            let _stopped = node_stopped.await;
        },
    ));
    let url = format!("http://{address}");
    let api = Client::new(
        Endpoint::parse(&url).expect("a socket address is a URL"),
        ClientConfig::default(),
    );
    for _ in 0..200 {
        let health = Request::new(Method::Get, "/eth/v1/node/health");
        if api.send(&health).await.is_ok() {
            break;
        }
        time::sleep(Duration::from_millis(10)).await;
    }

    // The client: every key local, enabled at once, behind slashing protection in memory.
    let timer = SlotTimer::new(clock, SlotClock::new(genesis_ms, SLOT_MS));
    let duties = duty_context(
        config,
        genesis_validators_root,
        validators,
        &url,
        timer.clone(),
    );
    let (stop_client, client_stopped) = oneshot::channel::<()>();
    let client = task::spawn(ValidatorClient::new(duties).run(async {
        let _stopped = client_stopped.await;
    }));

    // Timing: stop once the last slot's block is in and its aggregates are out.
    timer.wait_until(Slot(SLOTS), 9_000).await;
    let _stopping = stop_client.send(());
    client.await.expect("the client stops cleanly");

    // Every slot from 1 to 40 has its block, each one built by the node from the client's reveal.
    let head = data(&api, "/eth/v1/beacon/headers/head").await;
    let message = head
        .get("header")
        .and_then(|header| header.get("message"))
        .expect("a header has its message");
    assert_eq!(number(message, "slot"), SLOTS);
    for slot in 1..=SLOTS {
        data(&api, &format!("/eth/v1/beacon/headers/{slot}")).await;
    }

    // With every vote in the next slot's block, epoch 5 opens with epoch 4 justified and 3 final.
    let checkpoints = data(&api, "/eth/v1/beacon/states/head/finality_checkpoints").await;
    let epoch = |name: &str| {
        checkpoints.get(name).map_or_else(
            || panic!("{name} is a checkpoint"),
            |checkpoint| number(checkpoint, "epoch"),
        )
    };
    assert_eq!(epoch("current_justified"), 4);
    assert_eq!(epoch("finalized"), 3);

    let _stopping = stop_node.send(());
    node.await
        .expect("the node task joins")
        .expect("the node stops cleanly");
    let _ignored = fs::remove_dir_all(&directory);
}
