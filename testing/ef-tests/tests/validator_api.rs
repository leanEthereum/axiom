//! A node driven through the validator routes alone, as a validator client drives it.
//!
//! The test plays the validator client with the pyspec test keys.
//! It asks for duties, produces blocks, signs them, publishes them, and attests through the pool.
//! A local state follows the published chain and checks every block with every signature.

use std::{
    env, fs,
    net::{SocketAddr, TcpListener},
    path::PathBuf,
    process,
    sync::Arc,
    time::Duration,
};

use axiom_beacon_json::ApiJson;
use axiom_bls::SecretKey;
use axiom_ef_tests::{Case, Vectors, chain_builder::PYSPEC_GENESIS};
use axiom_http::{Client, ClientConfig, Endpoint, Method, Request, Response, StatusCode};
use axiom_json::{Data, Json};
use axiom_node::{AnchorSource, Clock, ManualClock, Node, NodeConfig, NodeError};
use axiom_ssz::Ssz;
use axiom_state_transition::{KnownVerdict, State, Verification};
use axiom_types::{
    BlsSignature, ChainConfig, Epoch, ForkName, Minimal, Root, Slot, ValidatorIndex,
    accessors::CoreState,
    altair::SyncCommitteeMessage,
    combined,
    constants::{
        DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO, DOMAIN_SYNC_COMMITTEE,
    },
    phase0::{self, AttestationData, SigningData},
};
use tokio::{runtime::Builder, sync::oneshot, task, task::JoinHandle, time};

/// Slots driven: phase0 in epoch 0, Altair in epoch 1, Bellatrix before the merge in epoch 2.
const SLOTS: u64 = 20;

/// Validators of the pyspec genesis.
const VALIDATORS: u64 = 64;

/// The minimal configuration with Altair at epoch 1 and Bellatrix at epoch 2, never merging.
fn schedule() -> ChainConfig {
    ChainConfig::minimal()
        .with_fork_epoch(ForkName::Altair, Epoch(1))
        .with_fork_epoch(ForkName::Bellatrix, Epoch(2))
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

/// A free local TCP port, released for the node to bind.
fn free_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("a local port is free")
}

/// A node from the pyspec genesis, its API client, and the clock it reads.
struct Harness {
    /// The beacon API client.
    client: Client,
    /// The node's clock, set by the test.
    clock: Arc<ManualClock>,
    /// Genesis time, in milliseconds.
    genesis_ms: u64,
    /// Stops the node.
    stop: oneshot::Sender<()>,
    /// The node's task.
    task: JoinHandle<Result<(), NodeError>>,
    /// The genesis file's directory, removed at the end.
    directory: PathBuf,
}

impl Harness {
    /// Starts a node on the genesis, with its clock at slot 1.
    async fn start(genesis: &phase0::BeaconState<Minimal>) -> Self {
        let directory = env::temp_dir().join(format!("axiom-validator-api-{}", process::id()));
        fs::create_dir_all(&directory).expect("temporary directory is writable");
        let path = directory.join("genesis.ssz");
        fs::write(&path, genesis.encode()).expect("temporary directory is writable");
        let address = free_address();
        let config = NodeConfig {
            anchor: Some(AnchorSource::Genesis(path)),
            http_address: Some(address),
            ..NodeConfig::default()
        };
        let genesis_ms = genesis.genesis_time * 1000;
        let clock = Arc::new(ManualClock::at(genesis_ms));
        let (stop, stopped) = oneshot::channel::<()>();
        let task = task::spawn(Node::<Minimal>::run(
            schedule(),
            config,
            Arc::clone(&clock) as Arc<dyn Clock>,
            async move {
                let _stopped = stopped.await;
            },
        ));
        let client = Client::new(
            Endpoint::parse(&format!("http://{address}")).expect("a socket address is a URL"),
            ClientConfig::default(),
        );
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
        Self {
            client,
            clock,
            genesis_ms,
            stop,
            task,
            directory,
        }
    }

    /// Sets the clock to the start of a slot, and lets the node's ticker see it.
    async fn at_slot(&self, slot: Slot) {
        self.clock.set(self.genesis_ms + slot.0 * 6000);
        time::sleep(Duration::from_millis(600)).await;
    }

    /// Sends a request, which the node must answer.
    async fn send(&self, request: Request) -> Response {
        self.client.send(&request).await.expect("node answers")
    }

    /// Sends a JSON body to a route.
    async fn post_json(&self, path: &str, body: &Json, fork: ForkName) -> Response {
        let request = Request::new(Method::Post, path)
            .with_header("eth-consensus-version", fork.to_string())
            .with_body("application/json", body.to_string().into_bytes());
        self.send(request).await
    }

    /// The JSON reply of a GET route, which must succeed.
    async fn get_json(&self, path: &str) -> Json {
        let response = self.send(Request::new(Method::Get, path)).await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "{path}: {}",
            text(&response)
        );
        Json::parse(&response.body).expect("the reply is JSON")
    }

    /// Stops the node and removes its files.
    async fn stop(self) {
        let _sent = self.stop.send(());
        let _finished = self.task.await;
        let _ignored = fs::remove_dir_all(&self.directory);
    }
}

/// A response's body as text.
fn text(response: &Response) -> String {
    String::from_utf8_lossy(&response.body).into_owned()
}

/// A decimal string member of a JSON object.
fn number(value: &Json, name: &str) -> u64 {
    value
        .get(name)
        .and_then(Json::as_str)
        .and_then(|text| text.parse().ok())
        .unwrap_or_else(|| panic!("{name} is a decimal string"))
}

/// The pyspec genesis, or nothing when the vectors are absent.
fn pyspec_genesis() -> Option<phase0::BeaconState<Minimal>> {
    let case = Case::new(Vectors::locate()?.consensus().join(PYSPEC_GENESIS));
    Some(case.ssz("state").expect("the genesis vector decodes"))
}

/// What one produced block carried.
#[derive(Clone, Copy, Debug)]
struct Included {
    /// The block's slot.
    slot: Slot,
    /// Validators its attestations name.
    attesters: usize,
    /// Sync committee seats that signed, from Altair on.
    sync: Option<usize>,
}

impl Harness {
    /// Produces, signs, and publishes the block of a slot, and applies it to the local state.
    async fn propose(
        &self,
        local: &mut State<Minimal>,
        advanced: &State<Minimal>,
        slot: Slot,
    ) -> (combined::BeaconBlock<Minimal>, Included) {
        let config = schedule();
        let epoch = slot.epoch::<Minimal>();
        let fork = advanced.fork_name();
        let harness = self;
        // Duties: the node's proposer of the slot is the local state's.
        let duties = harness
            .get_json(&format!("/eth/v1/validator/duties/proposer/{epoch}"))
            .await;
        let data = duties
            .get("data")
            .and_then(Json::as_array)
            .expect("the node answers as the API defines");
        assert_eq!(data.len(), 8);
        let duty = data
            .iter()
            .find(|duty| number(duty, "slot") == slot.0)
            .expect("the node answers as the API defines");
        let proposer = ValidatorIndex(number(duty, "validator_index"));
        assert_eq!(
            proposer,
            advanced
                .beacon_proposer_index()
                .expect("the slot has a proposer")
        );

        // Production: the validator reveals its randao and the node builds the block.
        let reveal_root =
            SigningData::signing_root(&epoch, advanced.beacon().domain(DOMAIN_RANDAO, epoch));
        let reveal = sign(proposer, reveal_root);
        let path = format!(
            "/eth/v3/validator/blocks/{slot}?randao_reveal={}&graffiti=0x{}",
            reveal.0.to_data(),
            "61".repeat(32)
        );
        let response = harness
            .send(
                Request::new(Method::Get, &path).with_header("accept", "application/octet-stream"),
            )
            .await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "slot {slot}: {}",
            text(&response)
        );
        assert_eq!(
            response.headers.get("eth-consensus-version"),
            Some(fork.as_str())
        );
        assert_eq!(
            response.headers.get("eth-execution-payload-blinded"),
            Some("false")
        );
        let block = combined::BeaconBlock::<Minimal>::decode(&response.body, fork)
            .expect("the node answers as the API defines");
        assert_eq!(block.slot(), slot);

        // The validator signs and publishes; the local state checks every signature.
        let domain = advanced.beacon().domain(DOMAIN_BEACON_PROPOSER, epoch);
        let signing_root = SigningData {
            object_root: block.hash_tree_root(),
            domain,
        }
        .hash_tree_root();
        let signed =
            combined::SignedBeaconBlock::from_parts(block.clone(), sign(proposer, signing_root));
        let publish = Request::new(Method::Post, "/eth/v2/beacon/blocks")
            .with_header("eth-consensus-version", fork.to_string())
            .with_body("application/octet-stream", signed.encode());
        let response = harness.send(publish).await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "slot {slot}: {}",
            text(&response)
        );
        local
            .state_transition(&config, &signed, Verification::Verify, &KnownVerdict(true))
            .expect("the produced block is valid with every signature");
        let attesters: usize = block
            .committee_votes()
            .iter()
            .map(|vote| vote.bits.iter().filter(|bit| **bit).count())
            .sum();
        let sync = signed
            .sync_aggregate()
            .map(|aggregate| aggregate.sync_committee_bits.count_ones());
        (
            block,
            Included {
                slot,
                attesters,
                sync,
            },
        )
    }

    /// Every attester of the slot votes for the new head, one by one, through the pool.
    async fn attest(&self, local: &State<Minimal>, block_root: Root, slot: Slot, fork: ForkName) {
        let epoch = slot.epoch::<Minimal>();
        let harness = self;
        // Attestation: every attester of the slot votes for the new head, one by one.
        let indices = Json::Array(
            (0..VALIDATORS)
                .map(|index| Json::from(index.to_string()))
                .collect(),
        );
        let duties = harness
            .post_json(
                &format!("/eth/v1/validator/duties/attester/{epoch}"),
                &indices,
                fork,
            )
            .await;
        assert_eq!(duties.status, StatusCode::OK, "{}", text(&duties));
        let duties = Json::parse(&duties.body).expect("the node answers as the API defines");
        let mut votes = Vec::new();
        for duty in duties
            .get("data")
            .and_then(Json::as_array)
            .expect("the node answers as the API defines")
        {
            if number(duty, "slot") != slot.0 {
                continue;
            }
            let committee = number(duty, "committee_index");
            let reply = harness
                .get_json(&format!(
                    "/eth/v1/validator/attestation_data?slot={slot}&committee_index={committee}"
                ))
                .await;
            let data = AttestationData::from_json(
                reply
                    .get("data")
                    .expect("the node answers as the API defines"),
            )
            .expect("the node answers as the API defines");
            assert_eq!(data.beacon_block_root, block_root);
            let attester = ValidatorIndex(number(duty, "validator_index"));
            let domain = local.beacon().domain(DOMAIN_BEACON_ATTESTER, epoch);
            let mut bits = phase0::AggregationBits::<Minimal>::with_len(number(
                duty,
                "committee_length",
            ) as usize)
            .expect("the node answers as the API defines");
            bits.set(number(duty, "validator_committee_index") as usize, true);
            let vote = phase0::Attestation::<Minimal> {
                aggregation_bits: bits,
                signature: sign(attester, SigningData::signing_root(&data, domain)),
                data,
            };
            votes.push(vote.to_json());
        }
        assert_eq!(votes.len(), 8, "slot {slot}");
        let response = harness
            .post_json(
                "/eth/v2/beacon/pool/attestations",
                &Json::Array(votes),
                fork,
            )
            .await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "slot {slot}: {}",
            text(&response)
        );
    }

    /// From Altair, every sync committee seat signs the new head.
    async fn sign_sync(
        &self,
        local: &State<Minimal>,
        block_root: Root,
        slot: Slot,
        fork: ForkName,
    ) {
        let epoch = slot.epoch::<Minimal>();
        let harness = self;
        let indices = Json::Array(
            (0..VALIDATORS)
                .map(|index| Json::from(index.to_string()))
                .collect(),
        );
        // Sync: from Altair, every seat signs the new head for the next block.
        if fork != ForkName::Phase0 {
            let duties = harness
                .post_json(
                    &format!("/eth/v1/validator/duties/sync/{epoch}"),
                    &indices,
                    fork,
                )
                .await;
            let duties = Json::parse(&duties.body).expect("the node answers as the API defines");
            let root = block_root;
            let domain = local.beacon().domain(DOMAIN_SYNC_COMMITTEE, epoch);
            let messages: Vec<Json> = duties
                .get("data")
                .and_then(Json::as_array)
                .expect("the node answers as the API defines")
                .iter()
                .map(|duty| {
                    let validator = ValidatorIndex(number(duty, "validator_index"));
                    SyncCommitteeMessage {
                        slot,
                        beacon_block_root: root,
                        validator_index: validator,
                        signature: sign(validator, SigningData::signing_root(&root, domain)),
                    }
                    .to_json()
                })
                .collect();
            let response = harness
                .post_json(
                    "/eth/v1/beacon/pool/sync_committees",
                    &Json::Array(messages),
                    fork,
                )
                .await;
            assert_eq!(
                response.status,
                StatusCode::OK,
                "slot {slot}: {}",
                text(&response)
            );
        }
    }

    /// An aggregator gets the best aggregate of committee 0's vote, with all 4 members.
    async fn check_aggregate(&self, slot: Slot) {
        let harness = self;
        // An aggregator asks for the best aggregate of committee 0's vote.
        let reply = harness
            .get_json(&format!(
                "/eth/v1/validator/attestation_data?slot={slot}&committee_index=0"
            ))
            .await;
        let data = AttestationData::from_json(
            reply
                .get("data")
                .expect("the node answers as the API defines"),
        )
        .expect("the node answers as the API defines");
        let aggregate = harness
            .get_json(&format!(
                "/eth/v2/validator/aggregate_attestation?attestation_data_root={}&slot={slot}&committee_index=0",
                data.hash_tree_root()
            ))
            .await;
        let attestation = phase0::Attestation::<Minimal>::from_json(
            aggregate
                .get("data")
                .expect("the node answers as the API defines"),
        )
        .expect("the node answers as the API defines");
        assert_eq!(attestation.aggregation_bits.count_ones(), 4, "slot {slot}");
    }
}

#[test]
fn a_validator_client_proposes_attests_and_syncs_through_the_api() {
    let Some(genesis) = pyspec_genesis() else {
        return;
    };
    let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let harness = Harness::start(&genesis).await;
        let config = schedule();
        let mut local = State::<Minimal>::new(genesis);
        let mut included = Vec::new();

        for slot in (1..=SLOTS).map(Slot) {
            harness.at_slot(slot).await;
            let mut advanced = local.clone();
            advanced.process_slots(&config, slot).unwrap();
            let fork = advanced.fork_name();
            let (block, carried) = harness.propose(&mut local, &advanced, slot).await;
            included.push(carried);
            let root = block.hash_tree_root();
            harness.attest(&local, root, slot, fork).await;
            if fork != ForkName::Phase0 {
                harness.sign_sync(&local, root, slot, fork).await;
            }
            harness.check_aggregate(slot).await;
        }
        harness.stop().await;

        // From slot 2 on, each block carries the 8 votes of the slot before.
        // From slot 9, the second Altair slot, each also carries all 32 sync signatures.
        for Included {
            slot,
            attesters,
            sync,
        } in included
        {
            let expected_votes = if slot.0 >= 2 { 8 } else { 0 };
            assert_eq!(attesters, expected_votes, "slot {slot}");
            let expected_sync = match slot.0 {
                0..8 => None,
                8 => Some(0),
                _ => Some(32),
            };
            assert_eq!(sync, expected_sync, "slot {slot}");
        }
    });
}
