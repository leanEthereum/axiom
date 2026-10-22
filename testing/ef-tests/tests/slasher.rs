//! A node with its slasher on catches an equivocating validator and slashes it on chain.
//!
//! The test plays every validator with the pyspec test keys, through the beacon API alone.
//! One validator votes for two heads in one slot: once alone, once as an aggregator.
//! The slasher finds the double vote, the pool takes the evidence, and a produced block carries it.
//! A local state follows the chain and checks every block with every signature.

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
use axiom_slasher::SlasherConfig;
use axiom_ssz::Ssz;
use axiom_state_transition::{KnownVerdict, State, Verification};
use axiom_types::{
    BlsSignature, ChainConfig, Epoch, ForkName, Minimal, Root, Slot, ValidatorIndex,
    accessors::CoreState,
    combined,
    constants::{
        DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO,
        DOMAIN_SELECTION_PROOF,
    },
    phase0::{self, AttestationData, SigningData},
};
use tokio::{runtime::Builder, sync::oneshot, task, task::JoinHandle, time};

/// Slots driven: phase0 in epoch 0, Altair from slot 8.
const SLOTS: u64 = 12;

/// The slot whose first attester equivocates.
const EQUIVOCATION_SLOT: u64 = 3;

/// Validators of the pyspec genesis.
const VALIDATORS: u64 = 64;

/// The minimal configuration with Altair at epoch 1.
fn schedule() -> ChainConfig {
    ChainConfig::minimal().with_fork_epoch(ForkName::Altair, Epoch(1))
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

/// One attester's duty in a slot.
#[derive(Clone, Debug)]
struct Duty {
    /// The attester.
    validator: ValidatorIndex,
    /// Members of its committee.
    committee_length: usize,
    /// Its place in the committee.
    position: usize,
    /// The vote the node asks it to cast.
    data: AttestationData,
}

/// A node with its slasher on, its API client, and the clock it reads.
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
    /// Starts a node on the genesis with a slasher over a 64-epoch window.
    async fn start(genesis: &phase0::BeaconState<Minimal>) -> Self {
        let directory = env::temp_dir().join(format!("axiom-slasher-e2e-{}", process::id()));
        fs::create_dir_all(&directory).expect("temporary directory is writable");
        let path = directory.join("genesis.ssz");
        fs::write(&path, genesis.encode()).expect("temporary directory is writable");
        let address = free_address();
        let config = NodeConfig {
            anchor: Some(AnchorSource::Genesis(path)),
            http_address: Some(address),
            slasher: Some(SlasherConfig {
                history_length: 64,
                validator_chunk_size: 16,
                record_chunk_size: 64,
                ..SlasherConfig::default()
            }),
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

    /// Sets the clock to the start of a slot, and lets the node's ticker and slasher see it.
    async fn at_slot(&self, slot: Slot) {
        self.clock.set(self.genesis_ms + slot.0 * 6000);
        time::sleep(Duration::from_millis(600)).await;
    }

    /// Sends a request, which the node must answer.
    async fn send(&self, request: Request) -> Response {
        self.client.send(&request).await.expect("node answers")
    }

    /// Sends a JSON body to a route, which must accept it.
    async fn post_json(&self, path: &str, body: &Json, fork: ForkName) -> Response {
        let request = Request::new(Method::Post, path)
            .with_header("eth-consensus-version", fork.to_string())
            .with_body("application/json", body.to_string().into_bytes());
        let response = self.send(request).await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "{path}: {}",
            text(&response)
        );
        response
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

    /// Produces, signs, and publishes the block of a slot, and applies it to the local state.
    async fn propose(
        &self,
        local: &mut State<Minimal>,
        advanced: &State<Minimal>,
        slot: Slot,
    ) -> combined::BeaconBlock<Minimal> {
        let epoch = slot.epoch::<Minimal>();
        let fork = advanced.fork_name();
        let proposer = advanced
            .beacon_proposer_index()
            .expect("the slot has a proposer");
        let reveal_root =
            SigningData::signing_root(&epoch, advanced.beacon().domain(DOMAIN_RANDAO, epoch));
        let path = format!(
            "/eth/v3/validator/blocks/{slot}?randao_reveal={}",
            sign(proposer, reveal_root).0.to_data(),
        );
        let request =
            Request::new(Method::Get, &path).with_header("accept", "application/octet-stream");
        let response = self.send(request).await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "slot {slot}: {}",
            text(&response)
        );
        let block = combined::BeaconBlock::<Minimal>::decode(&response.body, fork)
            .expect("the node answers as the API defines");

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
        let response = self.send(publish).await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "slot {slot}: {}",
            text(&response)
        );
        // The local transition checks every signature, the slashing's included.
        local
            .state_transition(
                &schedule(),
                &signed,
                Verification::Verify,
                &KnownVerdict(true),
            )
            .expect("the produced block is valid with every signature");
        block
    }

    /// The attester duties of a slot, with the vote the node asks each attester to cast.
    async fn duties(&self, slot: Slot, fork: ForkName) -> Vec<Duty> {
        let epoch = slot.epoch::<Minimal>();
        let indices = Json::Array(
            (0..VALIDATORS)
                .map(|index| Json::from(index.to_string()))
                .collect(),
        );
        let duties = self
            .post_json(
                &format!("/eth/v1/validator/duties/attester/{epoch}"),
                &indices,
                fork,
            )
            .await;
        let duties = Json::parse(&duties.body).expect("the node answers as the API defines");
        let mut found = Vec::new();
        for duty in duties
            .get("data")
            .and_then(Json::as_array)
            .expect("the node answers as the API defines")
        {
            if number(duty, "slot") != slot.0 {
                continue;
            }
            let committee = number(duty, "committee_index");
            let reply = self
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
            found.push(Duty {
                validator: ValidatorIndex(number(duty, "validator_index")),
                committee_length: number(duty, "committee_length") as usize,
                position: number(duty, "validator_committee_index") as usize,
                data,
            });
        }
        found
    }

    /// One attester's vote, signed, with its single participation bit.
    fn vote(
        local: &State<Minimal>,
        duty: &Duty,
        data: &AttestationData,
    ) -> phase0::Attestation<Minimal> {
        let domain = local
            .beacon()
            .domain(DOMAIN_BEACON_ATTESTER, data.target.epoch);
        let mut bits = phase0::AggregationBits::<Minimal>::with_len(duty.committee_length)
            .expect("a committee fits its bound");
        bits.set(duty.position, true);
        phase0::Attestation {
            aggregation_bits: bits,
            signature: sign(duty.validator, SigningData::signing_root(data, domain)),
            data: data.clone(),
        }
    }

    /// Every attester of the slot votes as the node asks, one by one, through the pool.
    async fn attest(&self, local: &State<Minimal>, duties: &[Duty], fork: ForkName) {
        let votes = duties
            .iter()
            .map(|duty| Self::vote(local, duty, &duty.data).to_json())
            .collect();
        self.post_json(
            "/eth/v2/beacon/pool/attestations",
            &Json::Array(votes),
            fork,
        )
        .await;
    }

    /// An attester votes for another head as an aggregator of its own committee.
    ///
    /// In the minimal preset every member of an 8-member committee aggregates.
    /// See `is_aggregator` in the phase0 validator guide.
    async fn equivocate(&self, local: &State<Minimal>, duty: &Duty, head: Root, fork: ForkName) {
        let data = AttestationData {
            beacon_block_root: head,
            ..duty.data.clone()
        };
        let slot = data.slot;
        let epoch = slot.epoch::<Minimal>();
        let beacon = local.beacon();
        let selection_root =
            SigningData::signing_root(&slot, beacon.domain(DOMAIN_SELECTION_PROOF, epoch));
        let message = phase0::AggregateAndProof {
            aggregator_index: duty.validator,
            aggregate: Self::vote(local, duty, &data),
            selection_proof: sign(duty.validator, selection_root),
        };
        let signing_root =
            SigningData::signing_root(&message, beacon.domain(DOMAIN_AGGREGATE_AND_PROOF, epoch));
        let signed = phase0::SignedAggregateAndProof {
            signature: sign(duty.validator, signing_root),
            message,
        };
        self.post_json(
            "/eth/v2/validator/aggregate_and_proofs",
            &Json::Array(vec![signed.to_json()]),
            fork,
        )
        .await;
    }
}

#[test]
fn an_equivocating_validator_is_slashed_on_chain() {
    let Some(genesis) = pyspec_genesis() else {
        return;
    };
    let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let harness = Harness::start(&genesis).await;
        let config = schedule();
        let mut local = State::<Minimal>::new(genesis);
        let mut parent = Root::ZERO;
        let mut equivocator = None;
        let mut carried = Vec::new();

        for slot in (1..=SLOTS).map(Slot) {
            harness.at_slot(slot).await;
            let mut advanced = local.clone();
            advanced.process_slots(&config, slot).unwrap();
            let fork = advanced.fork_name();
            let block = harness.propose(&mut local, &advanced, slot).await;
            carried.push((slot, block.conflicting_votes()));
            let root = block.hash_tree_root();
            let duties = harness.duties(slot, fork).await;
            harness.attest(&local, &duties, fork).await;

            // Mutation: at slot 3 the first attester also votes for the parent block.
            //
            //     honest vote:       head = block of slot 3, target = epoch 0
            //     conflicting vote:  head = block of slot 2, target = epoch 0
            //
            // Two votes for one target epoch with different data are a double vote.
            if slot.0 == EQUIVOCATION_SLOT {
                let duty = &duties[0];
                harness.equivocate(&local, duty, parent, fork).await;
                equivocator = Some(duty.validator);
            }
            parent = root;
        }
        harness.stop().await;

        // Exactly one block carries the evidence, against the equivocator alone.
        let equivocator = equivocator.expect("slot 3 has an attester");
        let with_evidence: Vec<_> = carried
            .iter()
            .filter(|(_, votes)| !votes.is_empty())
            .collect();
        assert_eq!(with_evidence.len(), 1, "{carried:?}");
        let (slot, votes) = with_evidence[0];
        assert!(slot.0 > EQUIVOCATION_SLOT);
        assert_eq!(votes.len(), 1);
        assert_eq!(votes[0].common_signers(), [equivocator]);

        // The chain slashed the equivocator, and nobody else.
        let slashed: Vec<ValidatorIndex> = local
            .beacon()
            .validators()
            .iter()
            .enumerate()
            .filter(|(_, validator)| validator.slashed)
            .map(|(index, _)| ValidatorIndex::from(index))
            .collect();
        assert_eq!(slashed, [equivocator]);
    });
}
