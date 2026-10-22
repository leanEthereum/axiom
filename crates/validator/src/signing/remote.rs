//! A key held by a remote signer, reached over the remote signing API.

use std::sync::Arc;

use axiom_beacon_json::{ApiJson, ApiJsonError, Fields};
use axiom_http::{Client, HttpError, Method, Request, StatusCode};
use axiom_json::{Data, Json, ParseError};
use axiom_types::{BlsPubkey, BlsSignature, Epoch, ForkName, Preset, Root};
use thiserror::Error;

use crate::signing::{AggregateAndProofRef, DomainScope, SigningContext, SigningRequest};

/// Media type of the request and response bodies.
const JSON: &str = "application/json";

/// A validator key that a remote signer holds and signs with.
///
/// The client sends the message, its fork, and the signing root it computed.
/// The signer recomputes the root, applies its own protection, and returns the signature.
/// See the `ethereum/remote-signing-api` repository.
#[derive(Clone, Debug)]
pub struct RemoteSigner {
    /// The signer's HTTP endpoint, shared by every key it holds.
    client: Arc<Client>,
    /// The key to sign with.
    pubkey: BlsPubkey,
}

impl RemoteSigner {
    /// A key held by the signer behind a client.
    #[must_use]
    pub const fn new(client: Arc<Client>, pubkey: BlsPubkey) -> Self {
        Self { client, pubkey }
    }

    /// The key.
    #[must_use]
    pub const fn pubkey(&self) -> BlsPubkey {
        self.pubkey
    }

    /// The URL of the signer, as configured.
    #[must_use]
    pub fn url(&self) -> String {
        let endpoint = self.client.endpoint();
        format!("http://{}:{}", endpoint.host(), endpoint.port())
    }

    /// The keys a signer holds.
    ///
    /// # Errors
    ///
    /// Fails when the signer is unreachable or answers with anything but a list of keys.
    pub async fn public_keys(client: &Client) -> Result<Vec<BlsPubkey>, RemoteError> {
        let request =
            Request::new(Method::Get, "/api/v1/eth2/publicKeys").with_header("accept", JSON);
        let response = client.send(&request).await?;
        if !response.status.is_success() {
            return Err(RemoteError::Status(response.status));
        }
        let json = Json::parse(&response.body)?;
        Ok(Vec::<BlsPubkey>::from_json(&json)?)
    }

    /// Asks the signer to sign a message, whose signing root is given for its check.
    ///
    /// # Errors
    ///
    /// Fails when the message has no remote form, the signer refuses, or the answer is malformed.
    pub async fn sign<P: Preset>(
        &self,
        request: &SigningRequest<'_, P>,
        signing_root: Root,
        context: &SigningContext,
    ) -> Result<BlsSignature, RemoteError> {
        let body = RemoteBody::new(request, signing_root, context)?;
        let target = format!("/api/v1/eth2/sign/{}", self.pubkey.0.to_data());
        let http = Request::new(Method::Post, &target)
            .with_header("accept", JSON)
            .with_body(JSON, body.0.to_string().into_bytes());
        let response = self.client.send(&http).await?;
        if !response.status.is_success() {
            return Err(RemoteError::Status(response.status));
        }
        RemoteBody::signature(&response.body)
    }
}

/// The JSON body of one signing request.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RemoteBody(Json);

impl RemoteBody {
    /// The body for a message: its type, its fork, the root, and the message itself.
    fn new<P: Preset>(
        request: &SigningRequest<'_, P>,
        signing_root: Root,
        context: &SigningContext,
    ) -> Result<Self, RemoteError> {
        let kind = request.kind();
        let epoch = match request.domain_scope() {
            DomainScope::Epoch(epoch) | DomainScope::VoluntaryExit(epoch) => epoch,
            DomainScope::Genesis | DomainScope::PreGenesis => Epoch::GENESIS,
        };
        let fork = context.config().fork_at(epoch);
        let version = Json::from(fork.as_str().to_uppercase());
        let (member, message) = match request {
            SigningRequest::Block(_) if !Self::takes_block_headers(fork) => {
                return Err(RemoteError::Unsupported { kind, fork });
            }
            SigningRequest::Block(header) => (
                "beacon_block",
                Json::from([("version", version), ("block_header", header.to_json())]),
            ),
            SigningRequest::RandaoReveal(epoch) => {
                ("randao_reveal", Json::from([("epoch", epoch.to_json())]))
            }
            SigningRequest::Attestation(data) => ("attestation", data.to_json()),
            SigningRequest::AggregationSlot(slot) => {
                ("aggregation_slot", Json::from([("slot", slot.to_json())]))
            }
            SigningRequest::AggregateAndProof(message) => {
                let data = match message {
                    AggregateAndProofRef::Phase0(message) => message.to_json(),
                    AggregateAndProofRef::Electra(message) => message.to_json(),
                    AggregateAndProofRef::Gloas(message) => message.to_json(),
                };
                (
                    "aggregate_and_proof",
                    Json::from([("version", version), ("data", data)]),
                )
            }
            SigningRequest::SyncCommitteeMessage {
                slot,
                beacon_block_root,
            } => (
                "sync_committee_message",
                Json::from([
                    ("beacon_block_root", beacon_block_root.to_json()),
                    ("slot", slot.to_json()),
                ]),
            ),
            SigningRequest::SyncSelectionProof(data) => {
                ("sync_aggregator_selection_data", data.to_json())
            }
            SigningRequest::ContributionAndProof(message) => {
                ("contribution_and_proof", message.to_json())
            }
            SigningRequest::PayloadAttestation(data) => (
                "payload_attestation_message",
                Json::from([("version", version), ("data", data.to_json())]),
            ),
            SigningRequest::ProposerPreferences(preferences) => (
                "proposer_preferences",
                Json::from([("version", version), ("data", preferences.to_json())]),
            ),
            SigningRequest::VoluntaryExit(exit) => ("voluntary_exit", exit.to_json()),
            SigningRequest::ValidatorRegistration(registration) => {
                ("validator_registration", registration.to_json())
            }
            SigningRequest::Deposit(message) => (
                "deposit",
                Json::from([
                    ("pubkey", message.pubkey.to_json()),
                    (
                        "withdrawal_credentials",
                        message.withdrawal_credentials.to_json(),
                    ),
                    ("amount", message.amount.to_json()),
                    (
                        "genesis_fork_version",
                        context.config().genesis_fork_version.to_json(),
                    ),
                ]),
            ),
            SigningRequest::ExecutionPayloadEnvelope(envelope) => (
                "execution_payload_envelope",
                Json::from([("version", version), ("data", envelope.to_json())]),
            ),
            // The API carries no credential change.
            SigningRequest::BlsToExecutionChange(_) => {
                return Err(RemoteError::Unsupported { kind, fork });
            }
        };
        let fork_info = Json::from([
            ("fork", context.fork(epoch).to_json()),
            (
                "genesis_validators_root",
                context.genesis_validators_root().to_json(),
            ),
        ]);
        Ok(Self(Json::from([
            ("type", Json::from(kind)),
            ("fork_info", fork_info),
            ("signingRoot", signing_root.to_json()),
            (member, message),
        ])))
    }

    /// Whether the API signs a block of a fork from its header alone.
    ///
    /// Phase0 and Altair requests carry the whole block, which this client does not encode.
    const fn takes_block_headers(fork: ForkName) -> bool {
        match fork {
            ForkName::Phase0 | ForkName::Altair => false,
            ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb
            | ForkName::Electra
            | ForkName::Fulu
            | ForkName::Gloas => true,
        }
    }

    /// Reads the signature from a response, in its JSON form or as bare hex text.
    fn signature(body: &[u8]) -> Result<BlsSignature, RemoteError> {
        let text = String::from_utf8_lossy(body);
        let text = text.trim();
        if text.starts_with('{') {
            let json = Json::parse(text)?;
            return Ok(Fields::of(&json)?.required("signature")?);
        }
        Ok(BlsSignature::from_json(&Json::from(text))?)
    }
}

/// Why a remote signer did not sign.
#[derive(Debug, Error)]
pub enum RemoteError {
    /// The remote signing API has no form for this message at this fork.
    #[error("the remote signing API cannot carry a {kind} message at {fork}")]
    Unsupported {
        /// The message kind.
        kind: &'static str,
        /// The fork of the message.
        fork: ForkName,
    },
    /// The signer could not be reached.
    #[error("remote signer unreachable: {0}")]
    Http(#[from] HttpError),
    /// The signer answered with an error status.
    #[error("remote signer refused with status {0}")]
    Status(StatusCode),
    /// The answer is not JSON.
    #[error("remote signer answer is not JSON: {0}")]
    Parse(#[from] ParseError),
    /// The answer is JSON of the wrong shape.
    #[error("remote signer answer is malformed: {0}")]
    Json(#[from] ApiJsonError),
}

#[cfg(test)]
mod tests {
    use std::{sync::Mutex, time::Duration};

    use axiom_bls::{PublicKey, SecretKey, Signature};
    use axiom_http::{ClientConfig, Endpoint, Response, Router, Server, ServerConfig};
    use axiom_types::{
        BuilderIndex, ChainConfig, CommitteeIndex, Minimal, Slot, gloas,
        phase0::{AttestationData, BeaconBlockHeader, Checkpoint},
    };
    use tokio::{runtime::Builder, sync::oneshot, task};

    use super::*;

    /// The secret key 7, which the stand-in signer holds.
    fn secret() -> SecretKey {
        let mut bytes = [0; 32];
        bytes[31] = 7;
        SecretKey::from_bytes(&bytes).unwrap()
    }

    /// A stand-in signer: it records each request body and signs the root it was sent.
    fn router(bodies: Arc<Mutex<Vec<Json>>>) -> Router {
        Router::new().route(
            Method::Post,
            "/api/v1/eth2/sign/{identifier}",
            move |request| {
                let bodies = Arc::clone(&bodies);
                async move {
                    let body = Json::parse(&request.body).unwrap();
                    let root = Fields::of(&body)
                        .unwrap()
                        .required::<Root>("signingRoot")
                        .unwrap();
                    bodies.lock().unwrap().push(body);
                    let signature = BlsSignature(secret().sign(&root.0).to_bytes());
                    let reply = Json::from([("signature", signature.to_json())]);
                    Response::new(StatusCode::OK).with_body(JSON, reply.to_string().into_bytes())
                }
            },
        )
    }

    #[test]
    fn an_attestation_is_signed_remotely_with_its_fork_and_root() {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                // Fixture state: a signer on a loopback port, holding the key 7.
                let bodies = Arc::new(Mutex::new(Vec::new()));
                let server = Server::bind(
                    "127.0.0.1:0",
                    router(Arc::clone(&bodies)),
                    ServerConfig::default(),
                )
                .await
                .unwrap();
                let address = server.local_addr().unwrap();
                let (stop, stopped) = oneshot::channel::<()>();
                let serving = task::spawn(server.serve(async {
                    let _stopped = stopped.await;
                }));
                let config = ClientConfig {
                    request_timeout: Duration::from_secs(5),
                    ..ClientConfig::default()
                };
                let client = Client::new(
                    Endpoint::parse(&format!("http://{address}")).unwrap(),
                    config,
                );
                let pubkey = BlsPubkey(secret().public_key().to_bytes());
                let signer = RemoteSigner::new(Arc::new(client), pubkey);

                // A vote at slot 9 on the minimal chain.
                let context = SigningContext::new(Arc::new(ChainConfig::minimal()), Root([3; 32]));
                let data = AttestationData {
                    slot: Slot(9),
                    index: CommitteeIndex(0),
                    beacon_block_root: Root([4; 32]),
                    source: Checkpoint::default(),
                    target: Checkpoint {
                        epoch: Epoch(1),
                        root: Root([4; 32]),
                    },
                };
                let request = SigningRequest::<Minimal>::Attestation(&data);
                let root = context.signing_root(&request);
                let signature = signer.sign(&request, root, &context).await.unwrap();

                // The signature verifies over the root the client computed.
                let public = PublicKey::from_bytes(&pubkey.0).unwrap();
                assert!(
                    Signature::from_bytes(&signature.0)
                        .unwrap()
                        .verify(&public, &root.0)
                );

                // The body named the type, the fork record of epoch 1, and the vote itself.
                let body = bodies.lock().unwrap().pop().unwrap();
                let expected = Json::from([
                    ("type", Json::from("ATTESTATION")),
                    (
                        "fork_info",
                        Json::from([
                            ("fork", context.fork(Epoch(1)).to_json()),
                            ("genesis_validators_root", Root([3; 32]).to_json()),
                        ]),
                    ),
                    ("signingRoot", root.to_json()),
                    ("attestation", data.to_json()),
                ]);
                assert_eq!(body, expected);

                let _stopping = stop.send(());
                serving.await.unwrap();
            });
    }

    #[test]
    fn a_phase0_block_has_no_remote_form_here() {
        // The minimal chain is phase0 throughout, whose block requests need the whole block.
        let context = SigningContext::new(Arc::new(ChainConfig::minimal()), Root([3; 32]));
        let header = BeaconBlockHeader::default();
        let request = SigningRequest::<Minimal>::Block(&header);
        assert!(matches!(
            RemoteBody::new(&request, Root::ZERO, &context),
            Err(RemoteError::Unsupported {
                kind: "BLOCK_V2",
                fork: ForkName::Phase0
            })
        ));
    }

    #[test]
    fn an_envelope_travels_whole_with_its_fork() {
        // Fixture state: Gloas from genesis, an envelope for slot 3 by builder 7.
        let config = ChainConfig::minimal().with_forks_at_genesis(ForkName::Gloas);
        let context = SigningContext::new(Arc::new(config), Root([3; 32]));
        let mut envelope = gloas::ExecutionPayloadEnvelope::<Minimal>::default();
        envelope.payload.slot_number = 3;
        envelope.builder_index = BuilderIndex(7);
        let request = SigningRequest::<Minimal>::ExecutionPayloadEnvelope(&envelope);

        // The body names the fork, and the signer can rebuild the root from the whole envelope.
        let body = RemoteBody::new(&request, Root([9; 32]), &context).unwrap();
        let expected = Json::from([
            ("type", Json::from("EXECUTION_PAYLOAD_ENVELOPE")),
            (
                "fork_info",
                Json::from([
                    ("fork", context.fork(Epoch(0)).to_json()),
                    ("genesis_validators_root", Root([3; 32]).to_json()),
                ]),
            ),
            ("signingRoot", Root([9; 32]).to_json()),
            (
                "execution_payload_envelope",
                Json::from([
                    ("version", Json::from("GLOAS")),
                    ("data", envelope.to_json()),
                ]),
            ),
        ]);
        assert_eq!(body, RemoteBody(expected));
    }
}
