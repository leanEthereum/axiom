//! The relay client and relay set against in-process mock relays, end to end over HTTP.

use std::{future::Future, net::TcpListener, slice, time::Duration};

use axiom_bls::SecretKey;
use axiom_builder_client::{
    BidError, BidRequest, BuilderError, GasLimitTarget, RelayClient, RelayFailure, RelayFailures,
    RelaySet, RelayTimeouts, RevealError, RevealedBlobs, RevealedPayload, UnblindedBlock,
    mock::{HeaderRequest, MockRelay},
};
use axiom_http::HttpError;
use axiom_ssz::{Ssz, U256};
use axiom_types::{
    BlsPubkey, BlsSignature, Bytes32, ChainConfig, ExecutionAddress, ForkName, Hash32,
    KzgCommitment, KzgProof, Minimal, Slot,
    bellatrix::{SignedValidatorRegistrationV1, UnblindError, ValidatorRegistrationV1},
    capella,
    combined::{BlindedBlockError, SignedBeaconBlock, SignedBlindedBeaconBlock, SignedBuilderBid},
    deneb,
};

/// Runs a test body on a single-threaded runtime with timers and sockets.
fn run<F: Future<Output = ()>>(test: F) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime builds")
        .block_on(test);
}

/// The minimal chain, whose genesis version fixes the builder domain.
fn config() -> ChainConfig {
    ChainConfig::minimal()
}

/// The builder's key: the scalar 7.
fn builder_key() -> SecretKey {
    let mut bytes = [0; 32];
    bytes[31] = 7;
    SecretKey::from_bytes(&bytes).expect("7 is a valid scalar")
}

/// The builder's public key bytes.
fn builder_pubkey() -> BlsPubkey {
    BlsPubkey(builder_key().public_key().to_bytes())
}

/// The fixture payload of a fork: slot 40's terms, on parent 0x11...11, block hash set by the test.
fn deneb_payload(block_hash: u8) -> deneb::ExecutionPayload<Minimal> {
    deneb::ExecutionPayload {
        parent_hash: Hash32([0x11; 32]),
        prev_randao: Bytes32([0x33; 32]),
        gas_limit: 30_000_000,
        timestamp: 1_700_000_480,
        block_hash: Hash32([block_hash; 32]),
        ..deneb::ExecutionPayload::default()
    }
}

/// The Capella payload with the same terms.
fn capella_payload(block_hash: u8) -> capella::ExecutionPayload<Minimal> {
    capella::ExecutionPayload {
        parent_hash: Hash32([0x11; 32]),
        prev_randao: Bytes32([0x33; 32]),
        gas_limit: 30_000_000,
        timestamp: 1_700_000_480,
        block_hash: Hash32([block_hash; 32]),
        ..capella::ExecutionPayload::default()
    }
}

/// The request of slot 40 in a fork, whose terms the fixture payloads meet.
///
/// The withdrawals root is that of no withdrawals, as the fixture payloads carry none.
fn request(fork: ForkName) -> BidRequest {
    BidRequest {
        fork,
        slot: Slot(40),
        parent_hash: Hash32([0x11; 32]),
        proposer: BlsPubkey([0x22; 48]),
        timestamp: 1_700_000_480,
        prev_randao: Bytes32([0x33; 32]),
        gas_limit: GasLimitTarget {
            parent: 30_000_000,
            target: 30_000_000,
        },
        withdrawals_root: Some(capella::Withdrawals::<Minimal>::default().hash_tree_root()),
    }
}

/// Signs a bid with the builder key.
fn sign(bid: SignedBuilderBid<Minimal>) -> SignedBuilderBid<Minimal> {
    let signature = BlsSignature(
        builder_key()
            .sign(bid.signing_root(&config()).as_bytes())
            .to_bytes(),
    );
    match bid {
        SignedBuilderBid::Capella(mut signed) => {
            signed.signature = signature;
            SignedBuilderBid::Capella(signed)
        }
        SignedBuilderBid::Deneb(mut signed) => {
            signed.signature = signature;
            SignedBuilderBid::Deneb(signed)
        }
        _ => unreachable!("the tests bid in Capella and Deneb only"),
    }
}

/// A signed Capella bid of some gwei for a payload.
fn capella_bid(
    payload: &capella::ExecutionPayload<Minimal>,
    gwei: u64,
) -> SignedBuilderBid<Minimal> {
    let mut signed = capella::SignedBuilderBid::<Minimal>::default();
    signed.message.header = payload.into();
    signed.message.value = U256::from_u64(gwei * 1_000_000_000);
    signed.message.pubkey = builder_pubkey();
    sign(SignedBuilderBid::Capella(signed))
}

/// A signed Deneb bid of some gwei for a payload with one blob committed as 0x02...02.
fn deneb_bid(payload: &deneb::ExecutionPayload<Minimal>, gwei: u64) -> SignedBuilderBid<Minimal> {
    let mut signed = deneb::SignedBuilderBid::<Minimal>::default();
    signed.message.header = payload.into();
    signed
        .message
        .blob_kzg_commitments
        .push(KzgCommitment([2; 48]))
        .expect("one commitment fits");
    signed.message.value = U256::from_u64(gwei * 1_000_000_000);
    signed.message.pubkey = builder_pubkey();
    sign(SignedBuilderBid::Deneb(signed))
}

/// The Deneb block of slot 40 on a payload, committing to the one blob, signed with 0x07...07.
fn deneb_block(payload: deneb::ExecutionPayload<Minimal>) -> deneb::SignedBeaconBlock<Minimal> {
    let mut block = deneb::BeaconBlock::<Minimal> {
        slot: Slot(40),
        ..deneb::BeaconBlock::default()
    };
    block.body.execution_payload = payload;
    block
        .body
        .blob_kzg_commitments
        .push(KzgCommitment([2; 48]))
        .expect("one commitment fits");
    deneb::SignedBeaconBlock {
        message: block,
        signature: BlsSignature([7; 96]),
    }
}

/// The block in blinded form, as the proposer signs it.
fn blinded(block: &deneb::SignedBeaconBlock<Minimal>) -> SignedBlindedBeaconBlock<Minimal> {
    SignedBlindedBeaconBlock::Deneb(deneb::SignedBlindedBeaconBlock {
        message: block.message.clone().into(),
        signature: block.signature,
    })
}

/// The honest reveal of a payload: it, its one blob, the commitment, and one proof.
fn deneb_reveal(
    payload: deneb::ExecutionPayload<Minimal>,
) -> deneb::ExecutionPayloadAndBlobsBundle<Minimal> {
    let mut revealed = deneb::ExecutionPayloadAndBlobsBundle::<Minimal> {
        execution_payload: payload,
        ..deneb::ExecutionPayloadAndBlobsBundle::default()
    };
    let bundle = &mut revealed.blobs_bundle;
    bundle
        .commitments
        .push(KzgCommitment([2; 48]))
        .expect("fits");
    bundle.proofs.push(KzgProof([3; 48])).expect("fits");
    bundle
        .blobs
        .push(deneb::Blob::<Minimal>::default())
        .expect("fits");
    revealed
}

/// A URL on which nothing listens: a port bound once, then released.
fn dead_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
    let address = listener.local_addr().expect("bound");
    drop(listener);
    format!("http://{address}")
}

#[test]
fn status_follows_the_relay_health() {
    run(async {
        let relay = MockRelay::start().await.expect("mock binds");
        let client = RelayClient::new(relay.url()).expect("mock URL parses");

        // Healthy: 200.
        client.status().await.expect("healthy relay");

        // Unhealthy: 503 with the relay's message.
        relay.set_healthy(false);
        let error = client.status().await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "relay replied with HTTP status 503 Service Unavailable: relay unhealthy"
        );
        relay.stop().await;
    });
}

#[test]
fn registrations_reach_the_relay() {
    run(async {
        let relay = MockRelay::start().await.expect("mock binds");
        let client = RelayClient::new(relay.url()).expect("mock URL parses");

        // Fixture state: two validators asking for a 36 million gas limit at time 1_700_000_000.
        let registrations: Vec<_> = [0x41, 0x42]
            .map(|byte| SignedValidatorRegistrationV1 {
                message: ValidatorRegistrationV1 {
                    fee_recipient: ExecutionAddress([byte; 20]),
                    gas_limit: 36_000_000,
                    timestamp: 1_700_000_000,
                    pubkey: BlsPubkey([byte; 48]),
                },
                signature: BlsSignature([byte; 96]),
            })
            .into();
        client
            .register_validators(&registrations)
            .await
            .expect("registered");
        assert_eq!(relay.registrations(), registrations);
        relay.stop().await;
    });
}

#[test]
fn a_capella_bid_is_fetched_and_verified() {
    run(async {
        let relay = MockRelay::start().await.expect("mock binds");
        let client = RelayClient::new(&relay.url_with_pubkey(&builder_pubkey())).expect("parses");
        let bid = capella_bid(&capella_payload(0x55), 3);
        relay.set_bid(&bid);

        let request = request(ForkName::Capella);
        let fetched = client
            .header::<Minimal>(
                ForkName::Capella,
                request.slot,
                request.parent_hash,
                request.proposer,
            )
            .await
            .expect("the relay answers")
            .expect("the relay bids");
        assert_eq!(fetched, bid);
        let verified = request
            .verify(fetched, &config(), client.pubkey())
            .expect("an honest bid");
        assert_eq!(verified.into_bid(), bid);

        // The request named slot 40, the parent, and the proposer, with a dated 1000 ms deadline.
        assert_eq!(
            relay.header_requests(),
            vec![HeaderRequest {
                slot: Slot(40),
                parent_hash: Hash32([0x11; 32]),
                pubkey: BlsPubkey([0x22; 48]),
                timeout_ms: Some(1_000),
                dated: true,
            }]
        );
        relay.stop().await;
    });
}

#[test]
fn no_bid_is_204_and_a_bid_of_another_fork_is_refused() {
    run(async {
        let relay = MockRelay::start().await.expect("mock binds");
        let client = RelayClient::new(relay.url()).expect("parses");
        let request = request(ForkName::Deneb);
        let ask = || {
            client.header::<Minimal>(
                ForkName::Deneb,
                request.slot,
                request.parent_hash,
                request.proposer,
            )
        };

        // No bid set: 204, nothing offered.
        assert_eq!(ask().await.expect("the relay answers"), None);

        // A Capella bid answering a Deneb request.
        relay.set_bid(&capella_bid(&capella_payload(0x55), 3));
        assert!(matches!(
            ask().await,
            Err(BuilderError::Version {
                expected: ForkName::Deneb,
                actual: ForkName::Capella,
            })
        ));

        // Gloas has no builder API: refused before any call.
        let calls = relay.header_requests().len();
        assert!(matches!(
            client
                .header::<Minimal>(
                    ForkName::Gloas,
                    request.slot,
                    request.parent_hash,
                    request.proposer
                )
                .await,
            Err(BuilderError::NoBuilderApi {
                fork: ForkName::Gloas
            })
        ));
        assert_eq!(relay.header_requests().len(), calls);
        relay.stop().await;
    });
}

#[test]
fn refused_bids_are_reported_per_relay() {
    run(async {
        // Relay 0 offers a bid on parent 0x99...99; relay 1 a bid whose value changed after signing.
        let wrong_parent = MockRelay::start().await.expect("mock binds");
        let mut payload = capella_payload(0x55);
        payload.parent_hash = Hash32([0x99; 32]);
        wrong_parent.set_bid(&capella_bid(&payload, 3));

        let forged = MockRelay::start().await.expect("mock binds");
        let SignedBuilderBid::Capella(mut bid) = capella_bid(&capella_payload(0x56), 3) else {
            unreachable!("built as Capella")
        };
        bid.message.value = U256::from_u64(90_000_000_000);
        forged.set_bid(&SignedBuilderBid::Capella(bid));

        let set = RelaySet::new(vec![
            RelayClient::new(wrong_parent.url()).expect("parses"),
            RelayClient::new(forged.url()).expect("parses"),
        ]);
        let auction = set
            .best_header::<Minimal>(&request(ForkName::Capella), &config())
            .await;

        assert_eq!(auction.winner, None);
        let reasons: Vec<_> = auction
            .failures
            .iter()
            .map(|failure| match &failure.error {
                BuilderError::Bid(error) => (failure.relay.clone(), error.clone()),
                other => panic!("a bid refusal, not {other}"),
            })
            .collect();
        assert_eq!(
            reasons,
            vec![
                (
                    wrong_parent.url().to_owned(),
                    BidError::ParentHash {
                        expected: Hash32([0x11; 32]),
                        actual: Hash32([0x99; 32]),
                    }
                ),
                (
                    forged.url().to_owned(),
                    BidError::BadSignature {
                        pubkey: builder_pubkey(),
                    }
                ),
            ]
        );
        wrong_parent.stop().await;
        forged.stop().await;
    });
}

#[test]
fn the_set_picks_the_highest_bid_and_survives_a_dead_relay() {
    run(async {
        // Fixture state: relay 0 is dead, relay 1 bids 2 gwei, relay 2 bids 5 gwei, relay 3 has no bid.
        let low = MockRelay::start().await.expect("mock binds");
        low.set_bid(&deneb_bid(&deneb_payload(0x61), 2));
        let high = MockRelay::start().await.expect("mock binds");
        let payload = deneb_payload(0x62);
        let winning = deneb_bid(&payload, 5);
        high.set_bid(&winning);
        let silent = MockRelay::start().await.expect("mock binds");

        let dead = dead_url();
        let set = RelaySet::new(vec![
            RelayClient::new(&dead).expect("parses"),
            RelayClient::new(low.url()).expect("parses"),
            RelayClient::new(high.url()).expect("parses"),
            RelayClient::new(silent.url()).expect("parses"),
        ]);
        let auction = set
            .best_header::<Minimal>(&request(ForkName::Deneb), &config())
            .await;

        // The 5 gwei bid wins, from relay 2 alone.
        let winner = auction.winner.expect("two relays bid");
        assert_eq!(winner.relays, vec![2]);
        assert_eq!(winner.bid.into_bid(), winning);

        // The dead relay is the one failure: its connection was refused.
        assert!(matches!(
            auction.failures.as_slice(),
            [RelayFailure { relay, error: BuilderError::Http(HttpError::Io(_)) }] if *relay == dead
        ));

        // The reveal goes to the winning relay only, and completes the block with its blob.
        let block = deneb_block(payload.clone());
        high.set_reveal(&RevealedPayload::Deneb(deneb_reveal(payload.clone())));
        let unblinded = set
            .submit_blinded_block(&blinded(&block))
            .await
            .expect("the winner reveals");
        assert_eq!(
            unblinded,
            UnblindedBlock {
                block: SignedBeaconBlock::Deneb(block.clone()),
                blobs: Some(RevealedBlobs::Deneb(deneb_reveal(payload).blobs_bundle)),
            }
        );
        assert_eq!(
            high.blinded_blocks::<Minimal>().expect("decodes"),
            vec![blinded(&block)]
        );
        assert_eq!(low.blinded_blocks::<Minimal>().expect("decodes"), vec![]);
        low.stop().await;
        high.stop().await;
        silent.stop().await;
    });
}

#[test]
fn a_slow_relay_misses_the_bid_deadline() {
    run(async {
        // Fixture state: the relay holds its bid 300 ms, the client waits 100 ms.
        let relay = MockRelay::start().await.expect("mock binds");
        relay.set_bid(&deneb_bid(&deneb_payload(0x61), 2));
        relay.set_header_delay(Duration::from_millis(300));
        let timeouts = RelayTimeouts {
            header: Duration::from_millis(100),
            ..RelayTimeouts::DEFAULT
        };
        let set = RelaySet::new(vec![
            RelayClient::with_timeouts(relay.url(), timeouts).expect("parses"),
        ]);

        let auction = set
            .best_header::<Minimal>(&request(ForkName::Deneb), &config())
            .await;
        assert_eq!(auction.winner, None);
        assert!(matches!(
            auction.failures.as_slice(),
            [RelayFailure {
                error: BuilderError::Http(HttpError::Timeout { after }),
                ..
            }] if *after == Duration::from_millis(100)
        ));
        relay.stop().await;
    });
}

/// A Deneb bid request for slot 1, as any relay test asks it.
async fn ask(client: &RelayClient) -> Option<SignedBuilderBid<Minimal>> {
    client
        .header::<Minimal>(
            ForkName::Deneb,
            Slot(1),
            Hash32::default(),
            BlsPubkey::default(),
        )
        .await
        .expect("the relay answers")
}

#[test]
fn ssz_is_preferred_once_the_relay_answers_in_it() {
    run(async {
        // Fixture state: a relay bidding for payload 0x64...64 and revealing it honestly.
        let payload = deneb_payload(0x64);
        let bid = deneb_bid(&payload, 5);
        let reveal = RevealedPayload::Deneb(deneb_reveal(payload.clone()));
        let block = blinded(&deneb_block(payload));
        let relay = MockRelay::start().await.expect("mock binds");
        relay.set_bid(&bid);
        relay.set_reveal(&reveal);

        // The bid comes back in SSZ, so the blinded block goes out in SSZ too.
        let client = RelayClient::new(relay.url()).expect("parses");
        assert_eq!(ask(&client).await, Some(bid.clone()));
        assert_eq!(client.submit_blinded_block(&block).await.unwrap(), reveal);

        // A client kept to JSON sends JSON to the same relay.
        let json = RelayClient::new(relay.url()).expect("parses").json_only();
        assert_eq!(ask(&json).await, Some(bid.clone()));
        assert_eq!(json.submit_blinded_block(&block).await.unwrap(), reveal);

        // A relay that answers JSON alone gets JSON from a client that prefers SSZ.
        relay.set_json_only(true);
        assert_eq!(ask(&client).await, Some(bid));
        assert_eq!(client.submit_blinded_block(&block).await.unwrap(), reveal);

        // Each block arrived intact, in SSZ only the first time.
        assert_eq!(relay.blinded_blocks_in_ssz(), [true, false, false]);
        assert_eq!(
            relay.blinded_blocks::<Minimal>().unwrap(),
            [block.clone(), block.clone(), block]
        );
        relay.stop().await;
    });
}

#[test]
fn a_reveal_of_another_payload_is_refused() {
    run(async {
        // Fixture state: the relay bid for payload 0x62...62, then reveals 0x63...63 instead.
        let relay = MockRelay::start().await.expect("mock binds");
        let payload = deneb_payload(0x62);
        relay.set_bid(&deneb_bid(&payload, 5));
        let swapped = deneb_payload(0x63);
        relay.set_reveal(&RevealedPayload::Deneb(deneb_reveal(swapped.clone())));
        let set = RelaySet::new(vec![RelayClient::new(relay.url()).expect("parses")]);
        let auction = set
            .best_header::<Minimal>(&request(ForkName::Deneb), &config())
            .await;
        assert!(auction.winner.is_some());

        let block = deneb_block(payload.clone());
        let error = set
            .submit_blinded_block(&blinded(&block))
            .await
            .unwrap_err();

        // The roots differ, so the block refuses the payload.
        let committed = deneb::ExecutionPayloadHeader::from(&payload).hash_tree_root();
        let actual = swapped.hash_tree_root();
        let BuilderError::AllRelaysFailed(RelayFailures(failures)) = error else {
            panic!("every relay failed, not {error}");
        };
        let reasons: Vec<_> = failures
            .iter()
            .map(|failure| match &failure.error {
                BuilderError::Reveal(error) => (failure.relay.clone(), error.clone()),
                other => panic!("a reveal refusal, not {other}"),
            })
            .collect();
        assert_eq!(
            reasons,
            vec![(
                relay.url().to_owned(),
                RevealError::Unblind(BlindedBlockError::Unblind(UnblindError::PayloadMismatch {
                    committed,
                    actual,
                }))
            )]
        );
        relay.stop().await;
    });
}

#[test]
fn an_unknown_slot_is_submitted_to_every_relay() {
    run(async {
        // Fixture state: no auction ran, so the set knows no winner for slot 40.
        // Relay 0 cannot reveal; relay 1 reveals the payload.
        let blind = MockRelay::start().await.expect("mock binds");
        let revealing = MockRelay::start().await.expect("mock binds");
        let payload = deneb_payload(0x62);
        revealing.set_reveal(&RevealedPayload::Deneb(deneb_reveal(payload.clone())));
        let set = RelaySet::new(vec![
            RelayClient::new(blind.url()).expect("parses"),
            RelayClient::new(revealing.url()).expect("parses"),
        ]);

        let block = deneb_block(payload);
        let unblinded = set
            .submit_blinded_block(&blinded(&block))
            .await
            .expect("relay 1 reveals");
        assert_eq!(unblinded.block, SignedBeaconBlock::Deneb(block.clone()));

        // Both relays received the block.
        assert_eq!(
            blind.blinded_blocks::<Minimal>().expect("decodes"),
            vec![blinded(&block)]
        );
        assert_eq!(
            revealing.blinded_blocks::<Minimal>().expect("decodes"),
            vec![blinded(&block)]
        );
        blind.stop().await;
        revealing.stop().await;
    });
}

#[test]
fn registrations_survive_a_dead_relay() {
    run(async {
        // Fixture state: relay 0 is dead, relay 1 accepts.
        let relay = MockRelay::start().await.expect("mock binds");
        let dead = dead_url();
        let set = RelaySet::new(vec![
            RelayClient::new(&dead).expect("parses"),
            RelayClient::new(relay.url()).expect("parses"),
        ]);
        let registration = SignedValidatorRegistrationV1::default();

        let failures = set
            .register_validators(slice::from_ref(&registration))
            .await;
        assert!(matches!(
            failures.as_slice(),
            [RelayFailure { relay, error: BuilderError::Http(HttpError::Io(_)) }] if *relay == dead
        ));
        assert_eq!(relay.registrations(), vec![registration]);
        relay.stop().await;
    });
}
