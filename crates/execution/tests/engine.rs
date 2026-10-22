//! The engine client against the in-process mock engine, end to end over HTTP and JWT.

use std::{
    future::Future,
    time::{SystemTime, UNIX_EPOCH},
};

use axiom_execution::{
    BlobAndProofV1, BlobAndProofV2, BlobsBundleV1, BlobsBundleV2, CAPABILITIES, EngineClient,
    EngineError, ForkchoiceState, ForkchoiceUpdated, ForkchoiceVersion, GetBlobsResponse,
    GetPayloadResponse, GetPayloadResponseV2, GetPayloadResponseV3, GetPayloadResponseV4,
    GetPayloadResponseV5, GetPayloadResponseV6, JsonCodec, JwtSecret, NewPayload,
    PayloadAttributes, PayloadAttributesV1, PayloadAttributesV2, PayloadAttributesV3,
    PayloadAttributesV4, PayloadId, PayloadStatus, PayloadStatusKind, RpcError, SyncStatus,
    WireError, WireErrorKind,
    mock::{MockEngine, RecordedCall},
};
use axiom_http::StatusCode;
use axiom_json::{Data, Json};
use axiom_ssz::{ByteList, ByteVector, List, ProgressiveList, U256, Vector};
use axiom_types::{
    Bytes32, ExecutionAddress, ForkName, Gwei, Hash32, KzgCommitment, KzgProof, Minimal, Root,
    Slot, ValidatorIndex, VersionedHash, WithdrawalIndex, bellatrix, capella, combined, deneb,
    electra, gloas,
};

/// Runs a test body on a single-threaded runtime with timers and sockets.
fn run<F: Future<Output = ()>>(test: F) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime builds")
        .block_on(test);
}

/// The secret both sides share in these tests.
const fn secret() -> JwtSecret {
    JwtSecret::new([0x42; 32])
}

/// Parses JSON text that must be valid.
fn json(text: &str) -> Json {
    Json::parse(text).expect("test JSON parses")
}

/// A mock engine and a client pointed at it.
async fn connect() -> (MockEngine, EngineClient) {
    let engine = MockEngine::start(secret()).await.expect("mock binds");
    let client = EngineClient::new(engine.url(), secret()).expect("mock URL parses");
    (engine, client)
}

/// A valid verdict on the fixture payload, whose block hash is 0x06...
fn valid() -> Json {
    json(&format!(
        r#"{{"status":"VALID","latestValidHash":"0x{}","validationError":null}}"#,
        "06".repeat(32)
    ))
}

/// The Bellatrix fixture payload: one transaction, every other member fixed.
fn payload_v1() -> bellatrix::ExecutionPayload<Minimal> {
    bellatrix::ExecutionPayload {
        parent_hash: Hash32([0x01; 32]),
        fee_recipient: ExecutionAddress([0x02; 20]),
        state_root: Bytes32([0x03; 32]),
        receipts_root: Bytes32([0x04; 32]),
        logs_bloom: ByteVector::default(),
        prev_randao: Bytes32([0x05; 32]),
        block_number: 1_000,
        gas_limit: 30_000_000,
        gas_used: 21_000,
        timestamp: 1_700_000_000,
        extra_data: ByteList::try_from(b"axiom".to_vec()).expect("within the limit"),
        base_fee_per_gas: U256::from_u64(7),
        block_hash: Hash32([0x06; 32]),
        transactions: List::try_from(vec![
            ByteList::try_from(vec![0x02, 0xf8, 0x6f]).expect("within the limit"),
        ])
        .expect("within the limit"),
    }
}

/// The fixture payload's V1 members, written out by hand from `src/engine/paris.md`.
///
/// ```text
///     blockNumber 1000          "0x3e8"
///     gasLimit 30000000         "0x1c9c380"
///     gasUsed 21000             "0x5208"
///     timestamp 1700000000      "0x6553f100"
///     extraData "axiom"         "0x6178696f6d"
/// ```
fn payload_v1_members() -> String {
    format!(
        concat!(
            r#""parentHash":"0x{}","feeRecipient":"0x{}","stateRoot":"0x{}","receiptsRoot":"0x{}","#,
            r#""logsBloom":"0x{}","prevRandao":"0x{}","blockNumber":"0x3e8","gasLimit":"0x1c9c380","#,
            r#""gasUsed":"0x5208","timestamp":"0x6553f100","extraData":"0x6178696f6d","#,
            r#""baseFeePerGas":"0x7","blockHash":"0x{}","transactions":["0x02f86f"]"#,
        ),
        "01".repeat(32),
        "02".repeat(20),
        "03".repeat(32),
        "04".repeat(32),
        "00".repeat(256),
        "05".repeat(32),
        "06".repeat(32),
    )
}

/// The fixture withdrawal: 32 ETH in Gwei to validator 300.
const fn withdrawal() -> capella::Withdrawal {
    capella::Withdrawal {
        index: WithdrawalIndex(7),
        validator_index: ValidatorIndex(300),
        address: ExecutionAddress([0xaa; 20]),
        amount: Gwei(32_000_000_000),
    }
}

/// The fixture withdrawal as WithdrawalV1 text; 32_000_000_000 Gwei is "0x773594000".
fn withdrawals_text() -> String {
    format!(
        r#"[{{"index":"0x7","validatorIndex":"0x12c","address":"0x{}","amount":"0x773594000"}}]"#,
        "aa".repeat(20)
    )
}

/// The Capella fixture payload: the V1 one plus one withdrawal.
fn payload_v2() -> capella::ExecutionPayload<Minimal> {
    let v1 = payload_v1();
    capella::ExecutionPayload {
        parent_hash: v1.parent_hash,
        fee_recipient: v1.fee_recipient,
        state_root: v1.state_root,
        receipts_root: v1.receipts_root,
        logs_bloom: v1.logs_bloom,
        prev_randao: v1.prev_randao,
        block_number: v1.block_number,
        gas_limit: v1.gas_limit,
        gas_used: v1.gas_used,
        timestamp: v1.timestamp,
        extra_data: v1.extra_data,
        base_fee_per_gas: v1.base_fee_per_gas,
        block_hash: v1.block_hash,
        transactions: v1.transactions,
        withdrawals: List::try_from(vec![withdrawal()]).expect("within the limit"),
    }
}

/// The fixture payload's V2 members.
fn payload_v2_members() -> String {
    format!(
        r#"{},"withdrawals":{}"#,
        payload_v1_members(),
        withdrawals_text()
    )
}

/// The Deneb fixture payload: the V2 one plus one blob's gas, 131072 or "0x20000".
fn payload_v3() -> deneb::ExecutionPayload<Minimal> {
    let v2 = payload_v2();
    deneb::ExecutionPayload {
        parent_hash: v2.parent_hash,
        fee_recipient: v2.fee_recipient,
        state_root: v2.state_root,
        receipts_root: v2.receipts_root,
        logs_bloom: v2.logs_bloom,
        prev_randao: v2.prev_randao,
        block_number: v2.block_number,
        gas_limit: v2.gas_limit,
        gas_used: v2.gas_used,
        timestamp: v2.timestamp,
        extra_data: v2.extra_data,
        base_fee_per_gas: v2.base_fee_per_gas,
        block_hash: v2.block_hash,
        transactions: v2.transactions,
        withdrawals: v2.withdrawals,
        blob_gas_used: 131_072,
        excess_blob_gas: 0,
    }
}

/// The fixture payload's V3 members.
fn payload_v3_members() -> String {
    format!(
        r#"{},"blobGasUsed":"0x20000","excessBlobGas":"0x0""#,
        payload_v2_members()
    )
}

/// The Gloas fixture payload: the V3 one plus the empty RLP list 0xc0 as access list, at slot 9.
fn payload_v4() -> gloas::ExecutionPayload<Minimal> {
    let v3 = payload_v3();
    gloas::ExecutionPayload {
        parent_hash: v3.parent_hash,
        fee_recipient: v3.fee_recipient,
        state_root: v3.state_root,
        receipts_root: v3.receipts_root,
        logs_bloom: v3.logs_bloom,
        prev_randao: v3.prev_randao,
        block_number: v3.block_number,
        gas_limit: v3.gas_limit,
        gas_used: v3.gas_used,
        timestamp: v3.timestamp,
        extra_data: v3.extra_data,
        base_fee_per_gas: v3.base_fee_per_gas,
        block_hash: v3.block_hash,
        transactions: v3
            .transactions
            .iter()
            .map(|tx| ProgressiveList::from(tx.to_vec()))
            .collect(),
        withdrawals: ProgressiveList::from(vec![withdrawal()]),
        blob_gas_used: v3.blob_gas_used,
        excess_blob_gas: v3.excess_blob_gas,
        block_access_list: ProgressiveList::from(vec![0xc0]),
        slot_number: 9,
    }
}

/// The fixture payload's V4 members.
fn payload_v4_members() -> String {
    format!(
        r#"{},"blockAccessList":"0xc0","slotNumber":"0x9""#,
        payload_v3_members()
    )
}

/// The one blob commitment of the fixture blocks.
const COMMITMENT: KzgCommitment = KzgCommitment([0x33; 48]);

/// The versioned hash of that commitment, computed independently.
///
/// It is SHA-256 of 48 bytes of 0x33, with the first byte replaced by version 0x01.
const VERSIONED_HASH: &str = "0x01300e97ac14843c50965f2334e0ef11e743565f780386a69b7cff9fa7886888";

/// The fixture parent beacon block root.
const PARENT_ROOT: Root = Root([0x09; 32]);

/// Electra fixture requests: one deposit with index 5, nothing else.
fn electra_requests() -> electra::ExecutionRequests<Minimal> {
    electra::ExecutionRequests {
        deposits: List::try_from(vec![electra::DepositRequest {
            index: 5,
            ..electra::DepositRequest::default()
        }])
        .expect("within the limit"),
        ..electra::ExecutionRequests::default()
    }
}

/// The Electra fixture requests as a requests list.
///
/// A deposit request is 192 bytes, its index the last 8, little-endian.
/// The list holds one element: type 0x00, then the one deposit.
fn electra_requests_text() -> String {
    format!(r#"["0x00{}05{}"]"#, "00".repeat(184), "00".repeat(7))
}

/// Gloas fixture requests: one builder exit, 20 address bytes and 48 key bytes of zeros.
fn gloas_requests() -> gloas::ExecutionRequests {
    gloas::ExecutionRequests {
        builder_exits: ProgressiveList::from(vec![gloas::BuilderExitRequest::default()]),
        ..gloas::ExecutionRequests::default()
    }
}

/// The Gloas fixture requests as a requests list: type 0x04, then 68 zero bytes.
fn gloas_requests_text() -> String {
    format!(r#"["0x04{}"]"#, "00".repeat(68))
}

/// One fixture block per fork from Bellatrix to Fulu, each carrying its fork's fixture payload.
fn block(fork: ForkName) -> combined::BeaconBlock<Minimal> {
    let commitments = List::try_from(vec![COMMITMENT]).expect("within the limit");
    match fork {
        ForkName::Bellatrix => {
            let mut block = bellatrix::BeaconBlock::default();
            block.body.execution_payload = payload_v1();
            combined::BeaconBlock::Bellatrix(block)
        }
        ForkName::Capella => {
            let mut block = capella::BeaconBlock::default();
            block.body.execution_payload = payload_v2();
            combined::BeaconBlock::Capella(block)
        }
        ForkName::Deneb => {
            let mut block = deneb::BeaconBlock {
                parent_root: PARENT_ROOT,
                ..deneb::BeaconBlock::default()
            };
            block.body.execution_payload = payload_v3();
            block.body.blob_kzg_commitments = commitments;
            combined::BeaconBlock::Deneb(block)
        }
        _ => {
            let mut block = electra::BeaconBlock {
                parent_root: PARENT_ROOT,
                ..electra::BeaconBlock::default()
            };
            block.body.execution_payload = payload_v3();
            block.body.blob_kzg_commitments = commitments;
            block.body.execution_requests = electra_requests();
            if fork == ForkName::Fulu {
                combined::BeaconBlock::Fulu(block)
            } else {
                combined::BeaconBlock::Electra(block)
            }
        }
    }
}

/// The Gloas fixture request, from an envelope and the bid its block committed to.
fn gloas_new_payload() -> NewPayload<Minimal> {
    let bid = gloas::ExecutionPayloadBid {
        blob_kzg_commitments: ProgressiveList::from(vec![COMMITMENT]),
        ..gloas::ExecutionPayloadBid::default()
    };
    let envelope = gloas::ExecutionPayloadEnvelope {
        payload: payload_v4(),
        execution_requests: gloas_requests(),
        parent_beacon_block_root: PARENT_ROOT,
        ..gloas::ExecutionPayloadEnvelope::default()
    };
    NewPayload::from_envelope(&envelope, &bid).expect("one blob is within the limit")
}

#[test]
fn new_payload_sends_each_forks_method_and_parameters() {
    run(async {
        let (engine, client) = connect().await;
        let hashes = format!(r#"["{VERSIONED_HASH}"]"#);
        let root = format!(r#""0x{}""#, "09".repeat(32));

        // Each fork's request, the method its execution fork defines, and the exact parameters.
        let cases = [
            (
                NewPayload::from_block(&block(ForkName::Bellatrix)).unwrap(),
                "engine_newPayloadV1",
                format!("[{{{}}}]", payload_v1_members()),
            ),
            (
                NewPayload::from_block(&block(ForkName::Capella)).unwrap(),
                "engine_newPayloadV2",
                format!("[{{{}}}]", payload_v2_members()),
            ),
            (
                NewPayload::from_block(&block(ForkName::Deneb)).unwrap(),
                "engine_newPayloadV3",
                format!("[{{{}}},{hashes},{root}]", payload_v3_members()),
            ),
            (
                NewPayload::from_block(&block(ForkName::Electra)).unwrap(),
                "engine_newPayloadV4",
                format!(
                    "[{{{}}},{hashes},{root},{}]",
                    payload_v3_members(),
                    electra_requests_text()
                ),
            ),
            (
                NewPayload::from_block(&block(ForkName::Fulu)).unwrap(),
                "engine_newPayloadV4",
                format!(
                    "[{{{}}},{hashes},{root},{}]",
                    payload_v3_members(),
                    electra_requests_text()
                ),
            ),
            (
                gloas_new_payload(),
                "engine_newPayloadV5",
                format!(
                    "[{{{}}},{hashes},{root},{}]",
                    payload_v4_members(),
                    gloas_requests_text()
                ),
            ),
        ];

        for (index, (request, method, params)) in cases.iter().enumerate() {
            engine.reply(method, valid());

            // The verdict comes back typed.
            let status = client.new_payload(request).await.unwrap();
            assert_eq!(
                status,
                PayloadStatus {
                    status: PayloadStatusKind::Valid,
                    latest_valid_hash: Some(Hash32([0x06; 32])),
                    validation_error: None,
                }
            );

            // The engine received exactly the method and the parameters the spec lists.
            let call = &engine.calls()[index];
            assert_eq!(call.method, *method, "{}", request.fork());
            assert_eq!(
                Json::Array(call.params.clone()),
                json(params),
                "{}",
                request.fork()
            );
        }

        // The token was issued within the engine's 60-second window of now.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(engine.calls()[0].issued_at.abs_diff(now) <= 1);
        engine.stop().await;
    });
}

/// One fork choice call per attributes version, then one without attributes.
///
/// Each case pairs a fork and its attributes with the method and the JSON parameters expected.
fn forkchoice_cases(
    state_text: &str,
) -> [(
    ForkName,
    Option<PayloadAttributes<Minimal>>,
    &'static str,
    String,
); 5] {
    // Fixture state: timestamp 12, randao 0x0c.., fee recipient 0x0d.., parent root 0x0e...
    let v1 = PayloadAttributesV1 {
        timestamp: 12,
        prev_randao: Bytes32([0x0c; 32]),
        suggested_fee_recipient: ExecutionAddress([0x0d; 20]),
    };
    let v1_members = format!(
        r#""timestamp":"0xc","prevRandao":"0x{}","suggestedFeeRecipient":"0x{}""#,
        "0c".repeat(32),
        "0d".repeat(20)
    );
    let v2 = PayloadAttributesV2::<Minimal> {
        timestamp: v1.timestamp,
        prev_randao: v1.prev_randao,
        suggested_fee_recipient: v1.suggested_fee_recipient,
        withdrawals: List::try_from(vec![withdrawal()]).expect("within the limit"),
    };
    let v2_members = format!(r#"{v1_members},"withdrawals":{}"#, withdrawals_text());
    let v3 = PayloadAttributesV3::<Minimal> {
        timestamp: v1.timestamp,
        prev_randao: v1.prev_randao,
        suggested_fee_recipient: v1.suggested_fee_recipient,
        withdrawals: v2.withdrawals.clone(),
        parent_beacon_block_root: Root([0x0e; 32]),
    };
    let v3_members = format!(
        r#"{v2_members},"parentBeaconBlockRoot":"0x{}""#,
        "0e".repeat(32)
    );
    // Slot 9 is "0x9"; a 60M gas target is "0x3938700".
    let v4 = PayloadAttributesV4 {
        timestamp: v1.timestamp,
        prev_randao: v1.prev_randao,
        suggested_fee_recipient: v1.suggested_fee_recipient,
        withdrawals: ProgressiveList::from(vec![withdrawal()]),
        parent_beacon_block_root: v3.parent_beacon_block_root,
        slot_number: Slot(9),
        target_gas_limit: 60_000_000,
    };
    let v4_members = format!(r#"{v3_members},"slotNumber":"0x9","targetGasLimit":"0x3938700""#);

    // Each fork with attributes of its version, then Fulu without any.
    [
        (
            ForkName::Bellatrix,
            Some(PayloadAttributes::V1(v1)),
            "engine_forkchoiceUpdatedV1",
            format!("[{state_text},{{{v1_members}}}]"),
        ),
        (
            ForkName::Capella,
            Some(PayloadAttributes::V2(v2)),
            "engine_forkchoiceUpdatedV2",
            format!("[{state_text},{{{v2_members}}}]"),
        ),
        (
            ForkName::Electra,
            Some(PayloadAttributes::V3(v3)),
            "engine_forkchoiceUpdatedV3",
            format!("[{state_text},{{{v3_members}}}]"),
        ),
        // Version 4 adds the custody columns, sent as null.
        (
            ForkName::Gloas,
            Some(PayloadAttributes::V4(v4)),
            "engine_forkchoiceUpdatedV4",
            format!("[{state_text},{{{v4_members}}},null]"),
        ),
        // Without attributes the second parameter is an explicit null.
        (
            ForkName::Fulu,
            None,
            "engine_forkchoiceUpdatedV3",
            format!("[{state_text},null]"),
        ),
    ]
}

#[test]
fn forkchoice_updated_sends_each_version() {
    run(async {
        let (engine, client) = connect().await;
        let reply = json(
            r#"{"payloadStatus":{"status":"SYNCING","latestValidHash":null,"validationError":null},"payloadId":"0x0000000000000abc"}"#,
        );
        for version in ["V1", "V2", "V3", "V4"] {
            engine.reply(&format!("engine_forkchoiceUpdated{version}"), reply.clone());
        }

        let state = ForkchoiceState {
            head_block_hash: Hash32([0x0a; 32]),
            safe_block_hash: Hash32([0x0b; 32]),
            finalized_block_hash: Hash32::ZERO,
        };
        let state_text = format!(
            r#"{{"headBlockHash":"0x{}","safeBlockHash":"0x{}","finalizedBlockHash":"0x{}"}}"#,
            "0a".repeat(32),
            "0b".repeat(32),
            "00".repeat(32)
        );

        let cases = forkchoice_cases(&state_text);

        for (index, (fork, attributes, method, params)) in cases.iter().enumerate() {
            // A syncing head still returns the build's id.
            let updated = client
                .forkchoice_updated(*fork, &state, attributes.as_ref())
                .await
                .unwrap();
            assert_eq!(
                updated,
                ForkchoiceUpdated {
                    payload_status: PayloadStatus {
                        status: PayloadStatusKind::Syncing,
                        latest_valid_hash: None,
                        validation_error: None,
                    },
                    payload_id: Some(PayloadId([0, 0, 0, 0, 0, 0, 0x0a, 0xbc])),
                }
            );

            let call = &engine.calls()[index];
            assert_eq!(call.method, *method, "{fork}");
            assert_eq!(Json::Array(call.params.clone()), json(params), "{fork}");
        }
        engine.stop().await;
    });
}

#[test]
fn forks_without_the_method_are_refused_before_any_call() {
    run(async {
        let (engine, client) = connect().await;
        let state = ForkchoiceState::default();

        // Phase0 predates the merge, so it calls no engine method at all.
        let error = client
            .forkchoice_updated::<Minimal>(ForkName::Phase0, &state, None)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            EngineError::NoMethod {
                fork: ForkName::Phase0,
                family: "engine API"
            }
        ));

        // Capella predates blobs, so it has no blob pool to read.
        let error = client
            .get_blobs::<Minimal>(ForkName::Capella, &[])
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            EngineError::NoMethod {
                fork: ForkName::Capella,
                family: "engine_getBlobs"
            }
        ));

        // Gloas calls version 4, so version 3 attributes are refused.
        let attributes = PayloadAttributes::<Minimal>::V3(PayloadAttributesV3::default());
        let error = client
            .forkchoice_updated(ForkName::Gloas, &state, Some(&attributes))
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            EngineError::AttributesVersion {
                fork: ForkName::Gloas,
                expected: ForkchoiceVersion::V4,
                actual: ForkchoiceVersion::V3
            }
        ));

        // None of the three reached the engine.
        assert_eq!(engine.calls(), Vec::<RecordedCall>::new());
        engine.stop().await;
    });
}

/// A blob of 131072 bytes of one value.
fn blob(byte: u8) -> deneb::Blob<Minimal> {
    ByteVector::try_from(vec![byte; 131_072].as_slice()).expect("exactly one blob")
}

/// The fixture blob as DATA text, bytes of 0x11.
fn blob_text() -> String {
    format!(r#""{}""#, vec![0x11; 131_072].to_data())
}

/// The fixture blob bundle of version 1: one blob of 0x11, commitment 0x33.., proof 0x22...
fn bundle_v1() -> (String, BlobsBundleV1<Minimal>) {
    let text = format!(
        r#"{{"commitments":["0x{}"],"proofs":["0x{}"],"blobs":[{}]}}"#,
        "33".repeat(48),
        "22".repeat(48),
        blob_text()
    );
    let bundle = BlobsBundleV1 {
        commitments: List::try_from(vec![COMMITMENT]).expect("within the limit"),
        proofs: List::try_from(vec![KzgProof([0x22; 48])]).expect("within the limit"),
        blobs: List::try_from(vec![blob(0x11)]).expect("within the limit"),
    };
    (text, bundle)
}

/// The fixture blob bundle of version 2: the same blob, with 128 cell proofs of 0x22...
fn bundle_v2() -> (String, BlobsBundleV2<Minimal>) {
    let proof = format!(r#""0x{}""#, "22".repeat(48));
    let text = format!(
        r#"{{"commitments":["0x{}"],"proofs":[{}],"blobs":[{}]}}"#,
        "33".repeat(48),
        vec![proof; 128].join(","),
        blob_text()
    );
    let bundle = BlobsBundleV2 {
        commitments: List::try_from(vec![COMMITMENT]).expect("within the limit"),
        proofs: List::try_from(vec![KzgProof([0x22; 48]); 128]).expect("within the limit"),
        blobs: List::try_from(vec![blob(0x11)]).expect("within the limit"),
    };
    (text, bundle)
}

/// One getPayload reply per version, written by hand, with the value it must decode to.
fn get_payload_cases() -> [(ForkName, &'static str, String, GetPayloadResponse<Minimal>); 6] {
    // Shared members: 1 ether is "0xde0b6b3a7640000" wei.
    let one_ether = U256::from_u64(1_000_000_000_000_000_000);
    let value = r#""blockValue":"0xde0b6b3a7640000""#;
    let (bundle_v1_text, bundle_v1) = bundle_v1();
    let (bundle_v2_text, bundle_v2) = bundle_v2();

    // Each fork's version, its reply written by hand, and the value it must decode to.
    [
        (
            ForkName::Bellatrix,
            "engine_getPayloadV1",
            format!("{{{}}}", payload_v1_members()),
            GetPayloadResponse::V1(payload_v1()),
        ),
        (
            ForkName::Capella,
            "engine_getPayloadV2",
            format!(
                r#"{{"executionPayload":{{{}}},{value}}}"#,
                payload_v2_members()
            ),
            GetPayloadResponse::V2(GetPayloadResponseV2 {
                execution_payload: payload_v2(),
                block_value: one_ether,
            }),
        ),
        (
            ForkName::Deneb,
            "engine_getPayloadV3",
            format!(
                r#"{{"executionPayload":{{{}}},{value},"blobsBundle":{bundle_v1_text},"shouldOverrideBuilder":true}}"#,
                payload_v3_members()
            ),
            GetPayloadResponse::V3(GetPayloadResponseV3 {
                execution_payload: payload_v3(),
                block_value: one_ether,
                blobs_bundle: bundle_v1.clone(),
                should_override_builder: true,
            }),
        ),
        (
            ForkName::Electra,
            "engine_getPayloadV4",
            format!(
                r#"{{"executionPayload":{{{}}},{value},"blobsBundle":{bundle_v1_text},"shouldOverrideBuilder":false,"executionRequests":{}}}"#,
                payload_v3_members(),
                electra_requests_text()
            ),
            GetPayloadResponse::V4(GetPayloadResponseV4 {
                execution_payload: payload_v3(),
                block_value: one_ether,
                blobs_bundle: bundle_v1,
                should_override_builder: false,
                execution_requests: electra_requests(),
            }),
        ),
        (
            ForkName::Fulu,
            "engine_getPayloadV5",
            format!(
                r#"{{"executionPayload":{{{}}},{value},"blobsBundle":{bundle_v2_text},"shouldOverrideBuilder":false,"executionRequests":{}}}"#,
                payload_v3_members(),
                electra_requests_text()
            ),
            GetPayloadResponse::V5(GetPayloadResponseV5 {
                execution_payload: payload_v3(),
                block_value: one_ether,
                blobs_bundle: bundle_v2.clone(),
                should_override_builder: false,
                execution_requests: electra_requests(),
            }),
        ),
        (
            ForkName::Gloas,
            "engine_getPayloadV6",
            format!(
                r#"{{"executionPayload":{{{}}},{value},"blobsBundle":{bundle_v2_text},"shouldOverrideBuilder":false,"executionRequests":{}}}"#,
                payload_v4_members(),
                gloas_requests_text()
            ),
            GetPayloadResponse::V6(GetPayloadResponseV6 {
                execution_payload: payload_v4(),
                block_value: one_ether,
                blobs_bundle: bundle_v2,
                should_override_builder: false,
                execution_requests: gloas_requests(),
            }),
        ),
    ]
}

#[test]
fn get_payload_decodes_each_version() {
    run(async {
        let (engine, client) = connect().await;

        let cases = get_payload_cases();

        let id = PayloadId([1, 2, 3, 4, 5, 6, 7, 8]);
        for (index, (fork, method, reply, expected)) in cases.into_iter().enumerate() {
            engine.reply(method, json(&reply));
            let built = client.get_payload::<Minimal>(fork, id).await.unwrap();
            assert_eq!(built, expected, "{fork}");

            // The id went out as 8 bytes of DATA, to the fork's method.
            let call = &engine.calls()[index];
            assert_eq!(call.method, method);
            assert_eq!(call.params, vec![Json::from("0x0102030405060708")]);
        }
        engine.stop().await;
    });
}

#[test]
fn get_payload_rejects_a_short_proof_list() {
    run(async {
        let (engine, client) = connect().await;

        // A Fulu reply with 127 cell proofs for one blob, one short of the 128 cells.
        let proofs = vec![format!(r#""0x{}""#, "22".repeat(48)); 127].join(",");
        engine.reply(
            "engine_getPayloadV5",
            json(&format!(
                r#"{{"executionPayload":{{{}}},"blockValue":"0x0","blobsBundle":{{"commitments":["0x{}"],"proofs":[{proofs}],"blobs":[{}]}},"shouldOverrideBuilder":false,"executionRequests":[]}}"#,
                payload_v3_members(),
                "33".repeat(48),
                blob_text()
            )),
        );

        let error = client
            .get_payload::<Minimal>(ForkName::Fulu, PayloadId::default())
            .await
            .unwrap_err();
        let EngineError::Wire(error) = error else {
            panic!("expected a wire error, got {error}");
        };
        assert_eq!(error.path(), "blobsBundle.proofs");
        assert_eq!(
            error.kind(),
            &WireErrorKind::LengthMismatch {
                expected: 128,
                actual: 127
            }
        );
        engine.stop().await;
    });
}

#[test]
fn get_blobs_v1_leaves_a_gap_per_missing_blob() {
    run(async {
        let (engine, client) = connect().await;
        let hashes = [VersionedHash([0x01; 32]), VersionedHash([0x02; 32])];

        // The pool holds the first blob but not the second.
        engine.reply(
            "engine_getBlobsV1",
            json(&format!(
                r#"[{{"blob":{},"proof":"0x{}"}},null]"#,
                blob_text(),
                "22".repeat(48)
            )),
        );
        let blobs = client
            .get_blobs::<Minimal>(ForkName::Deneb, &hashes)
            .await
            .unwrap();
        assert_eq!(
            blobs,
            GetBlobsResponse::V1(vec![
                Some(BlobAndProofV1 {
                    blob: blob(0x11),
                    proof: KzgProof([0x22; 48]),
                }),
                None,
            ])
        );

        // Both hashes went out, in order, as the one parameter.
        let call = &engine.calls()[0];
        assert_eq!(call.method, "engine_getBlobsV1");
        assert_eq!(
            call.params,
            vec![json(&format!(
                r#"["0x{}","0x{}"]"#,
                "01".repeat(32),
                "02".repeat(32)
            ))]
        );
        engine.stop().await;
    });
}

#[test]
fn get_blobs_v2_all_or_nothing() {
    run(async {
        let (engine, client) = connect().await;
        let hashes = [VersionedHash([0x01; 32])];

        // Null means at least one blob is missing.
        engine.reply("engine_getBlobsV2", Json::Null);
        assert_eq!(
            client
                .get_blobs::<Minimal>(ForkName::Fulu, &hashes)
                .await
                .unwrap(),
            GetBlobsResponse::V2(None)
        );

        // One blob of 0x11 with 128 proofs answers the one hash; Gloas calls the same version.
        let proofs = vec![format!(r#""0x{}""#, "22".repeat(48)); 128].join(",");
        let entry = format!(r#"{{"blob":{},"proofs":[{proofs}]}}"#, blob_text());
        engine.reply("engine_getBlobsV2", json(&format!("[{entry}]")));
        assert_eq!(
            client
                .get_blobs::<Minimal>(ForkName::Gloas, &hashes)
                .await
                .unwrap(),
            GetBlobsResponse::V2(Some(vec![BlobAndProofV2 {
                blob: blob(0x11),
                proofs: Vector::try_from(vec![KzgProof([0x22; 48]); 128]).unwrap(),
            }]))
        );

        // Two entries for one requested hash is a protocol violation.
        engine.reply("engine_getBlobsV2", json(&format!("[{entry},{entry}]")));
        let error = client
            .get_blobs::<Minimal>(ForkName::Fulu, &hashes)
            .await
            .unwrap_err();
        let EngineError::Wire(error) = error else {
            panic!("expected a wire error, got {error}");
        };
        assert_eq!(
            error,
            WireError::new(WireErrorKind::LengthMismatch {
                expected: 1,
                actual: 2
            })
        );
        engine.stop().await;
    });
}

#[test]
fn capabilities_chain_id_and_syncing() {
    run(async {
        let (engine, client) = connect().await;
        engine.reply(
            "engine_exchangeCapabilities",
            json(r#"["engine_newPayloadV4","engine_getPayloadV5"]"#),
        );
        engine.reply("eth_chainId", Json::from("0x1"));
        engine.reply(
            "eth_syncing",
            json(r#"{"startingBlock":"0x0","currentBlock":"0x10","highestBlock":"0x20","healedBytecodes":"0x0"}"#),
        );

        // The engine's list comes back; ours went out as the one parameter.
        let theirs = client.exchange_capabilities(CAPABILITIES).await.unwrap();
        assert_eq!(theirs, ["engine_newPayloadV4", "engine_getPayloadV5"]);
        let sent = &engine.calls()[0].params[0];
        assert_eq!(sent.as_array().unwrap().len(), CAPABILITIES.len());

        // Mainnet's chain id is 1.
        assert_eq!(client.chain_id().await.unwrap(), 1);

        // Unknown members of the sync object are ignored.
        assert_eq!(
            client.syncing().await.unwrap(),
            SyncStatus::Syncing {
                starting_block: 0,
                current_block: 16,
                highest_block: 32
            }
        );
        engine.reply("eth_syncing", Json::Bool(false));
        assert_eq!(client.syncing().await.unwrap(), SyncStatus::Synced);
        engine.stop().await;
    });
}

#[test]
fn engine_errors_surface_typed() {
    run(async {
        let (engine, client) = connect().await;
        let request = NewPayload::from_block(&block(ForkName::Fulu)).unwrap();

        // The engine refuses a payload from an unsupported fork with -38005.
        engine.reply_error(
            "engine_newPayloadV4",
            RpcError::new(RpcError::UNSUPPORTED_FORK, "Unsupported fork"),
        );
        let error = client.new_payload(&request).await.unwrap_err();
        let EngineError::Rpc(error) = error else {
            panic!("expected an engine error object, got {error}");
        };
        assert_eq!(
            error,
            RpcError::new(RpcError::UNSUPPORTED_FORK, "Unsupported fork")
        );

        // A method without a scripted reply is "method not found".
        let error = client.chain_id().await.unwrap_err();
        let EngineError::Rpc(error) = error else {
            panic!("expected an engine error object, got {error}");
        };
        assert_eq!(
            error,
            RpcError::new(RpcError::METHOD_NOT_FOUND, "Method not found")
        );

        // An unknown status string is a wire error located at the status member.
        engine.reply(
            "engine_newPayloadV4",
            json(r#"{"status":"MAYBE","latestValidHash":null,"validationError":null}"#),
        );
        let error = client.new_payload(&request).await.unwrap_err();
        let EngineError::Wire(error) = error else {
            panic!("expected a wire error, got {error}");
        };
        assert_eq!(error.path(), "status");
        assert_eq!(
            error.kind(),
            &WireErrorKind::UnknownStatus("MAYBE".to_owned())
        );
        engine.stop().await;
    });
}

#[test]
fn wrong_secret_is_rejected_before_any_call() {
    run(async {
        let engine = MockEngine::start(secret()).await.unwrap();
        engine.reply("eth_chainId", Json::from("0x1"));

        // A client holding a different secret signs tokens the engine cannot verify.
        let impostor = EngineClient::new(engine.url(), JwtSecret::new([0x43; 32])).unwrap();
        let error = impostor.chain_id().await.unwrap_err();
        assert!(matches!(
            error,
            EngineError::Status(StatusCode::UNAUTHORIZED)
        ));

        // The engine recorded nothing: authentication precedes the call.
        assert_eq!(engine.calls(), Vec::<RecordedCall>::new());
        engine.stop().await;
    });
}

/// The parameters of a lookup of a block hash.
fn lookup(hash: Hash32) -> Vec<Json> {
    vec![hash.to_json(), Json::Bool(false)]
}

#[test]
fn pow_blocks_are_looked_up_by_hash() {
    run(async {
        let (engine, client) = connect().await;
        // Fixture state: the engine knows block 0xbb.., child of 0xaa.., at total difficulty 1000.
        let known = bellatrix::PowBlock {
            block_hash: Hash32([0xbb; 32]),
            parent_hash: Hash32([0xaa; 32]),
            total_difficulty: U256::from_u64(1000),
        };
        engine.serve_pow_block(&known);
        // Every other hash is unknown, which the engine answers with null.
        engine.reply("eth_getBlockByHash", Json::Null);

        // The known block comes back whole, asked for by hash with transaction hashes only.
        assert_eq!(
            client.pow_block(Hash32([0xbb; 32])).await.unwrap(),
            Some(known.clone())
        );
        assert_eq!(engine.calls()[0].params, lookup(Hash32([0xbb; 32])));

        // Block 0xcc.. is unknown.
        assert_eq!(client.pow_block(Hash32([0xcc; 32])).await.unwrap(), None);
        engine.stop().await;
    });
}

#[test]
fn a_pow_block_reply_must_be_the_block_asked_for() {
    run(async {
        let (engine, client) = connect().await;
        // Mutation: the engine answers a lookup of 0xdd.. with block 0xbb...
        let other = bellatrix::PowBlock {
            block_hash: Hash32([0xbb; 32]),
            parent_hash: Hash32([0xaa; 32]),
            total_difficulty: U256::from_u64(1000),
        };
        engine.reply_to(
            "eth_getBlockByHash",
            lookup(Hash32([0xdd; 32])),
            other.to_json(),
        );

        let error = client.pow_block(Hash32([0xdd; 32])).await.unwrap_err();

        // Both hashes are named.
        assert_eq!(
            error.to_string(),
            format!(
                "asked for block {}, the engine returned block {}",
                Hash32([0xdd; 32]),
                Hash32([0xbb; 32])
            )
        );
        assert!(matches!(error, EngineError::BlockMismatch { .. }));
        engine.stop().await;
    });
}

#[test]
fn a_pow_block_without_its_total_difficulty_is_malformed() {
    run(async {
        let (engine, client) = connect().await;
        // Mutation: block 0xee.. in the current schema, which dropped the total difficulty.
        let partial = format!(
            r#"{{"hash":"0x{}","parentHash":"0x{}"}}"#,
            "ee".repeat(32),
            "aa".repeat(32)
        );
        engine.reply("eth_getBlockByHash", json(&partial));

        let error = client.pow_block(Hash32([0xee; 32])).await.unwrap_err();

        let EngineError::Wire(error) = error else {
            panic!("expected a wire error, got {error}");
        };
        assert_eq!(
            error,
            WireError::new(WireErrorKind::Missing).in_member("totalDifficulty")
        );
        engine.stop().await;
    });
}
