//! The engine client against the in-process mock engine, end to end over HTTP and JWT.

use std::{
    future::Future,
    time::{SystemTime, UNIX_EPOCH},
};

use axiom_execution::{
    CAPABILITIES, EngineClient, EngineError, ForkchoiceState, JsonCodec, JwtSecret,
    PayloadAttributes, PayloadId, PayloadStatus, PayloadStatusKind, RpcError, SyncStatus,
    WireErrorKind, mock::MockEngine,
};
use axiom_http::StatusCode;
use axiom_json::{Json, data};
use axiom_ssz::{ByteList, List, U256};
use axiom_types::{
    Bytes32, ConsolidationRequest, DepositRequest, ExecutionAddress, ExecutionPayload,
    ExecutionRequests, Gwei, Hash32, Minimal, NewPayloadRequest, Root, ValidatorIndex,
    VersionedHash, Withdrawal, WithdrawalIndex,
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

/// A payload with one transaction and one withdrawal, and requests of two types.
fn new_payload_request() -> NewPayloadRequest<Minimal> {
    let withdrawal = Withdrawal {
        index: WithdrawalIndex(7),
        validator_index: ValidatorIndex(300),
        address: ExecutionAddress([0xaa; 20]),
        amount: Gwei(32_000_000_000),
    };
    let payload = ExecutionPayload {
        parent_hash: Hash32([0x01; 32]),
        fee_recipient: ExecutionAddress([0x02; 20]),
        state_root: Bytes32([0x03; 32]),
        receipts_root: Bytes32([0x04; 32]),
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
        withdrawals: List::try_from(vec![withdrawal]).expect("within the limit"),
        blob_gas_used: 131_072,
        excess_blob_gas: 0,
        ..ExecutionPayload::default()
    };
    let requests = ExecutionRequests {
        deposits: List::try_from(vec![DepositRequest {
            index: 5,
            ..DepositRequest::default()
        }])
        .expect("within the limit"),
        withdrawals: List::default(),
        consolidations: List::try_from(vec![ConsolidationRequest::default()])
            .expect("within the limit"),
    };
    NewPayloadRequest {
        execution_payload: payload,
        versioned_hashes: List::try_from(vec![VersionedHash([0x01; 32])])
            .expect("within the limit"),
        parent_beacon_block_root: Root([0x09; 32]),
        execution_requests: requests,
    }
}

#[test]
fn new_payload_sends_the_prague_parameters() {
    run(async {
        let (engine, client) = connect().await;
        let block_hash = "0x".to_owned() + &"06".repeat(32);
        engine.reply(
            "engine_newPayloadV4",
            json(&format!(
                r#"{{"status":"VALID","latestValidHash":"{block_hash}","validationError":null}}"#
            )),
        );

        // The verdict comes back typed.
        let request = new_payload_request();
        let status = client.new_payload(&request).await.unwrap();
        assert_eq!(
            status,
            PayloadStatus {
                status: PayloadStatusKind::Valid,
                latest_valid_hash: Some(Hash32([0x06; 32])),
                validation_error: None,
            }
        );
        assert_eq!(status.verdict(), Some(true));

        // One authenticated call with four parameters reached the engine.
        let calls = engine.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].method, "engine_newPayloadV4");
        let params = &calls[0].params;
        assert_eq!(params.len(), 4);

        // Parameter 1, the payload: spot-check member names and both encodings.
        //
        //     blockNumber 1000          -> QUANTITY "0x3e8"
        //     gasLimit 30000000         -> QUANTITY "0x1c9c380"
        //     baseFeePerGas 7           -> QUANTITY "0x7"
        //     extraData "axiom"         -> DATA "0x6178696f6d"
        //     withdrawal amount 32 ETH  -> QUANTITY in Gwei "0x773594000"
        let payload = &params[0];
        assert_eq!(payload.get("blockNumber"), Some(&Json::from("0x3e8")));
        assert_eq!(payload.get("gasLimit"), Some(&Json::from("0x1c9c380")));
        assert_eq!(payload.get("baseFeePerGas"), Some(&Json::from("0x7")));
        assert_eq!(payload.get("excessBlobGas"), Some(&Json::from("0x0")));
        assert_eq!(payload.get("extraData"), Some(&Json::from("0x6178696f6d")));
        assert_eq!(payload.get("transactions"), Some(&json(r#"["0x02f86f"]"#)));
        assert_eq!(
            payload.get("withdrawals").unwrap().to_string(),
            format!(
                r#"[{{"index":"0x7","validatorIndex":"0x12c","address":"0x{}","amount":"0x773594000"}}]"#,
                "aa".repeat(20)
            )
        );
        // The JSON decodes back to the very payload that was sent.
        assert_eq!(
            ExecutionPayload::<Minimal>::from_json(payload),
            Ok(request.execution_payload.clone())
        );

        // Parameters 2 and 3: versioned hashes and the parent beacon block root.
        assert_eq!(params[1], json(&format!(r#"["0x{}"]"#, "01".repeat(32))));
        assert_eq!(params[2], Json::from(format!("0x{}", "09".repeat(32))));

        // Parameter 4: deposits typed 0x00, consolidations typed 0x02, no empty withdrawals.
        let list = params[3].as_array().unwrap();
        assert_eq!(list.len(), 2);
        assert!(list[0].as_str().unwrap().starts_with("0x00"));
        assert!(list[1].as_str().unwrap().starts_with("0x02"));

        // The token was issued within the engine's 60-second window of now.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(calls[0].issued_at.abs_diff(now) <= 1);

        engine.stop().await;
    });
}

#[test]
fn forkchoice_updated_with_and_without_attributes() {
    run(async {
        let (engine, client) = connect().await;
        engine.reply(
            "engine_forkchoiceUpdatedV3",
            json(
                r#"{"payloadStatus":{"status":"SYNCING","latestValidHash":null,"validationError":null},"payloadId":"0x0000000000000abc"}"#,
            ),
        );

        let state = ForkchoiceState {
            head_block_hash: Hash32([0x0a; 32]),
            safe_block_hash: Hash32([0x0b; 32]),
            finalized_block_hash: Hash32::ZERO,
        };
        let attributes = PayloadAttributes::<Minimal> {
            timestamp: 12,
            prev_randao: Bytes32([0x0c; 32]),
            suggested_fee_recipient: ExecutionAddress([0x0d; 20]),
            withdrawals: List::default(),
            parent_beacon_block_root: Root([0x0e; 32]),
        };

        // With attributes: a syncing head still returns the build's id.
        let updated = client
            .forkchoice_updated(&state, Some(&attributes))
            .await
            .unwrap();
        assert_eq!(updated.payload_status.status, PayloadStatusKind::Syncing);
        assert_eq!(updated.payload_status.verdict(), None);
        assert_eq!(
            updated.payload_id,
            Some(PayloadId([0, 0, 0, 0, 0, 0, 0x0a, 0xbc]))
        );

        // Without attributes: the second parameter is an explicit null.
        client
            .forkchoice_updated::<Minimal>(&state, None)
            .await
            .unwrap();

        let calls = engine.calls();
        assert_eq!(
            calls[0].params[0],
            json(&format!(
                r#"{{"headBlockHash":"0x{}","safeBlockHash":"0x{}","finalizedBlockHash":"0x{}"}}"#,
                "0a".repeat(32),
                "0b".repeat(32),
                "00".repeat(32)
            ))
        );
        assert_eq!(
            calls[0].params[1],
            json(&format!(
                r#"{{"timestamp":"0xc","prevRandao":"0x{}","suggestedFeeRecipient":"0x{}","withdrawals":[],"parentBeaconBlockRoot":"0x{}"}}"#,
                "0c".repeat(32),
                "0d".repeat(20),
                "0e".repeat(32)
            ))
        );
        assert_eq!(calls[1].params[1], Json::Null);

        engine.stop().await;
    });
}

/// A getPayloadV5 reply with one blob of 0x11 bytes and 128 cell proofs.
fn get_payload_reply(proofs: usize) -> Json {
    let payload = new_payload_request().execution_payload.to_json();
    let blob = data::encode(&vec![0x11; 131_072]);
    let proof = format!("\"0x{}\"", "22".repeat(48));
    let proofs = vec![proof; proofs].join(",");
    let deposit_list = format!("0x00{}", "00".repeat(192));
    json(&format!(
        r#"{{"executionPayload":{payload},"blockValue":"0xde0b6b3a7640000","blobsBundle":{{"commitments":["0x{}"],"proofs":[{proofs}],"blobs":["{blob}"]}},"shouldOverrideBuilder":false,"executionRequests":["{deposit_list}"]}}"#,
        "33".repeat(48)
    ))
}

#[test]
fn get_payload_decodes_blobs_and_requests() {
    run(async {
        let (engine, client) = connect().await;
        engine.reply("engine_getPayloadV5", get_payload_reply(128));

        let id = PayloadId([1, 2, 3, 4, 5, 6, 7, 8]);
        let built = client.get_payload::<Minimal>(id).await.unwrap();

        // 0xde0b6b3a7640000 wei is exactly 1 ether.
        assert_eq!(built.block_value, U256::from_u64(1_000_000_000_000_000_000));
        assert_eq!(
            built.execution_payload,
            new_payload_request().execution_payload
        );
        assert!(!built.should_override_builder);

        // One blob, one commitment, 128 cell proofs.
        let bundle = &built.blobs_bundle;
        assert_eq!((bundle.blobs.len(), bundle.commitments.len()), (1, 1));
        assert_eq!(bundle.proofs.len(), 128);
        assert!(bundle.blobs[0].iter().all(|&byte| byte == 0x11));

        // The 0x00-typed element holds one all-zero deposit request.
        assert_eq!(built.execution_requests.deposits.len(), 1);
        assert!(built.execution_requests.consolidations.is_empty());

        // The id went out as 8 bytes of DATA.
        assert_eq!(
            engine.calls()[0].params,
            vec![Json::from("0x0102030405060708")]
        );
        engine.stop().await;
    });
}

#[test]
fn get_payload_rejects_a_short_proof_list() {
    run(async {
        let (engine, client) = connect().await;
        // 127 proofs for one blob, one short of the 128 cells.
        engine.reply("engine_getPayloadV5", get_payload_reply(127));

        let error = client
            .get_payload::<Minimal>(PayloadId::default())
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
fn get_blobs_all_or_nothing() {
    run(async {
        let (engine, client) = connect().await;
        let hashes = [VersionedHash([0x01; 32])];

        // Null means at least one blob is missing.
        engine.reply("engine_getBlobsV2", Json::Null);
        assert_eq!(client.get_blobs::<Minimal>(&hashes).await.unwrap(), None);

        // One blob of zeros with 128 proofs answers the one hash.
        let blob = data::encode(&vec![0; 131_072]);
        let proofs = vec![format!("\"0x{}\"", "00".repeat(48)); 128].join(",");
        engine.reply(
            "engine_getBlobsV2",
            json(&format!(r#"[{{"blob":"{blob}","proofs":[{proofs}]}}]"#)),
        );
        let blobs = client.get_blobs::<Minimal>(&hashes).await.unwrap().unwrap();
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].proofs.len(), 128);

        // Two entries for one requested hash is a protocol violation.
        engine.reply(
            "engine_getBlobsV2",
            json(&format!(
                r#"[{{"blob":"{blob}","proofs":[{proofs}]}},{{"blob":"{blob}","proofs":[{proofs}]}}]"#
            )),
        );
        let error = client.get_blobs::<Minimal>(&hashes).await.unwrap_err();
        assert!(matches!(
            error,
            EngineError::Wire(ref wire) if wire.kind() == &WireErrorKind::LengthMismatch { expected: 1, actual: 2 }
        ));
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

        // The engine refuses a payload from an unsupported fork with -38005.
        engine.reply_error(
            "engine_newPayloadV4",
            RpcError::new(RpcError::UNSUPPORTED_FORK, "Unsupported fork"),
        );
        let error = client
            .new_payload(&new_payload_request())
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            EngineError::Rpc(RpcError {
                code: RpcError::UNSUPPORTED_FORK,
                ..
            })
        ));

        // A method without a scripted reply is "method not found".
        let error = client.chain_id().await.unwrap_err();
        assert!(matches!(
            error,
            EngineError::Rpc(RpcError {
                code: RpcError::METHOD_NOT_FOUND,
                ..
            })
        ));

        // An unknown status string is a wire error located at the status member.
        engine.reply(
            "engine_newPayloadV4",
            json(r#"{"status":"MAYBE","latestValidHash":null,"validationError":null}"#),
        );
        let error = client
            .new_payload(&new_payload_request())
            .await
            .unwrap_err();
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
        assert!(engine.calls().is_empty());
        engine.stop().await;
    });
}
