//! Laws of the JSON mapping, the requests list, and JWT, checked on random values.

use axiom_execution::{
    ForkchoiceState, JsonCodec, JwtSecret, PayloadAttributes, PayloadStatus, PayloadStatusKind,
    wire::RequestsList,
};
use axiom_json::Json;
use axiom_ssz::{ByteList, ByteVector, List, U256};
use axiom_types::{
    BlsPubkey, BlsSignature, Bytes32, ConsolidationRequest, DepositRequest, ExecutionAddress,
    ExecutionPayload, ExecutionRequests, Gwei, Hash32, Minimal, Root, ValidatorIndex, Withdrawal,
    WithdrawalIndex, WithdrawalRequest,
};
use proptest::prelude::*;

/// Any withdrawal.
fn withdrawal() -> impl Strategy<Value = Withdrawal> {
    (any::<u64>(), any::<u64>(), any::<[u8; 20]>(), any::<u64>()).prop_map(
        |(index, validator, address, amount)| Withdrawal {
            index: WithdrawalIndex(index),
            validator_index: ValidatorIndex(validator),
            address: ExecutionAddress(address),
            amount: Gwei(amount),
        },
    )
}

/// Any minimal-preset payload with up to three small transactions and four withdrawals.
fn payload() -> impl Strategy<Value = ExecutionPayload<Minimal>> {
    (
        (
            any::<[u8; 32]>(),
            any::<[u8; 20]>(),
            any::<[u8; 32]>(),
            any::<[u8; 32]>(),
        ),
        (
            proptest::collection::vec(any::<u8>(), 256),
            any::<[u8; 32]>(),
            any::<[u64; 4]>(),
        ),
        (
            proptest::collection::vec(any::<u8>(), 0..=32),
            any::<[u8; 32]>(),
            any::<[u8; 32]>(),
        ),
        (
            proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..40), 0..3),
            proptest::collection::vec(withdrawal(), 0..=4),
            any::<[u64; 2]>(),
        ),
    )
        .prop_map(
            |(
                (parent, fee_recipient, state_root, receipts_root),
                (bloom, randao, [number, gas_limit, gas_used, timestamp]),
                (extra, base_fee, block_hash),
                (transactions, withdrawals, [blob_gas_used, excess_blob_gas]),
            )| ExecutionPayload {
                parent_hash: Hash32(parent),
                fee_recipient: ExecutionAddress(fee_recipient),
                state_root: Bytes32(state_root),
                receipts_root: Bytes32(receipts_root),
                logs_bloom: ByteVector::try_from(bloom.as_slice()).expect("within the limit"),
                prev_randao: Bytes32(randao),
                block_number: number,
                gas_limit,
                gas_used,
                timestamp,
                extra_data: ByteList::try_from(extra).expect("within the limit"),
                base_fee_per_gas: U256(base_fee),
                block_hash: Hash32(block_hash),
                transactions: List::try_from(
                    transactions
                        .into_iter()
                        .map(|tx| ByteList::try_from(tx).expect("within the limit"))
                        .collect::<Vec<_>>(),
                )
                .expect("within the limit"),
                withdrawals: List::try_from(withdrawals).expect("within the limit"),
                blob_gas_used,
                excess_blob_gas,
            },
        )
}

/// Any requests with up to three of each type.
fn execution_requests() -> impl Strategy<Value = ExecutionRequests<Minimal>> {
    let deposit = (any::<u8>(), any::<u64>(), any::<u64>()).prop_map(|(byte, amount, index)| {
        DepositRequest {
            pubkey: BlsPubkey([byte; 48]),
            withdrawal_credentials: Bytes32([byte; 32]),
            amount: Gwei(amount),
            signature: BlsSignature([byte; 96]),
            index,
        }
    });
    let withdrawal = (any::<u8>(), any::<u64>()).prop_map(|(byte, amount)| WithdrawalRequest {
        source_address: ExecutionAddress([byte; 20]),
        validator_pubkey: BlsPubkey([byte; 48]),
        amount: Gwei(amount),
    });
    let consolidation = any::<u8>().prop_map(|byte| ConsolidationRequest {
        source_address: ExecutionAddress([byte; 20]),
        source_pubkey: BlsPubkey([byte; 48]),
        target_pubkey: BlsPubkey([byte.wrapping_add(1); 48]),
    });
    (
        proptest::collection::vec(deposit, 0..3),
        proptest::collection::vec(withdrawal, 0..3),
        proptest::collection::vec(consolidation, 0..=2),
    )
        .prop_map(
            |(deposits, withdrawals, consolidations)| ExecutionRequests {
                deposits: List::try_from(deposits).expect("within the limit"),
                withdrawals: List::try_from(withdrawals).expect("within the limit"),
                consolidations: List::try_from(consolidations).expect("within the limit"),
            },
        )
}

proptest! {
    #[test]
    fn payload_round_trip(payload in payload()) {
        // Through the JSON value and through its text: both come back unchanged.
        let value = payload.to_json();
        prop_assert_eq!(ExecutionPayload::<Minimal>::from_json(&value), Ok(payload.clone()));
        let reparsed = Json::parse(value.to_string()).unwrap();
        prop_assert_eq!(ExecutionPayload::<Minimal>::from_json(&reparsed), Ok(payload));
    }

    #[test]
    fn attributes_and_state_round_trip(
        withdrawals in proptest::collection::vec(withdrawal(), 0..=4),
        timestamp in any::<u64>(),
        hashes in any::<[[u8; 32]; 3]>(),
    ) {
        let attributes = PayloadAttributes::<Minimal> {
            timestamp,
            prev_randao: Bytes32(hashes[0]),
            suggested_fee_recipient: ExecutionAddress([hashes[1][0]; 20]),
            withdrawals: List::try_from(withdrawals).unwrap(),
            parent_beacon_block_root: Root(hashes[2]),
        };
        prop_assert_eq!(PayloadAttributes::from_json(&attributes.to_json()), Ok(attributes));

        let state = ForkchoiceState {
            head_block_hash: Hash32(hashes[0]),
            safe_block_hash: Hash32(hashes[1]),
            finalized_block_hash: Hash32(hashes[2]),
        };
        prop_assert_eq!(ForkchoiceState::from_json(&state.to_json()), Ok(state));
    }

    #[test]
    fn status_round_trip(
        kind in 0_usize..5,
        hash in proptest::option::of(any::<[u8; 32]>()),
        message in proptest::option::of(".{0,20}"),
    ) {
        let status = PayloadStatus {
            status: [
                PayloadStatusKind::Valid,
                PayloadStatusKind::Invalid,
                PayloadStatusKind::Syncing,
                PayloadStatusKind::Accepted,
                PayloadStatusKind::InvalidBlockHash,
            ][kind],
            latest_valid_hash: hash.map(Hash32),
            validation_error: message,
        };
        prop_assert_eq!(PayloadStatus::from_json(&status.to_json()), Ok(status));
    }

    #[test]
    fn requests_list_round_trip(requests in execution_requests()) {
        // The list holds one element per non-empty type, in ascending type order.
        let list = RequestsList::encode(&requests);
        let elements = list.as_slice();
        let non_empty = [
            !requests.deposits.is_empty(),
            !requests.withdrawals.is_empty(),
            !requests.consolidations.is_empty(),
        ];
        prop_assert_eq!(elements.len(), non_empty.iter().filter(|&&present| present).count());
        prop_assert!(elements.windows(2).all(|pair| pair[0][0] < pair[1][0]));
        prop_assert_eq!(list.decode::<Minimal>(), Ok(requests.clone()));

        // The JSON array form decodes back too.
        prop_assert_eq!(ExecutionRequests::<Minimal>::from_json(&requests.to_json()), Ok(requests));
    }

    #[test]
    fn requests_decoder_never_panics(
        list in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..400), 0..4),
    ) {
        // Arbitrary elements either decode or fail; nothing in between.
        let _ = RequestsList::from(list).decode::<Minimal>();
    }

    #[test]
    fn payload_decoder_never_panics(text in "[{}\\[\\]\":,a-zA-Z0-9x]{0,200}") {
        // Random JSON-ish text: parse failures and mapping failures are both fine.
        if let Ok(value) = Json::parse(&text) {
            let _ = ExecutionPayload::<Minimal>::from_json(&value);
            let _ = PayloadStatus::from_json(&value);
        }
    }

    #[test]
    fn jwt_round_trip_and_tamper_detection(
        key in any::<[u8; 32]>(),
        issued_at in 0_u64..4_000_000_000,
        position in any::<prop::sample::Index>(),
    ) {
        let secret = JwtSecret::new(key);
        let token = secret.token(issued_at);
        prop_assert_eq!(secret.verify(&token, issued_at).map(|claims| claims.issued_at), Ok(issued_at));

        // Replacing any one character with a different symbol breaks the token.
        let mut bytes = token.into_bytes();
        let at = position.index(bytes.len());
        bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).unwrap();
        prop_assert!(secret.verify(&tampered, issued_at).is_err());
    }
}
