//! Execution payloads, versions V1 to V4, and WithdrawalV1.
//!
//! Each version appends members to the one before it.
//! Each maps member by member onto the consensus container of the fork that introduced it.
//!
//! ```text
//!     JSON member        encoding        V1  V2  V3  V4   consensus field
//!     parentHash         DATA 32         x   x   x   x    parent_hash
//!     feeRecipient       DATA 20         x   x   x   x    fee_recipient
//!     stateRoot          DATA 32         x   x   x   x    state_root
//!     receiptsRoot       DATA 32         x   x   x   x    receipts_root
//!     logsBloom          DATA 256        x   x   x   x    logs_bloom
//!     prevRandao         DATA 32         x   x   x   x    prev_randao
//!     blockNumber        QUANTITY 64     x   x   x   x    block_number
//!     gasLimit           QUANTITY 64     x   x   x   x    gas_limit
//!     gasUsed            QUANTITY 64     x   x   x   x    gas_used
//!     timestamp          QUANTITY 64     x   x   x   x    timestamp
//!     extraData          DATA 0..32      x   x   x   x    extra_data
//!     baseFeePerGas      QUANTITY 256    x   x   x   x    base_fee_per_gas
//!     blockHash          DATA 32         x   x   x   x    block_hash
//!     transactions       array of DATA   x   x   x   x    transactions
//!     withdrawals        WithdrawalV1s       x   x   x    withdrawals
//!     blobGasUsed        QUANTITY 64             x   x    blob_gas_used
//!     excessBlobGas      QUANTITY 64             x   x    excess_blob_gas
//!     blockAccessList    DATA                        x    block_access_list
//!     slotNumber         QUANTITY 64                 x    slot_number
//! ```
//!
//! The versions are defined in the Paris, Shanghai, Cancun, and Amsterdam files of `src/engine/`.
//! Their containers come from Bellatrix, Capella, Deneb, and Gloas.
//!
//! Every member of a version is required.
//! A payload of an older version lacks the newer members and is refused.

mod v1;
mod v2;
mod v3;
mod v4;
mod withdrawal;

#[cfg(test)]
pub(crate) mod tests {
    use axiom_json::Json;
    use axiom_ssz::{ByteList, ByteVector, List, ProgressiveList, U256};
    use axiom_types::{
        Bytes32, ExecutionAddress, Gwei, Hash32, Minimal, ValidatorIndex, WithdrawalIndex,
        bellatrix, capella, deneb, gloas,
    };
    use proptest::prelude::*;

    use crate::{JsonCodec, PayloadStatus};

    /// Any withdrawal.
    pub(crate) fn withdrawal() -> impl Strategy<Value = capella::Withdrawal> {
        (any::<u64>(), any::<u64>(), any::<[u8; 20]>(), any::<u64>()).prop_map(
            |(index, validator, address, amount)| capella::Withdrawal {
                index: WithdrawalIndex(index),
                validator_index: ValidatorIndex(validator),
                address: ExecutionAddress(address),
                amount: Gwei(amount),
            },
        )
    }

    /// Any Deneb payload with up to three small transactions and four withdrawals.
    ///
    /// The other versions derive from it, dropping or adding members.
    pub(crate) fn payload_v3() -> impl Strategy<Value = deneb::ExecutionPayload<Minimal>> {
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
                )| deneb::ExecutionPayload {
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

    /// Any Bellatrix payload: a Deneb one without withdrawals and blob gas.
    pub(crate) fn payload_v1() -> impl Strategy<Value = bellatrix::ExecutionPayload<Minimal>> {
        payload_v3().prop_map(|payload| bellatrix::ExecutionPayload {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom,
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data,
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash,
            transactions: payload.transactions,
        })
    }

    /// Any Capella payload: a Deneb one without blob gas.
    pub(crate) fn payload_v2() -> impl Strategy<Value = capella::ExecutionPayload<Minimal>> {
        payload_v3().prop_map(|payload| capella::ExecutionPayload {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom,
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data,
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash,
            transactions: payload.transactions,
            withdrawals: payload.withdrawals,
        })
    }

    /// Any Gloas payload: a Deneb one with an access list and a slot number.
    pub(crate) fn payload_v4() -> impl Strategy<Value = gloas::ExecutionPayload<Minimal>> {
        (
            payload_v3(),
            proptest::collection::vec(any::<u8>(), 0..64),
            any::<u64>(),
        )
            .prop_map(
                |(payload, access_list, slot_number)| gloas::ExecutionPayload {
                    parent_hash: payload.parent_hash,
                    fee_recipient: payload.fee_recipient,
                    state_root: payload.state_root,
                    receipts_root: payload.receipts_root,
                    logs_bloom: payload.logs_bloom,
                    prev_randao: payload.prev_randao,
                    block_number: payload.block_number,
                    gas_limit: payload.gas_limit,
                    gas_used: payload.gas_used,
                    timestamp: payload.timestamp,
                    extra_data: payload.extra_data,
                    base_fee_per_gas: payload.base_fee_per_gas,
                    block_hash: payload.block_hash,
                    transactions: payload
                        .transactions
                        .iter()
                        .map(|tx| ProgressiveList::from(tx.to_vec()))
                        .collect(),
                    withdrawals: payload.withdrawals.iter().cloned().collect(),
                    blob_gas_used: payload.blob_gas_used,
                    excess_blob_gas: payload.excess_blob_gas,
                    block_access_list: ProgressiveList::from(access_list),
                    slot_number,
                },
            )
    }

    proptest! {
        #[test]
        fn payload_decoders_never_panic(text in "[{}\\[\\]\":,a-zA-Z0-9x]{0,200}") {
            // Random JSON-ish text: parse failures and mapping failures are both fine.
            if let Ok(value) = Json::parse(&text) {
                let _ = bellatrix::ExecutionPayload::<Minimal>::from_json(&value);
                let _ = capella::ExecutionPayload::<Minimal>::from_json(&value);
                let _ = deneb::ExecutionPayload::<Minimal>::from_json(&value);
                let _ = gloas::ExecutionPayload::<Minimal>::from_json(&value);
                let _ = PayloadStatus::from_json(&value);
            }
        }
    }
}
