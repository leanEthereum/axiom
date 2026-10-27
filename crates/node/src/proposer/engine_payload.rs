//! Between the engine's payload versions and the forms block production takes.

use axiom_block_production::{LocalBuild, LocalPayload, PayloadRequest};
use axiom_execution::{
    GetPayloadResponse, PayloadAttributes, PayloadAttributesV1, PayloadAttributesV2,
    PayloadAttributesV3, PayloadAttributesV4, RequestsError,
};
use axiom_ssz::{List, ProgressiveList, U256};
use axiom_types::{ExecutionAddress, ForkName, Preset, deneb, fulu};

/// What a proposer asks the engine to build: the slot's request, and the proposer's wishes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BuildOrder {
    /// What the state fixes: time, randomness, withdrawals, parent root.
    pub(crate) request: PayloadRequest,
    /// Where the priority fees go.
    pub(crate) fee_recipient: ExecutionAddress,
    /// The gas limit the proposer aims for, which Gloas attributes carry.
    pub(crate) gas_limit: u64,
}

impl BuildOrder {
    /// The payload attributes of the fork's engine method, or none before the merge.
    ///
    /// See `prepare_execution_payload` in the Bellatrix to Gloas validator specs.
    #[must_use]
    pub(crate) fn attributes<P: Preset>(&self, fork: ForkName) -> Option<PayloadAttributes<P>> {
        let request = &self.request;
        let withdrawals = request.withdrawals.clone();
        let attributes = match fork {
            ForkName::Phase0 | ForkName::Altair => return None,
            ForkName::Bellatrix => PayloadAttributes::V1(PayloadAttributesV1 {
                timestamp: request.timestamp,
                prev_randao: request.prev_randao,
                suggested_fee_recipient: self.fee_recipient,
            }),
            ForkName::Capella => PayloadAttributes::V2(PayloadAttributesV2 {
                timestamp: request.timestamp,
                prev_randao: request.prev_randao,
                suggested_fee_recipient: self.fee_recipient,
                // Invariant: the state caps the withdrawals due at the payload's bound.
                withdrawals: List::try_from(withdrawals).ok()?,
            }),
            ForkName::Deneb | ForkName::Electra | ForkName::Fulu => {
                PayloadAttributes::V3(PayloadAttributesV3 {
                    timestamp: request.timestamp,
                    prev_randao: request.prev_randao,
                    suggested_fee_recipient: self.fee_recipient,
                    withdrawals: List::try_from(withdrawals).ok()?,
                    parent_beacon_block_root: request.parent_beacon_block_root,
                })
            }
            ForkName::Gloas | ForkName::Hstar => PayloadAttributes::V4(PayloadAttributesV4 {
                timestamp: request.timestamp,
                prev_randao: request.prev_randao,
                suggested_fee_recipient: self.fee_recipient,
                withdrawals: ProgressiveList::from(withdrawals),
                parent_beacon_block_root: request.parent_beacon_block_root,
                slot_number: request.slot,
                target_gas_limit: self.gas_limit,
            }),
        };
        Some(attributes)
    }
}

/// A payload the engine returned, as block production takes it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct EnginePayload;

impl EnginePayload {
    /// The local build of an engine response, for a slot of a fork.
    ///
    /// The engine's first version reports no value, so the payload counts as worth nothing.
    /// Gloas and Hstar share the sixth version, whose requests list each fork reads as its own.
    ///
    /// # Errors
    ///
    /// Fails when the requests list holds a type the fork does not know, or is malformed.
    pub(crate) fn local_build<P: Preset>(
        response: GetPayloadResponse<P>,
        fork: ForkName,
    ) -> Result<LocalBuild<P>, RequestsError> {
        Ok(match response {
            GetPayloadResponse::V1(payload) => LocalBuild {
                payload: LocalPayload::Bellatrix(payload),
                value: U256::default(),
            },
            GetPayloadResponse::V2(response) => LocalBuild {
                payload: LocalPayload::Capella(response.execution_payload),
                value: response.block_value,
            },
            GetPayloadResponse::V3(response) => LocalBuild {
                payload: LocalPayload::Deneb {
                    payload: response.execution_payload,
                    blobs: deneb::BlobsBundle {
                        commitments: response.blobs_bundle.commitments,
                        proofs: response.blobs_bundle.proofs,
                        blobs: response.blobs_bundle.blobs,
                    },
                },
                value: response.block_value,
            },
            GetPayloadResponse::V4(response) => LocalBuild {
                payload: LocalPayload::Electra {
                    payload: response.execution_payload,
                    blobs: deneb::BlobsBundle {
                        commitments: response.blobs_bundle.commitments,
                        proofs: response.blobs_bundle.proofs,
                        blobs: response.blobs_bundle.blobs,
                    },
                    requests: response.execution_requests,
                },
                value: response.block_value,
            },
            GetPayloadResponse::V5(response) => LocalBuild {
                payload: LocalPayload::Fulu {
                    payload: response.execution_payload,
                    blobs: fulu::BlobsBundle {
                        commitments: response.blobs_bundle.commitments,
                        proofs: response.blobs_bundle.proofs,
                        blobs: response.blobs_bundle.blobs,
                    },
                    requests: response.execution_requests,
                },
                value: response.block_value,
            },
            GetPayloadResponse::V6(response) => {
                let blobs = fulu::BlobsBundle {
                    commitments: response.blobs_bundle.commitments,
                    proofs: response.blobs_bundle.proofs,
                    blobs: response.blobs_bundle.blobs,
                };
                let payload = response.execution_payload;
                let requests = response.execution_requests;
                let payload = if fork == ForkName::Hstar {
                    LocalPayload::Hstar {
                        payload,
                        blobs,
                        requests: requests.decode()?,
                    }
                } else {
                    LocalPayload::Gloas {
                        payload,
                        blobs,
                        requests: requests.decode()?,
                    }
                };
                LocalBuild {
                    payload,
                    value: response.block_value,
                }
            }
        })
    }
}
