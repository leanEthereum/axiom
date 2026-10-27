//! Execution requests of Hstar, with key authorizations from withdrawal addresses.
//!
//! See EIP-7685 and EIP-8450.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Merkleization, Ssz};

use crate::{
    Preset, Root,
    hstar::{
        BuilderDepositRequests, BuilderExitRequests, ConsolidationRequests, DepositRequests,
        ExecutionPayload, PqKeyAuthorizationRequests, VersionedHashes, WithdrawalRequests,
    },
};

/// Requests the execution layer passes to the consensus layer.
///
/// See EIP-7685 and EIP-8450.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionRequests {
    /// Deposit requests, see EIP-6110.
    pub deposits: DepositRequests,

    /// Withdrawal requests, see EIP-7002.
    pub withdrawals: WithdrawalRequests,

    /// Consolidation requests, see EIP-7251.
    pub consolidations: ConsolidationRequests,

    /// Builder deposit requests.
    pub builder_deposits: BuilderDepositRequests,

    /// Builder exit requests.
    pub builder_exits: BuilderExitRequests,

    /// Post-quantum key authorizations by withdrawal addresses, see EIP-8450.
    pub pq_key_authorizations: PqKeyAuthorizationRequests,
}

impl Container for ExecutionRequests {
    const FIELDS: &'static [Option<usize>] = &[
        DepositRequests::FIXED_SIZE,
        WithdrawalRequests::FIXED_SIZE,
        ConsolidationRequests::FIXED_SIZE,
        BuilderDepositRequests::FIXED_SIZE,
        BuilderExitRequests::FIXED_SIZE,
        PqKeyAuthorizationRequests::FIXED_SIZE,
    ];
    const MERKLEIZATION: Merkleization = Merkleization::Progressive(&[true; 6]);

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.deposits);
        visitor.field(&self.withdrawals);
        visitor.field(&self.consolidations);
        visitor.field(&self.builder_deposits);
        visitor.field(&self.builder_exits);
        visitor.field(&self.pq_key_authorizations);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            deposits: fields.field()?,
            withdrawals: fields.field()?,
            consolidations: fields.field()?,
            builder_deposits: fields.field()?,
            builder_exits: fields.field()?,
            pq_key_authorizations: fields.field()?,
        })
    }
}

/// Everything the execution engine needs to validate a payload.
///
/// See the Gloas beacon chain spec, with the requests of EIP-8450.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NewPayloadRequest<P: Preset> {
    /// The payload.
    pub execution_payload: ExecutionPayload<P>,

    /// Hashes of the payload's blob commitments.
    pub versioned_hashes: VersionedHashes<P>,

    /// Root of the parent beacon block, see EIP-4788.
    pub parent_beacon_block_root: Root,

    /// Requests the payload produced.
    pub execution_requests: ExecutionRequests,
}

impl<P: Preset> Container for NewPayloadRequest<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <ExecutionPayload<P>>::FIXED_SIZE,
        <VersionedHashes<P>>::FIXED_SIZE,
        Root::FIXED_SIZE,
        ExecutionRequests::FIXED_SIZE,
    ];
    const MERKLEIZATION: Merkleization = Merkleization::Progressive(&[true; 4]);

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.execution_payload);
        visitor.field(&self.versioned_hashes);
        visitor.field(&self.parent_beacon_block_root);
        visitor.field(&self.execution_requests);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            execution_payload: fields.field()?,
            versioned_hashes: fields.field()?,
            parent_beacon_block_root: fields.field()?,
            execution_requests: fields.field()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use axiom_ssz::Ssz;

    use super::*;
    use crate::{gloas, hstar::PqKeyAuthorizationRequest};

    #[test]
    fn appending_a_field_keeps_the_root_of_empty_requests_apart() {
        // Progressive containers merkleize the fields they have.
        // The sixth field therefore changes the root even when every list is empty.
        let gloas_root = gloas::ExecutionRequests::default().hash_tree_root();
        let hstar_root = ExecutionRequests::default().hash_tree_root();
        assert_ne!(gloas_root, hstar_root);
    }

    #[test]
    fn requests_round_trip_through_ssz() {
        // Fixture state: one key authorization, the rest empty.
        let mut requests = ExecutionRequests::default();
        requests
            .pq_key_authorizations
            .push(PqKeyAuthorizationRequest {
                public_keys_root: Root([7; 32]),
                ..PqKeyAuthorizationRequest::default()
            });

        let decoded = ExecutionRequests::decode(&requests.encode()).unwrap();

        assert_eq!(decoded, requests);
    }
}
