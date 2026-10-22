//! Builder API bids of Electra, which carry the payload's execution requests.
//!
//! See the Electra builder spec in the builder-specs repository.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Ssz, U256};

use crate::{
    BlsPubkey, BlsSignature, Preset,
    electra::{BlobKzgCommitments, ExecutionPayloadHeader, ExecutionRequests},
};

/// A builder's offer of a payload, committed to by its header, blobs, and requests.
///
/// See `BuilderBid` in the Electra builder spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuilderBid<P: Preset> {
    /// Header of the offered payload.
    pub header: ExecutionPayloadHeader<P>,

    /// Commitments to the payload's blobs, which the blinded block must carry.
    pub blob_kzg_commitments: BlobKzgCommitments<P>,

    /// Requests the payload produced, which the blinded block must carry.
    pub execution_requests: ExecutionRequests<P>,

    /// Wei the proposer's fee recipient receives.
    pub value: U256,

    /// The bidding builder.
    pub pubkey: BlsPubkey,
}

impl<P: Preset> Container for BuilderBid<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <ExecutionPayloadHeader<P>>::FIXED_SIZE,
        <BlobKzgCommitments<P>>::FIXED_SIZE,
        <ExecutionRequests<P>>::FIXED_SIZE,
        U256::FIXED_SIZE,
        BlsPubkey::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.header);
        visitor.field(&self.blob_kzg_commitments);
        visitor.field(&self.execution_requests);
        visitor.field(&self.value);
        visitor.field(&self.pubkey);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            header: fields.field()?,
            blob_kzg_commitments: fields.field()?,
            execution_requests: fields.field()?,
            value: fields.field()?,
            pubkey: fields.field()?,
        })
    }
}

/// A bid with its builder's signature.
///
/// See `SignedBuilderBid` in the Electra builder spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignedBuilderBid<P: Preset> {
    /// The bid.
    pub message: BuilderBid<P>,

    /// Builder's signature in the application builder domain.
    pub signature: BlsSignature,
}

impl<P: Preset> Container for SignedBuilderBid<P> {
    const FIELDS: &'static [Option<usize>] =
        &[<BuilderBid<P>>::FIXED_SIZE, BlsSignature::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.message);
        visitor.field(&self.signature);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            message: fields.field()?,
            signature: fields.field()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KzgCommitment, Minimal, electra::DepositRequest};

    #[test]
    fn bid_round_trips_through_ssz() {
        // Fixture state: a bid of 11 wei committing to one blob and one deposit request.
        let mut bid = SignedBuilderBid::<Minimal>::default();
        bid.message
            .blob_kzg_commitments
            .push(KzgCommitment([1; 48]))
            .unwrap();
        bid.message
            .execution_requests
            .deposits
            .push(DepositRequest::default())
            .unwrap();
        bid.message.value = U256::from(11);
        bid.signature = BlsSignature([2; 96]);

        let decoded = SignedBuilderBid::<Minimal>::decode(&bid.encode()).unwrap();

        assert_eq!(decoded, bid);
    }
}
