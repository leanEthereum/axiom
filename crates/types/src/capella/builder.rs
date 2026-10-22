//! Builder API bids of Capella, over the Capella payload header.
//!
//! See the Capella builder spec in the builder-specs repository.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Ssz, U256};

use crate::{BlsPubkey, BlsSignature, Preset, capella::ExecutionPayloadHeader};

/// A builder's offer of a payload, committed to by its header.
///
/// See `BuilderBid` in the Capella builder spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuilderBid<P: Preset> {
    /// Header of the offered payload.
    pub header: ExecutionPayloadHeader<P>,

    /// Wei the proposer's fee recipient receives.
    pub value: U256,

    /// The bidding builder.
    pub pubkey: BlsPubkey,
}

impl<P: Preset> Container for BuilderBid<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <ExecutionPayloadHeader<P>>::FIXED_SIZE,
        U256::FIXED_SIZE,
        BlsPubkey::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.header);
        visitor.field(&self.value);
        visitor.field(&self.pubkey);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            header: fields.field()?,
            value: fields.field()?,
            pubkey: fields.field()?,
        })
    }
}

/// A bid with its builder's signature.
///
/// See `SignedBuilderBid` in the Capella builder spec.
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
    use crate::{Minimal, Root};

    #[test]
    fn bid_round_trips_through_ssz() {
        // Fixture state: a bid of 7 wei whose payload withdraws to root 0x0303...03.
        let mut bid = SignedBuilderBid::<Minimal>::default();
        bid.message.header.withdrawals_root = Root([3; 32]);
        bid.message.value = U256::from(7);
        bid.signature = BlsSignature([1; 96]);

        let decoded = SignedBuilderBid::<Minimal>::decode(&bid.encode()).unwrap();

        assert_eq!(decoded, bid);
    }
}
