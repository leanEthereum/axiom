//! Messages of the builder API, through which a proposer buys an execution payload.
//!
//! These are not consensus containers.
//! Builder API messages are signed in the application builder domain, not in a fork's domain.
//! See the Bellatrix builder spec in the builder-specs repository.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Ssz, U256};

use crate::{BlsPubkey, BlsSignature, ExecutionAddress, Preset, bellatrix::ExecutionPayloadHeader};

/// A validator's standing preferences for the payloads built on its behalf.
///
/// See `ValidatorRegistrationV1` in the Bellatrix builder spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ValidatorRegistrationV1 {
    /// Address that receives the payload's fees.
    pub fee_recipient: ExecutionAddress,

    /// Gas limit the validator asks builders to target.
    pub gas_limit: u64,

    /// Unix time of the registration, so a newer one replaces an older one.
    pub timestamp: u64,

    /// The registering validator.
    pub pubkey: BlsPubkey,
}

impl Container for ValidatorRegistrationV1 {
    const FIELDS: &'static [Option<usize>] = &[
        ExecutionAddress::FIXED_SIZE,
        u64::FIXED_SIZE,
        u64::FIXED_SIZE,
        BlsPubkey::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.fee_recipient);
        visitor.field(&self.gas_limit);
        visitor.field(&self.timestamp);
        visitor.field(&self.pubkey);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            fee_recipient: fields.field()?,
            gas_limit: fields.field()?,
            timestamp: fields.field()?,
            pubkey: fields.field()?,
        })
    }
}

/// A registration with its validator's signature.
///
/// See `SignedValidatorRegistrationV1` in the Bellatrix builder spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignedValidatorRegistrationV1 {
    /// The registration.
    pub message: ValidatorRegistrationV1,

    /// Validator's signature in the application builder domain.
    pub signature: BlsSignature,
}

impl Container for SignedValidatorRegistrationV1 {
    const FIELDS: &'static [Option<usize>] = &[
        ValidatorRegistrationV1::FIXED_SIZE,
        BlsSignature::FIXED_SIZE,
    ];

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

/// A builder's offer of a payload, committed to by its header.
///
/// See `BuilderBid` in the Bellatrix builder spec.
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
/// See `SignedBuilderBid` in the Bellatrix builder spec.
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
    use crate::{Hash32, Minimal};

    #[test]
    fn registration_round_trips_through_ssz() {
        // Fixture state: a validator asking for a 30 million gas limit at time 1700000000.
        let registration = SignedValidatorRegistrationV1 {
            message: ValidatorRegistrationV1 {
                fee_recipient: ExecutionAddress([7; 20]),
                gas_limit: 30_000_000,
                timestamp: 1_700_000_000,
                pubkey: BlsPubkey([9; 48]),
            },
            signature: BlsSignature([3; 96]),
        };

        // Every field is fixed-size: 20 + 8 + 8 + 48 bytes, then the 96-byte signature.
        let bytes = registration.encode();
        assert_eq!(bytes.len(), 180);
        assert_eq!(
            SignedValidatorRegistrationV1::decode(&bytes).unwrap(),
            registration
        );
    }

    #[test]
    fn bid_round_trips_through_ssz() {
        // Fixture state: a bid of 5 wei for a payload with block hash 0x0404...04.
        let mut bid = SignedBuilderBid::<Minimal>::default();
        bid.message.header.block_hash = Hash32([4; 32]);
        bid.message.value = U256::from(5);
        bid.message.pubkey = BlsPubkey([2; 48]);
        bid.signature = BlsSignature([1; 96]);

        let decoded = SignedBuilderBid::<Minimal>::decode(&bid.encode()).unwrap();

        assert_eq!(decoded, bid);
    }
}
