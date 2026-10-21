//! Evidence of slashable behaviour.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Ssz};

use crate::{IndexedAttestation, Preset, SignedBeaconBlockHeader};

/// Two distinct signed headers from one proposer for one slot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProposerSlashing {
    /// The first header.
    pub signed_header_1: SignedBeaconBlockHeader,

    /// The conflicting second header.
    pub signed_header_2: SignedBeaconBlockHeader,
}

impl Container for ProposerSlashing {
    const FIELDS: &'static [Option<usize>] = &[
        SignedBeaconBlockHeader::FIXED_SIZE,
        SignedBeaconBlockHeader::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.signed_header_1);
        visitor.field(&self.signed_header_2);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            signed_header_1: fields.field()?,
            signed_header_2: fields.field()?,
        })
    }
}

/// Two attestations that violate a Casper FFG commandment.
///
/// They either vote for two targets in one epoch, or one surrounds the other.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttesterSlashing<P: Preset> {
    /// The first attestation.
    pub attestation_1: IndexedAttestation<P>,

    /// The conflicting second attestation.
    pub attestation_2: IndexedAttestation<P>,
}

impl<P: Preset> Container for AttesterSlashing<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <IndexedAttestation<P>>::FIXED_SIZE,
        <IndexedAttestation<P>>::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.attestation_1);
        visitor.field(&self.attestation_2);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            attestation_1: fields.field()?,
            attestation_2: fields.field()?,
        })
    }
}
