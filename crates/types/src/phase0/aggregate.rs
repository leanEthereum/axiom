//! Aggregates submitted by selected aggregators.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Ssz};

use crate::{BlsSignature, Preset, ValidatorIndex, phase0::Attestation};

/// An aggregate with proof that its sender was selected to aggregate.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AggregateAndProof<P: Preset> {
    /// The aggregator.
    pub aggregator_index: ValidatorIndex,

    /// The aggregate attestation.
    pub aggregate: Attestation<P>,

    /// Signature over the slot, whose hash proves selection.
    pub selection_proof: BlsSignature,
}

impl<P: Preset> Container for AggregateAndProof<P> {
    const FIELDS: &'static [Option<usize>] = &[
        ValidatorIndex::FIXED_SIZE,
        <Attestation<P>>::FIXED_SIZE,
        BlsSignature::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.aggregator_index);
        visitor.field(&self.aggregate);
        visitor.field(&self.selection_proof);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            aggregator_index: fields.field()?,
            aggregate: fields.field()?,
            selection_proof: fields.field()?,
        })
    }
}

/// An aggregate and proof, signed by the aggregator.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignedAggregateAndProof<P: Preset> {
    /// The aggregate and proof.
    pub message: AggregateAndProof<P>,

    /// Aggregator's signature.
    pub signature: BlsSignature,
}

impl<P: Preset> Container for SignedAggregateAndProof<P> {
    const FIELDS: &'static [Option<usize>] =
        &[<AggregateAndProof<P>>::FIXED_SIZE, BlsSignature::FIXED_SIZE];

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
