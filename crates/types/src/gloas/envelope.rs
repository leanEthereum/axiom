//! Execution payload envelopes, the payload a builder reveals after its bid was included.
//!
//! See EIP-7732 and the Gloas beacon chain spec.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Merkleization, Ssz};

use crate::{
    BlsSignature, BuilderIndex, Preset, Root,
    gloas::{ExecutionPayload, ExecutionRequests},
};

/// A revealed payload, bound to the block whose bid it honours.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionPayloadEnvelope<P: Preset> {
    /// The execution payload.
    pub payload: ExecutionPayload<P>,

    /// Requests the payload produced.
    pub execution_requests: ExecutionRequests,

    /// The builder revealing the payload.
    pub builder_index: BuilderIndex,

    /// Block whose bid the payload honours.
    pub beacon_block_root: Root,

    /// Parent of that block, see EIP-4788.
    pub parent_beacon_block_root: Root,
}

impl<P: Preset> Container for ExecutionPayloadEnvelope<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <ExecutionPayload<P>>::FIXED_SIZE,
        ExecutionRequests::FIXED_SIZE,
        BuilderIndex::FIXED_SIZE,
        Root::FIXED_SIZE,
        Root::FIXED_SIZE,
    ];
    const MERKLEIZATION: Merkleization = Merkleization::Progressive(&[true; 5]);

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.payload);
        visitor.field(&self.execution_requests);
        visitor.field(&self.builder_index);
        visitor.field(&self.beacon_block_root);
        visitor.field(&self.parent_beacon_block_root);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            payload: fields.field()?,
            execution_requests: fields.field()?,
            builder_index: fields.field()?,
            beacon_block_root: fields.field()?,
            parent_beacon_block_root: fields.field()?,
        })
    }
}

/// An envelope with its builder's signature.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignedExecutionPayloadEnvelope<P: Preset> {
    /// The envelope.
    pub message: ExecutionPayloadEnvelope<P>,

    /// Builder's signature.
    pub signature: BlsSignature,
}

impl<P: Preset> Container for SignedExecutionPayloadEnvelope<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <ExecutionPayloadEnvelope<P>>::FIXED_SIZE,
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
