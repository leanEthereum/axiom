//! Batches of history that have rolled out of the state's recent root vectors.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Ssz, Vector};

use crate::{Preset, Root};

/// One full period of block and state roots.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HistoricalBatch<P: Preset> {
    /// Block roots of the period.
    pub block_roots: Vector<Root, P::SlotsPerHistoricalRoot>,

    /// State roots of the period.
    pub state_roots: Vector<Root, P::SlotsPerHistoricalRoot>,
}

impl<P: Preset> Container for HistoricalBatch<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <Vector<Root, P::SlotsPerHistoricalRoot>>::FIXED_SIZE,
        <Vector<Root, P::SlotsPerHistoricalRoot>>::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.block_roots);
        visitor.field(&self.state_roots);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            block_roots: fields.field()?,
            state_roots: fields.field()?,
        })
    }
}
