//! Summaries of history that has rolled out of the state's recent root vectors.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Ssz, Vector};

use crate::{Preset, Root};

/// The roots of one full period of block and state roots.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HistoricalSummary {
    /// Root of the period's block roots.
    pub block_summary_root: Root,

    /// Root of the period's state roots.
    pub state_summary_root: Root,
}

impl Container for HistoricalSummary {
    const FIELDS: &'static [Option<usize>] = &[Root::FIXED_SIZE, Root::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.block_summary_root);
        visitor.field(&self.state_summary_root);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            block_summary_root: fields.field()?,
            state_summary_root: fields.field()?,
        })
    }
}

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
