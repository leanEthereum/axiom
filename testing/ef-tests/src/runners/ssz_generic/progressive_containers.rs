//! The progressive test containers of the generic SSZ vectors.
//!
//! The definitions follow the `progressive_containers` section of the consensus specs'
//! `tests/formats/ssz_generic/README.md`.
//! Each one lists its active positions, so inactive ones keep later fields in place, see EIP-7495.

use axiom_ssz::{
    Const, Container, DecodeError, FieldDecoder, FieldVisitor, List, Merkleization,
    ProgressiveBitList, ProgressiveList, Ssz,
};

use super::containers::{SmallTestStruct, VarTestStruct};

/// The bounded list of 16-bit integers the progressive containers share.
type Uint16List = List<u16, Const<123>>;

/// A progressive container with one byte at position 0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ProgressiveSingleFieldContainerTestStruct {
    /// The only field, a byte.
    a: u8,
}

impl Container for ProgressiveSingleFieldContainerTestStruct {
    const FIELDS: &'static [Option<usize>] = &[u8::FIXED_SIZE];
    const MERKLEIZATION: Merkleization = Merkleization::Progressive(&[true]);

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.a);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self { a: fields.field()? })
    }
}

/// A progressive container whose only field sits at position 4.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ProgressiveSingleListContainerTestStruct {
    /// The only field, a progressive bitlist.
    c: ProgressiveBitList,
}

impl Container for ProgressiveSingleListContainerTestStruct {
    const FIELDS: &'static [Option<usize>] = &[ProgressiveBitList::FIXED_SIZE];
    const MERKLEIZATION: Merkleization =
        Merkleization::Progressive(&[false, false, false, false, true]);

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.c);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self { c: fields.field()? })
    }
}

/// A progressive container with fields at positions 0, 2, and 4.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ProgressiveVarTestStruct {
    /// A byte, at position 0.
    a: u8,
    /// Up to 123 integers of 16 bits, at position 2.
    b: Uint16List,
    /// A progressive bitlist, at position 4.
    c: ProgressiveBitList,
}

impl Container for ProgressiveVarTestStruct {
    const FIELDS: &'static [Option<usize>] = &[
        u8::FIXED_SIZE,
        Uint16List::FIXED_SIZE,
        ProgressiveBitList::FIXED_SIZE,
    ];
    const MERKLEIZATION: Merkleization =
        Merkleization::Progressive(&[true, false, true, false, true]);

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.a);
        visitor.field(&self.b);
        visitor.field(&self.c);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            a: fields.field()?,
            b: fields.field()?,
            c: fields.field()?,
        })
    }
}

/// A progressive container of eight fields spread over 22 positions, nesting the others.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ProgressiveComplexTestStruct {
    /// A byte, at position 0.
    a: u8,
    /// Up to 123 integers of 16 bits, at position 2.
    b: Uint16List,
    /// A progressive bitlist, at position 4.
    c: ProgressiveBitList,
    /// Any number of 64-bit integers, at position 8.
    d: ProgressiveList<u64>,
    /// Any number of nested fixed-size binary containers, at position 12.
    e: ProgressiveList<SmallTestStruct>,
    /// Any number of lists of nested variable-size binary containers, at position 13.
    f: ProgressiveList<ProgressiveList<VarTestStruct>>,
    /// Up to ten nested single-field progressive containers, at position 20.
    g: List<ProgressiveSingleFieldContainerTestStruct, Const<10>>,
    /// Any number of nested variable-size progressive containers, at position 21.
    h: ProgressiveList<ProgressiveVarTestStruct>,
}

impl Container for ProgressiveComplexTestStruct {
    const FIELDS: &'static [Option<usize>] = &[
        u8::FIXED_SIZE,
        Uint16List::FIXED_SIZE,
        ProgressiveBitList::FIXED_SIZE,
        <ProgressiveList<u64>>::FIXED_SIZE,
        <ProgressiveList<SmallTestStruct>>::FIXED_SIZE,
        <ProgressiveList<ProgressiveList<VarTestStruct>>>::FIXED_SIZE,
        <List<ProgressiveSingleFieldContainerTestStruct, Const<10>>>::FIXED_SIZE,
        <ProgressiveList<ProgressiveVarTestStruct>>::FIXED_SIZE,
    ];
    const MERKLEIZATION: Merkleization = Merkleization::Progressive(&[
        true, false, true, false, true, false, false, false, true, false, false, false, true, true,
        false, false, false, false, false, false, true, true,
    ]);

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.a);
        visitor.field(&self.b);
        visitor.field(&self.c);
        visitor.field(&self.d);
        visitor.field(&self.e);
        visitor.field(&self.f);
        visitor.field(&self.g);
        visitor.field(&self.h);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            a: fields.field()?,
            b: fields.field()?,
            c: fields.field()?,
            d: fields.field()?,
            e: fields.field()?,
            f: fields.field()?,
            g: fields.field()?,
            h: fields.field()?,
        })
    }
}
