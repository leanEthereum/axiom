//! The test containers of the generic SSZ vectors.
//!
//! The definitions follow the consensus specs' `tests/formats/ssz_generic/README.md`.
//! Field names there are single capital letters, lowered here.

use axiom_ssz::{
    BitList, BitVector, Const, Container, DecodeError, FieldDecoder, FieldVisitor, List, Ssz,
    Vector,
};

/// A container of one byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SingleFieldTestStruct {
    /// The only field, a byte.
    a: u8,
}

impl Container for SingleFieldTestStruct {
    const FIELDS: &'static [Option<usize>] = &[u8::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.a);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self { a: fields.field()? })
    }
}

/// A container of two 16-bit integers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SmallTestStruct {
    /// First integer.
    a: u16,
    /// Second integer.
    b: u16,
}

impl Container for SmallTestStruct {
    const FIELDS: &'static [Option<usize>] = &[u16::FIXED_SIZE, u16::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.a);
        visitor.field(&self.b);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            a: fields.field()?,
            b: fields.field()?,
        })
    }
}

/// A fixed-size container of integers of mixed widths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FixedTestStruct {
    /// An 8-bit integer.
    a: u8,
    /// A 64-bit integer.
    b: u64,
    /// A 32-bit integer.
    c: u32,
}

impl Container for FixedTestStruct {
    const FIELDS: &'static [Option<usize>] = &[u8::FIXED_SIZE, u64::FIXED_SIZE, u32::FIXED_SIZE];

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

/// A container with one variable-size list between two fixed fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct VarTestStruct {
    /// A 16-bit integer.
    a: u16,
    /// Up to 1024 integers of 16 bits.
    b: List<u16, Const<1024>>,
    /// An 8-bit integer.
    c: u8,
}

impl Container for VarTestStruct {
    const FIELDS: &'static [Option<usize>] = &[
        u16::FIXED_SIZE,
        <List<u16, Const<1024>>>::FIXED_SIZE,
        u8::FIXED_SIZE,
    ];

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

/// A container nesting lists, containers, and vectors of both fixed and variable size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ComplexTestStruct {
    /// A 16-bit integer.
    a: u16,
    /// Up to 128 integers of 16 bits.
    b: List<u16, Const<128>>,
    /// An 8-bit integer.
    c: u8,
    /// Up to 256 bytes.
    d: List<u8, Const<256>>,
    /// A nested variable-size container.
    e: VarTestStruct,
    /// Four nested fixed-size containers.
    f: Vector<FixedTestStruct, Const<4>>,
    /// Two nested variable-size containers.
    g: Vector<VarTestStruct, Const<2>>,
}

impl Container for ComplexTestStruct {
    const FIELDS: &'static [Option<usize>] = &[
        u16::FIXED_SIZE,
        <List<u16, Const<128>>>::FIXED_SIZE,
        u8::FIXED_SIZE,
        <List<u8, Const<256>>>::FIXED_SIZE,
        VarTestStruct::FIXED_SIZE,
        <Vector<FixedTestStruct, Const<4>>>::FIXED_SIZE,
        <Vector<VarTestStruct, Const<2>>>::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.a);
        visitor.field(&self.b);
        visitor.field(&self.c);
        visitor.field(&self.d);
        visitor.field(&self.e);
        visitor.field(&self.f);
        visitor.field(&self.g);
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
        })
    }
}

/// A container of bitlists and bitvectors, interleaved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BitsStruct {
    /// Up to five bits.
    a: BitList<Const<5>>,
    /// Exactly two bits.
    b: BitVector<Const<2>>,
    /// Exactly one bit.
    c: BitVector<Const<1>>,
    /// Up to six bits.
    d: BitList<Const<6>>,
    /// Exactly eight bits.
    e: BitVector<Const<8>>,
}

impl Container for BitsStruct {
    const FIELDS: &'static [Option<usize>] = &[
        <BitList<Const<5>>>::FIXED_SIZE,
        <BitVector<Const<2>>>::FIXED_SIZE,
        <BitVector<Const<1>>>::FIXED_SIZE,
        <BitList<Const<6>>>::FIXED_SIZE,
        <BitVector<Const<8>>>::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.a);
        visitor.field(&self.b);
        visitor.field(&self.c);
        visitor.field(&self.d);
        visitor.field(&self.e);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            a: fields.field()?,
            b: fields.field()?,
            c: fields.field()?,
            d: fields.field()?,
            e: fields.field()?,
        })
    }
}
