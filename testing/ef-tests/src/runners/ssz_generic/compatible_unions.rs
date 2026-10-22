//! The compatible unions of the generic SSZ vectors.
//!
//! The definitions follow the `compatible_unions` section of the consensus specs'
//! `tests/formats/ssz_generic/README.md`.
//! Their options are the progressive test containers, so every pair merkleizes compatibly.

use axiom_ssz::{DecodeError, OptionVisitor, Ssz, UnionOptions};

use super::progressive_containers::{
    ProgressiveSingleFieldContainerTestStruct, ProgressiveSingleListContainerTestStruct,
    ProgressiveVarTestStruct,
};

/// One option: the single-field container under selector 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum CompatibleUnionA {
    /// Selector 1.
    SingleField(ProgressiveSingleFieldContainerTestStruct),
}

impl UnionOptions for CompatibleUnionA {
    const SELECTORS: &'static [u8] = &[1];

    fn selector(&self) -> u8 {
        match self {
            Self::SingleField(_) => 1,
        }
    }

    fn visit_option<V: OptionVisitor>(&self, visitor: &mut V) {
        match self {
            Self::SingleField(value) => visitor.option(value),
        }
    }

    fn decode_option(selector: u8, bytes: &[u8]) -> Result<Self, DecodeError> {
        match selector {
            1 => Ssz::decode(bytes).map(Self::SingleField),
            _ => Err(DecodeError::UnknownSelector { selector }),
        }
    }
}

/// Two options: the single-list container under selector 2, the variable one under 3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum CompatibleUnionBC {
    /// Selector 2.
    SingleList(ProgressiveSingleListContainerTestStruct),
    /// Selector 3.
    Var(ProgressiveVarTestStruct),
}

impl UnionOptions for CompatibleUnionBC {
    const SELECTORS: &'static [u8] = &[2, 3];

    fn selector(&self) -> u8 {
        match self {
            Self::SingleList(_) => 2,
            Self::Var(_) => 3,
        }
    }

    fn visit_option<V: OptionVisitor>(&self, visitor: &mut V) {
        match self {
            Self::SingleList(value) => visitor.option(value),
            Self::Var(value) => visitor.option(value),
        }
    }

    fn decode_option(selector: u8, bytes: &[u8]) -> Result<Self, DecodeError> {
        match selector {
            2 => Ssz::decode(bytes).map(Self::SingleList),
            3 => Ssz::decode(bytes).map(Self::Var),
            _ => Err(DecodeError::UnknownSelector { selector }),
        }
    }
}

/// Four options, the single-field container appearing twice, under selectors 1 and 4.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum CompatibleUnionABCA {
    /// Selector 1.
    SingleField(ProgressiveSingleFieldContainerTestStruct),
    /// Selector 2.
    SingleList(ProgressiveSingleListContainerTestStruct),
    /// Selector 3.
    Var(ProgressiveVarTestStruct),
    /// Selector 4, the same type as selector 1.
    SingleFieldAgain(ProgressiveSingleFieldContainerTestStruct),
}

impl UnionOptions for CompatibleUnionABCA {
    const SELECTORS: &'static [u8] = &[1, 2, 3, 4];

    fn selector(&self) -> u8 {
        match self {
            Self::SingleField(_) => 1,
            Self::SingleList(_) => 2,
            Self::Var(_) => 3,
            Self::SingleFieldAgain(_) => 4,
        }
    }

    fn visit_option<V: OptionVisitor>(&self, visitor: &mut V) {
        match self {
            Self::SingleField(value) | Self::SingleFieldAgain(value) => visitor.option(value),
            Self::SingleList(value) => visitor.option(value),
            Self::Var(value) => visitor.option(value),
        }
    }

    fn decode_option(selector: u8, bytes: &[u8]) -> Result<Self, DecodeError> {
        match selector {
            1 => Ssz::decode(bytes).map(Self::SingleField),
            2 => Ssz::decode(bytes).map(Self::SingleList),
            3 => Ssz::decode(bytes).map(Self::Var),
            4 => Ssz::decode(bytes).map(Self::SingleFieldAgain),
            _ => Err(DecodeError::UnknownSelector { selector }),
        }
    }
}
