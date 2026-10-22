//! Generic SSZ vectors: basic types, collections, and test containers outside any fork.
//!
//! # Overview
//!
//! A case name encodes its type, such as a vector of eight 16-bit integers.
//! Valid cases decode, re-encode to the same bytes, and hash to the expected root.
//! Invalid cases must fail to decode.
//!
//! The format lives in the consensus specs' `tests/formats/ssz_generic/README.md`.
//! Progressive types come from EIP-7916 and EIP-7495, compatible unions from EIP-8016.

mod compatible_unions;
mod containers;
mod progressive_containers;

use axiom_ssz::{
    BitList, BitVector, CompatibleUnion, Const, ProgressiveBitList, ProgressiveList, Root, Ssz,
    U256, Vector,
};
use axiom_yaml::Yaml;
use compatible_unions::{CompatibleUnionA, CompatibleUnionABCA, CompatibleUnionBC};
use containers::{
    BitsStruct, ComplexTestStruct, FixedTestStruct, ProgressiveBitsStruct, ProgressiveTestStruct,
    SingleFieldTestStruct, SmallTestStruct, VarTestStruct,
};
use progressive_containers::{
    ProgressiveComplexTestStruct, ProgressiveSingleFieldContainerTestStruct,
    ProgressiveSingleListContainerTestStruct, ProgressiveVarTestStruct,
};

use crate::{Case, Failure, Runner};

/// Runs every generic SSZ case.
#[derive(Clone, Copy, Debug, Default)]
pub struct SszGeneric;

/// What a case expects of its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expectation {
    /// The bytes are the encoding of a value of the type.
    Valid,
    /// The bytes encode no value of the type.
    Invalid,
}

impl Expectation {
    /// The expectation of a case, read from the suite directory holding it.
    fn of(case: &Case) -> Result<Self, Failure> {
        let suite = case
            .path()
            .parent()
            .and_then(|suite| suite.file_name())
            .and_then(|suite| suite.to_str());
        match suite {
            Some("valid") => Ok(Self::Valid),
            Some("invalid") => Ok(Self::Invalid),
            other => Err(Failure(format!("unknown suite {other:?}"))),
        }
    }
}

/// The parts of a case name, split on underscores.
#[derive(Clone, Debug)]
struct CaseName {
    /// The underscore-separated parts.
    parts: Vec<String>,
}

impl CaseName {
    /// The name of a case.
    fn of(case: &Case) -> Self {
        Self {
            parts: case.name().split('_').map(str::to_owned).collect(),
        }
    }

    /// The part at an index, as text.
    fn text(&self, index: usize) -> Result<&str, Failure> {
        self.parts
            .get(index)
            .map(String::as_str)
            .ok_or_else(|| Failure(format!("case name {:?} lacks part {index}", self.parts)))
    }

    /// The part at an index, as a number.
    fn number(&self, index: usize) -> Result<usize, Failure> {
        let text = self.text(index)?;
        text.parse()
            .map_err(|_| Failure(format!("case name part {text:?} is not a number")))
    }
}

impl SszGeneric {
    /// Checks a case against one type.
    fn check<T: Ssz>(case: &Case) -> Result<(), Failure> {
        let bytes = case.ssz_bytes("serialized")?;
        let decoded = T::decode(&bytes);
        let value = match (Expectation::of(case)?, decoded) {
            (Expectation::Invalid, Err(_)) => return Ok(()),
            (Expectation::Invalid, Ok(_)) => {
                return Err(Failure::new("invalid bytes decoded"));
            }
            (Expectation::Valid, Err(error)) => {
                return Err(Failure(format!("decode failed: {error}")));
            }
            (Expectation::Valid, Ok(value)) => value,
        };

        // The root commits to the decoded value, so a matching root proves the decode right.
        let expected = case
            .yaml("meta.yaml")?
            .get("root")
            .and_then(Yaml::as_hex_array::<32>)
            .map(Root)
            .ok_or_else(|| Failure::new("meta.yaml has no root"))?;
        let root = value.hash_tree_root();
        if root != expected {
            return Err(Failure(format!("root {root} is not {expected}")));
        }
        if value.encode() != bytes {
            return Err(Failure::new("re-encoding differs from the vector"));
        }
        Ok(())
    }

    /// Checks a case declaring a zero-length type, which the spec forbids.
    ///
    /// Such a type does not compile here, so only invalid cases may declare one.
    /// The generator writes their bytes against the one-element type, so they run against it.
    fn zero_length<T: Ssz>(case: &Case) -> Result<(), Failure> {
        match Expectation::of(case)? {
            Expectation::Invalid => Self::check::<T>(case),
            Expectation::Valid => Err(Failure::new("a zero-length type has no valid value")),
        }
    }

    /// Checks a case against a vector of some length.
    fn vector<T: Ssz>(length: usize, case: &Case) -> Result<(), Failure> {
        match length {
            0 => Self::zero_length::<Vector<T, Const<1>>>(case),
            1 => Self::check::<Vector<T, Const<1>>>(case),
            2 => Self::check::<Vector<T, Const<2>>>(case),
            3 => Self::check::<Vector<T, Const<3>>>(case),
            4 => Self::check::<Vector<T, Const<4>>>(case),
            5 => Self::check::<Vector<T, Const<5>>>(case),
            8 => Self::check::<Vector<T, Const<8>>>(case),
            16 => Self::check::<Vector<T, Const<16>>>(case),
            31 => Self::check::<Vector<T, Const<31>>>(case),
            512 => Self::check::<Vector<T, Const<512>>>(case),
            513 => Self::check::<Vector<T, Const<513>>>(case),
            other => Err(Failure(format!("unsupported vector length {other}"))),
        }
    }

    /// Checks a case named after a vector's element type and length.
    fn basic_vector(case: &Case) -> Result<(), Failure> {
        let name = CaseName::of(case);
        let length = name.number(2)?;
        match name.text(1)? {
            "bool" => Self::vector::<bool>(length, case),
            "uint8" => Self::vector::<u8>(length, case),
            "uint16" => Self::vector::<u16>(length, case),
            "uint32" => Self::vector::<u32>(length, case),
            "uint64" => Self::vector::<u64>(length, case),
            "uint128" => Self::vector::<u128>(length, case),
            "uint256" => Self::vector::<U256>(length, case),
            other => Err(Failure(format!("unsupported element type {other}"))),
        }
    }

    /// Checks a case named after a bitlist's limit.
    fn bitlist(case: &Case) -> Result<(), Failure> {
        match CaseName::of(case).number(1)? {
            1 => Self::check::<BitList<Const<1>>>(case),
            2 => Self::check::<BitList<Const<2>>>(case),
            3 => Self::check::<BitList<Const<3>>>(case),
            4 => Self::check::<BitList<Const<4>>>(case),
            5 => Self::check::<BitList<Const<5>>>(case),
            6 => Self::check::<BitList<Const<6>>>(case),
            7 => Self::check::<BitList<Const<7>>>(case),
            8 => Self::check::<BitList<Const<8>>>(case),
            9 => Self::check::<BitList<Const<9>>>(case),
            15 => Self::check::<BitList<Const<15>>>(case),
            16 => Self::check::<BitList<Const<16>>>(case),
            17 => Self::check::<BitList<Const<17>>>(case),
            31 => Self::check::<BitList<Const<31>>>(case),
            32 => Self::check::<BitList<Const<32>>>(case),
            33 => Self::check::<BitList<Const<33>>>(case),
            511 => Self::check::<BitList<Const<511>>>(case),
            512 => Self::check::<BitList<Const<512>>>(case),
            513 => Self::check::<BitList<Const<513>>>(case),
            other => Err(Failure(format!("unsupported bitlist limit {other}"))),
        }
    }

    /// Checks a case named after a bitvector's length.
    fn bitvector(case: &Case) -> Result<(), Failure> {
        match CaseName::of(case).number(1)? {
            0 => Self::zero_length::<BitVector<Const<1>>>(case),
            1 => Self::check::<BitVector<Const<1>>>(case),
            2 => Self::check::<BitVector<Const<2>>>(case),
            3 => Self::check::<BitVector<Const<3>>>(case),
            4 => Self::check::<BitVector<Const<4>>>(case),
            5 => Self::check::<BitVector<Const<5>>>(case),
            6 => Self::check::<BitVector<Const<6>>>(case),
            7 => Self::check::<BitVector<Const<7>>>(case),
            8 => Self::check::<BitVector<Const<8>>>(case),
            9 => Self::check::<BitVector<Const<9>>>(case),
            15 => Self::check::<BitVector<Const<15>>>(case),
            16 => Self::check::<BitVector<Const<16>>>(case),
            17 => Self::check::<BitVector<Const<17>>>(case),
            31 => Self::check::<BitVector<Const<31>>>(case),
            32 => Self::check::<BitVector<Const<32>>>(case),
            33 => Self::check::<BitVector<Const<33>>>(case),
            511 => Self::check::<BitVector<Const<511>>>(case),
            512 => Self::check::<BitVector<Const<512>>>(case),
            513 => Self::check::<BitVector<Const<513>>>(case),
            other => Err(Failure(format!("unsupported bitvector length {other}"))),
        }
    }

    /// Checks a case named after an integer's width in bits.
    fn uint(case: &Case) -> Result<(), Failure> {
        match CaseName::of(case).number(1)? {
            8 => Self::check::<u8>(case),
            16 => Self::check::<u16>(case),
            32 => Self::check::<u32>(case),
            64 => Self::check::<u64>(case),
            128 => Self::check::<u128>(case),
            256 => Self::check::<U256>(case),
            other => Err(Failure(format!("unsupported integer width {other}"))),
        }
    }

    /// Checks a case named after its test container.
    fn container(case: &Case) -> Result<(), Failure> {
        match CaseName::of(case).text(0)? {
            "SingleFieldTestStruct" => Self::check::<SingleFieldTestStruct>(case),
            "SmallTestStruct" => Self::check::<SmallTestStruct>(case),
            "FixedTestStruct" => Self::check::<FixedTestStruct>(case),
            "VarTestStruct" => Self::check::<VarTestStruct>(case),
            "ComplexTestStruct" => Self::check::<ComplexTestStruct>(case),
            "BitsStruct" => Self::check::<BitsStruct>(case),
            "ProgressiveTestStruct" => Self::check::<ProgressiveTestStruct>(case),
            "ProgressiveBitsStruct" => Self::check::<ProgressiveBitsStruct>(case),
            other => Err(Failure(format!("unsupported container {other}"))),
        }
    }

    /// Checks a case named after a progressive list's element type.
    fn progressive_list(case: &Case) -> Result<(), Failure> {
        match CaseName::of(case).text(1)? {
            "bool" => Self::check::<ProgressiveList<bool>>(case),
            "uint8" => Self::check::<ProgressiveList<u8>>(case),
            "uint16" => Self::check::<ProgressiveList<u16>>(case),
            "uint32" => Self::check::<ProgressiveList<u32>>(case),
            "uint64" => Self::check::<ProgressiveList<u64>>(case),
            "uint128" => Self::check::<ProgressiveList<u128>>(case),
            "uint256" => Self::check::<ProgressiveList<U256>>(case),
            other => Err(Failure(format!("unsupported element type {other}"))),
        }
    }

    /// Checks a case named after its progressive test container.
    fn progressive_container(case: &Case) -> Result<(), Failure> {
        match CaseName::of(case).text(0)? {
            "ProgressiveSingleFieldContainerTestStruct" => {
                Self::check::<ProgressiveSingleFieldContainerTestStruct>(case)
            }
            "ProgressiveSingleListContainerTestStruct" => {
                Self::check::<ProgressiveSingleListContainerTestStruct>(case)
            }
            "ProgressiveVarTestStruct" => Self::check::<ProgressiveVarTestStruct>(case),
            "ProgressiveComplexTestStruct" => Self::check::<ProgressiveComplexTestStruct>(case),
            other => Err(Failure(format!(
                "unsupported progressive container {other}"
            ))),
        }
    }

    /// Checks a case named after its compatible union.
    fn compatible_union(case: &Case) -> Result<(), Failure> {
        match CaseName::of(case).text(0)? {
            "CompatibleUnionA" => Self::check::<CompatibleUnion<CompatibleUnionA>>(case),
            "CompatibleUnionBC" => Self::check::<CompatibleUnion<CompatibleUnionBC>>(case),
            "CompatibleUnionABCA" => Self::check::<CompatibleUnion<CompatibleUnionABCA>>(case),
            other => Err(Failure(format!("unsupported compatible union {other}"))),
        }
    }
}

impl Runner for SszGeneric {
    fn name(&self) -> &'static str {
        "ssz_generic"
    }

    fn run_case(&self, handler: &str, case: &Case) -> Result<(), Failure> {
        match handler {
            "basic_vector" => Self::basic_vector(case),
            "bitlist" => Self::bitlist(case),
            "bitvector" => Self::bitvector(case),
            "boolean" => Self::check::<bool>(case),
            "containers" => Self::container(case),
            "uints" => Self::uint(case),
            "basic_progressive_list" => Self::progressive_list(case),
            "progressive_bitlist" => Self::check::<ProgressiveBitList>(case),
            "progressive_containers" => Self::progressive_container(case),
            "compatible_unions" => Self::compatible_union(case),
            other => Err(Failure(format!("unsupported handler {other}"))),
        }
    }
}
