//! Conformance of the progressive types against the spec's generic SSZ vectors.
//!
//! The vectors live outside the repository.
//! Point AXIOM_VECTORS at their root, which defaults to the workspace's testing/vectors.
//! Every suite skips when the vectors are absent.
//!
//! ```text
//!     $AXIOM_VECTORS/consensus-spec-general/tests/general/phase0/ssz_generic/<handler>/<valid|invalid>/<case>
//! ```
//!
//! A valid case decodes, hashes to its root, and re-encodes to the same bytes.
//! An invalid case must fail to decode.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use axiom_snappy::raw;
use axiom_ssz::{
    Const, Container, DecodeError, FieldDecoder, FieldVisitor, List, Merkleization,
    ProgressiveBitList, ProgressiveList, Root, Ssz, U256,
};
use axiom_yaml::Yaml;

/// Largest decompressed fixture accepted.
const MAX_FIXTURE_BYTES: usize = 1 << 24;

/// A progressive container with one active position, holding a byte.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SingleField {
    a: u8,
}

impl Container for SingleField {
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
struct SingleList {
    c: ProgressiveBitList,
}

impl Container for SingleList {
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
struct Var {
    a: u8,
    b: List<u16, Const<123>>,
    c: ProgressiveBitList,
}

impl Container for Var {
    const FIELDS: &'static [Option<usize>] = &[
        u8::FIXED_SIZE,
        <List<u16, Const<123>>>::FIXED_SIZE,
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

/// The generic SSZ vectors, or nothing when they are absent.
fn generic_vectors() -> Option<PathBuf> {
    let root = env::var_os("AXIOM_VECTORS").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing/vectors"),
        PathBuf::from,
    );
    let dir = root.join("consensus-spec-general/tests/general/phase0/ssz_generic");
    dir.is_dir().then_some(dir)
}

/// Case directories of a handler's valid or invalid suite, sorted by name.
fn cases(handler: &str, suite: &str) -> Vec<PathBuf> {
    let Some(root) = generic_vectors() else {
        return Vec::new();
    };
    let mut cases: Vec<PathBuf> = fs::read_dir(root.join(handler).join(suite))
        .map(|entries| entries.filter_map(Result::ok).map(|e| e.path()).collect())
        .unwrap_or_default();
    cases.sort();
    cases
}

/// The decompressed serialization of a case.
fn serialized(case: &Path) -> Vec<u8> {
    let compressed = fs::read(case.join("serialized.ssz_snappy")).expect("readable serialization");
    raw::decompress(&compressed, MAX_FIXTURE_BYTES).expect("valid snappy")
}

/// The expected root of a valid case.
fn expected_root(case: &Path) -> Root {
    let text = fs::read_to_string(case.join("meta.yaml")).expect("readable metadata");
    let yaml = Yaml::parse(&text).expect("valid YAML");
    Root(
        yaml.get("root")
            .and_then(Yaml::as_hex_array::<32>)
            .expect("root field"),
    )
}

/// Checks a valid case: decode, root, and re-encoding.
fn check_valid<T: Ssz>(case: &Path) {
    let bytes = serialized(case);
    let value = T::decode(&bytes)
        .unwrap_or_else(|error| panic!("{}: decode failed: {error}", case.display()));
    assert_eq!(
        value.hash_tree_root(),
        expected_root(case),
        "{}: root",
        case.display()
    );
    assert_eq!(value.encode(), bytes, "{}: re-encoding", case.display());
}

/// Checks an invalid case: decoding must fail.
fn check_invalid<T: Ssz>(case: &Path) {
    assert!(
        T::decode(&serialized(case)).is_err(),
        "{}: invalid bytes decoded",
        case.display()
    );
}

/// Runs a check over every case of a suite whose name starts with a prefix.
///
/// Returns how many cases ran.
fn run(handler: &str, suite: &str, prefix: &str, check: fn(&Path)) -> usize {
    let mut count = 0;
    for case in cases(handler, suite) {
        let name = case
            .file_name()
            .expect("case directory name")
            .to_string_lossy()
            .into_owned();
        if name.starts_with(prefix) {
            check(&case);
            count += 1;
        }
    }
    count
}

/// Runs the valid and invalid cases of one element type of the progressive lists.
fn run_list<T: Ssz>(prefix: &str) -> usize {
    run(
        "basic_progressive_list",
        "valid",
        prefix,
        check_valid::<ProgressiveList<T>>,
    ) + run(
        "basic_progressive_list",
        "invalid",
        prefix,
        check_invalid::<ProgressiveList<T>>,
    )
}

#[test]
fn basic_progressive_lists() {
    if generic_vectors().is_none() {
        eprintln!("skipping: generic SSZ vectors not found (set AXIOM_VECTORS)");
        return;
    }
    let count = run_list::<bool>("proglist_bool_")
        + run_list::<u8>("proglist_uint8_")
        + run_list::<u16>("proglist_uint16_")
        + run_list::<u32>("proglist_uint32_")
        + run_list::<u64>("proglist_uint64_")
        + run_list::<u128>("proglist_uint128_")
        + run_list::<U256>("proglist_uint256_");

    // Every case of the handler belongs to one of the element types above.
    let total = cases("basic_progressive_list", "valid").len()
        + cases("basic_progressive_list", "invalid").len();
    assert_eq!(count, total);
}

#[test]
fn progressive_bitlists() {
    if generic_vectors().is_none() {
        eprintln!("skipping: generic SSZ vectors not found (set AXIOM_VECTORS)");
        return;
    }
    let count = run(
        "progressive_bitlist",
        "valid",
        "",
        check_valid::<ProgressiveBitList>,
    ) + run(
        "progressive_bitlist",
        "invalid",
        "",
        check_invalid::<ProgressiveBitList>,
    );

    assert!(count > 0);
}

#[test]
fn progressive_containers() {
    if generic_vectors().is_none() {
        eprintln!("skipping: generic SSZ vectors not found (set AXIOM_VECTORS)");
        return;
    }
    let handler = "progressive_containers";
    let count = run(
        handler,
        "valid",
        "ProgressiveSingleFieldContainerTestStruct",
        check_valid::<SingleField>,
    ) + run(
        handler,
        "valid",
        "ProgressiveSingleListContainerTestStruct",
        check_valid::<SingleList>,
    ) + run(
        handler,
        "valid",
        "ProgressiveVarTestStruct",
        check_valid::<Var>,
    ) + run(
        handler,
        "invalid",
        "ProgressiveSingleFieldContainerTestStruct",
        check_invalid::<SingleField>,
    ) + run(
        handler,
        "invalid",
        "ProgressiveSingleListContainerTestStruct",
        check_invalid::<SingleList>,
    ) + run(
        handler,
        "invalid",
        "ProgressiveVarTestStruct",
        check_invalid::<Var>,
    );

    assert!(count > 0);
}
