//! Conformance against the c-kzg-4844 reference vectors.
//!
//! The vectors live outside the repository.
//! Point AXIOM_VECTORS at their root.
//! It defaults to the workspace's testing/vectors, then to the main checkout's, and every suite skips when both are absent.
//!
//! ```text
//!     $AXIOM_VECTORS/kzg/tests/<handler>/kzg-mainnet/<case>/data.yaml
//! ```
//!
//! A null output means the inputs must be rejected.
//! Inputs this crate rejects at construction, such as a short blob, count as rejected.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use axiom_kzg::{Blob, Bytes32, Bytes48, Cell, CellIndex, CellsAndProofs, Kzg};
use axiom_yaml::Yaml;

/// The main checkout's vectors, for worktrees whose own testing/vectors is empty.
const MAIN_CHECKOUT_VECTORS: &str = "/home/utilisateur/Documents/axiom/testing/vectors";

/// A comparable outcome: the shape of every output in the vectors.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    /// A byte string: a commitment, a proof, a field element, or a cell.
    Bytes(Vec<u8>),
    /// A verification result.
    Bool(bool),
    /// A list of outcomes, such as cells, or a pair of a proof and an evaluation.
    List(Vec<Self>),
}

impl Outcome {
    /// Reads the expected output of a case, none for null.
    fn expected(yaml: &Yaml) -> Option<Self> {
        match yaml {
            Yaml::Null => None,
            Yaml::Bool(value) => Some(Self::Bool(*value)),
            Yaml::Sequence(items) => items
                .iter()
                .map(Self::expected)
                .collect::<Option<_>>()
                .map(Self::List),
            other => Some(Self::Bytes(other.as_hex_bytes().expect("hex output"))),
        }
    }

    /// Wraps cells and proofs as the vectors list them: cells first, then proofs.
    fn cells_and_proofs((cells, proofs): &CellsAndProofs) -> Self {
        Self::List(vec![
            Self::List(
                cells
                    .iter()
                    .map(|cell| Self::Bytes(cell.to_bytes()))
                    .collect(),
            ),
            Self::List(
                proofs
                    .iter()
                    .map(|proof| Self::Bytes(proof.0.to_vec()))
                    .collect(),
            ),
        ])
    }
}

/// The vectors root: AXIOM_VECTORS, the workspace's testing/vectors, or the main checkout's.
fn vectors_root() -> Option<PathBuf> {
    // The variable wins, so any checkout can point at shared vectors.
    if let Some(root) = env::var_os("AXIOM_VECTORS") {
        return Some(PathBuf::from(root));
    }
    [
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing/vectors"),
        PathBuf::from(MAIN_CHECKOUT_VECTORS),
    ]
    .into_iter()
    .find(|root| root.join("kzg").is_dir())
}

/// Runs a check on every case of a handler and returns how many ran.
///
/// The check maps the case's input to the actual outcome, none for a rejection.
/// Every mismatch is collected, then the test fails listing them all.
#[expect(
    clippy::print_stderr,
    reason = "the suite reports its case count, or why it skipped, to the test output"
)]
fn run(handler: &str, check: impl Fn(&Kzg, &Yaml) -> Option<Outcome>) -> usize {
    let Some(root) = vectors_root() else {
        eprintln!("skipping {handler}: KZG vectors not found (set AXIOM_VECTORS)");
        return 0;
    };
    let directory = root.join("kzg/tests").join(handler).join("kzg-mainnet");
    let mut cases: Vec<PathBuf> = fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("{}: {error}", directory.display()))
        .map(|entry| entry.expect("directory entry").path())
        .collect();
    cases.sort();

    let kzg = Kzg::mainnet();
    let mut failures = Vec::new();
    for case in &cases {
        let path = case.join("data.yaml");
        let data =
            Yaml::parse(&fs::read_to_string(&path).expect("readable vector")).expect("valid YAML");
        let expected = Outcome::expected(data.get("output").expect("output field"));
        let actual = check(kzg, data.get("input").expect("input field"));
        if expected != actual {
            failures.push(
                case.file_name()
                    .map(|name| name.to_string_lossy().into_owned()),
            );
        }
    }
    assert!(failures.is_empty(), "{handler}: failing cases {failures:?}");
    assert!(
        !cases.is_empty(),
        "{handler}: no cases in {}",
        directory.display()
    );
    eprintln!("{handler}: {} cases passed", cases.len());
    cases.len()
}

/// Reads a list field of the input.
fn list<'a>(input: &'a Yaml, key: &str) -> &'a [Yaml] {
    input
        .get(key)
        .and_then(Yaml::as_sequence)
        .expect("list input")
}

/// Decodes a blob, none when its length or an element is invalid.
fn blob(yaml: &Yaml) -> Option<Blob> {
    Blob::from_bytes(&yaml.as_hex_bytes()?).ok()
}

/// Decodes a 48-byte string, none for any other length.
fn bytes48(yaml: &Yaml) -> Option<Bytes48> {
    yaml.as_hex_array().map(Bytes48)
}

/// Decodes a 32-byte string, none for any other length.
fn bytes32(yaml: &Yaml) -> Option<Bytes32> {
    yaml.as_hex_array().map(Bytes32)
}

/// Decodes a cell, none when its length or an element is invalid.
fn cell(yaml: &Yaml) -> Option<Cell> {
    Cell::from_bytes(&yaml.as_hex_bytes()?).ok()
}

/// Decodes a cell index, none when it is out of range.
fn cell_index(yaml: &Yaml) -> Option<CellIndex> {
    CellIndex::new(yaml.as_u64()?).ok()
}

/// Decodes every item of a list, none when any item fails.
fn all<T>(items: &[Yaml], decode: fn(&Yaml) -> Option<T>) -> Option<Vec<T>> {
    items.iter().map(decode).collect()
}

#[test]
fn blob_to_kzg_commitment() {
    // Output: the commitment, or null for an invalid blob.
    run("blob_to_kzg_commitment", |kzg, input| {
        let blob = blob(input.get("blob")?)?;
        Some(Outcome::Bytes(kzg.blob_to_kzg_commitment(&blob).0.to_vec()))
    });
}

#[test]
fn compute_kzg_proof() {
    // Output: [proof, y], or null for an invalid blob or point.
    run("compute_kzg_proof", |kzg, input| {
        let blob = blob(input.get("blob")?)?;
        let z = bytes32(input.get("z")?)?;
        let (proof, y) = kzg.compute_kzg_proof(&blob, &z).ok()?;
        Some(Outcome::List(vec![
            Outcome::Bytes(proof.0.to_vec()),
            Outcome::Bytes(y.0.to_vec()),
        ]))
    });
}

#[test]
fn compute_blob_kzg_proof() {
    // Output: the proof, or null for an invalid blob or commitment.
    run("compute_blob_kzg_proof", |kzg, input| {
        let blob = blob(input.get("blob")?)?;
        let commitment = bytes48(input.get("commitment")?)?;
        let proof = kzg.compute_blob_kzg_proof(&blob, &commitment).ok()?;
        Some(Outcome::Bytes(proof.0.to_vec()))
    });
}

#[test]
fn verify_kzg_proof() {
    // Output: whether the proof verifies, or null for a malformed input.
    run("verify_kzg_proof", |kzg, input| {
        let commitment = bytes48(input.get("commitment")?)?;
        let z = bytes32(input.get("z")?)?;
        let y = bytes32(input.get("y")?)?;
        let proof = bytes48(input.get("proof")?)?;
        kzg.verify_kzg_proof(&commitment, &z, &y, &proof)
            .ok()
            .map(Outcome::Bool)
    });
}

#[test]
fn verify_blob_kzg_proof() {
    // Output: whether the proof verifies, or null for a malformed input.
    run("verify_blob_kzg_proof", |kzg, input| {
        let blob = blob(input.get("blob")?)?;
        let commitment = bytes48(input.get("commitment")?)?;
        let proof = bytes48(input.get("proof")?)?;
        kzg.verify_blob_kzg_proof(&blob, &commitment, &proof)
            .ok()
            .map(Outcome::Bool)
    });
}

#[test]
fn verify_blob_kzg_proof_batch() {
    // Output: whether every proof verifies, or null for a malformed input.
    run("verify_blob_kzg_proof_batch", |kzg, input| {
        let blobs = all(list(input, "blobs"), blob)?;
        let commitments = all(list(input, "commitments"), bytes48)?;
        let proofs = all(list(input, "proofs"), bytes48)?;
        kzg.verify_blob_kzg_proof_batch(&blobs, &commitments, &proofs)
            .ok()
            .map(Outcome::Bool)
    });
}

#[test]
fn compute_cells() {
    // Output: the 128 cells, or null for an invalid blob.
    run("compute_cells", |kzg, input| {
        let blob = blob(input.get("blob")?)?;
        let cells = kzg.compute_cells(&blob);
        Some(Outcome::List(
            cells
                .iter()
                .map(|cell| Outcome::Bytes(cell.to_bytes()))
                .collect(),
        ))
    });
}

#[test]
fn compute_cells_and_kzg_proofs() {
    // Output: [cells, proofs], or null for an invalid blob.
    run("compute_cells_and_kzg_proofs", |kzg, input| {
        let blob = blob(input.get("blob")?)?;
        Some(Outcome::cells_and_proofs(
            &kzg.compute_cells_and_kzg_proofs(&blob),
        ))
    });
}

#[test]
fn verify_cell_kzg_proof_batch() {
    // Output: whether every cell verifies, or null for a malformed input.
    run("verify_cell_kzg_proof_batch", |kzg, input| {
        let commitments = all(list(input, "commitments"), bytes48)?;
        let cell_indices = all(list(input, "cell_indices"), cell_index)?;
        let cells = all(list(input, "cells"), cell)?;
        let proofs = all(list(input, "proofs"), bytes48)?;
        kzg.verify_cell_kzg_proof_batch(&commitments, &cell_indices, &cells, &proofs)
            .ok()
            .map(Outcome::Bool)
    });
}

#[test]
fn recover_cells_and_kzg_proofs() {
    // Output: [cells, proofs] of the whole extended blob, or null for a malformed input.
    run("recover_cells_and_kzg_proofs", |kzg, input| {
        let cell_indices = all(list(input, "cell_indices"), cell_index)?;
        let cells = all(list(input, "cells"), cell)?;
        let recovered = kzg
            .recover_cells_and_kzg_proofs(&cell_indices, &cells)
            .ok()?;
        Some(Outcome::cells_and_proofs(&recovered))
    });
}
