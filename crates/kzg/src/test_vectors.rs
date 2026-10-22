//! The c-kzg-4844 vectors of the internal challenge handlers, for unit tests.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use axiom_yaml::Yaml;

use crate::Bytes48;

/// The cases of one handler, which must number exactly the given count, or none when absent.
///
/// The lookup mirrors the conformance suite: AXIOM_VECTORS, else this checkout's testing/vectors.
/// A missing set fails when AXIOM_REQUIRE_VECTORS is set, as CI does.
pub(crate) fn cases(handler: &str, count: usize) -> Vec<Yaml> {
    let root = env::var_os("AXIOM_VECTORS").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing/vectors"),
        PathBuf::from,
    );
    let directory = root.join("kzg/tests").join(handler).join("kzg-mainnet");
    if !directory.is_dir() {
        assert!(
            env::var_os("AXIOM_REQUIRE_VECTORS").is_none(),
            "vectors required but missing under {}",
            directory.display()
        );
        return Vec::new();
    }
    let cases: Vec<Yaml> = fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            let text = fs::read_to_string(entry.unwrap().path().join("data.yaml")).unwrap();
            Yaml::parse(&text).unwrap()
        })
        .collect();
    assert_eq!(cases.len(), count, "{handler}: case count");
    cases
}

/// Reads a list of 48-byte strings.
pub(crate) fn points(items: &[Yaml]) -> Vec<Bytes48> {
    items
        .iter()
        .map(|item| Bytes48(item.as_hex_array().unwrap()))
        .collect()
}
