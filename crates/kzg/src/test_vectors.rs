//! The c-kzg-4844 vectors of the internal challenge handlers, for unit tests.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use axiom_yaml::Yaml;

use crate::Bytes48;

/// The cases of one handler, or none when the vectors are absent.
///
/// The lookup mirrors the conformance suite: AXIOM_VECTORS, this checkout, then the main checkout.
pub(crate) fn cases(handler: &str) -> Vec<Yaml> {
    let roots = [
        env::var_os("AXIOM_VECTORS").map(PathBuf::from),
        Some(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing/vectors")),
        Some(PathBuf::from(
            "/home/utilisateur/Documents/axiom/testing/vectors",
        )),
    ];
    let Some(directory) = roots
        .into_iter()
        .flatten()
        .map(|root| root.join("kzg/tests").join(handler).join("kzg-mainnet"))
        .find(|directory| directory.is_dir())
    else {
        return Vec::new();
    };
    fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            let text = fs::read_to_string(entry.unwrap().path().join("data.yaml")).unwrap();
            Yaml::parse(&text).unwrap()
        })
        .collect()
}

/// Reads a list of 48-byte strings.
pub(crate) fn points(items: &[Yaml]) -> Vec<Bytes48> {
    items
        .iter()
        .map(|item| Bytes48(item.as_hex_array().unwrap()))
        .collect()
}
