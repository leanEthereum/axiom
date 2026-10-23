//! An operator's KZG trusted setup, read from the JSON file the consensus specs publish.

use std::{fs, path::Path};

use axiom_json::{Data, HexError, Json, ParseError};
use axiom_kzg::{Kzg, KzgError};
use thiserror::Error;

use crate::NodeError;

/// Why a trusted setup file cannot be used.
#[derive(Debug, Error)]
pub enum TrustedSetupError {
    /// The file is not JSON.
    #[error("not JSON: {0}")]
    Json(#[from] ParseError),
    /// A basis is missing, or is not a list of strings.
    #[error("{0} is missing or not a list of strings")]
    Basis(&'static str),
    /// A point is not hex of the length its group's compressed encoding takes.
    #[error("{basis} point {index}: {source}")]
    Hex {
        /// The basis.
        basis: &'static str,
        /// Position of the point in its basis.
        index: usize,
        /// Why the text is not the point's bytes.
        #[source]
        source: HexError,
    },
    /// The points do not make a setup the scheme can use.
    #[error(transparent)]
    Kzg(#[from] KzgError),
}

/// A trusted setup file: three lists of compressed points in 0x-prefixed hex.
///
/// The file names its bases G1 monomial, G1 Lagrange, and G2 monomial.
/// The Lagrange basis lists its points in natural order.
/// See `presets/mainnet/trusted_setups/trusted_setup_4096.json` in the consensus specs.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TrustedSetupFile<'a>(pub(crate) &'a Path);

impl TrustedSetupFile<'_> {
    /// Makes the file's setup the one every KZG operation of the process uses.
    ///
    /// It runs once, before the node starts, so no operation ever saw another setup.
    ///
    /// # Errors
    ///
    /// Fails like loading, and when the process already trusts a setup.
    pub(crate) fn trust(self) -> Result<(), NodeError> {
        let kzg = self.load()?;
        kzg.trust().map_err(|source| self.error(source.into()))?;
        Ok(())
    }

    /// Reads and checks the setup, every point in its subgroup.
    ///
    /// # Errors
    ///
    /// Fails when the file is unreadable, malformed, or holds points the scheme cannot use.
    pub(crate) fn load(self) -> Result<Kzg, NodeError> {
        let bytes = fs::read(self.0).map_err(|error| NodeError::File {
            context: "reading the trusted setup",
            path: self.0.to_owned(),
            error,
        })?;
        Self::decode(&bytes).map_err(|source| self.error(source))
    }

    /// The node error naming this file.
    fn error(self, source: TrustedSetupError) -> NodeError {
        NodeError::TrustedSetup {
            path: self.0.to_owned(),
            source,
        }
    }

    /// Decodes the setup from the file's bytes.
    fn decode(bytes: &[u8]) -> Result<Kzg, TrustedSetupError> {
        let json = Json::parse(bytes)?;
        let g1_monomial = Self::basis::<48>(&json, "g1_monomial")?;
        let g1_lagrange = Self::basis::<48>(&json, "g1_lagrange")?;
        let g2_monomial = Self::basis::<96>(&json, "g2_monomial")?;
        Ok(Kzg::from_trusted_setup(
            &g1_monomial,
            &g1_lagrange,
            &g2_monomial,
        )?)
    }

    /// One basis of compressed points of N bytes each.
    fn basis<const N: usize>(
        json: &Json,
        name: &'static str,
    ) -> Result<Vec<[u8; N]>, TrustedSetupError> {
        let points = json
            .get(name)
            .and_then(Json::as_array)
            .ok_or(TrustedSetupError::Basis(name))?;
        points
            .iter()
            .enumerate()
            .map(|(index, point)| {
                let text = point.as_str().ok_or(TrustedSetupError::Basis(name))?;
                <[u8; N]>::from_data(text).map_err(|source| TrustedSetupError::Hex {
                    basis: name,
                    index,
                    source,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use axiom_kzg::Blob;

    use super::*;

    /// The embedded mainnet setup, in its text form: counts, then Lagrange, G2, and monomial lines.
    const MAINNET_TEXT: &str = include_str!("../../kzg/src/trusted_setup.txt");

    /// The mainnet setup rewritten in the consensus specs' JSON form.
    fn mainnet_json() -> Json {
        let lines: Vec<&str> = MAINNET_TEXT.lines().skip(2).map(str::trim).collect();
        let list = |range: &[&str]| {
            Json::Array(
                range
                    .iter()
                    .map(|line| Json::from(format!("0x{line}")))
                    .collect(),
            )
        };
        Json::from([
            ("g1_lagrange", list(&lines[..4096])),
            ("g2_monomial", list(&lines[4096..4161])),
            ("g1_monomial", list(&lines[4161..8257])),
        ])
    }

    #[test]
    fn the_specs_json_setup_commits_as_the_mainnet_one() {
        // A blob of 4096 elements, element i set to i in its last byte, modulo 256.
        let mut bytes = vec![0; 4096 * 32];
        for (index, element) in bytes.chunks_mut(32).enumerate() {
            element[31] = index as u8;
        }
        let blob = Blob::from_bytes(&bytes).unwrap();

        // The same ceremony read from JSON commits the blob exactly as the embedded copy does.
        let kzg = TrustedSetupFile::decode(mainnet_json().to_string().as_bytes()).unwrap();
        assert_eq!(
            kzg.blob_to_kzg_commitment(&blob),
            Kzg::mainnet().blob_to_kzg_commitment(&blob)
        );
    }

    #[test]
    fn malformed_setup_files_name_their_fault() {
        // A missing basis is named.
        let missing = Json::from([("g1_monomial", Json::Array(Vec::new()))]).to_string();
        assert!(matches!(
            TrustedSetupFile::decode(missing.as_bytes()),
            Err(TrustedSetupError::Basis("g1_lagrange"))
        ));

        // A G2 point of G1 length fails as hex of the wrong length, at its index.
        let mut json = mainnet_json();
        if let Json::Object(object) = &mut json {
            object.insert(
                "g2_monomial",
                Json::Array(vec![Json::from(format!("0x{}", "aa".repeat(48)))]),
            );
        }
        assert!(matches!(
            TrustedSetupFile::decode(json.to_string().as_bytes()),
            Err(TrustedSetupError::Hex {
                basis: "g2_monomial",
                index: 0,
                ..
            })
        ));
    }
}
