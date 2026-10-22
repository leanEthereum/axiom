//! EIP-2334 derivation paths through the EIP-2333 key tree.

use std::{fmt, str::FromStr};

use crate::keys::{KeyError, PathError, SecretKeyBytes};

/// A path from the master key m down the tree, such as m/12381/3600/0/0/0.
///
/// Any depth is representable, as EIP-2333 notation allows.
/// The validator constructors build the four- and five-level paths EIP-2334 assigns.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct DerivationPath {
    /// Child indices, from the level below m down.
    indices: Vec<u32>,
}

impl DerivationPath {
    /// The purpose level: the name of the curve, BLS12-381, per EIP-2334.
    pub const PURPOSE: u32 = 12381;

    /// The coin type of Ethereum's BLS keys, 60^2, per EIP-2334.
    pub const COIN_TYPE: u32 = 3600;

    /// A path through the given child indices.
    #[must_use]
    pub const fn new(indices: Vec<u32>) -> Self {
        Self { indices }
    }

    /// The withdrawal key of validator i: m/12381/3600/i/0.
    #[must_use]
    pub fn validator_withdrawal(index: u32) -> Self {
        Self::new(vec![Self::PURPOSE, Self::COIN_TYPE, index, 0])
    }

    /// The signing key of validator i: m/12381/3600/i/0/0, the first child of its withdrawal key.
    #[must_use]
    pub fn validator_signing(index: u32) -> Self {
        Self::new(vec![Self::PURPOSE, Self::COIN_TYPE, index, 0, 0])
    }

    /// The child indices, from the level below m down.
    #[must_use]
    pub fn indices(&self) -> &[u32] {
        &self.indices
    }

    /// The key at this path in the tree a seed grows.
    ///
    /// # Errors
    ///
    /// Fails when the seed is shorter than 32 bytes.
    pub fn derive(&self, seed: &[u8]) -> Result<SecretKeyBytes, KeyError> {
        let master = SecretKeyBytes::from_seed(seed)?;
        Ok(self
            .indices
            .iter()
            .fold(master, |parent, &index| parent.child(index)))
    }

    /// The index one level of the text names, when it is canonical decimal below 2^32.
    fn index(level: &str) -> Option<u32> {
        let digits = !level.is_empty() && level.bytes().all(|byte| byte.is_ascii_digit());
        let canonical = level == "0" || !level.starts_with('0');
        (digits && canonical).then(|| level.parse().ok()).flatten()
    }
}

impl FromStr for DerivationPath {
    type Err = PathError;

    /// Parses the notation of EIP-2333: m, then a slash before each decimal index.
    ///
    /// Only the canonical form is accepted: no spaces, no signs, no leading zeros.
    /// Hardened markers are refused, since every EIP-2333 child is hardened already.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let mut levels = text.split('/');
        if levels.next() != Some("m") {
            return Err(PathError::MissingMaster {
                path: text.to_owned(),
            });
        }
        let indices = levels
            .enumerate()
            .map(|(position, level)| {
                Self::index(level).ok_or_else(|| PathError::InvalidIndex {
                    path: text.to_owned(),
                    level: position + 1,
                })
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { indices })
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("m")?;
        for index in &self.indices {
            write!(f, "/{index}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validator_paths_follow_eip_2334() {
        assert_eq!(
            DerivationPath::validator_signing(7).to_string(),
            "m/12381/3600/7/0/0"
        );
        assert_eq!(
            DerivationPath::validator_withdrawal(7).to_string(),
            "m/12381/3600/7/0"
        );
    }

    #[test]
    fn canonical_text_round_trips() {
        // The EIP-2335 scrypt vector's path, with indices near 2^32.
        let text = "m/12381/60/3141592653/589793238";
        let path: DerivationPath = text.parse().unwrap();
        assert_eq!(path.indices(), [12381, 60, 3_141_592_653, 589_793_238]);
        assert_eq!(path.to_string(), text);

        // The master node alone and the largest index.
        assert_eq!("m".parse(), Ok(DerivationPath::new(Vec::new())));
        assert_eq!(
            "m/4294967295".parse(),
            Ok(DerivationPath::new(vec![u32::MAX]))
        );
    }

    #[test]
    fn non_canonical_text_is_refused() {
        // Each text breaks one rule; the error names the level that breaks it.
        let invalid = |text: &str, level| {
            assert_eq!(
                text.parse::<DerivationPath>(),
                Err(PathError::InvalidIndex {
                    path: text.to_owned(),
                    level
                })
            );
        };
        invalid("m/4294967296", 1); // 2^32 does not fit
        invalid("m/12381/3600/0'", 3); // hardened marker
        invalid("m/12381/03600", 2); // leading zero
        invalid("m/12381/", 2); // empty level
        invalid("m/+1", 1); // sign
        invalid("m/ 1", 1); // space

        assert_eq!(
            "12381/3600".parse::<DerivationPath>(),
            Err(PathError::MissingMaster {
                path: "12381/3600".to_owned()
            })
        );
        assert_eq!(
            "".parse::<DerivationPath>(),
            Err(PathError::MissingMaster {
                path: String::new()
            })
        );
    }

    #[test]
    fn derivation_walks_the_tree_from_the_master_key() {
        // A path of two levels equals two explicit child steps from the master key.
        let seed = [0x42; 32];
        let master = SecretKeyBytes::from_seed(&seed).unwrap();
        let derived = DerivationPath::new(vec![3, 9]).derive(&seed).unwrap();
        assert_eq!(derived.as_bytes(), master.child(3).child(9).as_bytes());

        // The signing key is the first child of the withdrawal key.
        let withdrawal = DerivationPath::validator_withdrawal(1)
            .derive(&seed)
            .unwrap();
        let signing = DerivationPath::validator_signing(1).derive(&seed).unwrap();
        assert_eq!(signing.as_bytes(), withdrawal.child(0).as_bytes());
    }
}
