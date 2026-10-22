//! The byte layout of slashing protection records in the store.
//!
//! Keys start with the validator's key, then a big-endian slot or epoch.
//! One validator's records then sit together, in slot or epoch order.

use axiom_types::{BlsPubkey, Epoch, Root};

use crate::protection::ProtectionError;

/// Bytes of a validator's key.
const PUBKEY_LEN: usize = 48;

/// Bytes of a key made of a validator's key and one big-endian integer.
const KEYED_LEN: usize = PUBKEY_LEN + 8;

/// Table of chain-wide facts, such as the genesis validators root.
pub(crate) const META: &str = "protection_meta";

/// Table of registered validators.
pub(crate) const VALIDATORS: &str = "protection_validators";

/// Table of signed blocks.
pub(crate) const BLOCKS: &str = "protection_blocks";

/// Table of signed votes.
pub(crate) const VOTES: &str = "protection_votes";

/// Key of the genesis validators root in the chain-wide table.
pub(crate) const GENESIS_VALIDATORS_ROOT: &[u8] = b"genesis_validators_root";

/// A record key: a validator's key followed by a big-endian slot or epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecordKey(pub(crate) [u8; KEYED_LEN]);

impl RecordKey {
    /// The key of a validator's record at a slot or epoch.
    pub(crate) fn new(pubkey: &BlsPubkey, position: u64) -> Self {
        let mut key = [0; KEYED_LEN];
        key[..PUBKEY_LEN].copy_from_slice(&pubkey.0);
        key[PUBKEY_LEN..].copy_from_slice(&position.to_be_bytes());
        Self(key)
    }

    /// Reads a stored key back into the validator and the position.
    pub(crate) fn decode(
        bytes: &[u8],
        table: &'static str,
    ) -> Result<(BlsPubkey, u64), ProtectionError> {
        let corrupt = || ProtectionError::Corrupt {
            table,
            len: bytes.len(),
        };
        let (pubkey, position) = bytes
            .split_first_chunk::<PUBKEY_LEN>()
            .ok_or_else(corrupt)?;
        let position: [u8; 8] = position.try_into().map_err(|_| corrupt())?;
        Ok((BlsPubkey(*pubkey), u64::from_be_bytes(position)))
    }

    /// Reads a key that is a validator's key alone.
    pub(crate) fn decode_pubkey(
        bytes: &[u8],
        table: &'static str,
    ) -> Result<BlsPubkey, ProtectionError> {
        bytes
            .try_into()
            .map(BlsPubkey)
            .map_err(|_| ProtectionError::Corrupt {
                table,
                len: bytes.len(),
            })
    }
}

/// A signing root that may be unknown: no bytes when unknown, 32 bytes otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StoredRoot(pub(crate) Option<Root>);

impl StoredRoot {
    /// The stored bytes.
    pub(crate) fn encode(self) -> Vec<u8> {
        self.0.map_or_else(Vec::new, |root| root.0.to_vec())
    }

    /// Reads stored bytes.
    pub(crate) fn decode(bytes: &[u8], table: &'static str) -> Result<Self, ProtectionError> {
        if bytes.is_empty() {
            return Ok(Self(None));
        }
        let root: [u8; 32] = bytes.try_into().map_err(|_| ProtectionError::Corrupt {
            table,
            len: bytes.len(),
        })?;
        Ok(Self(Some(Root(root))))
    }
}

/// A vote's stored value: its source epoch, then its signing root when known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StoredVote {
    /// The source epoch.
    pub(crate) source: Epoch,
    /// The signing root, when known.
    pub(crate) root: Option<Root>,
}

impl StoredVote {
    /// The stored bytes.
    pub(crate) fn encode(self) -> Vec<u8> {
        let mut value = self.source.0.to_be_bytes().to_vec();
        value.extend_from_slice(&StoredRoot(self.root).encode());
        value
    }

    /// Reads stored bytes.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, ProtectionError> {
        let (source, root) = bytes
            .split_first_chunk::<8>()
            .ok_or(ProtectionError::Corrupt {
                table: VOTES,
                len: bytes.len(),
            })?;
        Ok(Self {
            source: Epoch(u64::from_be_bytes(*source)),
            root: StoredRoot::decode(root, VOTES)?.0,
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn records_round_trip(
            pubkey in any::<[u8; 32]>(),
            position in any::<u64>(),
            source in any::<u64>(),
            root in prop::option::of(any::<[u8; 32]>()),
        ) {
            // A 48-byte key built from 32 random bytes and 16 fixed ones.
            let mut key = [7; 48];
            key[..32].copy_from_slice(&pubkey);
            let pubkey = BlsPubkey(key);

            let record = RecordKey::new(&pubkey, position);
            prop_assert_eq!(RecordKey::decode(&record.0, BLOCKS).unwrap(), (pubkey, position));
            let vote = StoredVote { source: Epoch(source), root: root.map(Root) };
            prop_assert_eq!(StoredVote::decode(&vote.encode()).unwrap(), vote);
        }
    }

    #[test]
    fn a_short_root_is_corrupt() {
        assert!(matches!(
            StoredRoot::decode(&[0; 31], BLOCKS),
            Err(ProtectionError::Corrupt {
                table: BLOCKS,
                len: 31
            })
        ));
    }
}
