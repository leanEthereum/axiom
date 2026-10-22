//! The versions of the status handshake, and the message shape each one carries.

use axiom_ssz::{DecodeError, Ssz};
use axiom_types::Slot;

use super::{Protocol, Status, StatusV1};

/// A version of the status handshake.
///
/// Fulu added the second version, which appends the earliest available slot.
/// Each stream negotiates one version, and both sides speak its shape.
/// See Status in the phase0 p2p spec and Status v2 in the Fulu p2p spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StatusVersion {
    /// The phase0 handshake.
    V1,
    /// The Fulu handshake.
    V2,
}

impl StatusVersion {
    /// The newest version, which a handshake proposes first.
    pub const NEWEST: Self = Self::V2;

    /// The version a req/resp protocol carries, if it is a status protocol.
    #[must_use]
    pub const fn of(protocol: Protocol) -> Option<Self> {
        match protocol {
            Protocol::StatusV1 => Some(Self::V1),
            Protocol::StatusV2 => Some(Self::V2),
            _ => None,
        }
    }

    /// The req/resp protocol of this version.
    #[must_use]
    pub const fn protocol(self) -> Protocol {
        match self {
            Self::V1 => Protocol::StatusV1,
            Self::V2 => Protocol::StatusV2,
        }
    }

    /// The version before this one, for a peer that refuses this one.
    #[must_use]
    pub const fn older(self) -> Option<Self> {
        match self {
            Self::V1 => None,
            Self::V2 => Some(Self::V1),
        }
    }

    /// Encodes a status in this version's shape.
    ///
    /// The first version drops the earliest available slot.
    #[must_use]
    pub fn encode(self, status: &Status) -> Vec<u8> {
        match self {
            Self::V1 => StatusV1 {
                fork_digest: status.fork_digest,
                finalized_root: status.finalized_root,
                finalized_epoch: status.finalized_epoch,
                head_root: status.head_root,
                head_slot: status.head_slot,
            }
            .encode(),
            Self::V2 => status.encode(),
        }
    }

    /// Decodes a status in this version's shape.
    ///
    /// A first-version status names no earliest slot, so it reads as genesis.
    ///
    /// # Errors
    ///
    /// Fails when the bytes are not exactly one status of this version.
    pub fn decode(self, bytes: &[u8]) -> Result<Status, DecodeError> {
        match self {
            Self::V1 => {
                let status = StatusV1::decode(bytes)?;
                Ok(Status {
                    fork_digest: status.fork_digest,
                    finalized_root: status.finalized_root,
                    finalized_epoch: status.finalized_epoch,
                    head_root: status.head_root,
                    head_slot: status.head_slot,
                    earliest_available_slot: Slot::GENESIS,
                })
            }
            Self::V2 => Status::decode(bytes),
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{Epoch, ForkDigest, Root};

    use super::*;

    /// A status whose earliest available slot is 64, not genesis.
    fn status() -> Status {
        Status {
            fork_digest: ForkDigest([0xaa, 0xbb, 0xcc, 0xdd]),
            finalized_root: Root::from([1; 32]),
            finalized_epoch: Epoch(5),
            head_root: Root::from([2; 32]),
            head_slot: Slot(200),
            earliest_available_slot: Slot(64),
        }
    }

    #[test]
    fn each_version_speaks_its_own_shape() {
        let status = status();

        // Version 2: all 92 bytes, and back unchanged.
        let v2 = StatusVersion::V2.encode(&status);
        assert_eq!(v2, status.encode());
        assert_eq!(StatusVersion::V2.decode(&v2), Ok(status));

        // Version 1: the first 84 bytes, without the earliest slot at 84..92.
        let v1 = StatusVersion::V1.encode(&status);
        assert_eq!(v1, v2[..84]);

        // Decoded, the first version reads the earliest slot as genesis, not 64.
        assert_eq!(
            StatusVersion::V1.decode(&v1),
            Ok(Status {
                earliest_available_slot: Slot::GENESIS,
                ..status
            })
        );

        // Each version refuses the other's 84 or 92 bytes.
        assert!(StatusVersion::V1.decode(&v2).is_err());
        assert!(StatusVersion::V2.decode(&v1).is_err());
    }

    #[test]
    fn versions_map_to_protocols_and_fall_back_once() {
        // Each version round-trips through its protocol.
        for version in [StatusVersion::V1, StatusVersion::V2] {
            assert_eq!(StatusVersion::of(version.protocol()), Some(version));
        }
        // Other methods carry no status.
        assert_eq!(StatusVersion::of(Protocol::PingV1), None);

        // The newest version falls back to the first, which has nothing older.
        assert_eq!(StatusVersion::NEWEST.older(), Some(StatusVersion::V1));
        assert_eq!(StatusVersion::V1.older(), None);
    }
}
