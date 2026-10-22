//! Distances in the keyspace: the XOR metric and its logarithm.

use std::{error::Error, fmt};

/// The XOR of two node identifiers, compared as a 256-bit big-endian number.
///
/// See discv5-theory.md, "Nodes, Records and Distances".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Distance(pub [u8; 32]);

impl Distance {
    /// The bit length of the distance, from 0 for equal identifiers to 256.
    #[must_use]
    pub fn log2(&self) -> LogDistance {
        // Skip zero bytes from the top, then count the bits of the first nonzero one.
        for (index, byte) in self.0.iter().enumerate() {
            if *byte != 0 {
                let bits = (32 - index) * 8 - byte.leading_zeros() as usize;
                // Invariant: bits is at most 256.
                return LogDistance(bits as u16);
            }
        }
        LogDistance::ZERO
    }
}

/// A logarithmic distance: the bit length of an XOR distance, in 0 to 256.
///
/// FINDNODE asks for nodes by this value, and the routing table files them by it.
/// Zero names the queried node itself.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LogDistance(u16);

impl LogDistance {
    /// The distance of a node to itself.
    pub const ZERO: Self = Self(0);

    /// The largest distance: identifiers that differ in the top bit.
    pub const MAX: Self = Self(256);

    /// A distance from its value.
    ///
    /// # Errors
    ///
    /// Fails above 256.
    pub const fn new(value: u16) -> Result<Self, DistanceError> {
        // The keyspace is 256 bits wide, so no XOR is longer.
        if value > Self::MAX.0 {
            return Err(DistanceError(value));
        }
        Ok(Self(value))
    }

    /// The value, in 0 to 256.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }

    /// The routing table bucket that holds nodes at this distance, absent for zero.
    ///
    /// Bucket i holds distance i + 1, so 256 buckets cover distances 1 to 256.
    #[must_use]
    pub const fn bucket(self) -> Option<usize> {
        // The local node has no bucket; every other distance shifts down by one.
        match self.0 {
            0 => None,
            value => Some(value as usize - 1),
        }
    }
}

/// A logarithmic distance above 256.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DistanceError(pub u16);

impl fmt::Display for DistanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "log distance {} exceeds 256", self.0)
    }
}

impl Error for DistanceError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_and_buckets() {
        // 256 is the largest distance, 257 is refused.
        assert_eq!(LogDistance::new(256), Ok(LogDistance::MAX));
        assert_eq!(LogDistance::new(257), Err(DistanceError(257)));
        // Distance 1 lands in bucket 0, distance 256 in bucket 255.
        assert_eq!(LogDistance::new(1).unwrap().bucket(), Some(0));
        assert_eq!(LogDistance::MAX.bucket(), Some(255));
        // Distance 0 is the node itself and has no bucket.
        assert_eq!(LogDistance::ZERO.bucket(), None);
    }

    #[test]
    fn distances_order_as_numbers() {
        // 0x01.. is farther than 0x00ff.. because the top byte dominates.
        let mut near = [0; 32];
        near[1] = 0xff;
        let mut far = [0; 32];
        far[0] = 0x01;
        assert!(Distance(near) < Distance(far));
        assert_eq!(Distance(near).log2().get(), 248);
        assert_eq!(Distance(far).log2().get(), 249);
    }
}
