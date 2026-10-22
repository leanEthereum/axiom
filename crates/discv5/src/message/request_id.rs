//! The identifier that ties a response to its request.

use std::fmt;

/// Most bytes a request id may hold.
const MAX_LEN: usize = 8;

/// An opaque byte string of at most 8 bytes, chosen by the requester and mirrored back.
///
/// See discv5-wire.md, "Protocol Messages".
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RequestId {
    /// The bytes, left-aligned.
    bytes: [u8; MAX_LEN],
    /// How many bytes are used.
    len: u8,
}

impl RequestId {
    /// A request id from its bytes, absent past 8 bytes.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Option<Self> {
        // Threshold: the wire spec caps request ids at 8 bytes.
        if bytes.len() > MAX_LEN {
            return None;
        }
        let mut id = Self::default();
        id.bytes[..bytes.len()].copy_from_slice(bytes);
        // Invariant: the length is at most 8.
        id.len = bytes.len() as u8;
        Some(id)
    }

    /// A request id from a counter, as 8 big-endian bytes.
    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        Self {
            bytes: value.to_be_bytes(),
            len: 8,
        }
    }

    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl fmt::Debug for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Hex, as the wire carries it.
        write!(f, "RequestId(0x")?;
        for byte in self.as_bytes() {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}
