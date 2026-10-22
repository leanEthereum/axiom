//! Connection ids: opaque labels that route packets to a connection.

use std::fmt;

use super::DecodeError;

/// A connection id of up to 20 bytes, per RFC 9000, section 5.1.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionId {
    /// Bytes in use.
    len: u8,
    /// The id, zero past its length.
    bytes: [u8; Self::MAX_LEN],
}

impl ConnectionId {
    /// The longest id version 1 allows.
    pub const MAX_LEN: usize = 20;

    /// The zero-length id.
    pub const EMPTY: Self = Self {
        len: 0,
        bytes: [0; Self::MAX_LEN],
    };

    /// Copies an id from bytes.
    ///
    /// # Errors
    ///
    /// Fails when the bytes exceed 20.
    pub fn new(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > Self::MAX_LEN {
            return Err(DecodeError::ConnectionIdTooLong { len: bytes.len() });
        }
        let mut id = Self::EMPTY;
        id.bytes[..bytes.len()].copy_from_slice(bytes);
        // Invariant: the length is at most 20, so it fits a byte.
        id.len = bytes.len() as u8;
        Ok(id)
    }

    /// The id bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// Bytes in the id.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether the id is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Appends the length byte, then the id, as long headers write it.
    pub fn encode_with_length(&self, out: &mut Vec<u8>) {
        out.push(self.len);
        out.extend_from_slice(self.as_bytes());
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_bytes() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds() {
        // Twenty bytes is the limit; twenty-one is refused.
        assert_eq!(ConnectionId::new(&[7; 20]).map(|id| id.len()), Ok(20));
        assert_eq!(
            ConnectionId::new(&[7; 21]),
            Err(DecodeError::ConnectionIdTooLong { len: 21 })
        );
        assert!(ConnectionId::new(&[]).is_ok_and(|id| id.is_empty() && id == ConnectionId::EMPTY));
    }

    #[test]
    fn encodes_with_length_and_prints_hex() {
        let id = ConnectionId::new(&[0x83, 0x94, 0xc8]).unwrap();
        let mut out = Vec::new();
        id.encode_with_length(&mut out);
        assert_eq!(out, [3, 0x83, 0x94, 0xc8]);
        assert_eq!(id.to_string(), "8394c8");
    }
}
