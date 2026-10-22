//! ECDSA signatures in the compact form r || s.

use super::{error::P384Error, scalar::Scalar};

/// An ECDSA signature (r, s) with both components in [1, n).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Signature {
    /// The x-coordinate of the nonce point, reduced modulo n.
    pub(super) r: Scalar,
    /// The proof scalar k^-1 (z + r d).
    pub(super) s: Scalar,
}

impl Signature {
    /// Bytes in the compact form.
    pub const LEN: usize = 96;

    /// Decodes the 96-byte compact form r || s, both big-endian.
    ///
    /// This is the IEEE P1363 encoding.
    ///
    /// # Errors
    ///
    /// Fails when r or s is zero or not below n.
    pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self, P384Error> {
        let (components, _) = bytes.as_chunks::<48>();
        Ok(Self {
            r: Self::component(&components[0], 0)?,
            s: Self::component(&components[1], 48)?,
        })
    }

    /// Decodes the component at a byte offset, refusing zero and values at or above n.
    fn component(bytes: &[u8; 48], offset: usize) -> Result<Scalar, P384Error> {
        Scalar::from_bytes_nonzero(bytes).ok_or(P384Error::InvalidSignature { offset })
    }

    /// The 96-byte compact form r || s.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut out = [0_u8; 96];
        out[..48].copy_from_slice(&self.r.to_bytes());
        out[48..].copy_from_slice(&self.s.to_bytes());
        out
    }

    /// The component r, big-endian.
    #[must_use]
    pub fn r(&self) -> [u8; 48] {
        self.r.to_bytes()
    }

    /// The component s, big-endian.
    #[must_use]
    pub fn s(&self) -> [u8; 48] {
        self.s.to_bytes()
    }
}
