//! ECDSA signatures in the compact form r || s.

use super::{error::P256Error, scalar::Scalar};

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
    pub const LEN: usize = 64;

    /// Decodes the 64-byte compact form r || s, both big-endian.
    ///
    /// This is the IEEE P1363 encoding.
    ///
    /// # Errors
    ///
    /// Fails when r or s is zero or not below n.
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self, P256Error> {
        let (r, s) = bytes.split_at(32);
        Ok(Self {
            r: Self::component(r, 0)?,
            s: Self::component(s, 32)?,
        })
    }

    /// Decodes the component at a byte offset, refusing zero and values at or above n.
    fn component(bytes: &[u8], offset: usize) -> Result<Scalar, P256Error> {
        bytes
            .try_into()
            .ok()
            .and_then(Scalar::from_bytes_nonzero)
            .ok_or(P256Error::InvalidSignature { offset })
    }

    /// The 64-byte compact form r || s.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0_u8; 64];
        out[..32].copy_from_slice(&self.r.to_bytes());
        out[32..].copy_from_slice(&self.s.to_bytes());
        out
    }

    /// The component r, big-endian.
    #[must_use]
    pub fn r(&self) -> [u8; 32] {
        self.r.to_bytes()
    }

    /// The component s, big-endian.
    #[must_use]
    pub fn s(&self) -> [u8; 32] {
        self.s.to_bytes()
    }
}
