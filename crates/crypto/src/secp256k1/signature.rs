//! ECDSA signatures, their recovery identifiers, and public key recovery.

use super::{
    error::Secp256k1Error, field::FieldElement, keys::PublicKey, point::AffinePoint,
    scalar::Scalar, table::GeneratorTable,
};

/// An ECDSA signature (r, s) with both components in [1, n).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Signature {
    /// The x-coordinate of the nonce point, reduced modulo n.
    pub(super) r: Scalar,
    /// The proof scalar k^-1 (z + r d).
    pub(super) s: Scalar,
}

impl Signature {
    /// Decodes the 64-byte compact form r || s, both big-endian.
    ///
    /// # Errors
    ///
    /// Fails when r or s is zero or not below n.
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self, Secp256k1Error> {
        // r occupies the first 32 bytes, s the last 32.
        let (r_bytes, s_bytes) = bytes.split_at(32);
        let r = Self::component(r_bytes, 0)?;
        let s = Self::component(s_bytes, 32)?;
        Ok(Self { r, s })
    }

    /// Decodes the component at a byte offset, refusing zero and values at or above n.
    fn component(bytes: &[u8], offset: usize) -> Result<Scalar, Secp256k1Error> {
        // Exactly 32 bytes, then 1 <= value < n.
        let bytes: &[u8; 32] = bytes
            .try_into()
            .map_err(|_| Secp256k1Error::InvalidSignature { offset })?;
        match Scalar::from_bytes(bytes) {
            Some(value) if !value.is_zero().reveal() => Ok(value),
            _ => Err(Secp256k1Error::InvalidSignature { offset }),
        }
    }

    /// The 64-byte compact form r || s.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 64] {
        // r then s, each 32 bytes big-endian.
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

    /// Whether s lies in the lower half [1, n / 2], the canonical form of BIP 62 and EIP-2.
    #[must_use]
    pub fn is_low_s(&self) -> bool {
        !self.s.is_high().reveal()
    }

    /// The equivalent signature with s in the lower half.
    ///
    /// (r, s) and (r, n - s) both verify, so either form can be normalized to the low one.
    #[must_use]
    pub fn normalize_s(&self) -> Self {
        // Replace s by n - s exactly when s is high.
        let high = self.s.is_high();
        Self {
            r: self.r,
            s: Scalar::select(high, self.s.neg(), self.s),
        }
    }
}

/// Which of up to four candidate nonce points a signature came from.
///
/// # Overview
///
/// Two bits pin down the nonce point R from r alone, per SEC 1, section 4.1.6.
///
/// ```text
/// bit 0 : y of R is odd
/// bit 1 : x of R is r + n rather than r, possible only when x >= n
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RecoveryId(u8);

impl RecoveryId {
    /// An identifier from its value in 0..=3.
    ///
    /// # Errors
    ///
    /// Fails for values above 3.
    pub const fn new(id: u8) -> Result<Self, Secp256k1Error> {
        // Two bits: y parity and x overflow.
        if id > 3 {
            return Err(Secp256k1Error::InvalidRecoveryId(id));
        }
        Ok(Self(id))
    }

    /// The value in 0..=3.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        self.0
    }

    /// Whether the nonce point has an odd y-coordinate.
    #[must_use]
    pub const fn is_y_odd(self) -> bool {
        self.0 & 1 == 1
    }

    /// Whether the nonce point's x-coordinate is r + n.
    #[must_use]
    pub const fn is_x_reduced(self) -> bool {
        self.0 & 2 == 2
    }
}

/// A signature together with the recovery identifier that recovers its signer.
///
/// Ethereum transactions and the precompile at address 0x01 carry this form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RecoverableSignature {
    /// The plain signature.
    pub(super) signature: Signature,
    /// The nonce point selector.
    pub(super) recovery_id: RecoveryId,
}

impl RecoverableSignature {
    /// A recoverable signature from its parts.
    #[must_use]
    pub const fn new(signature: Signature, recovery_id: RecoveryId) -> Self {
        Self {
            signature,
            recovery_id,
        }
    }

    /// Decodes the 65-byte form r || s || v with v in 0..=3.
    ///
    /// # Errors
    ///
    /// Fails when r or s is out of range or v is above 3.
    pub fn from_bytes(bytes: &[u8; 65]) -> Result<Self, Secp256k1Error> {
        // The compact signature, then one byte of recovery identifier.
        let mut compact = [0_u8; 64];
        compact.copy_from_slice(&bytes[..64]);
        let signature = Signature::from_bytes(&compact)?;
        let recovery_id = RecoveryId::new(bytes[64])?;
        Ok(Self {
            signature,
            recovery_id,
        })
    }

    /// The 65-byte form r || s || v.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 65] {
        // The compact signature, then the recovery identifier.
        let mut out = [0_u8; 65];
        out[..64].copy_from_slice(&self.signature.to_bytes());
        out[64] = self.recovery_id.to_byte();
        out
    }

    /// The plain signature.
    #[must_use]
    pub const fn signature(&self) -> Signature {
        self.signature
    }

    /// The recovery identifier.
    #[must_use]
    pub const fn recovery_id(&self) -> RecoveryId {
        self.recovery_id
    }

    /// The public key that produced this signature over the hash.
    ///
    /// High-s signatures are accepted, as the Ethereum ecrecover precompile accepts them.
    /// The computation runs in variable time: every input is public.
    ///
    /// # Algorithm
    ///
    /// Per SEC 1, section 4.1.6, with z the hash reduced modulo n.
    ///
    /// ```text
    /// R = the point with x = r (+ n) and the stated y parity
    /// Q = r^-1 (s R - z G) = (-z r^-1) G + (s r^-1) R
    /// ```
    ///
    /// # Errors
    ///
    /// Fails when no curve point has the stated x, or when Q is the identity.
    pub fn recover(&self, hash: &[u8; 32]) -> Result<PublicKey, Secp256k1Error> {
        let Signature { r, s } = self.signature;

        // Phase 1: rebuild the nonce point R.
        let mut x_value = r.to_uint();
        if self.recovery_id.is_x_reduced() {
            // x = r + n must stay below p.
            // A carry, or a value past p, means no such point.
            let (sum, carry) = x_value.add_with_carry(Scalar::ORDER);
            if carry == 1 {
                return Err(Secp256k1Error::RecoveryFailed);
            }
            x_value = sum;
        }
        let x = FieldElement::from_uint(x_value).ok_or(Secp256k1Error::RecoveryFailed)?;
        let big_r = AffinePoint::decompress(x, self.recovery_id.is_y_odd())
            .ok_or(Secp256k1Error::RecoveryFailed)?;

        // Phase 2: Q = u1 G + u2 R.
        let (z, _) = Scalar::from_bytes_reduced(hash);
        let r_inv = r.invert();
        let u1 = z.mul(r_inv).neg();
        let u2 = s.mul(r_inv);
        let q = GeneratorTable::get().double_mul_vartime(&u1, &u2, &big_r);
        q.to_affine()
            .map(PublicKey::from_point)
            .ok_or(Secp256k1Error::RecoveryFailed)
    }
}
