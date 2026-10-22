//! Public keys that verify signatures.

use std::fmt;

use super::{
    error::P384Error, field::FieldElement, point::AffinePoint, scalar::Scalar, signature::Signature,
};

/// A P-384 public key: a finite curve point.
///
/// Every constructor checks the point lies on the curve.
/// The cofactor is 1, so that point also lies in the prime-order group.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey {
    /// The point d G.
    point: AffinePoint,
}

impl PublicKey {
    /// Bytes in the compressed SEC 1 encoding.
    pub const COMPRESSED_LEN: usize = 49;

    /// Bytes in the uncompressed SEC 1 encoding.
    pub const UNCOMPRESSED_LEN: usize = 97;

    /// Decodes either SEC 1 encoding, told apart by length and prefix.
    ///
    /// # Errors
    ///
    /// Fails on any length other than 49 or 97, a wrong prefix, or a point off the curve.
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, P384Error> {
        if let Ok(compressed) = bytes.try_into() {
            return Self::from_compressed(compressed);
        }
        if let Ok(uncompressed) = bytes.try_into() {
            return Self::from_uncompressed(uncompressed);
        }
        Err(P384Error::InvalidPublicKeyLength(bytes.len()))
    }

    /// Decodes the 49-byte compressed form, prefix 0x02 or 0x03 then x.
    ///
    /// # Errors
    ///
    /// Fails on a wrong prefix, x not below p, or x with no point on the curve.
    pub fn from_compressed(bytes: &[u8; 49]) -> Result<Self, P384Error> {
        AffinePoint::from_compressed(bytes)
            .map(|point| Self { point })
            .ok_or(P384Error::InvalidPublicKey)
    }

    /// Decodes the 97-byte uncompressed form, prefix 0x04 then x then y.
    ///
    /// The hybrid prefixes 0x06 and 0x07 of SEC 1 are refused: no profile in use allows them.
    ///
    /// # Errors
    ///
    /// Fails on a wrong prefix, a coordinate not below p, or a point off the curve.
    pub fn from_uncompressed(bytes: &[u8; 97]) -> Result<Self, P384Error> {
        AffinePoint::from_uncompressed(bytes)
            .map(|point| Self { point })
            .ok_or(P384Error::InvalidPublicKey)
    }

    /// The 49-byte compressed form.
    #[must_use]
    pub fn to_compressed(&self) -> [u8; 49] {
        self.point.to_compressed()
    }

    /// The 97-byte uncompressed form.
    #[must_use]
    pub fn to_uncompressed(&self) -> [u8; 97] {
        self.point.to_uncompressed()
    }

    /// Checks a signature over a message hash of any length.
    ///
    /// The hash becomes an integer by bits2int: its leftmost 384 bits, then reduction modulo n.
    /// SHA-384 fits exactly, SHA-512 loses its last 16 bytes, and SHA-256 is read whole.
    ///
    /// Both halves of s are accepted, as X.509 and TLS 1.3 require.
    /// The computation runs in variable time: the key, hash and signature are all public.
    ///
    /// # Algorithm
    ///
    /// ECDSA verification per FIPS 186-4, section 6.4.2, and SEC 1, section 4.1.4.
    ///
    /// ```text
    /// w = s^-1,  u1 = z w,  u2 = r w
    /// X = u1 G + u2 Q
    /// accept when X is finite and x(X) = r mod n
    /// ```
    ///
    /// The final check avoids an inversion: x(X) = X / Z, so compare X with r Z.
    /// Since x(X) < p < 2n, the only other candidate is r + n, when that is below p.
    ///
    /// # Errors
    ///
    /// Fails when the signature does not verify.
    pub fn verify(&self, hash: &[u8], signature: &Signature) -> Result<(), P384Error> {
        let Signature { r, s } = *signature;

        // Phase 1: X = u1 G + u2 Q.
        let z = Scalar::from_hash(hash);
        let w = s.invert();
        let g = AffinePoint::GENERATOR.to_projective();
        let x = g.double_mul_vartime(&z.mul(w), &self.point.to_projective(), &r.mul(w));
        if x.is_identity() {
            return Err(P384Error::VerificationFailed);
        }

        // Phase 2: compare in projective form against r, then r + n.
        let (r_plus_n, carry) = r.to_uint().add_with_carry(Scalar::ORDER);
        let candidates = [Some(r.to_uint()), (carry == 0).then_some(r_plus_n)];
        for value in candidates.into_iter().flatten() {
            // A candidate at or above p is no field element and cannot match.
            if let Some(candidate) = FieldElement::from_uint(value)
                && candidate.mul(x.z) == x.x
            {
                return Ok(());
            }
        }
        Err(P384Error::VerificationFailed)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Print the compressed encoding in hex, the form keys are usually quoted in.
        f.write_str("PublicKey(")?;
        for byte in self.to_compressed() {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}
