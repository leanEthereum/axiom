//! Secret keys that sign and public keys that verify.

use std::{fmt, slice};

use super::{
    error::P256Error, field::FieldElement, point::AffinePoint, scalar::Scalar,
    signature::Signature, table::GeneratorTable,
};
use crate::{
    ct::{Mask, wipe},
    rfc6979::NonceGenerator,
};

/// A P-256 secret key: a scalar d in [1, n).
///
/// The scalar is cleared from memory when the key is dropped.
#[derive(Clone, Eq)]
pub struct SecretKey {
    /// The scalar d.
    scalar: Scalar,
}

impl SecretKey {
    /// A key from its 32-byte big-endian encoding.
    ///
    /// The range check runs in constant time and reveals only its outcome.
    ///
    /// # Errors
    ///
    /// Fails when the value is zero or not below n.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, P256Error> {
        // Zero is a valid scalar but not a valid key: its public key is the identity.
        Scalar::from_bytes_nonzero(bytes)
            .map(|scalar| Self { scalar })
            .ok_or(P256Error::InvalidSecretKey)
    }

    /// The 32-byte big-endian encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.scalar.to_bytes()
    }

    /// The public key d G, computed in constant time.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        let point = GeneratorTable::get().mul_ct(&self.scalar);
        // Invariant: 1 <= d < n and G has order n, so d G is never the identity.
        PublicKey {
            point: point.to_affine().expect("d G is finite for d in [1, n)"),
        }
    }

    /// Signs a 32-byte message hash with a deterministic nonce.
    ///
    /// The signature is not normalized to low s.
    /// X.509 and TLS accept either half, and the RFC 6979 known answers keep the computed s.
    ///
    /// # Algorithm
    ///
    /// ECDSA per FIPS 186-4, section 6.4, with the nonce of RFC 6979, section 3.2.
    ///
    /// ```text
    /// z = hash mod n
    /// k = RFC 6979 nonce from (d, z)
    /// R = k G,  r = x(R) mod n
    /// s = k^-1 (z + r d) mod n
    /// ```
    ///
    /// The scalar multiplication and both inversions run in constant time.
    #[must_use]
    pub fn sign(&self, hash: &[u8; 32]) -> Signature {
        // z: the hash as an integer modulo n, bits2int then reduction.
        let z = Scalar::from_bytes_reduced(hash);
        let mut secret = self.scalar.to_bytes();
        let mut nonces = NonceGenerator::new(&secret, &z.to_bytes());
        wipe(&mut secret);

        loop {
            let mut k = nonces.next_nonce(Scalar::from_bytes_nonzero);

            // Invariant: k is in [1, n), so k G is finite.
            let big_r = GeneratorTable::get()
                .mul_ct(&k)
                .to_affine()
                .expect("k G is finite for k in [1, n)");

            // r = x mod n, then s = k^-1 (z + r d).
            let r = Scalar::from_bytes_reduced(&big_r.x.to_bytes());
            let s = k.invert().mul(z.add(r.mul(self.scalar)));
            wipe(slice::from_mut(&mut k));

            // Timing: r = 0 or s = 0 happens with probability about 2^-256.
            // Retrying is public, and RFC 6979, section 3.4, continues the same stream.
            if r.is_zero().reveal() || s.is_zero().reveal() {
                continue;
            }
            return Signature { r, s };
        }
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        // Compare every byte, so the time reveals nothing about where keys differ.
        Mask::bytes_equal(&self.to_bytes(), &other.to_bytes()).reveal()
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        wipe(slice::from_mut(&mut self.scalar));
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The scalar is secret: never print it.
        f.debug_struct("SecretKey").finish_non_exhaustive()
    }
}

/// A P-256 public key: a finite curve point.
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
    pub const COMPRESSED_LEN: usize = 33;

    /// Bytes in the uncompressed SEC 1 encoding.
    pub const UNCOMPRESSED_LEN: usize = 65;

    /// Decodes either SEC 1 encoding, told apart by length and prefix.
    ///
    /// # Errors
    ///
    /// Fails on any length other than 33 or 65, a wrong prefix, or a point off the curve.
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, P256Error> {
        if let Ok(compressed) = bytes.try_into() {
            return Self::from_compressed(compressed);
        }
        if let Ok(uncompressed) = bytes.try_into() {
            return Self::from_uncompressed(uncompressed);
        }
        Err(P256Error::InvalidPublicKeyLength(bytes.len()))
    }

    /// Decodes the 33-byte compressed form, prefix 0x02 or 0x03 then x.
    ///
    /// # Errors
    ///
    /// Fails on a wrong prefix, x not below p, or x with no point on the curve.
    pub fn from_compressed(bytes: &[u8; 33]) -> Result<Self, P256Error> {
        AffinePoint::from_compressed(bytes)
            .map(|point| Self { point })
            .ok_or(P256Error::InvalidPublicKey)
    }

    /// Decodes the 65-byte uncompressed form, prefix 0x04 then x then y.
    ///
    /// The hybrid prefixes 0x06 and 0x07 of SEC 1 are refused: no profile in use allows them.
    ///
    /// # Errors
    ///
    /// Fails on a wrong prefix, a coordinate not below p, or a point off the curve.
    pub fn from_uncompressed(bytes: &[u8; 65]) -> Result<Self, P256Error> {
        AffinePoint::from_uncompressed(bytes)
            .map(|point| Self { point })
            .ok_or(P256Error::InvalidPublicKey)
    }

    /// The 33-byte compressed form.
    #[must_use]
    pub fn to_compressed(&self) -> [u8; 33] {
        self.point.to_compressed()
    }

    /// The 65-byte uncompressed form.
    #[must_use]
    pub fn to_uncompressed(&self) -> [u8; 65] {
        self.point.to_uncompressed()
    }

    /// Checks a signature over a 32-byte message hash.
    ///
    /// Both halves of s are accepted, as X.509 and TLS 1.3 require.
    /// The computation runs in variable time: the key, hash and signature are all public.
    ///
    /// # Algorithm
    ///
    /// ECDSA verification per FIPS 186-4, section 6.4.2, with z the hash reduced modulo n.
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
    pub fn verify(&self, hash: &[u8; 32], signature: &Signature) -> Result<(), P256Error> {
        let Signature { r, s } = *signature;

        // Phase 1: X = u1 G + u2 Q.
        let z = Scalar::from_bytes_reduced(hash);
        let w = s.invert();
        let x = GeneratorTable::get().double_mul_vartime(&z.mul(w), &r.mul(w), &self.point);
        if x.is_identity().reveal() {
            return Err(P256Error::VerificationFailed);
        }

        // Phase 2: compare in projective form against r, then r + n.
        let (r_plus_n, carry) = r.to_uint().add_with_carry(Scalar::ORDER);
        let candidates = [Some(r.to_uint()), (carry == 0).then_some(r_plus_n)];
        for value in candidates.into_iter().flatten() {
            // A candidate at or above p is no field element and cannot match.
            if let Some(candidate) = FieldElement::from_uint(value)
                && candidate.mul(x.z).equals(x.x).reveal()
            {
                return Ok(());
            }
        }
        Err(P256Error::VerificationFailed)
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
