//! Secret keys, public keys, and the shared secrets they agree on.

use std::{fmt, slice};

use super::{
    error::Secp256k1Error,
    field::{FieldElement, add_with_carry, limbs_to_be_bytes},
    point::AffinePoint,
    rfc6979::NonceGenerator,
    scalar::Scalar,
    signature::{RecoverableSignature, RecoveryId, Signature},
    table::GeneratorTable,
};
use crate::ct::wipe;

/// SEC 1 prefix of a compressed point with even y.
const TAG_EVEN: u8 = 0x02;

/// SEC 1 prefix of a compressed point with odd y.
const TAG_ODD: u8 = 0x03;

/// SEC 1 prefix of an uncompressed point.
const TAG_UNCOMPRESSED: u8 = 0x04;

/// A secp256k1 secret key: a scalar d in [1, n).
///
/// The scalar is cleared from memory when the key is dropped.
///
/// # Examples
///
/// ```
/// use axiom_crypto::secp256k1::SecretKey;
///
/// let key = SecretKey::from_bytes(&[0x11; 32]).unwrap();
/// let hash = [0x22; 32];
/// let signature = key.sign(&hash);
/// assert!(key.public_key().verify(&hash, &signature).is_ok());
/// ```
#[derive(Clone)]
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
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Secp256k1Error> {
        // Zero is a valid scalar but not a valid key: its public key is the identity.
        match Scalar::from_bytes(bytes) {
            Some(scalar) if !scalar.is_zero().reveal() => Ok(Self { scalar }),
            _ => Err(Secp256k1Error::InvalidSecretKey),
        }
    }

    /// The 32-byte big-endian encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.scalar.to_bytes()
    }

    /// The public key d G, computed in constant time.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        // Fixed-base comb over the precomputed generator table.
        let point = GeneratorTable::get().mul_ct(&self.scalar);
        // Invariant: 1 <= d < n and G has order n, so d G is never the identity.
        PublicKey::from_point(point.to_affine().expect("d G is finite for d in [1, n)"))
    }

    /// Signs a 32-byte message hash with a deterministic nonce, returning a low-s signature.
    #[must_use]
    pub fn sign(&self, hash: &[u8; 32]) -> Signature {
        // The plain signature drops the recovery identifier.
        self.sign_recoverable(hash).signature()
    }

    /// Signs a 32-byte message hash and returns the recovery identifier alongside.
    ///
    /// # Algorithm
    ///
    /// ECDSA per SEC 1, section 4.1.3, with the nonce of RFC 6979.
    ///
    /// ```text
    /// z = hash mod n
    /// k = RFC 6979 nonce from (d, z)
    /// R = k G,  r = x(R) mod n
    /// s = k^-1 (z + r d) mod n
    /// if s > n / 2: s = n - s, and R's y parity flips
    /// ```
    ///
    /// The scalar multiplication, both inversions, and the low-s choice run in constant time.
    #[must_use]
    pub fn sign_recoverable(&self, hash: &[u8; 32]) -> RecoverableSignature {
        // z: the hash as an integer modulo n, bits2int then reduction.
        let (z, _) = Scalar::from_bytes_reduced(hash);
        let mut secret = self.scalar.to_bytes();
        let mut nonces = NonceGenerator::new(&secret, &z.to_bytes());
        wipe(&mut secret);

        loop {
            let mut k = nonces.next_nonce();

            // Invariant: k is in [1, n), so k G is finite.
            let big_r = GeneratorTable::get()
                .mul_ct(&k)
                .to_affine()
                .expect("k G is finite for k in [1, n)");

            // r = x mod n.
            // The case x >= n has probability about 2^-128 and sets recovery bit 1.
            let (r, x_reduced) = Scalar::from_bytes_reduced(&big_r.x.to_bytes());
            let s = k.invert().mul(z.add(r.mul(self.scalar)));
            wipe(slice::from_mut(&mut k));

            // Timing: r = 0 or s = 0 happens with probability about 2^-256.
            // Retrying is public.
            if r.is_zero().reveal() || s.is_zero().reveal() {
                continue;
            }

            // Low-s: negating s matches negating k, which mirrors R and flips its y parity.
            let high = s.is_high();
            let s = Scalar::select(high, s.neg(), s);
            let y_odd = big_r.y.is_odd().bit() ^ high.bit();
            let id = (y_odd | (x_reduced.bit() << 1)) as u8;

            // Invariant: id is built from two bits, so it is at most 3.
            let recovery_id = RecoveryId::new(id).expect("two bits fit a recovery id");
            return RecoverableSignature::new(Signature { r, s }, recovery_id);
        }
    }

    /// The Diffie-Hellman shared point d Q with a peer's public key, in constant time.
    #[must_use]
    pub fn diffie_hellman(&self, peer: &PublicKey) -> SharedSecret {
        // Fixed-window ladder with full-scan table reads.
        let point = peer.point.to_jacobian().mul_ct(&self.scalar);
        // Invariant: Q has order n and 1 <= d < n, so d Q is never the identity.
        SharedSecret {
            point: point.to_affine().expect("d Q is finite for d in [1, n)"),
        }
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

/// A secp256k1 public key: a finite curve point.
///
/// Every constructor checks the point lies on the curve.
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

    /// Wraps a point the caller knows to be valid.
    pub(super) const fn from_point(point: AffinePoint) -> Self {
        Self { point }
    }

    /// Decodes either SEC 1 encoding, told apart by length and prefix.
    ///
    /// # Errors
    ///
    /// Fails on any length other than 33 or 65, a wrong prefix, or a point off the curve.
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, Secp256k1Error> {
        // Dispatch on length: 33 bytes compressed, 65 bytes uncompressed.
        if let Ok(compressed) = bytes.try_into() {
            return Self::from_compressed(compressed);
        }
        if let Ok(uncompressed) = bytes.try_into() {
            return Self::from_uncompressed(uncompressed);
        }
        Err(Secp256k1Error::InvalidPublicKey)
    }

    /// Decodes the 33-byte compressed form, prefix 0x02 or 0x03 then x.
    ///
    /// # Errors
    ///
    /// Fails on a wrong prefix, x not below p, or x with no point on the curve.
    pub fn from_compressed(bytes: &[u8; 33]) -> Result<Self, Secp256k1Error> {
        // The prefix byte carries the parity of y.
        let (tag, x) = bytes
            .split_first()
            .ok_or(Secp256k1Error::InvalidPublicKey)?;
        let y_is_odd = match *tag {
            TAG_EVEN => false,
            TAG_ODD => true,
            _ => return Err(Secp256k1Error::InvalidPublicKey),
        };
        let x = Self::coordinate(x)?;
        AffinePoint::decompress(x, y_is_odd)
            .map(Self::from_point)
            .ok_or(Secp256k1Error::InvalidPublicKey)
    }

    /// Decodes the 65-byte uncompressed form, prefix 0x04 then x then y.
    ///
    /// The hybrid prefixes 0x06 and 0x07 of SEC 1 are refused, as libsecp256k1 does by default.
    ///
    /// # Errors
    ///
    /// Fails on a wrong prefix, a coordinate not below p, or a point off the curve.
    pub fn from_uncompressed(bytes: &[u8; 65]) -> Result<Self, Secp256k1Error> {
        // Only the plain uncompressed prefix is accepted.
        if bytes[0] != TAG_UNCOMPRESSED {
            return Err(Secp256k1Error::InvalidPublicKey);
        }
        let x = Self::coordinate(&bytes[1..33])?;
        let y = Self::coordinate(&bytes[33..])?;
        AffinePoint::new(x, y)
            .map(Self::from_point)
            .ok_or(Secp256k1Error::InvalidPublicKey)
    }

    /// Decodes one coordinate, refusing values not below p.
    fn coordinate(bytes: &[u8]) -> Result<FieldElement, Secp256k1Error> {
        // Exactly 32 bytes, then the range check against p.
        let bytes: &[u8; 32] = bytes
            .try_into()
            .map_err(|_| Secp256k1Error::InvalidPublicKey)?;
        FieldElement::from_bytes(bytes).ok_or(Secp256k1Error::InvalidPublicKey)
    }

    /// The 33-byte compressed form.
    #[must_use]
    pub fn to_compressed(&self) -> [u8; 33] {
        compress(&self.point)
    }

    /// The 65-byte uncompressed form.
    #[must_use]
    pub fn to_uncompressed(&self) -> [u8; 65] {
        // Prefix 0x04, then x and y big-endian.
        let mut out = [0_u8; 65];
        out[0] = TAG_UNCOMPRESSED;
        out[1..33].copy_from_slice(&self.point.x.to_bytes());
        out[33..].copy_from_slice(&self.point.y.to_bytes());
        out
    }

    /// Checks a signature over a 32-byte message hash.
    ///
    /// Verification is strict: high-s signatures are refused, as libsecp256k1 does.
    /// Normalize a signature first to accept both forms.
    /// The computation runs in variable time: every input is public.
    ///
    /// # Algorithm
    ///
    /// Per SEC 1, section 4.1.4, with z the hash reduced modulo n.
    ///
    /// ```text
    /// w = s^-1,  u1 = z w,  u2 = r w
    /// X = u1 G + u2 Q
    /// accept when X is finite and x(X) = r mod n
    /// ```
    ///
    /// The final check avoids an inversion: x(X) = X / Z^2, so compare X with r Z^2.
    /// Since x(X) < p < 2n, the only other candidate is r + n, when that is below p.
    ///
    /// # Errors
    ///
    /// Fails with a high-s error, or when the signature does not verify.
    pub fn verify(&self, hash: &[u8; 32], signature: &Signature) -> Result<(), Secp256k1Error> {
        // Strict low-s, per BIP 62 and libsecp256k1.
        let Signature { r, s } = *signature;
        if s.is_high().reveal() {
            return Err(Secp256k1Error::HighS);
        }

        // Phase 1: X = u1 G + u2 Q.
        let (z, _) = Scalar::from_bytes_reduced(hash);
        let w = s.invert();
        let x = GeneratorTable::get().double_mul_vartime(&z.mul(w), &r.mul(w), &self.point);
        if x.is_identity().reveal() {
            return Err(Secp256k1Error::VerificationFailed);
        }

        // Phase 2: compare in projective form against r, then r + n.
        let zz = x.z.square();
        let mut candidates = [Some(r.limbs()), None];
        let (r_plus_n, carry) = add_with_carry(r.limbs(), Scalar::ORDER);
        if carry == 0 {
            candidates[1] = Some(r_plus_n);
        }
        for limbs in candidates.into_iter().flatten() {
            // A candidate at or above p is no field element and cannot match.
            if let Some(candidate) = FieldElement::from_bytes(&limbs_to_be_bytes(limbs))
                && candidate.mul(zz).equals(x.x).reveal()
            {
                return Ok(());
            }
        }
        Err(Secp256k1Error::VerificationFailed)
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

/// The point shared by two parties after a Diffie-Hellman exchange.
///
/// The point is cleared from memory when dropped.
pub struct SharedSecret {
    /// The point d_A d_B G.
    point: AffinePoint,
}

impl SharedSecret {
    /// The 32-byte x-coordinate of the shared point.
    #[must_use]
    pub fn x_coordinate(&self) -> [u8; 32] {
        self.point.x.to_bytes()
    }

    /// The 33-byte compressed shared point.
    ///
    /// discv5 feeds exactly these bytes into its session key derivation.
    #[must_use]
    pub fn to_compressed(&self) -> [u8; 33] {
        compress(&self.point)
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        wipe(slice::from_mut(&mut self.point.x));
        wipe(slice::from_mut(&mut self.point.y));
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The shared point is secret: never print it.
        f.debug_struct("SharedSecret").finish_non_exhaustive()
    }
}

/// The 33-byte SEC 1 compressed encoding of a point, per section 2.3.3.
fn compress(point: &AffinePoint) -> [u8; 33] {
    // Prefix 0x02 or 0x03 by parity of y, then x big-endian.
    let mut out = [0_u8; 33];
    // Timing: the parity bit is added, not branched on, since a shared point is secret.
    out[0] = TAG_EVEN + point.y.is_odd().bit() as u8;
    out[1..].copy_from_slice(&point.x.to_bytes());
    out
}
