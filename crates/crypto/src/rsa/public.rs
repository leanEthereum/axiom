//! RSA public keys and signature verification, per RFC 8017, sections 8.1.2 and 8.2.2.

use std::fmt;

use super::{
    bignum::BigUint, encoding::MessageDigest, error::RsaError, hash::RsaHash, montgomery::Modulus,
};
use crate::ct::Mask;

/// The smallest modulus accepted, in bits.
///
/// The caller enforces any stricter floor; TLS profiles ask for 2048 bits.
const MIN_BITS: usize = 1024;

/// The largest modulus accepted, in bits.
///
/// Threshold: it bounds the work an attacker-chosen key can cause, as the largest common key size.
const MAX_BITS: usize = 8192;

/// An RSA public key (n, e).
///
/// # Invariants
///
/// The modulus is odd and between 1024 and 8192 bits.
/// The exponent is odd, at least 3, and below the modulus.
#[derive(Clone)]
pub struct RsaPublicKey {
    /// The modulus n, with its Montgomery constants.
    modulus: Modulus,
    /// The public exponent e.
    exponent: BigUint,
    /// The bit length of n.
    bits: usize,
}

impl RsaPublicKey {
    /// A key from its big-endian modulus and exponent.
    ///
    /// Leading zero bytes are ignored, as DER writes a zero before a set top bit.
    ///
    /// # Errors
    ///
    /// Fails when the modulus is even or outside 1024 to 8192 bits.
    /// Fails when the exponent is even, below 3, or not below the modulus.
    pub fn new(modulus_be: &[u8], exponent_be: &[u8]) -> Result<Self, RsaError> {
        let modulus = BigUint::from_be_bytes_minimal(modulus_be);
        let bits = modulus.bits_vartime();
        if !(MIN_BITS..=MAX_BITS).contains(&bits) {
            return Err(RsaError::ModulusSize {
                bits,
                min: MIN_BITS,
                max: MAX_BITS,
            });
        }
        if !modulus.is_odd() {
            return Err(RsaError::EvenModulus);
        }

        let exponent = BigUint::from_be_bytes_minimal(exponent_be);
        let exponent_bits = exponent.bits_vartime();
        // Two bits or fewer means at most 3, so the low limb holds the whole value.
        if exponent_bits <= 2 && exponent.limbs()[0] < 3 {
            return Err(RsaError::ExponentTooSmall {
                exponent: exponent.limbs()[0],
            });
        }
        if !exponent.is_odd() {
            return Err(RsaError::EvenExponent);
        }
        let below = exponent_bits < bits
            || (exponent_bits == bits
                && exponent
                    .resized(modulus.width())
                    .is_some_and(|wide| wide.less_than(&modulus).reveal()));
        if !below {
            return Err(RsaError::ExponentTooLarge {
                exponent_bits,
                modulus_bits: bits,
            });
        }

        Ok(Self {
            modulus: Modulus::new(modulus),
            exponent,
            bits,
        })
    }

    /// The bit length of the modulus.
    #[must_use]
    pub const fn bits(&self) -> usize {
        self.bits
    }

    /// The length of the modulus in bytes, which is the signature length k.
    pub(super) const fn len(&self) -> usize {
        self.bits.div_ceil(8)
    }

    /// The modulus as an integer.
    pub(super) const fn modulus(&self) -> &BigUint {
        self.modulus.value()
    }

    /// The public exponent as an integer.
    pub(super) const fn exponent(&self) -> &BigUint {
        &self.exponent
    }

    /// Checks an RSASSA-PKCS1-v1_5 signature over a message digest, per RFC 8017, section 8.2.2.
    ///
    /// The recovered block is compared in full with a fresh encoding of the digest.
    /// Nothing is parsed out of the recovered block, which closes the padding-forgery family.
    /// See Bleichenbacher's 2006 forgery against lenient parsers of low-exponent signatures.
    ///
    /// # Errors
    ///
    /// Fails when the digest length does not match the hash.
    /// Fails when the signature length is not the modulus length, or its value is not below n.
    /// Fails when the signature does not verify.
    pub fn verify_pkcs1v15(
        &self,
        hash: RsaHash,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<(), RsaError> {
        let message = MessageDigest::new(hash, digest)?;

        // Steps 1 and 2: s < n, then m = s^e mod n as k bytes.
        let k = self.len();
        let m = self.recover(signature)?;
        let Some(em) = m.to_be_bytes(k) else {
            return Err(RsaError::VerificationFailed);
        };

        // Steps 3 and 4: re-encode and compare every byte.
        let expected = message.pkcs1v15(k)?;
        if Mask::bytes_equal(&em, &expected).reveal() {
            Ok(())
        } else {
            Err(RsaError::VerificationFailed)
        }
    }

    /// Checks an RSASSA-PSS signature over a message digest, per RFC 8017, section 8.1.2.
    ///
    /// MGF1 runs over the same hash as the digest, and the salt length is fixed by the caller.
    /// TLS 1.3 fixes it to the digest length, per RFC 8446, section 4.2.3.
    ///
    /// # Errors
    ///
    /// Fails when the digest length does not match the hash.
    /// Fails when the signature length is not the modulus length, or its value is not below n.
    /// Fails when the signature does not verify.
    pub fn verify_pss(
        &self,
        hash: RsaHash,
        digest: &[u8],
        signature: &[u8],
        salt_len: usize,
    ) -> Result<(), RsaError> {
        let message = MessageDigest::new(hash, digest)?;

        // Step 2: m = s^e mod n, as emLen bytes with emBits = modBits - 1.
        // A value too wide for emLen bytes is no valid encoding.
        let em_bits = self.bits - 1;
        let m = self.recover(signature)?;
        let Some(em) = m.to_be_bytes(em_bits.div_ceil(8)) else {
            return Err(RsaError::VerificationFailed);
        };

        // Step 3: EMSA-PSS-VERIFY.
        if message.pss_verify(&em, em_bits, salt_len) {
            Ok(())
        } else {
            Err(RsaError::VerificationFailed)
        }
    }

    /// The integer m = s^e mod n of a k-byte signature, per RSAVP1 of RFC 8017, section 5.2.2.
    ///
    /// # Errors
    ///
    /// Fails when the length is not k or the value is not below n.
    fn recover(&self, signature: &[u8]) -> Result<BigUint, RsaError> {
        let k = self.len();
        if signature.len() != k {
            return Err(RsaError::SignatureLength {
                expected: k,
                actual: signature.len(),
            });
        }
        // Invariant: k bytes fit the modulus width, which holds ceil(k / 8) limbs.
        let s = BigUint::from_be_bytes(signature, self.modulus.width())
            .expect("k bytes fit the modulus width");
        if !s.less_than(self.modulus()).reveal() {
            return Err(RsaError::SignatureOutOfRange);
        }
        Ok(self.apply(&s))
    }

    /// The RSA permutation s^e mod n of a value below n, in variable time.
    ///
    /// Every input is public: a signature being checked, or one about to be released.
    pub(super) fn apply(&self, s: &BigUint) -> BigUint {
        let power = self
            .modulus
            .pow_vartime(&self.modulus.encode(s), &self.exponent);
        self.modulus.decode(&power)
    }
}

impl PartialEq for RsaPublicKey {
    fn eq(&self, other: &Self) -> bool {
        // Both values are public, so a plain comparison is fine.
        self.modulus.value() == other.modulus.value() && self.exponent == other.exponent
    }
}

impl Eq for RsaPublicKey {}

impl fmt::Debug for RsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The key is public, but a modulus of up to 1 KiB of hex buries a log line: show its size.
        f.debug_struct("RsaPublicKey")
            .field("bits", &self.bits)
            .finish_non_exhaustive()
    }
}
