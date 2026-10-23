//! RSA private keys in CRT form and constant-time signing, per RFC 8017, sections 5.2.1, 8.1.1 and 8.2.1.

use std::fmt;

use super::{
    bignum::BigUint, encoding::MessageDigest, error::RsaError, hash::RsaHash, montgomery::Modulus,
    public::RsaPublicKey,
};

/// One prime factor of the modulus with its CRT exponent.
///
/// Both are secret, and are cleared from memory when dropped.
#[derive(Clone)]
struct PrimeFactor {
    /// The prime, with its Montgomery constants, in the width shared by both primes.
    modulus: Modulus,
    /// The CRT exponent d mod (prime - 1), in the same width.
    exponent: BigUint,
}

impl PrimeFactor {
    /// Checks a prime and its CRT exponent against the private and public exponents.
    ///
    /// The prime is checked to be odd and at least 3, not to be prime.
    /// A composite factor would fail the fault check of every signature instead.
    ///
    /// # Errors
    ///
    /// Fails with the factor's index when the prime or the CRT exponent is inconsistent.
    fn new(
        prime: BigUint,
        crt_exponent: &[u8],
        index: usize,
        private_exponent: &BigUint,
        public_exponent: &BigUint,
    ) -> Result<Self, RsaError> {
        // Timing: the bit length of a prime is the key size, a public fact.
        if !prime.is_odd() || prime.bits_vartime() < 2 {
            return Err(RsaError::InvalidPrime { index });
        }
        let width = prime.width();
        let mismatch = RsaError::CrtExponentMismatch { index };
        let exponent = BigUint::from_be_bytes(crt_exponent, width).ok_or(mismatch)?;

        // The prime is odd, so prime - 1 is the prime with bit 0 cleared.
        let mut order = prime.clone();
        order.limbs_mut()[0] &= !1;

        // d_p = d mod (p - 1), and e d_p = 1 mod (p - 1).
        // Long division runs in time set by the widths, so neither check leaks the prime.
        let reduced = private_exponent.rem(&order);
        let inverse = public_exponent.mul(&exponent).rem(&order);
        let one = BigUint::from_u64(1, width);
        if !reduced.equals(&exponent).and(inverse.equals(&one)).reveal() {
            return Err(mismatch);
        }

        Ok(Self {
            modulus: Modulus::new(prime),
            exponent,
        })
    }

    /// The power m^(d_p) mod p in Montgomery form, for any m below p R.
    fn power(&self, m: &BigUint) -> BigUint {
        // The wide reduction maps m into Montgomery form without dividing by the secret prime.
        self.modulus.pow(&self.modulus.reduce(m), &self.exponent)
    }
}

/// An RSA private key with the CRT parameters of RFC 8017, section 3.2, second representation.
///
/// # Timing
///
/// Signing runs in constant time with respect to every secret.
///
/// - Each CRT half is a fixed-window exponentiation whose table is read by full scan.
/// - Every Montgomery product ends with a masked subtraction, never a branch.
/// - The input reaches each prime by Montgomery reduction, never by division by the prime.
///
/// Message blinding is not used.
/// Blinding hides the base of an exponentiation whose timing depends on it.
/// Here the timing depends on no value at all, and the base is the public encoded message.
///
/// # Faults
///
/// A fault in one CRT half yields a signature s with s^e = m mod one prime only.
/// Then gcd(s^e - m, n) reveals that prime, per Boneh, DeMillo and Lipton, EUROCRYPT 1997.
/// Each signature is therefore checked with the public exponent before it is released.
#[derive(Clone)]
pub struct RsaPrivateKey {
    /// The public half (n, e).
    public: RsaPublicKey,
    /// The prime p and d mod (p - 1).
    p: PrimeFactor,
    /// The prime q and d mod (q - 1).
    q: PrimeFactor,
    /// The CRT coefficient q^-1 mod p, in Montgomery form modulo p.
    coefficient: BigUint,
}

impl RsaPrivateKey {
    /// A key from its eight big-endian integers, in the order of RFC 8017, appendix A.1.2.
    ///
    /// Leading zero bytes are ignored.
    /// The checks below run once, at load, in time set by the widths.
    ///
    /// - n and e form a valid public key.
    /// - p and q are odd, at least 3, and their product is n.
    /// - d_p = d mod (p - 1) and e d_p = 1 mod (p - 1), and likewise for q.
    /// - q_inv is below p and q_inv q = 1 mod p.
    ///
    /// # Errors
    ///
    /// Fails with the first check that does not hold.
    #[expect(
        clippy::too_many_arguments,
        reason = "the eight integers of the RSAPrivateKey structure, in their standard order"
    )]
    #[expect(
        clippy::many_single_char_names,
        reason = "the names follow RFC 8017, section 3.2"
    )]
    pub fn from_components(
        n: &[u8],
        e: &[u8],
        d: &[u8],
        p: &[u8],
        q: &[u8],
        dp: &[u8],
        dq: &[u8],
        qinv: &[u8],
    ) -> Result<Self, RsaError> {
        let public = RsaPublicKey::new(n, e)?;

        // Both primes share the width of the wider one.
        // Then q < R_p and p < R_q, which the wide reductions of signing need.
        let p = BigUint::from_be_bytes_minimal(p);
        let q = BigUint::from_be_bytes_minimal(q);
        let width = p.width().max(q.width());
        // Invariant: widening never drops limbs, so the resize succeeds.
        let p = p.resized(width).expect("widening keeps every limb");
        let q = q.resized(width).expect("widening keeps every limb");

        // n = p q, compared across both widths.
        if !p.mul(&q).equals(public.modulus()).reveal() {
            if !p.is_odd() || p.bits_vartime() < 2 {
                return Err(RsaError::InvalidPrime { index: 0 });
            }
            if !q.is_odd() || q.bits_vartime() < 2 {
                return Err(RsaError::InvalidPrime { index: 1 });
            }
            return Err(RsaError::PrimeProductMismatch);
        }

        let d = BigUint::from_be_bytes_minimal(d);
        let q_value = q.clone();
        let p = PrimeFactor::new(p, dp, 0, &d, public.exponent())?;
        let q = PrimeFactor::new(q, dq, 1, &d, public.exponent())?;

        // q_inv < p, and q_inv (q mod p) = 1 mod p.
        let modulus = &p.modulus;
        let qinv = BigUint::from_be_bytes(qinv, width).ok_or(RsaError::CoefficientMismatch)?;
        if !qinv.less_than(modulus.value()).reveal() {
            return Err(RsaError::CoefficientMismatch);
        }
        let coefficient = modulus.encode(&qinv);
        let q_mod_p = modulus.encode(&q_value.rem(modulus.value()));
        if !modulus
            .mul(&coefficient, &q_mod_p)
            .equals(modulus.one())
            .reveal()
        {
            return Err(RsaError::CoefficientMismatch);
        }

        Ok(Self {
            public,
            p,
            q,
            coefficient,
        })
    }

    /// The public half of the key.
    #[must_use]
    pub const fn public_key(&self) -> &RsaPublicKey {
        &self.public
    }

    /// Signs a message digest with RSASSA-PKCS1-v1_5, per RFC 8017, section 8.2.1.
    ///
    /// The signature is deterministic and k bytes long, k being the modulus length.
    ///
    /// # Errors
    ///
    /// Fails when the digest length does not match the hash.
    /// Fails when the result does not pass the fault check.
    pub fn sign_pkcs1v15(&self, hash: RsaHash, digest: &[u8]) -> Result<Vec<u8>, RsaError> {
        let em = MessageDigest::new(hash, digest)?.pkcs1v15(self.public.len())?;
        self.sign_encoded(&em)
    }

    /// Signs a message digest with RSASSA-PSS, per RFC 8017, section 8.1.1.
    ///
    /// MGF1 runs over the same hash as the digest.
    /// The caller draws the salt; TLS 1.3 asks for a random one as long as the digest.
    ///
    /// # Errors
    ///
    /// Fails when the digest length does not match the hash.
    /// Fails when the salt and digest do not fit the modulus.
    /// Fails when the result does not pass the fault check.
    pub fn sign_pss(&self, hash: RsaHash, digest: &[u8], salt: &[u8]) -> Result<Vec<u8>, RsaError> {
        let em = MessageDigest::new(hash, digest)?.pss_encode(salt, self.public.bits() - 1)?;
        self.sign_encoded(&em)
    }

    /// The signature of an encoded message, checked before release.
    fn sign_encoded(&self, em: &[u8]) -> Result<Vec<u8>, RsaError> {
        // Invariant: EM has at most k bytes, which fit the modulus width.
        let m = BigUint::from_be_bytes(em, self.public.modulus().width())
            .expect("an encoded message fits the modulus width");

        // Both encodings start below n: PKCS #1 with a zero byte, PSS with its top bits cleared.
        let s = self.private_permutation(&m);

        // Bellcore check: s^e must give back m before s leaves this function.
        if !self.public.apply(&s).equals(&m).reveal() {
            return Err(RsaError::FaultDetected);
        }
        // Invariant: s < n, so it fits k bytes.
        Ok(s.to_be_bytes(self.public.len())
            .expect("a value below n fits k bytes"))
    }

    /// The RSA private permutation m^d mod n by the CRT, per RSASP1 of RFC 8017, section 5.2.1, step 2.b.
    ///
    /// # Algorithm
    ///
    /// Garner's recombination of the two half-size powers.
    ///
    /// ```text
    /// m_1 = m^(d_p) mod p
    /// m_2 = m^(d_q) mod q
    /// h   = q_inv (m_1 - m_2) mod p
    /// s   = m_2 + q h
    /// ```
    ///
    /// # Invariants
    ///
    /// With m_2 < q and h < p, s is at most q - 1 + q (p - 1) = n - 1, so no reduction follows.
    #[expect(
        clippy::many_single_char_names,
        reason = "the names follow RFC 8017, section 5.2.1"
    )]
    fn private_permutation(&self, m: &BigUint) -> BigUint {
        let (p, q) = (&self.p.modulus, &self.q.modulus);
        let width = p.width();

        // Invariant: n = p q < 2^(128 k), so m < n fits 2k limbs.
        let wide = m.resized(2 * width).expect("m < n fits 2k limbs");
        let m1 = self.p.power(&wide);
        let m2 = q.decode(&self.q.power(&wide));

        // h = q_inv (m_1 - m_2) mod p, with m_2 brought into Montgomery form modulo p.
        // Invariant: m_2 < q < R, so the wide reduction accepts it.
        let difference = p.sub(&m1, &p.reduce(&m2));
        let h = p.decode(&p.mul(&difference, &self.coefficient));

        // s = m_2 + q h, below n by the invariant above.
        let mut s = q.value().mul(&h);
        let m2 = m2.resized(2 * width).expect("widening keeps every limb");
        s.add_assign(&m2);
        s.resized(self.public.modulus().width())
            .expect("s < n fits the modulus width")
    }
}

impl fmt::Debug for RsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The primes and exponents are secret: show only the public half.
        f.debug_struct("RsaPrivateKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsa::tests::key;

    #[test]
    fn a_faulty_half_is_withheld() {
        // Fixture state: the 1024-bit test key, which signs correctly.
        let mut key = key();
        assert!(key.sign_pkcs1v15(RsaHash::Sha256, &[1; 32]).is_ok());

        // Mutation: flip bit 1 of d_p after loading, as a glitch in the p half would.
        // The result is then right modulo q only, and its release would reveal q.
        key.p.exponent.limbs_mut()[0] ^= 2;
        assert_eq!(
            key.sign_pkcs1v15(RsaHash::Sha256, &[1; 32]),
            Err(RsaError::FaultDetected)
        );
        assert_eq!(
            key.sign_pss(RsaHash::Sha256, &[1; 32], &[2; 32]),
            Err(RsaError::FaultDetected)
        );
    }
}
