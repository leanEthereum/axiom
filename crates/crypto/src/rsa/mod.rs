//! RSA signatures, per RFC 8017: PKCS #1 v1.5 and PSS, over SHA-256, SHA-384 and SHA-512.
//!
//! # Overview
//!
//! Web PKI certificates and TLS handshakes are still mostly signed with RSA.
//!
//! - Public keys check signatures of either scheme, for moduli of 1024 to 8192 bits.
//! - Private keys in CRT form sign with either scheme.
//! - PKCS #1 v1.5 verification re-encodes the digest and compares whole blocks, parsing nothing.
//! - PSS uses MGF1 over the message hash, with a salt length the caller fixes.
//!
//! Integers have a width chosen at run time, and products use Montgomery arithmetic.
//! There is no key generation.
//!
//! # Timing
//!
//! Signing runs in constant time with respect to the primes and exponents.
//! Verification touches only public data and takes faster variable-time paths.

mod bignum;
mod encoding;
mod error;
mod hash;
mod montgomery;
mod private;
mod public;

pub use error::RsaError;
pub use hash::RsaHash;
pub use private::RsaPrivateKey;
pub use public::RsaPublicKey;

#[cfg(test)]
mod tests {
    use proptest::{collection, prelude::*};

    use super::*;

    /// Decodes hex, left-padding an odd number of digits with a zero.
    fn hex(text: &str) -> Vec<u8> {
        let padded = if text.len() % 2 == 1 {
            format!("0{text}")
        } else {
            text.to_owned()
        };
        (0..padded.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&padded[i..i + 2], 16).unwrap())
            .collect()
    }

    // Fixture state: a 1024-bit key with e = 65537, two 512-bit primes with p > q.
    // The CRT values follow from d = e^-1 mod lcm(p - 1, q - 1).
    const N: &str = "efcf43af94e3a484216d547b9c1606d816f674020fa6a4d4b06d1ec602f6441c21f3270e7e2467d2772ca42ca87d21450587aa67e59235c76767b2e86c9f2fcab6390705e15cda0852f2608c96bd6109ab96df12f60d6114a12b6510c7c7891c0472e475b1ff003a2de380a3528657c9ed3f16309adf7f10caab5ab01fc00f3d";
    const E: &str = "010001";
    const D: &str = "75c41b4146a4e44ddefc89d88a3666f60790d03792e80b5a47a9cecafef961494f82d15354af1c2d47492cf6a16791c70b882c2f09965bc2a90d4bd6c841047e5cb5f74e58ee60bcc4f3bf73cce612d6b7bf8d2464c018dd50164e17b56c577e64b70e69cca1df5bf93d775f74433ce47fd643ed65680585daa65ab73d0e1621";
    const P: &str = "ff7896df59ca6c48d5c15124a7e04901d3dacc3b4aa5813a9a603091b47084cf027099d00196fb331daa30b6a35bbbdf1a935bc5057b3bb2f4ecc0e76bbd1e17";
    const Q: &str = "f04e5fb2d7449746aa8f0341665a84ce8d2b54ac20f742d2c3c21eaf89699f5af94fb59bfe13094ee6c95ffc1e5055bb1f951bb00b1257bf11049e8316db45cb";
    const DP: &str = "ff66a076b47ec158e3923bbc08b51a67e053da5fe055abe759949699e429a52c8b84e4d0e5f5fa36750ec35aa3e03ee761db3620b745273ed6cba662f5fc008b";
    const DQ: &str = "68e5cd608417acf16c0281a94ac4b8b4716b38caea9904d27c2180c39f783bd7ba7cd10a071ec831690cfe994fa241ca2d3f2996ef3e528f551e6f134a26ed9";
    const QINV: &str = "82e9c4f040930d2a211a007eacc3328a0f39433d6ce0cdd2cfed0fce7b10390d742f8938a50d58ef6ae86057bcef9e62625c27e1dfa5c09c3423e99c933c83c6";

    /// The components in the order of the constructor, with one replaced.
    fn components(replace: Option<(usize, &str)>) -> Vec<Vec<u8>> {
        let mut texts = [N, E, D, P, Q, DP, DQ, QINV];
        if let Some((index, text)) = replace {
            texts[index] = text;
        }
        texts.iter().map(|text| hex(text)).collect()
    }

    /// The key built from a list of components.
    fn key_from(parts: &[Vec<u8>]) -> Result<RsaPrivateKey, RsaError> {
        RsaPrivateKey::from_components(
            &parts[0], &parts[1], &parts[2], &parts[3], &parts[4], &parts[5], &parts[6], &parts[7],
        )
    }

    /// The fixture key.
    pub(super) fn key() -> RsaPrivateKey {
        key_from(&components(None)).unwrap()
    }

    /// Any hash with a digest of its length.
    fn arb_digest() -> impl Strategy<Value = (RsaHash, Vec<u8>)> {
        prop_oneof![
            Just(RsaHash::Sha256),
            Just(RsaHash::Sha384),
            Just(RsaHash::Sha512)
        ]
        .prop_flat_map(|hash| (Just(hash), collection::vec(any::<u8>(), hash.output_len())))
    }

    #[test]
    fn public_key_bounds() {
        // The fixture modulus has 1024 bits.
        let public = RsaPublicKey::new(&hex(N), &hex(E)).unwrap();
        assert_eq!(public.bits(), 1024);

        // A leading zero byte, as DER writes it, changes nothing.
        let mut padded = vec![0];
        padded.extend_from_slice(&hex(N));
        assert_eq!(RsaPublicKey::new(&padded, &hex(E)).unwrap().bits(), 1024);

        // Threshold: 1023 bits is too small, and 8193 bits too large.
        let mut small = hex(N);
        small[0] = 0x7f;
        assert_eq!(
            RsaPublicKey::new(&small, &hex(E)).unwrap_err(),
            RsaError::ModulusSize {
                bits: 1023,
                min: 1024,
                max: 8192
            }
        );
        let mut large = vec![1];
        large.extend_from_slice(&[0xff; 1024]);
        assert_eq!(
            RsaPublicKey::new(&large, &hex(E)).unwrap_err(),
            RsaError::ModulusSize {
                bits: 8193,
                min: 1024,
                max: 8192
            }
        );

        // Mutation: an even modulus.
        let mut even = hex(N);
        even[127] ^= 1;
        assert_eq!(
            RsaPublicKey::new(&even, &hex(E)).unwrap_err(),
            RsaError::EvenModulus
        );
    }

    #[test]
    fn public_exponent_bounds() {
        // 3 is the smallest exponent; 1 and 2 are refused, and 4 is even.
        let n = hex(N);
        assert!(RsaPublicKey::new(&n, &[3]).is_ok());
        assert_eq!(
            RsaPublicKey::new(&n, &[0, 1]).unwrap_err(),
            RsaError::ExponentTooSmall { exponent: 1 }
        );
        assert_eq!(
            RsaPublicKey::new(&n, &[2]).unwrap_err(),
            RsaError::ExponentTooSmall { exponent: 2 }
        );
        assert_eq!(
            RsaPublicKey::new(&n, &[4]).unwrap_err(),
            RsaError::EvenExponent
        );

        // n - 2 is odd and below n; n itself is not below n.
        let mut below = n.clone();
        below[127] -= 2;
        assert!(RsaPublicKey::new(&n, &below).is_ok());
        assert_eq!(
            RsaPublicKey::new(&n, &n).unwrap_err(),
            RsaError::ExponentTooLarge {
                exponent_bits: 1024,
                modulus_bits: 1024
            }
        );
    }

    #[test]
    fn private_key_consistency() {
        // The fixture loads.
        assert_eq!(key().public_key().bits(), 1024);

        // Mutation: each component in turn.
        // Fixture state: Q with its last digit 0xcb changed to 0xc9 stays odd.
        let q_changed = &format!("{}c9", &Q[..Q.len() - 2]);
        let p_even = &format!("{}16", &P[..P.len() - 2]);
        let dp_changed = &format!("{}8d", &DP[..DP.len() - 2]);
        let dq_changed = &format!("{}8", &DQ[..DQ.len() - 1]);
        let qinv_changed = &format!("{}c7", &QINV[..QINV.len() - 2]);
        let cases = [
            ((3, p_even.as_str()), RsaError::InvalidPrime { index: 0 }),
            ((4, q_changed.as_str()), RsaError::PrimeProductMismatch),
            ((2, "03"), RsaError::CrtExponentMismatch { index: 0 }),
            (
                (5, dp_changed.as_str()),
                RsaError::CrtExponentMismatch { index: 0 },
            ),
            (
                (6, dq_changed.as_str()),
                RsaError::CrtExponentMismatch { index: 1 },
            ),
            ((7, qinv_changed.as_str()), RsaError::CoefficientMismatch),
            ((7, P), RsaError::CoefficientMismatch),
        ];
        for ((index, text), expected) in cases {
            assert_eq!(
                key_from(&components(Some((index, text)))).unwrap_err(),
                expected,
                "component {index}"
            );
        }
    }

    #[test]
    fn signing_refusals() {
        let key = key();

        // A digest of the wrong length.
        assert_eq!(
            key.sign_pkcs1v15(RsaHash::Sha256, &[0; 48]).unwrap_err(),
            RsaError::DigestLength {
                expected: 32,
                actual: 48
            }
        );

        // Threshold: emLen = 128 holds a 64-byte digest with a salt of 62, not 63.
        assert!(key.sign_pss(RsaHash::Sha512, &[0; 64], &[0; 62]).is_ok());
        assert_eq!(
            key.sign_pss(RsaHash::Sha512, &[0; 64], &[0; 63])
                .unwrap_err(),
            RsaError::EncodingTooShort {
                required: 129,
                available: 128
            }
        );
    }

    #[test]
    fn signature_shape_is_checked() {
        let key = key();
        let public = key.public_key();
        let signature = key.sign_pkcs1v15(RsaHash::Sha256, &[9; 32]).unwrap();

        // A length other than k = 128 bytes.
        assert_eq!(
            public
                .verify_pkcs1v15(RsaHash::Sha256, &[9; 32], &signature[1..])
                .unwrap_err(),
            RsaError::SignatureLength {
                expected: 128,
                actual: 127
            }
        );

        // n with its last byte raised to 0xff is k bytes long but not below n.
        let mut wrapped = hex(N);
        wrapped[127] = 0xff;
        assert_eq!(
            public
                .verify_pkcs1v15(RsaHash::Sha256, &[9; 32], &wrapped)
                .unwrap_err(),
            RsaError::SignatureOutOfRange
        );

        // The same signature under another hash fails.
        assert_eq!(
            public
                .verify_pkcs1v15(RsaHash::Sha384, &[9; 48], &signature)
                .unwrap_err(),
            RsaError::VerificationFailed
        );
    }

    #[test]
    fn debug_output_hides_secrets() {
        let key = key();
        assert_eq!(
            format!("{key:?}"),
            "RsaPrivateKey { public: RsaPublicKey { bits: 1024, .. }, .. }"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        #[test]
        fn pkcs1v15_sign_verify_round_trip(
            (hash, digest) in arb_digest(),
            flip in 0_usize..256,
        ) {
            // Law: a fresh signature verifies under the public key.
            let key = key();
            let signature = key.sign_pkcs1v15(hash, &digest).unwrap();
            prop_assert_eq!(signature.len(), 128);
            prop_assert_eq!(key.public_key().verify_pkcs1v15(hash, &digest, &signature), Ok(()));

            // Mutation: one flipped digest bit makes it fail.
            let mut other = digest.clone();
            other[flip % digest.len()] ^= 1 << (flip % 8);
            prop_assert_eq!(
                key.public_key().verify_pkcs1v15(hash, &other, &signature),
                Err(RsaError::VerificationFailed)
            );
        }

        #[test]
        fn pss_sign_verify_round_trip(
            (hash, digest) in arb_digest(),
            salt in collection::vec(any::<u8>(), 0..=32),
            flip in 0_usize..1024,
        ) {
            // Law: a fresh signature verifies with the salt length it was made with.
            let key = key();
            let signature = key.sign_pss(hash, &digest, &salt).unwrap();
            let public = key.public_key();
            prop_assert_eq!(public.verify_pss(hash, &digest, &signature, salt.len()), Ok(()));

            // Mutation: another salt length, or one flipped signature bit, makes it fail.
            prop_assert_eq!(
                public.verify_pss(hash, &digest, &signature, salt.len() + 1),
                Err(RsaError::VerificationFailed)
            );
            let mut forged = signature;
            forged[flip / 8] ^= 1 << (flip % 8);
            prop_assert!(public.verify_pss(hash, &digest, &forged, salt.len()).is_err());
        }
    }
}
