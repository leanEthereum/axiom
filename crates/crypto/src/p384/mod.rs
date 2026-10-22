//! ECDSA verification over NIST P-384, a curve of web PKI certificates.
//!
//! # Overview
//!
//! The curve is y^2 = x^3 - 3x + b over GF(p) with p = 2^384 - 2^128 - 2^96 + 2^32 - 1.
//! Its points form a group of prime order n, about 2^384, with generator G.
//! The parameters are those of FIPS 186-4, appendix D.1.2.4.
//!
//! - Verification follows FIPS 186-4, section 6.4.2, for a hash of any length.
//! - Both halves of s are accepted: certificates and TLS never ask for low s.
//! - Public keys travel in the SEC 1 compressed or uncompressed encodings.
//!
//! There is no signing: the TLS client only checks P-384 certificate chains and handshake signatures.
//!
//! Field elements live in Montgomery form, and points in projective coordinates.
//! Point formulas are the complete ones of Renes, Costello and Batina, EUROCRYPT 2016.
//!
//! # Timing
//!
//! Every input is public, so all arithmetic takes variable-time paths.

mod error;
mod field;
mod keys;
mod montgomery;
mod point;
mod scalar;
mod signature;

pub use error::P384Error;
pub use keys::PublicKey;
pub use signature::Signature;

#[cfg(test)]
mod tests {
    use std::array;

    use proptest::prelude::*;
    use sha2::{Digest, Sha256, Sha384, Sha512};

    use super::{point::AffinePoint, scalar::Scalar, *};

    /// Decodes a hex string of known length.
    fn hex<const N: usize>(text: &str) -> [u8; N] {
        array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
    }

    /// The group order n, big-endian.
    const ORDER: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";

    /// The key of RFC 6979, appendix A.2.6: x, then Q = x G uncompressed without its prefix.
    const RFC_6979_SECRET: &str = "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5";
    const RFC_6979_PUBLIC: &str = "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc138015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720";

    /// The public key of RFC 6979, appendix A.2.6.
    fn rfc_6979_key() -> PublicKey {
        let mut bytes = [0x04_u8; 97];
        bytes[1..].copy_from_slice(&hex::<96>(RFC_6979_PUBLIC));
        PublicKey::from_uncompressed(&bytes).unwrap()
    }

    /// Signs with a given nonce: the textbook formula, for tests only.
    ///
    /// Returns none when r or s is zero.
    fn sign(secret: Scalar, nonce: Scalar, hash: &[u8]) -> Option<Signature> {
        // r = x(k G) mod n, s = k^-1 (z + r d) mod n.
        let point = AffinePoint::GENERATOR
            .to_projective()
            .mul_vartime(&nonce)
            .to_affine()?;
        let r = Scalar::from_hash(&point.x.to_bytes());
        let s = nonce
            .invert()
            .mul(Scalar::from_hash(hash).add(r.mul(secret)));
        (!r.is_zero() && !s.is_zero()).then_some(Signature { r, s })
    }

    /// Any scalar in [1, n).
    fn arb_nonzero() -> impl Strategy<Value = Scalar> {
        any::<[u8; 48]>().prop_filter_map("in [1, n)", |bytes| Scalar::from_bytes_nonzero(&bytes))
    }

    #[test]
    fn rfc_6979_p384_vectors() {
        // RFC 6979, appendix A.2.6: the key's public point is x G.
        let secret = Scalar::from_bytes(&hex(RFC_6979_SECRET)).unwrap();
        let derived = AffinePoint::GENERATOR.to_projective().mul_vartime(&secret);
        assert_eq!(
            derived.to_affine().unwrap().to_uncompressed()[1..],
            hex::<96>(RFC_6979_PUBLIC)
        );

        // Each tuple: hash of the message, r, s.
        // SHA-256 is read whole, SHA-384 fits exactly, and SHA-512 is truncated to 384 bits.
        let key = rfc_6979_key();
        let cases: [(Vec<u8>, &str, &str); 3] = [
            (
                Sha384::digest(b"sample").to_vec(),
                "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe46",
                "99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8",
            ),
            (
                Sha256::digest(b"sample").to_vec(),
                "21b13d1e013c7fa1392d03c5f99af8b30c570c6f98d4ea8e354b63a21d3daa33bde1e888e63355d92fa2b3c36d8fb2cd",
                "f3aa443fb107745bf4bd77cb3891674632068a10ca67e3d45db2266fa7d1feebefdc63eccd1ac42ec0cb8668a4fa0ab0",
            ),
            (
                Sha512::digest(b"test").to_vec(),
                "a0d5d090c9980faf3c2ce57b7ae951d31977dd11c775d314af55f76c676447d06fb6495cd21b4b6e340fc236584fb277",
                "976984e59b4c77b0e8e4460dca3d9f20e07b9bb1f63beefaf576f6b2e8b224634a2092cd3792e0159ad9cee37659c736",
            ),
        ];
        for (hash, r, s) in cases {
            let mut compact = [0_u8; 96];
            compact[..48].copy_from_slice(&hex::<48>(r));
            compact[48..].copy_from_slice(&hex::<48>(s));
            let signature = Signature::from_bytes(&compact).unwrap();
            assert_eq!(key.verify(&hash, &signature), Ok(()), "{r}");

            // Only the leftmost 384 bits count: the first 48 bytes of a longer hash verify too.
            if hash.len() > 48 {
                assert_eq!(key.verify(&hash[..48], &signature), Ok(()), "{r}");
            }

            // Mutation: one flipped bit in the first byte fails.
            let mut other = hash.clone();
            other[0] ^= 1;
            assert_eq!(
                key.verify(&other, &signature),
                Err(P384Error::VerificationFailed)
            );
        }
    }

    #[test]
    fn public_key_encodings_are_validated() {
        let key = rfc_6979_key();
        let compressed = key.to_compressed();
        let uncompressed = key.to_uncompressed();

        // Both encodings round-trip through the length-dispatching decoder.
        assert_eq!(PublicKey::from_sec1_bytes(&compressed), Ok(key));
        assert_eq!(PublicKey::from_sec1_bytes(&uncompressed), Ok(key));

        // Mutation: wrong prefixes, including the hybrid 0x06 and 0x07 forms.
        for tag in [0x00, 0x01, 0x04, 0x05] {
            let mut bad = compressed;
            bad[0] = tag;
            assert_eq!(
                PublicKey::from_compressed(&bad),
                Err(P384Error::InvalidPublicKey)
            );
        }
        for tag in [0x00, 0x02, 0x03, 0x06, 0x07] {
            let mut bad = uncompressed;
            bad[0] = tag;
            assert_eq!(
                PublicKey::from_uncompressed(&bad),
                Err(P384Error::InvalidPublicKey)
            );
        }

        // Mutation: flipping the low bit of y leaves the curve.
        let mut off_curve = uncompressed;
        off_curve[96] ^= 1;
        assert_eq!(
            PublicKey::from_uncompressed(&off_curve),
            Err(P384Error::InvalidPublicKey)
        );

        // Mutation: x = p is no field element.
        let mut x_is_p = [0x02_u8; 49];
        x_is_p[1..].copy_from_slice(&hex::<48>(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
        ));
        assert_eq!(
            PublicKey::from_compressed(&x_is_p),
            Err(P384Error::InvalidPublicKey)
        );

        // Mutation: lengths other than 49 and 97, including the P-256 sizes.
        for length in [0, 33, 48, 65, 96, 98] {
            assert_eq!(
                PublicKey::from_sec1_bytes(&vec![0x04; length]),
                Err(P384Error::InvalidPublicKeyLength(length))
            );
        }
    }

    #[test]
    fn signature_encodings_are_validated() {
        // r = 0 and s = n are refused; r = s = n - 1 is the largest accepted.
        let n = hex::<48>(ORDER);
        let mut bytes = [1_u8; 96];
        bytes[..48].fill(0);
        assert_eq!(
            Signature::from_bytes(&bytes),
            Err(P384Error::InvalidSignature { offset: 0 })
        );
        let mut bytes = [1_u8; 96];
        bytes[48..].copy_from_slice(&n);
        assert_eq!(
            Signature::from_bytes(&bytes),
            Err(P384Error::InvalidSignature { offset: 48 })
        );
        let mut n_minus_one = n;
        n_minus_one[47] -= 1;
        let mut bytes = [0_u8; 96];
        bytes[..48].copy_from_slice(&n_minus_one);
        bytes[48..].copy_from_slice(&n_minus_one);
        let signature = Signature::from_bytes(&bytes).unwrap();
        assert_eq!(signature.to_bytes(), bytes);
        assert_eq!((signature.r(), signature.s()), (n_minus_one, n_minus_one));
    }

    #[test]
    fn debug_output_shows_the_compressed_key() {
        let debug = format!("{:?}", rfc_6979_key());
        assert_eq!(debug.len(), "PublicKey()".len() + 2 * 49);
        assert!(debug.starts_with("PublicKey(02ec3a4e") || debug.starts_with("PublicKey(03ec3a4e"));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn sign_verify_round_trip(
            secret in arb_nonzero(),
            nonce in arb_nonzero(),
            hash in any::<[u8; 48]>(),
            flip in 0_usize..384,
        ) {
            // Law: a textbook signature verifies, and so does its twin (r, n - s).
            let point = AffinePoint::GENERATOR.to_projective().mul_vartime(&secret);
            let key = PublicKey::from_uncompressed(&point.to_affine().unwrap().to_uncompressed()).unwrap();
            let Some(signature) = sign(secret, nonce, &hash) else {
                return Ok(());
            };
            prop_assert_eq!(key.verify(&hash, &signature), Ok(()));
            let twin = Signature { r: signature.r, s: signature.s.neg() };
            prop_assert_eq!(key.verify(&hash, &twin), Ok(()));

            // Mutation: one flipped hash bit makes it fail.
            let mut other = hash;
            other[flip / 8] ^= 1 << (flip % 8);
            prop_assert_eq!(key.verify(&other, &signature), Err(P384Error::VerificationFailed));
        }
    }
}
