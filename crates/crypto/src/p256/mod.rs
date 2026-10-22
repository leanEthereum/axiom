//! ECDSA and ECDH over NIST P-256, the curve of TLS certificate keys and key shares.
//!
//! # Overview
//!
//! The curve is y^2 = x^3 - 3x + b over GF(p) with p = 2^256 - 2^224 + 2^192 + 2^96 - 1.
//! Its points form a group of prime order n, about 2^256, with generator G.
//! The parameters are those of FIPS 186-4, appendix D.1.2.3.
//!
//! - Signatures follow FIPS 186-4, section 6.4, with RFC 6979 nonces.
//! - Signatures keep the computed s: certificates and TLS never ask for low s.
//! - Public keys travel in the SEC 1 compressed or uncompressed encodings.
//! - Key agreement returns the x-coordinate of d Q, per SEC 1, section 3.3.1.
//!
//! Field elements live in Montgomery form, and points in projective coordinates.
//! Point formulas are the complete ones of Renes, Costello and Batina, EUROCRYPT 2016.
//!
//! # Timing
//!
//! Every operation on a secret key runs in constant time.
//! Fixed-base multiplication reads its table by full scan, and inversions use fixed exponents.
//! Variable-base multiplication uses fixed windows and reads its table by full scan too.
//! The complete formulas have no exceptional inputs, so no secret ever selects a branch.
//!
//! Verification touches only public data and takes faster variable-time paths.

mod error;
mod field;
mod keys;
mod montgomery;
mod point;
mod scalar;
mod signature;
mod table;

pub use error::P256Error;
pub use keys::{PublicKey, SecretKey, SharedSecret};
pub use signature::Signature;

#[cfg(test)]
mod tests {
    use std::array;

    use proptest::prelude::*;
    use sha2::{Digest, Sha256};

    use super::*;

    /// Decodes a hex string of known length.
    fn hex<const N: usize>(text: &str) -> [u8; N] {
        array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
    }

    /// The group order n, big-endian.
    const ORDER: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

    /// Any valid secret key.
    fn arb_secret() -> impl Strategy<Value = SecretKey> {
        any::<[u8; 32]>().prop_filter_map("in [1, n)", |bytes| SecretKey::from_bytes(&bytes).ok())
    }

    #[test]
    fn rfc_6979_p256_sha256_vectors() {
        // RFC 6979, appendix A.2.5: the key pair, then "sample" and "test" under SHA-256.
        let key = SecretKey::from_bytes(&hex(
            "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        ))
        .unwrap();
        let mut public = [0x04_u8; 65];
        public[1..].copy_from_slice(&hex::<64>(
            "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
        ));
        assert_eq!(key.public_key().to_uncompressed(), public);

        // Each tuple: message, r, s.
        // The "sample" s is above n / 2, which shows no low-s normalization happens.
        let cases = [
            (
                "sample",
                "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
                "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
            ),
            (
                "test",
                "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367",
                "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
            ),
        ];
        for (message, r, s) in cases {
            let hash: [u8; 32] = Sha256::digest(message.as_bytes()).into();
            let signature = key.sign(&hash);
            assert_eq!(signature.r(), hex::<32>(r), "{message}");
            assert_eq!(signature.s(), hex::<32>(s), "{message}");
            assert_eq!(key.public_key().verify(&hash, &signature), Ok(()));
        }
    }

    #[test]
    fn public_key_vectors() {
        // 1 G = G, 2 G, 3 G and (n - 1) G = -G in uncompressed form, checked against affine arithmetic over big integers.
        let mut n_minus_one = hex::<32>(ORDER);
        n_minus_one[31] -= 1;
        let mut two = [0_u8; 32];
        two[31] = 2;
        let mut three = [0_u8; 32];
        three[31] = 3;
        let cases = [
            (
                hex::<32>("0000000000000000000000000000000000000000000000000000000000000001"),
                "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
            ),
            (
                two,
                "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1",
            ),
            (
                three,
                "5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032",
            ),
            (
                n_minus_one,
                "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
            ),
        ];
        for (secret, point) in cases {
            let public = SecretKey::from_bytes(&secret).unwrap().public_key();
            assert_eq!(public.to_uncompressed()[1..], hex::<64>(point));
        }
    }

    #[test]
    fn secret_key_range() {
        // 0, n and 2^256 - 1 are refused; n - 1 is the largest key.
        let n = hex::<32>(ORDER);
        for bytes in [[0; 32], n, [0xff; 32]] {
            assert_eq!(
                SecretKey::from_bytes(&bytes).unwrap_err(),
                P256Error::InvalidSecretKey
            );
        }
        let mut n_minus_one = n;
        n_minus_one[31] -= 1;
        assert_eq!(
            SecretKey::from_bytes(&n_minus_one).map(|key| key.to_bytes()),
            Ok(n_minus_one)
        );
    }

    #[test]
    fn public_key_encodings_are_validated() {
        let g = SecretKey::from_bytes(&hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        ))
        .unwrap()
        .public_key();
        let compressed = g.to_compressed();
        let uncompressed = g.to_uncompressed();

        // Both encodings round-trip through the length-dispatching decoder.
        // G's y is odd, so its compressed prefix is 0x03.
        assert_eq!(compressed[0], 0x03);
        assert_eq!(PublicKey::from_sec1_bytes(&compressed), Ok(g));
        assert_eq!(PublicKey::from_sec1_bytes(&uncompressed), Ok(g));

        // Mutation: wrong prefixes, including the hybrid 0x06 and 0x07 forms.
        for tag in [0x00, 0x01, 0x04, 0x05] {
            let mut bad = compressed;
            bad[0] = tag;
            assert_eq!(
                PublicKey::from_compressed(&bad),
                Err(P256Error::InvalidPublicKey)
            );
        }
        for tag in [0x00, 0x02, 0x03, 0x06, 0x07] {
            let mut bad = uncompressed;
            bad[0] = tag;
            assert_eq!(
                PublicKey::from_uncompressed(&bad),
                Err(P256Error::InvalidPublicKey)
            );
        }

        // Mutation: y + 1 is off the curve.
        let mut off_curve = uncompressed;
        off_curve[64] ^= 1;
        assert_eq!(
            PublicKey::from_uncompressed(&off_curve),
            Err(P256Error::InvalidPublicKey)
        );

        // Mutation: x = p is no field element, though x = 0 would be on the curve.
        let mut x_is_p = [0x02_u8; 33];
        x_is_p[1..].copy_from_slice(&hex::<32>(
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        ));
        assert_eq!(
            PublicKey::from_compressed(&x_is_p),
            Err(P256Error::InvalidPublicKey)
        );

        // Mutation: lengths other than 33 and 65.
        assert_eq!(
            PublicKey::from_sec1_bytes(&uncompressed[..64]),
            Err(P256Error::InvalidPublicKeyLength(64))
        );
        assert_eq!(
            PublicKey::from_sec1_bytes(&[]),
            Err(P256Error::InvalidPublicKeyLength(0))
        );
    }

    #[test]
    fn signature_encodings_are_validated() {
        // r = 0 and s = n are refused; r = s = n - 1 is the largest accepted.
        let n = hex::<32>(ORDER);
        let mut bytes = [1_u8; 64];
        bytes[..32].fill(0);
        assert_eq!(
            Signature::from_bytes(&bytes),
            Err(P256Error::InvalidSignature { offset: 0 })
        );
        let mut bytes = [1_u8; 64];
        bytes[32..].copy_from_slice(&n);
        assert_eq!(
            Signature::from_bytes(&bytes),
            Err(P256Error::InvalidSignature { offset: 32 })
        );
        let mut n_minus_one = n;
        n_minus_one[31] -= 1;
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(&n_minus_one);
        bytes[32..].copy_from_slice(&n_minus_one);
        assert_eq!(
            Signature::from_bytes(&bytes).map(|signature| signature.to_bytes()),
            Ok(bytes)
        );
    }

    #[test]
    fn debug_output_hides_secrets() {
        let key = SecretKey::from_bytes(&[7; 32]).unwrap();
        assert_eq!(format!("{key:?}"), "SecretKey { .. }");
        assert!(format!("{:?}", key.public_key()).starts_with("PublicKey(0"));
        let shared = key.diffie_hellman(&key.public_key());
        assert_eq!(format!("{shared:?}"), "SharedSecret { .. }");
    }

    #[test]
    fn diffie_hellman_known_answer() {
        // Wycheproof ecdh_secp256r1_ecpoint_test.json, tcId 1: a normal exchange.
        let key = SecretKey::from_bytes(&hex(
            "0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346",
        ))
        .unwrap();
        let mut peer = [0x04_u8; 65];
        peer[1..].copy_from_slice(&hex::<64>(
            "62d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f26ac333a93a9e70a81cd5a95b5bf8d13990eb741c8c38872b4a07d275a014e30cf",
        ));
        let peer = PublicKey::from_uncompressed(&peer).unwrap();
        assert_eq!(
            key.diffie_hellman(&peer).x_coordinate(),
            hex("53020d908b0219328b658b525f26780e3ae12bcd952bb25a93bc0895e1714285")
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn sign_verify_round_trip(
            key in arb_secret(),
            hash in any::<[u8; 32]>(),
            flip in 0_usize..256,
        ) {
            // Law: a fresh signature verifies, and so does its twin (r, n - s).
            let signature = key.sign(&hash);
            let public = key.public_key();
            prop_assert_eq!(public.verify(&hash, &signature), Ok(()));
            let twin = Signature { r: signature.r, s: signature.s.neg() };
            prop_assert_eq!(public.verify(&hash, &twin), Ok(()));

            // Mutation: one flipped hash bit makes it fail.
            let mut other = hash;
            other[flip / 8] ^= 1 << (flip % 8);
            prop_assert_eq!(
                public.verify(&other, &signature),
                Err(P256Error::VerificationFailed)
            );
        }

        #[test]
        fn diffie_hellman_agrees(a in arb_secret(), b in arb_secret()) {
            // Law: a (b G) = b (a G), so both sides derive the same x-coordinate.
            let ab = a.diffie_hellman(&b.public_key()).x_coordinate();
            let ba = b.diffie_hellman(&a.public_key()).x_coordinate();
            prop_assert_eq!(ab, ba);

            // a (a G) is the x-coordinate of the public key of a^2, by the fixed-base comb.
            let scalar = scalar::Scalar::from_bytes(&a.to_bytes()).unwrap();
            let square = SecretKey::from_bytes(&scalar.mul(scalar).to_bytes()).unwrap();
            let expected: [u8; 32] = square.public_key().to_uncompressed()[1..33].try_into().unwrap();
            prop_assert_eq!(a.diffie_hellman(&a.public_key()).x_coordinate(), expected);
        }

        #[test]
        fn encodings_round_trip(key in arb_secret()) {
            // Keys and signatures survive their byte encodings.
            let public = key.public_key();
            prop_assert_eq!(PublicKey::from_compressed(&public.to_compressed()), Ok(public));
            prop_assert_eq!(PublicKey::from_uncompressed(&public.to_uncompressed()), Ok(public));
            prop_assert_eq!(SecretKey::from_bytes(&key.to_bytes()), Ok(key.clone()));
            let signature = key.sign(&[1; 32]);
            prop_assert_eq!(Signature::from_bytes(&signature.to_bytes()), Ok(signature));
        }
    }
}
