//! ECDSA and ECDH over secp256k1, the curve of Ethereum node identities.
//!
//! # Overview
//!
//! The curve is y^2 = x^3 + 7 over GF(p) with p = 2^256 - 2^32 - 977, per SEC 2.
//! Its points form a group of prime order n, about 2^256, with generator G.
//!
//! - Signatures follow SEC 1, section 4.1, with RFC 6979 nonces and low-s output.
//! - Public keys travel in the SEC 1 compressed or uncompressed encodings.
//! - Recovery rebuilds the signer's key from a signature, as Ethereum's ecrecover does.
//! - The shared point of ECDH is offered both as an x-coordinate and compressed.
//!
//! # Timing
//!
//! Every operation on a secret key runs in constant time.
//! Fixed-window scalar multiplication reads tables by full scan, and inversions use fixed chains.
//!
//! Verification and recovery touch only public data and take faster variable-time paths.
//!
//! # Examples
//!
//! ```
//! use axiom_crypto::secp256k1::SecretKey;
//!
//! let alice = SecretKey::from_bytes(&[0xa1; 32]).unwrap();
//! let bob = SecretKey::from_bytes(&[0xb0; 32]).unwrap();
//!
//! let hash = [0x42; 32];
//! let signature = alice.sign_recoverable(&hash);
//! assert_eq!(signature.recover(&hash).unwrap(), alice.public_key());
//!
//! let ab = alice.diffie_hellman(&bob.public_key());
//! let ba = bob.diffie_hellman(&alice.public_key());
//! assert_eq!(ab.to_compressed(), ba.to_compressed());
//! ```

mod error;
mod field;
mod keys;
mod point;
mod rfc6979;
mod scalar;
mod signature;
mod table;
mod uint;

pub use error::Secp256k1Error;
pub use keys::{PublicKey, SecretKey, SharedSecret};
pub use signature::{RecoverableSignature, RecoveryId, Signature};

#[cfg(test)]
mod tests {
    use std::array;

    use proptest::prelude::*;
    use sha2::{Digest, Sha256};

    use super::{scalar::Scalar, *};
    use crate::keccak::Keccak256;

    /// Decodes a hex string of known length.
    fn hex<const N: usize>(text: &str) -> [u8; N] {
        array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
    }

    /// The 20-byte Ethereum address of a key: the last 20 bytes of Keccak-256(x || y).
    fn address(key: &PublicKey) -> [u8; 20] {
        let digest = Keccak256::digest(&key.to_uncompressed()[1..]);
        digest[12..].try_into().unwrap()
    }

    /// Any valid secret key.
    fn arb_secret() -> impl Strategy<Value = SecretKey> {
        any::<[u8; 32]>().prop_filter_map("in [1, n)", |bytes| SecretKey::from_bytes(&bytes).ok())
    }

    #[test]
    fn rfc_6979_signature_vectors() {
        // The secp256k1 RFC 6979 vectors of Trezor, bitcoinjs, and python-ecdsa, all low-s.
        // Each tuple: secret key, message, r, s, recovery id.
        let cases = [
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "Satoshi Nakamoto",
                "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8",
                "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5",
                1,
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "All those moments will be lost in time, like tears in rain. Time to die...",
                "8600dbd41e348fe5c9465ab92d23e3db8b98b873beecd930736488696438cb6b",
                "547fe64427496db33bf66019dacbf0039c04199abb0122918601db38a72cfc21",
                0,
            ),
            (
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "Satoshi Nakamoto",
                "fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993447cd6af2d0",
                "6b39cd0eb1bc8603e159ef5c20a5c8ad685a45b06ce9bebed3f153d10d93bed5",
                0,
            ),
            (
                "f8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181",
                "Alan Turing",
                "7063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15c",
                "58dfcc1e00a35e1572f366ffe34ba0fc47db1e7189759b9fb233c5b05ab388ea",
                0,
            ),
            (
                "e91671c46231f833a6406ccbea0e3e392c76c167bac1cb013f6f1013980455c2",
                "There is a computer disease that anybody who works with computers knows about. It's a very serious disease and it interferes completely with the work. The trouble with computers is that you 'play' with them!",
                "b552edd27580141f3b2a5463048cb7cd3e047b97c9f98076c32dbdf85a68718b",
                "279fa72dd19bfae05577e06c7c0c1900c371fcd5893f7e1d56a37d30174671f6",
                1,
            ),
        ];
        for (secret, message, r, s, id) in cases {
            let key = SecretKey::from_bytes(&hex(secret)).unwrap();
            let hash: [u8; 32] = Sha256::digest(message.as_bytes()).into();
            let signature = key.sign_recoverable(&hash);
            assert_eq!(signature.signature().r(), hex::<32>(r), "{message}");
            assert_eq!(signature.signature().s(), hex::<32>(s), "{message}");
            assert_eq!(signature.recovery_id().to_byte(), id, "{message}");

            // Each vector verifies and recovers its signer.
            assert_eq!(
                key.public_key().verify(&hash, &signature.signature()),
                Ok(())
            );
            assert_eq!(signature.recover(&hash), Ok(key.public_key()));
        }
    }

    #[test]
    fn public_key_vectors() {
        // 1 G = G, 2 G, 3 G and (n - 1) G = -G in uncompressed form.
        let cases = [
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000002",
                "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000003",
                "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672",
            ),
            (
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777",
            ),
        ];
        for (secret, point) in cases {
            let public = SecretKey::from_bytes(&hex(secret)).unwrap().public_key();
            assert_eq!(public.to_uncompressed()[1..], hex::<64>(point));
        }
    }

    #[test]
    fn ethereum_address_and_signature_vectors() {
        // go-ethereum's crypto test key and its address.
        let key = SecretKey::from_bytes(&hex(
            "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032",
        ))
        .unwrap();
        assert_eq!(
            address(&key.public_key()),
            hex::<20>("970e8128ab834e8eac17ab8e3812f010678cf791")
        );

        // Its signature over Keccak-256("foo"), r || s || v, as libsecp256k1 produces it.
        let hash = Keccak256::digest(b"foo");
        let signature = key.sign_recoverable(&hash);
        assert_eq!(
            signature.to_bytes(),
            hex::<65>(
                "d155e94305af7e07dd8c32873e5c03cb95c9e05960ef85be9c07f671da58c73718c19adc397a211aa9e87e519e2038c5a3b658618db335f74f800b8e0cfeef4401"
            )
        );
        assert_eq!(
            address(&signature.recover(&hash).unwrap()),
            address(&key.public_key())
        );
    }

    #[test]
    fn ecrecover_precompile_vector() {
        // The ecrecover precompile test of go-ethereum: v = 28 means recovery id 1.
        let hash = hex::<32>("456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3");
        let mut bytes = [0_u8; 65];
        bytes[..32].copy_from_slice(&hex::<32>(
            "9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608",
        ));
        bytes[32..64].copy_from_slice(&hex::<32>(
            "4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada",
        ));
        bytes[64] = 28 - 27;
        let signature = RecoverableSignature::from_bytes(&bytes).unwrap();
        let signer = signature.recover(&hash).unwrap();
        assert_eq!(
            address(&signer),
            hex::<20>("7156526fbd7a3c72969b54f64e42c10fbb768c8a")
        );

        // The recovered key verifies the plain signature too.
        assert_eq!(signer.verify(&hash, &signature.signature()), Ok(()));
    }

    #[test]
    fn ecdh_vector() {
        // Secrets 0x1d2e3f and 0x4a5b6c7d share the point (0x1d2e3f * 0x4a5b6c7d) G.
        // The expected x and parity come from an independent big-integer computation.
        let mut a = [0_u8; 32];
        a[29..].copy_from_slice(&[0x1d, 0x2e, 0x3f]);
        let mut b = [0_u8; 32];
        b[28..].copy_from_slice(&[0x4a, 0x5b, 0x6c, 0x7d]);
        let (a, b) = (
            SecretKey::from_bytes(&a).unwrap(),
            SecretKey::from_bytes(&b).unwrap(),
        );
        let shared = a.diffie_hellman(&b.public_key());
        let x = hex::<32>("9e27f3c747cbac04eb845a4b56a9c5067c47cc725e09df1205861aa9ff252b6e");
        assert_eq!(shared.x_coordinate(), x);

        // discv5 form: odd y gives prefix 0x03.
        let mut compressed = [0x03_u8; 33];
        compressed[1..].copy_from_slice(&x);
        assert_eq!(shared.to_compressed(), compressed);
    }

    #[test]
    fn secret_key_range() {
        // 0 and n are refused.
        // 1 and n - 1 are the extremes accepted.
        let n = hex::<32>("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        assert_eq!(
            SecretKey::from_bytes(&[0; 32]).unwrap_err(),
            Secp256k1Error::InvalidSecretKey
        );
        assert_eq!(
            SecretKey::from_bytes(&n).unwrap_err(),
            Secp256k1Error::InvalidSecretKey
        );
        assert_eq!(
            SecretKey::from_bytes(&[0xff; 32]).unwrap_err(),
            Secp256k1Error::InvalidSecretKey
        );
        let mut n_minus_one = n;
        n_minus_one[31] -= 1;
        assert!(SecretKey::from_bytes(&n_minus_one).is_ok());
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

        // Both encodings round-trip, through the length-dispatching decoder too.
        assert_eq!(PublicKey::from_sec1_bytes(&compressed), Ok(g));
        assert_eq!(PublicKey::from_sec1_bytes(&uncompressed), Ok(g));

        // Mutation: wrong prefixes, including the hybrid 0x06 / 0x07 forms.
        for tag in [0x00, 0x01, 0x04, 0x05] {
            let mut bad = compressed;
            bad[0] = tag;
            assert_eq!(
                PublicKey::from_compressed(&bad),
                Err(Secp256k1Error::InvalidPublicKey)
            );
        }
        for tag in [0x00, 0x02, 0x03, 0x06, 0x07] {
            let mut bad = uncompressed;
            bad[0] = tag;
            assert_eq!(
                PublicKey::from_uncompressed(&bad),
                Err(Secp256k1Error::InvalidPublicKey)
            );
        }

        // Mutation: y + 1 is off the curve.
        let mut off_curve = uncompressed;
        off_curve[64] ^= 1;
        assert_eq!(
            PublicKey::from_uncompressed(&off_curve),
            Err(Secp256k1Error::InvalidPublicKey)
        );

        // Mutation: x = p is no field element, and x = 0 has no point (7 is a non-residue).
        let mut x_is_p = [0xff_u8; 33];
        x_is_p[0] = 0x02;
        x_is_p[28..].copy_from_slice(&[0xfe, 0xff, 0xff, 0xfc, 0x2f]);
        assert_eq!(
            PublicKey::from_compressed(&x_is_p),
            Err(Secp256k1Error::InvalidPublicKey)
        );
        let mut x_is_zero = [0_u8; 33];
        x_is_zero[0] = 0x02;
        assert_eq!(
            PublicKey::from_compressed(&x_is_zero),
            Err(Secp256k1Error::InvalidPublicKey)
        );

        // Mutation: lengths other than 33 and 65.
        assert_eq!(
            PublicKey::from_sec1_bytes(&uncompressed[..64]),
            Err(Secp256k1Error::InvalidPublicKeyLength(64))
        );
        assert_eq!(
            PublicKey::from_sec1_bytes(&[]),
            Err(Secp256k1Error::InvalidPublicKeyLength(0))
        );
    }

    #[test]
    fn signature_encodings_are_validated() {
        // r = 0 and s = n are refused.
        // A recovery id of 4 is refused.
        let n = hex::<32>("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        let mut bytes = [1_u8; 64];
        bytes[..32].fill(0);
        assert_eq!(
            Signature::from_bytes(&bytes),
            Err(Secp256k1Error::InvalidSignature { offset: 0 })
        );
        let mut bytes = [1_u8; 64];
        bytes[32..].copy_from_slice(&n);
        assert_eq!(
            Signature::from_bytes(&bytes),
            Err(Secp256k1Error::InvalidSignature { offset: 32 })
        );
        let mut recoverable = [1_u8; 65];
        recoverable[64] = 4;
        assert_eq!(
            RecoverableSignature::from_bytes(&recoverable),
            Err(Secp256k1Error::InvalidRecoveryId(4))
        );
    }

    #[test]
    fn verification_is_strict_about_s() {
        // The high-s twin of a valid signature is refused, then accepted once normalized.
        let key = SecretKey::from_bytes(&[3; 32]).unwrap();
        let hash = [9; 32];
        let low = key.sign(&hash);
        let mut bytes = low.to_bytes();
        let high_s = Scalar::from_bytes(&low.s()).unwrap().neg().to_bytes();
        bytes[32..].copy_from_slice(&high_s);
        let high = Signature::from_bytes(&bytes).unwrap();
        assert!(!high.is_low_s());
        assert_eq!(
            key.public_key().verify(&hash, &high),
            Err(Secp256k1Error::HighS)
        );
        assert_eq!(high.normalize_s(), low);
    }

    #[test]
    fn recovery_refuses_impossible_nonce_points() {
        // Recovery id 2 asks for x = r + n.
        // With r near n that exceeds p, so no point exists.
        let mut bytes = [0xff_u8; 65];
        bytes[..32].copy_from_slice(&hex::<32>(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
        ));
        bytes[32..64].copy_from_slice(&[0x11; 32]);
        bytes[64] = 2;
        let signature = RecoverableSignature::from_bytes(&bytes).unwrap();
        assert_eq!(
            signature.recover(&[5; 32]),
            Err(Secp256k1Error::RecoveryFailed)
        );
    }

    #[test]
    fn debug_output_hides_secrets() {
        let key = SecretKey::from_bytes(&[7; 32]).unwrap();
        assert_eq!(format!("{key:?}"), "SecretKey { .. }");
        assert!(format!("{:?}", key.public_key()).starts_with("PublicKey(0"));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn sign_verify_round_trip(
            key in arb_secret(),
            hash in any::<[u8; 32]>(),
            flip in 0_usize..256,
        ) {
            // Law: a fresh signature is low-s and verifies.
            let signature = key.sign(&hash);
            prop_assert!(signature.is_low_s());
            prop_assert_eq!(key.public_key().verify(&hash, &signature), Ok(()));

            // Mutation: one flipped hash bit makes it fail.
            let mut other = hash;
            other[flip / 8] ^= 1 << (flip % 8);
            prop_assert_eq!(
                key.public_key().verify(&other, &signature),
                Err(Secp256k1Error::VerificationFailed)
            );
        }

        #[test]
        fn recovery_round_trip(key in arb_secret(), hash in any::<[u8; 32]>()) {
            // Law: recovery returns the signer, for low-s and, with flipped parity, high-s forms.
            let signature = key.sign_recoverable(&hash);
            prop_assert_eq!(signature.recover(&hash), Ok(key.public_key()));

            // The high-s twin pairs with the other parity of R.
            let plain = signature.signature();
            let mut bytes = plain.to_bytes();
            let high_s = Scalar::from_bytes(&plain.s()).unwrap().neg().to_bytes();
            bytes[32..].copy_from_slice(&high_s);
            let twin = RecoverableSignature::new(
                Signature::from_bytes(&bytes).unwrap(),
                RecoveryId::new(signature.recovery_id().to_byte() ^ 1).unwrap(),
            );
            prop_assert_eq!(twin.recover(&hash), Ok(key.public_key()));
        }

        #[test]
        fn encodings_round_trip(key in arb_secret()) {
            // Keys and signatures survive their byte encodings.
            let public = key.public_key();
            prop_assert_eq!(PublicKey::from_compressed(&public.to_compressed()), Ok(public));
            prop_assert_eq!(PublicKey::from_uncompressed(&public.to_uncompressed()), Ok(public));
            prop_assert_eq!(SecretKey::from_bytes(&key.to_bytes()).unwrap().public_key(), public);
            let signature = key.sign_recoverable(&[1; 32]);
            prop_assert_eq!(RecoverableSignature::from_bytes(&signature.to_bytes()), Ok(signature));
        }

        #[test]
        fn ecdh_is_symmetric(a in arb_secret(), b in arb_secret()) {
            // Law: a (b G) = b (a G), in both output forms.
            let ab = a.diffie_hellman(&b.public_key());
            let ba = b.diffie_hellman(&a.public_key());
            prop_assert_eq!(ab.x_coordinate(), ba.x_coordinate());
            prop_assert_eq!(ab.to_compressed(), ba.to_compressed());
        }
    }
}
