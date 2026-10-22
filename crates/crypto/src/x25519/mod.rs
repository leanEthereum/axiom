//! X25519 Diffie-Hellman of RFC 7748, the key agreement of the libp2p Noise handshake.

mod field;

use std::fmt;

use field::FieldElement;
use thiserror::Error;

use crate::ct::{Mask, wipe};

/// The constant (A - 2) / 4 = 121665 of the ladder step, for A = 486662, per RFC 7748, section 5.
const A24: u32 = 121_665;

/// The u-coordinate 9 of the Curve25519 base point.
const BASE_POINT: [u8; 32] = {
    let mut point = [0_u8; 32];
    point[0] = 9;
    point
};

/// An X25519 secret scalar.
///
/// Any 32 bytes form a valid key.
/// Clamping happens at each use, so the stored bytes stay as given.
#[derive(Clone)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    /// A key from 32 uniformly random bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The bytes as given, before clamping.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// The public key: the scalar times the base point 9.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        // The base point has u = 9.
        PublicKey(Self::ladder(&self.0, &BASE_POINT))
    }

    /// The shared secret with a peer's public key.
    ///
    /// # Errors
    ///
    /// Fails when the result is all zeros.
    /// That happens exactly when the peer key lies in the small subgroup.
    /// RFC 7748, section 6.1, lets protocols reject it, and Noise does.
    pub fn diffie_hellman(&self, peer: &PublicKey) -> Result<SharedSecret, X25519Error> {
        // The ladder on the peer's u-coordinate.
        let shared = SharedSecret(Self::ladder(&self.0, &peer.0));

        // Timing: the zero check reads all 32 bytes.
        if Mask::bytes_equal(&shared.0, &[0; 32]).reveal() {
            return Err(X25519Error::LowOrderPoint);
        }
        Ok(shared)
    }

    /// The function X25519(k, u) of RFC 7748, section 5.
    ///
    /// # Algorithm
    ///
    /// The Montgomery ladder keeps two points whose difference is always the input point u.
    ///
    /// ```text
    ///             bit = 0                         bit = 1
    ///   (R0, R1) -> (2 R0, R0 + R1)     (R0, R1) -> (R0 + R1, 2 R1)
    ///
    ///   invariant: R1 - R0 = u, and R0 = (top bits of k so far) * u
    /// ```
    ///
    /// Both branches run the same formulas after a conditional swap.
    /// The scalar therefore never steers a branch or an address.
    #[expect(clippy::many_single_char_names, reason = "the names follow RFC 7748")]
    fn ladder(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
        // Clamp, per RFC 7748, section 5.
        //
        //     clear bits 0, 1, 2  -> a multiple of the cofactor 8
        //     clear bit 255, set bit 254 -> a fixed ladder length
        let mut k = *scalar;
        k[0] &= 0b1111_1000;
        k[31] &= 0b0111_1111;
        k[31] |= 0b0100_0000;

        // Projective (X : Z) coordinates: R0 starts at infinity (1 : 0), R1 at u (u : 1).
        let x1 = FieldElement::from_bytes(u);
        let mut x2 = FieldElement::ONE;
        let mut z2 = FieldElement::ZERO;
        let mut x3 = x1;
        let mut z3 = FieldElement::ONE;

        // The swap state carries over between steps, so each step costs one swap, not two.
        let mut swapped = 0_u64;
        for t in (0..255).rev() {
            let bit = u64::from((k[t / 8] >> (t % 8)) & 1);
            let swap = Mask::from_bit(swapped ^ bit);
            FieldElement::conditional_swap(&mut x2, &mut x3, swap);
            FieldElement::conditional_swap(&mut z2, &mut z3, swap);
            swapped = bit;

            // One combined differential addition and doubling, per RFC 7748, section 5.
            //
            //     (x2 : z2) <- 2 (x2 : z2)
            //     (x3 : z3) <- (x2 : z2) + (x3 : z3), with difference x1
            let a = x2.add(z2);
            let aa = a.square();
            let b = x2.sub(z2);
            let bb = b.square();
            let e = aa.sub(bb);
            let c = x3.add(z3);
            let d = x3.sub(z3);
            let da = d.mul(a);
            let cb = c.mul(b);
            x3 = da.add(cb).square();
            z3 = x1.mul(da.sub(cb).square());
            x2 = aa.mul(bb);
            z2 = e.mul(aa.add(e.mul_small(A24)));
        }
        let swap = Mask::from_bit(swapped);
        FieldElement::conditional_swap(&mut x2, &mut x3, swap);
        FieldElement::conditional_swap(&mut z2, &mut z3, swap);

        // Back to affine: u = X / Z, with 0 for the point at infinity since 0^(p-2) = 0.
        let out = x2.mul(z2.invert()).to_bytes();
        wipe(&mut k);
        out
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The scalar is secret: never print it.
        f.debug_struct("SecretKey").finish_non_exhaustive()
    }
}

/// An X25519 public key: the u-coordinate of a point, little-endian.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// A key from its 32-byte encoding.
    ///
    /// Every encoding is accepted, as RFC 7748, section 5, requires.
    /// The top bit is ignored and non-canonical values reduce modulo p.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The 32-byte encoding.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// The 32-byte encoding, borrowed.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The output of a Diffie-Hellman exchange, to feed into a key derivation.
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    /// The 32 shared bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The shared secret is secret: never print it.
        f.debug_struct("SharedSecret").finish_non_exhaustive()
    }
}

/// A Diffie-Hellman exchange that must be refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum X25519Error {
    /// The peer key has small order, so the shared secret is all zeros.
    #[error("peer public key has low order")]
    LowOrderPoint,
}

#[cfg(test)]
mod tests {
    use std::array;

    use proptest::prelude::*;

    use super::*;

    /// Decodes a 32-byte hex string in a test vector.
    fn hex(text: &str) -> [u8; 32] {
        array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
    }

    /// One application of X25519 through the public API.
    fn x25519(k: [u8; 32], u: [u8; 32]) -> [u8; 32] {
        // The vectors never hit a low-order point, so the exchange succeeds.
        *SecretKey::from_bytes(k)
            .diffie_hellman(&PublicKey::from_bytes(u))
            .unwrap()
            .as_bytes()
    }

    #[test]
    fn rfc_7748_scalar_multiplication_vectors() {
        // RFC 7748, section 5.2: two (scalar, u) pairs.
        assert_eq!(
            x25519(
                hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
                hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
            ),
            hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        );

        // The second u has its top bit set, which the decoder must ignore.
        let scalar = hex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let expected = hex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
        let u = hex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        assert_eq!(x25519(scalar, u), expected);
        let mut u_cleared = u;
        u_cleared[31] &= 0x7f;
        assert_eq!(x25519(scalar, u_cleared), expected);
    }

    #[test]
    fn rfc_7748_iterated_vectors() {
        // RFC 7748, section 5.2: start with k = u = 9, then k, u <- X25519(k, u), k.
        let mut k = BASE_POINT;
        let mut u = BASE_POINT;
        for iteration in 1..=1000 {
            let next = x25519(k, u);
            u = k;
            k = next;

            // After one iteration.
            if iteration == 1 {
                assert_eq!(
                    k,
                    hex("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
                );
            }
        }
        // After 1000 iterations.
        assert_eq!(
            k,
            hex("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
        );
    }

    #[test]
    #[ignore = "one million ladders take minutes; run with --ignored"]
    fn rfc_7748_iterated_one_million() {
        // RFC 7748, section 5.2: the same iteration, one million times.
        let mut k = BASE_POINT;
        let mut u = BASE_POINT;
        for _ in 0..1_000_000 {
            let next = x25519(k, u);
            u = k;
            k = next;
        }
        assert_eq!(
            k,
            hex("7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424")
        );
    }

    #[test]
    fn rfc_7748_diffie_hellman() {
        // RFC 7748, section 6.1: Alice and Bob derive the same secret.
        let alice = SecretKey::from_bytes(hex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let bob = SecretKey::from_bytes(hex(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        ));
        assert_eq!(
            alice.public_key().to_bytes(),
            hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            bob.public_key().to_bytes(),
            hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );
        let shared = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(
            alice.diffie_hellman(&bob.public_key()).unwrap().as_bytes(),
            &shared
        );
        assert_eq!(
            bob.diffie_hellman(&alice.public_key()).unwrap().as_bytes(),
            &shared
        );
    }

    #[test]
    fn low_order_points_are_rejected() {
        // u = 0 has order 1 and u = 1 has order 4: every clamped scalar kills them.
        let key = SecretKey::from_bytes([0x42; 32]);
        let mut one = [0_u8; 32];
        one[0] = 1;
        for u in [[0; 32], one] {
            assert_eq!(
                key.diffie_hellman(&PublicKey::from_bytes(u)).unwrap_err(),
                X25519Error::LowOrderPoint
            );
        }

        // p - 1 has order 2, encoded as ec ff .. ff 7f.
        let mut minus_one = [0xff_u8; 32];
        minus_one[0] = 0xec;
        minus_one[31] = 0x7f;
        assert!(
            key.diffie_hellman(&PublicKey::from_bytes(minus_one))
                .is_err()
        );
    }

    #[test]
    fn clamped_bits_do_not_matter() {
        // Scalars differing only in the clamped bits 0, 1, 2, 254, 255 give the same key.
        let mut a = [0x5a_u8; 32];
        let mut b = a;
        a[0] |= 0b111;
        b[0] &= !0b111;
        a[31] = 0xff;
        b[31] = 0x3f;
        assert_eq!(
            SecretKey::from_bytes(a).public_key(),
            SecretKey::from_bytes(b).public_key()
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn exchange_is_symmetric(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
            // Law: a (b G) = b (a G).
            let (a, b) = (SecretKey::from_bytes(a), SecretKey::from_bytes(b));
            let ab = a.diffie_hellman(&b.public_key()).unwrap();
            let ba = b.diffie_hellman(&a.public_key()).unwrap();
            prop_assert_eq!(ab.as_bytes(), ba.as_bytes());
        }
    }
}
