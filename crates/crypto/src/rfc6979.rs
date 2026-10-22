//! Deterministic ECDSA nonces from HMAC-SHA256, per RFC 6979, section 3.2.
//!
//! Every curve here has a 256-bit order and signs 256-bit hashes, so one generator serves all.

use crate::{ct::wipe, hmac::HmacSha256};

/// The HMAC-DRBG state that turns a key and a message into a stream of nonce candidates.
///
/// # Overview
///
/// The nonce is a pseudorandom function of the secret key and the message hash.
/// It never repeats across messages and never needs a random number generator.
///
/// ```text
/// V = 0x01 * 32, K = 0x00 * 32
/// K = HMAC_K(V || 0x00 || x || h),  V = HMAC_K(V)
/// K = HMAC_K(V || 0x01 || x || h),  V = HMAC_K(V)
/// loop: V = HMAC_K(V); accept V if 1 <= V < n
///       else K = HMAC_K(V || 0x00), V = HMAC_K(V)
/// ```
///
/// With a 256-bit order and a 256-bit hash, bits2int is the identity on 32 bytes.
/// The curve decides which candidates are in range, so the generator never names a scalar type.
pub(crate) struct NonceGenerator {
    /// The HMAC key K.
    key: [u8; 32],
    /// The chaining value V.
    value: [u8; 32],
    /// Whether a candidate was already handed out, so the next one needs the retry update.
    started: bool,
}

impl NonceGenerator {
    /// Seeds the generator with the secret key and the reduced message hash.
    ///
    /// Both inputs are 32-byte big-endian integers modulo n: int2octets and bits2octets of the RFC.
    pub(crate) fn new(secret: &[u8; 32], message: &[u8; 32]) -> Self {
        // Step b and c of RFC 6979, section 3.2: V = 0x01 * 32, K = 0x00 * 32.
        let mut generator = Self {
            key: [0; 32],
            value: [1; 32],
            started: false,
        };

        // Steps d to g of RFC 6979, section 3.2: reseed twice, with separators 0 and 1.
        for separator in [0x00, 0x01] {
            let mut mac = HmacSha256::new(&generator.key);
            mac.update(&generator.value);
            mac.update(&[separator]);
            mac.update(secret);
            mac.update(message);
            generator.key = mac.finalize();
            generator.value = HmacSha256::mac(&generator.key, &generator.value);
        }
        generator
    }

    /// The next candidate the curve accepts, decoded by it.
    ///
    /// The decoder returns a nonce for a candidate in [1, n), and nothing otherwise.
    /// A signer calls again when the nonce gives r = 0 or s = 0, which RFC 6979 also covers.
    pub(crate) fn next_nonce<S>(&mut self, decode: impl Fn(&[u8; 32]) -> Option<S>) -> S {
        loop {
            // Step h.3 of RFC 6979: after any rejected candidate, stir K and V.
            if self.started {
                let mut mac = HmacSha256::new(&self.key);
                mac.update(&self.value);
                mac.update(&[0x00]);
                self.key = mac.finalize();
                self.value = HmacSha256::mac(&self.key, &self.value);
            }
            self.started = true;

            // Step h.2: one HMAC output fills the 256-bit candidate.
            self.value = HmacSha256::mac(&self.key, &self.value);

            // Timing: for a 256-bit order a refusal is rare, and whether it happened is not secret.
            if let Some(nonce) = decode(&self.value) {
                return nonce;
            }
        }
    }
}

impl Drop for NonceGenerator {
    fn drop(&mut self) {
        // K and V determine every nonce, which in turn reveals the key.
        wipe(&mut self.key);
        wipe(&mut self.value);
    }
}

#[cfg(test)]
mod tests {
    use std::array;

    use super::*;

    /// Decodes a 32-byte hex string in a test vector.
    fn hex(text: &str) -> [u8; 32] {
        array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
    }

    /// Takes every candidate as it comes, which holds for these vectors' first candidates.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "it has the shape of a curve's decoder"
    )]
    fn accept_all(candidate: &[u8; 32]) -> Option<[u8; 32]> {
        Some(*candidate)
    }

    #[test]
    fn nonces_of_the_well_known_secp256k1_vectors() {
        // The secp256k1 RFC 6979 vectors used by Bitcoin and Ethereum libraries.
        // Each hash is SHA-256 of the quoted message.
        //
        //     x = 1,     "Satoshi Nakamoto"
        //     x = 1,     "All those moments will be lost in time, ..."
        //     x = n - 1, "Satoshi Nakamoto"
        let one = hex("0000000000000000000000000000000000000000000000000000000000000001");
        let n_minus_one = hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
        let satoshi = hex("a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e");
        let tears = hex("7d1833f54854ac51659521afcd0ec6dca2ce2351429614bfa28a756b1b3c637f");
        let cases = [
            (
                one,
                satoshi,
                "8f8a276c19f4149656b280621e358cce24f5f52542772691ee69063b74f15d15",
            ),
            (
                one,
                tears,
                "38aa22d72376b4dbc472e06c3ba403ee0a394da63fc58d88686c611aba98d6b3",
            ),
            (
                n_minus_one,
                satoshi,
                "33a19b60e25fb6f4435af53a3d42d493644827367e6453928554f43e49aa6f90",
            ),
        ];
        for (secret, message, nonce) in cases {
            let mut generator = NonceGenerator::new(&secret, &message);
            assert_eq!(generator.next_nonce(accept_all), hex(nonce));
        }
    }

    #[test]
    fn nonces_of_the_p256_vectors() {
        // RFC 6979, appendix A.2.5: NIST P-256 with SHA-256.
        // Both hashes are below n, so reduction leaves them unchanged.
        //
        //     SHA-256("sample") = af2bdbe1...
        //     SHA-256("test")   = 9f86d081...
        let secret = hex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let cases = [
            (
                "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
                "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60",
            ),
            (
                "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                "d16b6ae827f17175e040871a1c7ec3500192c4c92677336ec2537acaee0008e0",
            ),
        ];
        for (message, nonce) in cases {
            let mut generator = NonceGenerator::new(&secret, &hex(message));
            assert_eq!(generator.next_nonce(accept_all), hex(nonce));
        }
    }

    #[test]
    fn rejected_candidates_are_skipped() {
        // A decoder that refuses the first candidate receives the second one.
        let mut reference = NonceGenerator::new(&[1; 32], &[2; 32]);
        let first = reference.next_nonce(accept_all);
        let second = reference.next_nonce(accept_all);
        let mut generator = NonceGenerator::new(&[1; 32], &[2; 32]);
        let nonce = generator.next_nonce(|candidate| (*candidate != first).then_some(*candidate));
        assert_eq!(nonce, second);
    }

    #[test]
    fn retries_continue_the_stream() {
        // A second candidate differs from the first and is again in range.
        let mut generator = NonceGenerator::new(&[1; 32], &[2; 32]);
        let first = generator.next_nonce(accept_all);
        let second = generator.next_nonce(accept_all);
        assert_ne!(first, second);

        // The stream is deterministic: a fresh generator repeats it.
        let mut again = NonceGenerator::new(&[1; 32], &[2; 32]);
        assert_eq!(again.next_nonce(accept_all), first);
        assert_eq!(again.next_nonce(accept_all), second);
    }
}
