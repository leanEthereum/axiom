//! The pseudorandom function that expands one secret key into every chain start and every signing nonce.
//!
//! # Overview
//!
//! The PRF is SHAKE128 over a domain separator, a kind byte, the key, and the inputs.
//! Each output field element takes 16 bytes of the stream, read as a big-endian integer modulo p.
//!
//! ```text
//! chain start : SHAKE128(SEP || 0x00 || key || epoch_be32 || chain_be64)
//! randomness  : SHAKE128(SEP || 0x01 || key || epoch_be32 || message || counter_be64)
//! ```
//!
//! A 128-bit integer modulo a 31-bit p is within 2^-97 of uniform.
//! Deriving the nonce from the message makes signing deterministic: signing twice gives one signature.

use axiom_crypto::keccak::Shake128;

use crate::{
    entropy::Entropy,
    field::KoalaBear,
    words::{Digest, Randomness, Words},
};

/// Bytes of a PRF key.
pub(crate) const PRF_KEY_LEN: usize = 32;

/// Stream bytes per output field element.
const BYTES_PER_ELEMENT: usize = 16;

/// The PRF's domain separator.
const DOMAIN_SEPARATOR: [u8; 16] = [
    0xae, 0xae, 0x22, 0xff, 0x00, 0x01, 0xfa, 0xff, 0x21, 0xaf, 0x12, 0x00, 0x01, 0x11, 0xff, 0x00,
];

/// The kind byte of chain starts.
const CHAIN_START: u8 = 0x00;

/// The kind byte of encoding randomness.
const RANDOMNESS: u8 = 0x01;

/// The secret PRF key, from which every one-time secret key derives.
///
/// The bytes are overwritten with zeros when the key drops.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PrfKey([u8; PRF_KEY_LEN]);

impl PrfKey {
    /// A uniform key drawn from entropy, one byte per word.
    pub(crate) fn sample(entropy: &mut impl Entropy) -> Self {
        Self(std::array::from_fn(|_| entropy.byte()))
    }

    /// The key of stored bytes.
    pub(crate) const fn from_bytes(bytes: [u8; PRF_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// The key's bytes, for storage.
    pub(crate) const fn as_bytes(&self) -> &[u8; PRF_KEY_LEN] {
        &self.0
    }

    /// The secret start of one chain of one epoch's one-time key.
    pub(crate) fn chain_start(&self, epoch: u32, chain: u64, len: usize) -> Digest {
        let mut shake = self.absorb(CHAIN_START, epoch);
        shake.update(&chain.to_be_bytes());
        Self::squeeze(shake, len)
    }

    /// The randomness of one encoding attempt of a message at an epoch.
    pub(crate) fn randomness(
        &self,
        epoch: u32,
        message: &[u8; 32],
        counter: u64,
        len: usize,
    ) -> Randomness {
        let mut shake = self.absorb(RANDOMNESS, epoch);
        shake.update(message);
        shake.update(&counter.to_be_bytes());
        Self::squeeze(shake, len)
    }

    /// The shared prefix: separator, kind, key, and epoch.
    fn absorb(&self, kind: u8, epoch: u32) -> Shake128 {
        let mut shake = Shake128::new();
        shake.update(&DOMAIN_SEPARATOR);
        shake.update(&[kind]);
        shake.update(&self.0);
        shake.update(&epoch.to_be_bytes());
        shake
    }

    /// Field elements from the output stream, 16 big-endian bytes each.
    fn squeeze<const CAP: usize>(shake: Shake128, len: usize) -> Words<CAP> {
        let mut reader = shake.finalize_xof();
        Words::from_fn(len, |_| {
            let mut bytes = [0; BYTES_PER_ELEMENT];
            reader.read(&mut bytes);
            // The reduction is a fixed sequence of multiplies, so the secret stream never meets a division.
            KoalaBear::from_u128(u128::from_be_bytes(bytes))
        })
    }
}

impl Drop for PrfKey {
    fn drop(&mut self) {
        // The barrier keeps the compiler from dropping the store as dead.
        self.0 = [0; PRF_KEY_LEN];
        std::hint::black_box(&self.0);
    }
}

impl std::fmt::Debug for PrfKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrfKey(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical values of some words.
    fn canonical<const CAP: usize>(words: &Words<CAP>) -> Vec<u32> {
        words.elements().iter().map(|e| e.to_canonical()).collect()
    }

    #[test]
    fn chain_starts() {
        // Fixture state: the key 0x00, 0x01, ..., 0x1f.
        let key = PrfKey::from_bytes(std::array::from_fn(|i| i as u8));

        // Eight elements extend the seven-element output: the stream is the same.
        let expected = [
            1_617_529_907,
            484_813_519,
            1_391_994_054,
            2_116_114_443,
            1_310_920_627,
            1_623_946_583,
            874_772_112,
            780_793_951,
        ];
        assert_eq!(canonical(&key.chain_start(0, 0, 7)), expected[..7]);
        assert_eq!(canonical(&key.chain_start(0, 0, 8)), expected);

        // The largest epoch.
        assert_eq!(
            canonical(&key.chain_start(u32::MAX, 45, 7)),
            [
                908_512_734,
                895_610_457,
                471_822_218,
                706_449_615,
                1_050_789_000,
                1_994_673_693,
                1_612_951_017
            ]
        );
    }

    #[test]
    fn randomness() {
        // Fixture state: the same key, message bytes 0xa0, 0xa1, ..., 0xbf.
        let key = PrfKey::from_bytes(std::array::from_fn(|i| i as u8));
        let message: [u8; 32] = std::array::from_fn(|i| 0xa0 + i as u8);
        assert_eq!(
            canonical(&key.randomness(7, &message, 3, 7)),
            [
                724_965_459,
                1_668_632_232,
                433_160_905,
                1_005_497_235,
                2_112_254_166,
                2_100_336_779,
                1_826_413_386
            ]
        );
        assert_eq!(
            canonical(&key.randomness(0, &message, 0, 6)),
            [
                2_022_512_418,
                430_306_057,
                859_112_437,
                113_661_395,
                1_210_433_093,
                2_084_700_888
            ]
        );
    }
}
