//! The randomness key generation consumes, and a seeded stream of it.

use axiom_crypto::keccak::{Shake128, ShakeReader};

use crate::field::KoalaBear;

/// A source of uniform 32-bit words for key generation.
///
/// The operating system's generator backs it in a node.
/// A seeded stream backs it in tests, simulations, and keys derived from a seed.
pub trait Entropy {
    /// The next uniform word.
    fn next_u32(&mut self) -> u32;

    /// A uniform field element.
    ///
    /// # Algorithm
    ///
    /// Rejection sampling: drop the low bit, and retry until the 31-bit word is below p.
    /// The accepted word is taken as a Montgomery form, which is uniform since the map is a bijection.
    /// A retry happens with probability 2^24 / 2^31 = 1/128 and reveals only the dropped word.
    fn element(&mut self) -> KoalaBear {
        loop {
            if let Some(element) = KoalaBear::from_montgomery(self.next_u32() >> 1) {
                return element;
            }
        }
    }

    /// A uniform byte, the low byte of a word.
    fn byte(&mut self) -> u8 {
        self.next_u32() as u8
    }
}

/// A deterministic word stream: SHAKE128 of a seed, read four bytes at a time.
///
/// The seed must carry at least 128 bits of entropy for the keys it derives to be secure.
#[derive(Clone, Debug)]
pub struct SeedStream {
    /// The squeezing SHAKE128 state.
    reader: ShakeReader<168>,
}

impl SeedStream {
    /// The stream of a seed.
    #[must_use]
    pub fn new(seed: &[u8]) -> Self {
        let mut shake = Shake128::new();
        shake.update(seed);
        Self {
            reader: shake.finalize_xof(),
        }
    }
}

impl Entropy for SeedStream {
    fn next_u32(&mut self) -> u32 {
        let mut word = [0; 4];
        self.reader.read(&mut word);
        u32::from_le_bytes(word)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sampling_from_a_seeded_stream() {
        // Fixture state: the stream of the seed "sampling".
        // Five field elements, then a 32-byte key of one byte per word.
        let mut stream = SeedStream::new(b"sampling");
        let elements: Vec<u32> = (0..5).map(|_| stream.element().to_canonical()).collect();
        let key: Vec<u8> = (0..32).map(|_| stream.byte()).collect();
        assert_eq!(
            elements,
            [
                452_731_200,
                1_326_041_309,
                430_925_779,
                347_473_805,
                2_055_814_933
            ]
        );
        assert_eq!(
            key,
            [
                0x2e, 0x62, 0x4a, 0xdd, 0x65, 0x2a, 0x35, 0x94, 0x65, 0xf1, 0xa2, 0xe2, 0x99, 0xca,
                0xd3, 0x14, 0x96, 0x94, 0xca, 0xa6, 0xac, 0x8f, 0xe8, 0xc5, 0x68, 0x29, 0x15, 0x3d,
                0x56, 0x7a, 0x22, 0x1d
            ]
        );
    }

    #[test]
    fn rejected_words_are_skipped() {
        /// Words handed out in order.
        struct Script(Vec<u32>);
        impl Entropy for Script {
            fn next_u32(&mut self) -> u32 {
                self.0.remove(0)
            }
        }

        // Words whose top 31 bits are p and 2^31 - 1 are rejected; p - 1 is accepted.
        let p = KoalaBear::ORDER;
        let mut script = Script(vec![p << 1, u32::MAX, (p - 1) << 1]);
        assert_eq!(script.element(), KoalaBear::from_montgomery(p - 1).unwrap());
        assert_eq!(script.0, Vec::<u32>::new());
    }
}
