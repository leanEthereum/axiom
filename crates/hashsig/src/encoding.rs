//! The incomparable encoding: a message, an epoch and randomness to a codeword of chain positions.
//!
//! # Overview
//!
//! A codeword x = (x_1, ..., x_v) has entries in [0, w).
//! The signer reveals position x_i of chain i, and the verifier walks the rest of each chain.
//!
//! The encoding is incomparable: no two codewords satisfy x_i >= x'_i for every i.
//! Otherwise a signature for x would let anyone walk forward to a signature for x'.
//! A fixed coordinate sum T achieves this, since raising any entry raises the sum.
//!
//! ```text
//! C = { x in [0, w)^v : sum_i x_i = T }
//! ```
//!
//! A hash that misses the target is retried with fresh randomness by the signer.
//!
//! eprint 2025/055, construction 6, defines the target-sum encoding.

use crate::{
    error::EncodingError,
    field::KoalaBear,
    poseidon::POSEIDON1_24,
    tweak_hash::{TWEAK_LEN, Tweak},
    words::{PARAMETER_LEN, PublicParameter, Randomness},
};

/// Bytes of a signed message: a 32-byte signing root.
pub const MESSAGE_LEN: usize = 32;

/// Field elements of an encoded message: 9 base-p digits hold 256 bits, since 9 * 30 >= 256.
const MESSAGE_ELEMENTS: usize = 9;

/// How the message hash's field elements become codeword chunks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum MessageHash {
    /// The output elements form one base-p integer, written in base w.
    ///
    /// The base must be a power of two, so the digits are bit fields.
    BaseP {
        /// Field elements of hash output.
        output_len: usize,
    },
    /// Each output element below Q * w^z yields z base-w digits, and any other aborts.
    ///
    /// With p = Q * w^z + alpha, an element aborts with probability alpha / p.
    /// For KoalaBear, Q = 127, w = 8, z = 8 leave alpha = 1, so an abort has probability 2^-31.
    ///
    /// eprint 2026/016, section 6.1, shows the result is indifferentiable from an aborting random oracle.
    Aborting {
        /// Field elements of hash output.
        output_len: usize,
        /// Digits z per element.
        digits_per_element: usize,
        /// The quotient Q.
        quotient: u32,
    },
}

impl MessageHash {
    /// Field elements of hash output.
    pub(crate) const fn output_len(self) -> usize {
        match self {
            Self::BaseP { output_len } | Self::Aborting { output_len, .. } => output_len,
        }
    }

    /// The codeword chunks of a message, before the target-sum filter.
    pub(crate) fn chunks(
        self,
        shape: Shape,
        parameter: &PublicParameter,
        epoch: u32,
        randomness: &Randomness,
        message: &[u8; MESSAGE_LEN],
    ) -> Result<Vec<u8>, EncodingError> {
        let output = self.evaluate(parameter, epoch, randomness, message);
        match self {
            Self::BaseP { .. } => Ok(Self::base_p_chunks(shape, &output)),
            Self::Aborting {
                digits_per_element,
                quotient,
                ..
            } => Self::hypercube_chunks(shape, &output, digits_per_element, quotient),
        }
    }

    /// The hash: PoseidonCompress_24(message || parameter || tweak || randomness), truncated.
    fn evaluate(
        self,
        parameter: &PublicParameter,
        epoch: u32,
        randomness: &Randomness,
        message: &[u8; MESSAGE_LEN],
    ) -> Vec<KoalaBear> {
        // Layout: 9 + 5 + 2 + 6 or 7 of 24 words, the rest zero.
        let mut input = [KoalaBear::ZERO; 24];
        let mut at = 0;
        for chunk in [
            &message_elements(message)[..],
            &parameter.0[..],
            &Tweak::Message { epoch }.elements()[..],
            randomness.elements(),
        ] {
            input[at..at + chunk.len()].copy_from_slice(chunk);
            at += chunk.len();
        }
        debug_assert_eq!(
            at,
            MESSAGE_ELEMENTS + PARAMETER_LEN + TWEAK_LEN + randomness.elements().len()
        );
        let output: [KoalaBear; 24] = POSEIDON1_24.compress(&input);
        output[..self.output_len()].to_vec()
    }

    /// Base-w digits of the output read as one integer, most significant element first.
    ///
    /// # Algorithm
    ///
    /// ```text
    /// n = sum_i a_i * p^(l - 1 - i)
    /// x_j = floor(n / w^j) mod w, for j in [0, v)
    /// ```
    ///
    /// With w = 2^b the digit x_j is bits [j * b, (j + 1) * b) of n.
    fn base_p_chunks(shape: Shape, output: &[KoalaBear]) -> Vec<u8> {
        let mut integer = WideInt::ZERO;
        for element in output {
            integer.mul_add(
                u64::from(KoalaBear::ORDER),
                u64::from(element.to_canonical()),
            );
        }
        let bits = shape.base.trailing_zeros();
        (0..shape.dimension as u32)
            .map(|j| integer.bits(j * bits, bits) as u8)
            .collect()
    }

    /// Base-w digits of each element's quotient by Q, or an abort.
    ///
    /// ```text
    /// a_i >= Q * w^z  : abort
    /// d_i = floor(a_i / Q), written as z base-w digits, least significant first
    /// ```
    fn hypercube_chunks(
        shape: Shape,
        output: &[KoalaBear],
        digits_per_element: usize,
        quotient: u32,
    ) -> Result<Vec<u8>, EncodingError> {
        let base = shape.base as u64;
        let bound = u64::from(quotient) * base.pow(digits_per_element as u32);
        let mut chunks = Vec::with_capacity(shape.dimension);
        for (index, element) in output.iter().enumerate() {
            if chunks.len() == shape.dimension {
                break;
            }
            // The hash output is public: it is recomputed from the signature.
            let value = u64::from(element.to_canonical());
            if value >= bound {
                return Err(EncodingError::Aborted { index });
            }
            let mut digits = value / u64::from(quotient);
            let take = digits_per_element.min(shape.dimension - chunks.len());
            for _ in 0..take {
                chunks.push((digits % base) as u8);
                digits /= base;
            }
        }
        Ok(chunks)
    }
}

/// The shape of a codeword: v chunks in base w, summing to T.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Shape {
    /// Chunks v, one per chain.
    pub(crate) dimension: usize,
    /// Base w, the chain length.
    pub(crate) base: usize,
    /// Target sum T.
    pub(crate) target_sum: usize,
}

impl Shape {
    /// Keeps chunks that hit the target sum.
    pub(crate) fn filter(self, chunks: Vec<u8>) -> Result<Vec<u8>, EncodingError> {
        let sum: usize = chunks.iter().map(|&chunk| usize::from(chunk)).sum();
        if sum == self.target_sum {
            Ok(chunks)
        } else {
            Err(EncodingError::SumMismatch {
                expected: self.target_sum,
                actual: sum,
            })
        }
    }
}

/// The message as base-p digits of its little-endian integer, least significant first.
fn message_elements(message: &[u8; MESSAGE_LEN]) -> [KoalaBear; MESSAGE_ELEMENTS] {
    let mut integer = WideInt::ZERO;
    for (limb, bytes) in integer.0.iter_mut().zip(message.as_chunks::<8>().0) {
        *limb = u64::from_le_bytes(*bytes);
    }
    std::array::from_fn(|_| KoalaBear::new(integer.div_rem(u64::from(KoalaBear::ORDER)) as u32))
}

/// A 256-bit unsigned integer in little-endian 64-bit limbs, for public data only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WideInt([u64; 4]);

impl WideInt {
    /// Zero.
    const ZERO: Self = Self([0; 4]);

    /// self = self * factor + addend, dropping overflow past 256 bits.
    fn mul_add(&mut self, factor: u64, addend: u64) {
        let mut carry = u128::from(addend);
        for limb in &mut self.0 {
            let wide = u128::from(*limb) * u128::from(factor) + carry;
            *limb = wide as u64;
            carry = wide >> 64;
        }
    }

    /// Divides in place by a small divisor and returns the remainder.
    fn div_rem(&mut self, divisor: u64) -> u64 {
        let mut remainder = 0_u128;
        for limb in self.0.iter_mut().rev() {
            let wide = (remainder << 64) | u128::from(*limb);
            *limb = (wide / u128::from(divisor)) as u64;
            remainder = wide % u128::from(divisor);
        }
        remainder as u64
    }

    /// Bits [start, start + count) as a word, for a count of at most 8.
    fn bits(&self, start: u32, count: u32) -> u64 {
        let wide = (u128::from(self.0[(start / 64) as usize]))
            | (u128::from(*self.0.get((start / 64) as usize + 1).unwrap_or(&0)) << 64);
        ((wide >> (start % 64)) as u64) & ((1 << count) - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{entropy::SeedStream, words::Words};

    /// The fixture of the message hash known answers: a parameter and a message from a stream.
    fn fixture() -> (SeedStream, PublicParameter, [u8; 32]) {
        let mut stream = SeedStream::new(b"message-hash");
        let parameter = PublicParameter::sample(&mut stream);
        let message = std::array::from_fn(|_| crate::entropy::Entropy::byte(&mut stream));
        (stream, parameter, message)
    }

    /// The four base-p shapes: chunk sizes 1, 2, 4 and 8 bits.
    const SHAPES: [Shape; 4] = [
        Shape {
            dimension: 155,
            base: 2,
            target_sum: 78,
        },
        Shape {
            dimension: 78,
            base: 4,
            target_sum: 117,
        },
        Shape {
            dimension: 39,
            base: 16,
            target_sum: 293,
        },
        Shape {
            dimension: 20,
            base: 256,
            target_sum: 2550,
        },
    ];

    /// The hypercube shape of the lifetime 2^32 instantiation.
    const HYPERCUBE: Shape = Shape {
        dimension: 46,
        base: 8,
        target_sum: 200,
    };

    /// The hypercube message hash.
    const ABORTING: MessageHash = MessageHash::Aborting {
        output_len: 8,
        digits_per_element: 8,
        quotient: 127,
    };

    #[test]
    fn message_elements_are_base_p_digits() {
        // Fixture state: the message 2^256 - 1, so every digit is checked against plain division.
        let mut expected = WideInt([u64::MAX; 4]);
        let digits = message_elements(&[0xff; 32]);
        for digit in digits {
            assert_eq!(
                u64::from(digit.to_canonical()),
                expected.div_rem(u64::from(KoalaBear::ORDER))
            );
        }
        assert_eq!(expected, WideInt::ZERO);
    }

    #[test]
    fn known_answers_at_epoch_zero() {
        // Fixture state: the stream's parameter and message, then randomness of 6 and 7 elements.
        let (mut stream, parameter, message) = fixture();
        let rho6: Randomness = Words::sample(6, &mut stream);
        let base_p = MessageHash::BaseP { output_len: 5 };
        let chunks: Vec<Vec<u8>> = SHAPES
            .iter()
            .map(|&shape| {
                base_p
                    .chunks(shape, &parameter, 0, &rho6, &message)
                    .unwrap()
            })
            .collect();

        // The one-bit and four-bit chunks, and the sum the four-bit target filter rejects.
        assert_eq!(
            chunks[0][..32],
            [
                1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1,
                0, 1, 0, 1
            ]
        );
        assert_eq!(chunks[0].len(), 155);
        assert_eq!(
            SHAPES[2].filter(chunks[2].clone()),
            Err(EncodingError::SumMismatch {
                expected: 293,
                actual: 288
            })
        );

        let rho7: Randomness = Words::sample(7, &mut stream);
        assert_eq!(
            ABORTING.chunks(HYPERCUBE, &parameter, 0, &rho7, &message),
            Ok(vec![
                0, 0, 7, 5, 0, 0, 3, 2, 4, 5, 4, 5, 2, 7, 3, 2, 6, 3, 7, 3, 3, 6, 5, 3, 3, 0, 0, 4,
                1, 7, 5, 3, 2, 7, 0, 3, 6, 1, 7, 5, 6, 6, 6, 2, 1, 6
            ])
        );
    }

    #[test]
    fn hypercube_digits_and_abort() {
        // Fixture state: v = 10 digits from z = 8 per element, so the second element gives 2.
        let shape = Shape {
            dimension: 10,
            base: 8,
            target_sum: 0,
        };

        // a = 127 * (1 + 2 * 8 + 7 * 8^7) + 126: the remainder 126 is dropped.
        let first = 127 * (1 + 2 * 8 + 7 * 8_u32.pow(7)) + 126;
        // a = 127 * (8^8 - 1), the largest accepted value, gives eight digits of 7.
        let second = 127 * (8_u32.pow(8) - 1);
        let output = [first, second].map(KoalaBear::new);
        assert_eq!(
            MessageHash::hypercube_chunks(shape, &output, 8, 127),
            Ok(vec![1, 2, 0, 0, 0, 0, 0, 7, 7, 7])
        );

        // a = 127 * 8^8 = p - 1 is the one rejected value, since p = 127 * 8^8 + 1.
        let output = [KoalaBear::new(0), KoalaBear::new(KoalaBear::ORDER - 1)];
        assert_eq!(
            MessageHash::hypercube_chunks(shape, &output, 8, 127),
            Err(EncodingError::Aborted { index: 1 })
        );
    }

    #[test]
    fn target_sum_hits() {
        // Randomness the reference found to hit each target, at epochs 11 and 48.
        let (_, parameter, message) = fixture();
        let elements = |values: &[u32]| {
            Words::from_fn(values.len(), |i| {
                KoalaBear::from_canonical(values[i]).unwrap()
            })
        };
        let rho = elements(&[
            1_350_234_098,
            2_038_728_749,
            1_370_105_139,
            659_341_822,
            1_607_964_714,
            230_338_468,
        ]);
        let chunks = MessageHash::BaseP { output_len: 5 }
            .chunks(SHAPES[2], &parameter, 11, &rho, &message)
            .and_then(|chunks| SHAPES[2].filter(chunks));
        assert_eq!(
            chunks,
            Ok(vec![
                2, 12, 1, 9, 15, 6, 1, 3, 14, 10, 2, 13, 1, 0, 6, 13, 11, 12, 3, 7, 8, 15, 3, 8,
                12, 8, 4, 8, 5, 15, 13, 8, 12, 12, 9, 9, 0, 3, 0
            ])
        );

        let rho = elements(&[
            1_667_921_130,
            1_961_855_992,
            905_441_298,
            1_167_495_152,
            1_672_022_789,
            2_063_042_675,
            937_762_119,
        ]);
        let chunks = ABORTING
            .chunks(HYPERCUBE, &parameter, 48, &rho, &message)
            .and_then(|chunks| HYPERCUBE.filter(chunks));
        assert_eq!(
            chunks,
            Ok(vec![
                4, 3, 3, 2, 6, 4, 2, 0, 5, 7, 6, 0, 5, 2, 3, 7, 4, 5, 5, 7, 3, 7, 4, 5, 4, 5, 7, 3,
                0, 4, 5, 4, 7, 5, 6, 4, 6, 6, 6, 3, 3, 7, 6, 7, 2, 1
            ])
        );
    }
}
