//! The SHAKE extendable-output functions of FIPS 202, section 6.2.

use crate::keccak::{KeccakF1600, sponge::Sponge};

/// The SHAKE domain byte: the suffix bits 1111, then the first pad bit.
const DOMAIN: u8 = 0x1f;

/// An incremental SHAKE absorber with a RATE-byte rate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shake<const RATE: usize> {
    /// The absorbing sponge.
    sponge: Sponge<RATE>,
}

/// SHAKE128: 168 bytes of rate, 128-bit security.
pub type Shake128 = Shake<168>;

/// SHAKE256: 136 bytes of rate, 256-bit security.
pub type Shake256 = Shake<136>;

impl<const RATE: usize> Shake<RATE> {
    /// An absorber over no bytes yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sponge: Sponge::new(),
        }
    }

    /// Feeds more bytes.
    pub fn update(&mut self, data: &[u8]) {
        self.sponge.absorb(data);
    }

    /// Pads and switches to squeezing an output stream of any length.
    #[must_use]
    pub fn finalize_xof(self) -> ShakeReader<RATE> {
        ShakeReader {
            state: self.sponge.pad(DOMAIN),
            block: [0; RATE],
            position: RATE,
        }
    }

    /// The first bytes of the output stream of one byte string.
    pub fn digest_into(data: &[u8], out: &mut [u8]) {
        let mut shake = Self::new();
        shake.update(data);
        shake.finalize_xof().read(out);
    }
}

impl<const RATE: usize> Default for Shake<RATE> {
    fn default() -> Self {
        Self::new()
    }
}

/// The squeezing phase of SHAKE: an endless stream read in any pieces.
///
/// # Invariants
///
/// The block holds the current squeezed block, and position bytes of it are already read.
/// A position equal to the rate means the next read permutes first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShakeReader<const RATE: usize> {
    /// The permutation state after the last squeezed block.
    state: KeccakF1600,
    /// The current squeezed block.
    block: [u8; RATE],
    /// Bytes of the block already read.
    position: usize,
}

impl<const RATE: usize> ShakeReader<RATE> {
    /// Fills the buffer with the next bytes of the stream.
    pub fn read(&mut self, mut out: &mut [u8]) {
        while !out.is_empty() {
            if self.position == RATE {
                // The first block comes straight from padding.
                // Every later block needs one more permutation.
                self.state.extract(&mut self.block);
                self.state.permute();
                self.position = 0;
            }
            let take = (RATE - self.position).min(out.len());
            out[..take].copy_from_slice(&self.block[self.position..self.position + take]);
            self.position += take;
            out = &mut out[take..];
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Decodes a hex string in a test vector.
    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn empty_message() {
        // The FIPS 202 examples for the empty string.
        let mut out = [0; 32];
        Shake128::digest_into(b"", &mut out);
        assert_eq!(
            out.to_vec(),
            hex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
        );
        let mut out = [0; 64];
        Shake256::digest_into(b"", &mut out);
        assert_eq!(
            out.to_vec(),
            hex(
                "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f\
                 d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
            )
        );
    }

    proptest! {
        #[test]
        fn reading_in_pieces_reads_the_same_stream(
            data in prop::collection::vec(any::<u8>(), 0..200),
            cuts in prop::collection::vec(0_usize..400, 0..6),
        ) {
            // Fixture state: 600 bytes span four 168-byte blocks.
            let mut whole = [0; 600];
            Shake128::digest_into(&data, &mut whole);

            // Reading the same stream in arbitrary pieces gives the same bytes.
            let mut points = cuts;
            points.sort_unstable();
            let mut reader = {
                let mut shake = Shake128::new();
                shake.update(&data);
                shake.finalize_xof()
            };
            let mut pieces = [0; 600];
            let mut start = 0;
            for point in points {
                reader.read(&mut pieces[start..point.max(start)]);
                start = point.max(start);
            }
            reader.read(&mut pieces[start..]);
            prop_assert_eq!(pieces, whole);
        }
    }
}
