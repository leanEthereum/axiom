//! Keccak-256, the hash Ethereum uses for addresses and node identities.
//!
//! # Overview
//!
//! Keccak-256 is the sponge from the Keccak submission to the SHA-3 competition.
//! It differs from the standardized SHA3-256 of FIPS 202 in one byte only.
//!
//! ```text
//! Keccak-256 : message || 0x01 || 0x00 ... 0x00 || 0x80
//! SHA3-256   : message || 0x06 || 0x00 ... 0x00 || 0x80
//! ```
//!
//! Ethereum fixed its hash before FIPS 202 added the two domain bits, so it keeps the 0x01 pad.

use crate::keccak::sponge::Sponge;

/// Bytes absorbed per permutation for a 256-bit output.
///
/// The capacity is twice the output, 512 bits, which leaves 1600 - 512 = 1088 bits of rate.
const RATE: usize = 136;

/// The domain byte of the original Keccak padding: the first pad bit alone.
const DOMAIN: u8 = 0x01;

/// An incremental Keccak-256 hasher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Keccak256 {
    /// The absorbing sponge.
    sponge: Sponge<RATE>,
}

impl Keccak256 {
    /// Bytes in a digest.
    pub const OUTPUT_LEN: usize = 32;

    /// A hasher over no bytes yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sponge: Sponge::new(),
        }
    }

    /// The digest of one byte string.
    #[must_use]
    pub fn digest(data: &[u8]) -> [u8; Self::OUTPUT_LEN] {
        // One-shot form of new, update, finalize.
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }

    /// Feeds more bytes.
    pub fn update(&mut self, data: &[u8]) {
        self.sponge.absorb(data);
    }

    /// Pads, squeezes, and returns the digest.
    #[must_use]
    pub fn finalize(self) -> [u8; Self::OUTPUT_LEN] {
        // Squeeze: 32 bytes fit in the first four lanes, so one permutation suffices.
        let mut digest = [0_u8; Self::OUTPUT_LEN];
        self.sponge.pad(DOMAIN).extract(&mut digest);
        digest
    }
}

impl Default for Keccak256 {
    fn default() -> Self {
        Self::new()
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
    fn short_message_vectors() {
        // The empty string: the hash of an empty account's code in Ethereum.
        assert_eq!(
            Keccak256::digest(b"").to_vec(),
            hex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        );
        assert_eq!(
            Keccak256::digest(b"abc").to_vec(),
            hex("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
        );
        assert_eq!(
            Keccak256::digest(b"The quick brown fox jumps over the lazy dog").to_vec(),
            hex("4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15")
        );
    }

    #[test]
    fn long_message_vectors() {
        // The 1600-bit message of 200 bytes 0xa3 from the SHA-3 examples: two blocks.
        assert_eq!(
            Keccak256::digest(&[0xa3; 200]).to_vec(),
            hex("3a57666b048777f2c953dc4456f45a2588e1cb6f2da760122d530ac2ce607d4a")
        );

        // One million ASCII "a": 7353 blocks and a 72-byte tail.
        assert_eq!(
            Keccak256::digest(&vec![b'a'; 1_000_000]).to_vec(),
            hex("fadae6b49f129bbb812be8407b7b2894f34aecf6dbd1f9b0f0c7e9853098fc96")
        );
    }

    #[test]
    fn padding_at_every_block_boundary() {
        // Messages of bytes i mod 251 around the 136-byte rate.
        //
        //     135 : pad fits in one byte, 0x81
        //     136 : a whole extra block of padding
        //     137 : one byte spills into a second block
        //     271, 272 : the same edges one block later
        let vectors: [(usize, &str); 5] = [
            (
                135,
                "cbdfd9dee5faad3818d6b06f95a219fd290b0e1706f6a82e5a595b9ce9faca62",
            ),
            (
                136,
                "7ce759f1ab7f9ce437719970c26b0a66ff11fe3e38e17df89cf5d29c7d7f807e",
            ),
            (
                137,
                "ac73d4fae68b8453f764007c1a20ce95994187861f0c3227a3a8e99a73a3b1db",
            ),
            (
                271,
                "27eceb59ebc3dc8a04a5b135be641591a7278540e4556a2ba9f408194e666ec3",
            ),
            (
                272,
                "8e2476e65823b24d96ebe239f2c1534cdf763e689e2410c3b1cb0c74e6177bfc",
            ),
        ];
        for (len, expected) in vectors {
            let message: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            assert_eq!(
                Keccak256::digest(&message).to_vec(),
                hex(expected),
                "length {len}"
            );
        }
    }

    proptest! {
        #[test]
        fn pieces_hash_like_the_whole(
            data in prop::collection::vec(any::<u8>(), 0..600),
            cuts in prop::collection::vec(any::<prop::sample::Index>(), 0..4),
        ) {
            // Feeding the bytes in arbitrary pieces gives the one-shot digest.
            let mut points: Vec<usize> = cuts.iter().map(|c| c.index(data.len() + 1)).collect();
            points.sort_unstable();
            let mut hasher = Keccak256::new();
            let mut start = 0;
            for point in points {
                hasher.update(&data[start..point]);
                start = point;
            }
            hasher.update(&data[start..]);
            prop_assert_eq!(hasher.finalize(), Keccak256::digest(&data));
        }
    }
}
