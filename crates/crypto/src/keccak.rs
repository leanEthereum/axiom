//! Keccak-f\[1600\] and Keccak-256, the hash Ethereum uses for addresses and node identities.
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

/// Lanes of the permutation state, a 5 x 5 grid of 64-bit words.
const LANES: usize = 25;

/// Rounds of Keccak-f\[1600\]: 12 + 2 * log_2(64), per the Keccak reference, section 1.2.
const ROUNDS: usize = 24;

/// Bytes absorbed per permutation for a 256-bit output.
///
/// The capacity is twice the output, 512 bits, which leaves 1600 - 512 = 1088 bits of rate.
const RATE: usize = 136;

/// Round constants of the iota step, one per round.
///
/// Each one is the output of a degree-8 LFSR, per the Keccak reference, section 1.2.
const ROUND_CONSTANTS: [u64; ROUNDS] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Rotation amounts of the rho step, in the order the pi step visits the lanes.
///
/// Entry t is (t + 1)(t + 2) / 2 mod 64, per the Keccak reference, section 1.2.
const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// Lane visit order of the pi step, starting from lane 1.
///
/// Lane (x, y) at index x + 5y moves to (y, 2x + 3y), and the chain covers all 24 non-origin lanes.
const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// The 1600-bit Keccak state and its permutation.
///
/// Lane (x, y) sits at index x + 5y.
/// Bytes enter lanes in little-endian order, per FIPS 202, section 3.1.2.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeccakF1600 {
    /// The 25 lanes.
    lanes: [u64; LANES],
}

impl KeccakF1600 {
    /// The all-zero state.
    #[must_use]
    pub const fn new() -> Self {
        Self { lanes: [0; LANES] }
    }

    /// A state with the given lanes.
    #[must_use]
    pub const fn from_lanes(lanes: [u64; LANES]) -> Self {
        Self { lanes }
    }

    /// The lanes of the state.
    #[must_use]
    pub const fn lanes(&self) -> &[u64; LANES] {
        &self.lanes
    }

    /// Applies the 24-round permutation in place.
    ///
    /// # Algorithm
    ///
    /// Each round chains five steps, per the Keccak reference, section 1.2.
    ///
    /// ```text
    /// theta : each lane absorbs the parity of two neighbouring columns
    /// rho   : each lane rotates by its own fixed amount
    /// pi    : lanes move to new positions
    /// chi   : each row passes through the only non-linear map, a ^ (!b & c)
    /// iota  : lane (0, 0) absorbs the round constant
    /// ```
    pub fn permute(&mut self) {
        // Lanes in place, 24 rounds.
        let a = &mut self.lanes;
        for &round_constant in &ROUND_CONSTANTS {
            // Theta, phase 1: parity of each of the five columns.
            let mut parity = [0_u64; 5];
            for (x, column) in parity.iter_mut().enumerate() {
                *column = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            }

            // Theta, phase 2: lane (x, y) absorbs column x - 1 and column x + 1 rotated by one.
            for x in 0..5 {
                let d = parity[(x + 4) % 5] ^ parity[(x + 1) % 5].rotate_left(1);
                for y in 0..5 {
                    a[x + 5 * y] ^= d;
                }
            }

            // Rho and pi together: walk the pi cycle, rotating each lane as it moves.
            //
            //     lane 1 -> lane 10 (rotated by 1)
            //     lane 10 -> lane 7 (rotated by 3)
            //     ...
            //     lane 6 -> lane 1  (rotated by 44)
            let mut carried = a[1];
            for (&target, &rotation) in PI.iter().zip(&RHO) {
                let displaced = a[target];
                a[target] = carried.rotate_left(rotation);
                carried = displaced;
            }

            // Chi: each row of five lanes mixes non-linearly, from a copy of the row.
            for y in 0..5 {
                let row = [
                    a[5 * y],
                    a[5 * y + 1],
                    a[5 * y + 2],
                    a[5 * y + 3],
                    a[5 * y + 4],
                ];
                for x in 0..5 {
                    a[5 * y + x] = row[x] ^ (!row[(x + 1) % 5] & row[(x + 2) % 5]);
                }
            }

            // Iota: break the symmetry between rounds.
            a[0] ^= round_constant;
        }
    }

    /// XORs one rate-sized block into the leading lanes.
    fn absorb_block(&mut self, block: &[u8; RATE]) {
        // 17 little-endian words fill the 136-byte rate.
        // The 8 capacity lanes stay untouched.
        let (words, _) = block.as_chunks::<8>();
        for (lane, word) in self.lanes.iter_mut().zip(words) {
            *lane ^= u64::from_le_bytes(*word);
        }
    }
}

/// An incremental Keccak-256 hasher.
///
/// # Examples
///
/// ```
/// use axiom_crypto::keccak::Keccak256;
///
/// let mut hasher = Keccak256::new();
/// hasher.update(b"a");
/// hasher.update(b"bc");
/// assert_eq!(hasher.finalize(), Keccak256::digest(b"abc"));
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Keccak256 {
    /// The sponge state.
    state: KeccakF1600,
    /// Bytes of the current block not yet absorbed.
    buffer: [u8; RATE],
    /// How many bytes of the buffer are filled, always below the rate.
    filled: usize,
}

impl Keccak256 {
    /// Bytes in a digest.
    pub const OUTPUT_LEN: usize = 32;

    /// A hasher over no bytes yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: KeccakF1600::new(),
            buffer: [0; RATE],
            filled: 0,
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
    pub fn update(&mut self, mut data: &[u8]) {
        // Phase 1: top up a partly filled buffer.
        if self.filled > 0 {
            let take = (RATE - self.filled).min(data.len());
            self.buffer[self.filled..self.filled + take].copy_from_slice(&data[..take]);
            self.filled += take;
            data = &data[take..];
            if self.filled < RATE {
                return;
            }
            self.state.absorb_block(&self.buffer);
            self.state.permute();
            self.filled = 0;
        }

        // Phase 2: absorb whole blocks straight from the input.
        let (blocks, tail) = data.as_chunks::<RATE>();
        for block in blocks {
            self.state.absorb_block(block);
            self.state.permute();
        }

        // Phase 3: keep the tail for the next call.
        self.buffer[..tail.len()].copy_from_slice(tail);
        self.filled = tail.len();
    }

    /// Pads, squeezes, and returns the digest.
    #[must_use]
    pub fn finalize(mut self) -> [u8; Self::OUTPUT_LEN] {
        // Pad10*1 with the Keccak domain byte, per the Keccak reference, section 1.1.
        //
        //     [ tail ... | 0x01 | 0x00 ... 0x00 | 0x80 ]
        //
        // With one free byte the two pad bits share it: 0x01 | 0x80 = 0x81.
        self.buffer[self.filled..].fill(0);
        self.buffer[self.filled] ^= 0x01;
        self.buffer[RATE - 1] ^= 0x80;
        self.state.absorb_block(&self.buffer);
        self.state.permute();

        // Squeeze: 32 bytes fit in the first four lanes, so one permutation suffices.
        let mut digest = [0_u8; Self::OUTPUT_LEN];
        let (words, _) = digest.as_chunks_mut::<8>();
        for (word, lane) in words.iter_mut().zip(self.state.lanes()) {
            *word = lane.to_le_bytes();
        }
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
    fn permutation_of_the_zero_state() {
        // The Keccak team's known answer: Keccak-f[1600] on 1600 zero bits.
        let mut state = KeccakF1600::new();
        state.permute();
        assert_eq!(
            state.lanes()[..4],
            [
                0xf125_8f79_40e1_dde7,
                0x84d5_ccf9_33c0_478a,
                0xd598_261e_a65a_a9ee,
                0xbd15_4730_6f80_494d,
            ]
        );
    }

    #[test]
    fn permutation_with_sha3_padding_matches_fips_202() {
        // Swapping the pad byte to 0x06 turns the sponge into SHA3-256.
        // FIPS 202's published "abc" digest then pins the permutation independently.
        let mut block = [0_u8; RATE];
        block[..3].copy_from_slice(b"abc");
        block[3] = 0x06;
        block[RATE - 1] = 0x80;
        let mut state = KeccakF1600::new();
        state.absorb_block(&block);
        state.permute();

        let digest: Vec<u8> = state.lanes()[..4]
            .iter()
            .flat_map(|l| l.to_le_bytes())
            .collect();
        assert_eq!(
            digest,
            hex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
        );
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
