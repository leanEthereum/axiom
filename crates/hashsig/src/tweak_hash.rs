//! The tweakable hash: Poseidon1 keyed by the public parameter and domain-separated by a tweak.
//!
//! # Overview
//!
//! Every hash call takes the public parameter P, a tweak T naming the call's position, and a message.
//! Distinct tweaks make every position its own function, which the multi-target security proof needs.
//! Three shapes of message exist, each with its own mode.
//!
//! ```text
//! chain step : PoseidonCompress_16(value || P || T)            one digest in
//! tree node  : PoseidonCompress_24(P || T || left || right)    two digests in
//! leaf       : Sponge_24(P || T || end_1 || ... || end_v)      all chain ends in
//! ```
//!
//! The chain step puts the value first so a circuit can chain calls without moving it.
//!
//! eprint 2025/055, section 7, defines the tweakable hash from Poseidon.

use crate::{
    field::KoalaBear,
    poseidon::{POSEIDON1_16, POSEIDON1_24},
    words::{Digest, PARAMETER_LEN, PublicParameter},
};

/// Field elements of an encoded tweak.
pub(crate) const TWEAK_LEN: usize = 2;

/// Elements of the sponge state reserved for the capacity.
const CAPACITY: usize = 9;

/// Elements the sponge absorbs per permutation: the width-24 state minus the capacity.
const RATE: usize = 24 - CAPACITY;

/// The tweak separator of chain steps.
const CHAIN_SEPARATOR: u64 = 0x00;

/// The tweak separator of tree nodes and leaves.
const TREE_SEPARATOR: u64 = 0x01;

/// The tweak separator of the message hash.
const MESSAGE_SEPARATOR: u64 = 0x02;

/// The position of one hash call, which domain-separates it from every other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tweak {
    /// A node of the Merkle tree, or a leaf at level 0.
    Tree {
        /// The node's level, 0 for leaves.
        level: u8,
        /// The node's index within its level.
        position: u32,
    },
    /// A step along a hash chain.
    Chain {
        /// The epoch whose one-time key the chain belongs to.
        epoch: u32,
        /// The chain's index.
        chain: u8,
        /// The position the step arrives at, from 1.
        step: u8,
    },
    /// The message hash of an epoch.
    Message {
        /// The signing epoch.
        epoch: u32,
    },
}

impl Tweak {
    /// The tweak as two field elements: one integer, written in base p.
    ///
    /// ```text
    /// tree    : level << 40 | position << 8 | 0x01     below 2^48
    /// chain   : epoch << 24 | chain << 16 | step << 8  below 2^56
    /// message : epoch << 8 | 0x02                      below 2^40
    /// ```
    ///
    /// Each integer is below p^2, about 2^62, so two base-p digits hold it exactly.
    /// The low byte separates the three kinds; distinct tweaks therefore give distinct elements.
    pub(crate) fn elements(self) -> [KoalaBear; TWEAK_LEN] {
        let value = match self {
            Self::Tree { level, position } => {
                (u64::from(level) << 40) | (u64::from(position) << 8) | TREE_SEPARATOR
            }
            Self::Chain { epoch, chain, step } => {
                (u64::from(epoch) << 24)
                    | (u64::from(chain) << 16)
                    | (u64::from(step) << 8)
                    | CHAIN_SEPARATOR
            }
            Self::Message { epoch } => (u64::from(epoch) << 8) | MESSAGE_SEPARATOR,
        };
        // The tweak is public, so a division is fine here.
        let p = u64::from(KoalaBear::ORDER);
        [(value % p) as u32, (value / p) as u32].map(KoalaBear::new)
    }
}

/// The tweakable hash of one key pair: the public parameter, the digest length, and the sponge's capacity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TweakHash {
    /// The public parameter of the key pair.
    parameter: PublicParameter,
    /// Field elements per digest.
    hash_len: usize,
    /// The sponge's initial capacity, which encodes the leaf input's shape.
    capacity: [KoalaBear; CAPACITY],
}

impl TweakHash {
    /// The hash of a key pair whose leaves absorb a given number of chain ends.
    pub(crate) fn new(parameter: PublicParameter, hash_len: usize, chains: usize) -> Self {
        // Phase 1: the input lengths, as one 128-bit integer in base 2^32.
        //
        //     [parameter length, tweak length, chains, digest length] = [5, 2, v, h]
        let lengths = [PARAMETER_LEN, TWEAK_LEN, chains, hash_len];
        let mut integer = lengths
            .iter()
            .fold(0_u128, |acc, &len| (acc << 32) | len as u128);

        // Phase 2: the integer in base p, compressed into the capacity.
        // A sponge over inputs of another shape starts elsewhere, so the shapes never collide.
        let p = u128::from(KoalaBear::ORDER);
        let digits: [KoalaBear; 24] = std::array::from_fn(|_| {
            let digit = (integer % p) as u32;
            integer /= p;
            KoalaBear::new(digit)
        });
        Self {
            parameter,
            hash_len,
            capacity: POSEIDON1_24.compress(&digits),
        }
    }

    /// The public parameter.
    pub(crate) const fn parameter(&self) -> &PublicParameter {
        &self.parameter
    }

    /// One step along a chain: the value at a position from the value before it.
    pub(crate) fn chain_step(&self, epoch: u32, chain: u8, step: u8, value: &Digest) -> Digest {
        // Layout: [value | parameter | tweak | zeros], 7 + 5 + 2 or 8 + 5 + 2 of 16 words.
        let h = self.hash_len;
        let mut input = [KoalaBear::ZERO; 16];
        input[..h].copy_from_slice(value.elements());
        input[h..h + PARAMETER_LEN].copy_from_slice(&self.parameter.0);
        input[h + PARAMETER_LEN..h + PARAMETER_LEN + TWEAK_LEN]
            .copy_from_slice(&Tweak::Chain { epoch, chain, step }.elements());
        let output: [KoalaBear; 8] = POSEIDON1_16.compress(&input);
        Digest::from_slice(&output[..h])
    }

    /// Walks a chain: from a value at one position, the value a number of steps further.
    ///
    /// # Invariants
    ///
    /// The walk stays below position 256: start plus steps is at most the chain length minus one.
    pub(crate) fn walk(
        &self,
        epoch: u32,
        chain: u8,
        start: u8,
        steps: usize,
        value: &Digest,
    ) -> Digest {
        let mut value = *value;
        for step in 1..=steps {
            value = self.chain_step(epoch, chain, start + step as u8, &value);
        }
        value
    }

    /// A tree node from its two children.
    pub(crate) fn node(&self, level: u8, position: u32, left: &Digest, right: &Digest) -> Digest {
        // Layout: [parameter | tweak | left | right | zeros], at most 5 + 2 + 16 of 24 words.
        let h = self.hash_len;
        let mut input = [KoalaBear::ZERO; 24];
        let (head, tail) = input.split_at_mut(PARAMETER_LEN + TWEAK_LEN);
        head[..PARAMETER_LEN].copy_from_slice(&self.parameter.0);
        head[PARAMETER_LEN..].copy_from_slice(&Tweak::Tree { level, position }.elements());
        tail[..h].copy_from_slice(left.elements());
        tail[h..2 * h].copy_from_slice(right.elements());
        let output: [KoalaBear; 8] = POSEIDON1_24.compress(&input);
        Digest::from_slice(&output[..h])
    }

    /// A Merkle leaf: the hash of all chain ends of one epoch's one-time public key.
    pub(crate) fn leaf(&self, epoch: u32, ends: &[Digest]) -> Digest {
        let mut sponge = Sponge::new(&self.capacity);
        sponge.absorb(&self.parameter.0);
        sponge.absorb(
            &Tweak::Tree {
                level: 0,
                position: epoch,
            }
            .elements(),
        );
        for end in ends {
            sponge.absorb(end.elements());
        }
        sponge.squeeze(self.hash_len)
    }
}

/// A sponge over the width-24 permutation that overwrites its rate instead of adding to it.
///
/// # Overview
///
/// The state is [capacity | rate].
/// Each full block of 15 elements replaces the rate, then the state is permuted.
/// A final partial block is zero-padded, which is sound because every leaf input has one fixed length.
///
/// Overwriting saves an addition per element in a circuit and keeps the sponge's security.
#[derive(Debug)]
struct Sponge {
    /// The permutation state.
    state: [KoalaBear; 24],
    /// Rate elements of the current block already written.
    filled: usize,
}

impl Sponge {
    /// A sponge whose capacity starts at a domain separator.
    fn new(capacity: &[KoalaBear; CAPACITY]) -> Self {
        let mut state = [KoalaBear::ZERO; 24];
        state[..CAPACITY].copy_from_slice(capacity);
        Self { state, filled: 0 }
    }

    /// Writes elements into the rate, permuting after each full block.
    fn absorb(&mut self, elements: &[KoalaBear]) {
        for &element in elements {
            self.state[CAPACITY + self.filled] = element;
            self.filled += 1;
            if self.filled == RATE {
                POSEIDON1_24.permute(&mut self.state);
                self.filled = 0;
            }
        }
    }

    /// Pads a partial block with zeros, permutes it, and reads the digest from the rate.
    fn squeeze(mut self, hash_len: usize) -> Digest {
        if self.filled > 0 {
            self.state[CAPACITY + self.filled..].fill(KoalaBear::ZERO);
            POSEIDON1_24.permute(&mut self.state);
        }
        // Every digest is shorter than the rate, so one block suffices.
        Digest::from_slice(&self.state[CAPACITY..CAPACITY + hash_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{entropy::SeedStream, words::Words};

    /// The fixture of one known answer: the stream's parameter, two digests, and chain ends.
    fn fixture(
        label: &[u8],
        hash_len: usize,
        chains: usize,
    ) -> (TweakHash, Digest, Digest, Vec<Digest>) {
        let mut stream = SeedStream::new(label);
        let parameter = PublicParameter::sample(&mut stream);
        let a = Words::sample(hash_len, &mut stream);
        let b = Words::sample(hash_len, &mut stream);
        let ends = (0..chains)
            .map(|_| Words::sample(hash_len, &mut stream))
            .collect();
        (TweakHash::new(parameter, hash_len, chains), a, b, ends)
    }

    /// Canonical values of a digest.
    fn canonical(digest: &Digest) -> Vec<u32> {
        digest.elements().iter().map(|e| e.to_canonical()).collect()
    }

    #[test]
    fn tweaks_in_base_p() {
        // Fixture state: level 9, position 0xabcdef gives 9 * 2^40 + 0xabcdef00 + 1.
        let p = u64::from(KoalaBear::ORDER);
        let tree = (9 << 40) + (0x00ab_cdef << 8) + 1;
        let expected = [tree % p, tree / p].map(|d| KoalaBear::new(d as u32));
        assert_eq!(
            Tweak::Tree {
                level: 9,
                position: 0x00ab_cdef
            }
            .elements(),
            expected
        );

        // The largest chain tweak, epoch 2^32 - 1, chain 255, step 255, still fits two digits.
        let chain = Tweak::Chain {
            epoch: u32::MAX,
            chain: 255,
            step: 255,
        }
        .elements();
        let value = (u64::from(u32::MAX) << 24) | (255 << 16) | (255 << 8);
        assert_eq!(
            chain,
            [value % p, value / p].map(|d| KoalaBear::new(d as u32))
        );

        // The three kinds differ even at equal numbers.
        let message = Tweak::Message { epoch: 0 }.elements();
        let leaf = Tweak::Tree {
            level: 0,
            position: 0,
        }
        .elements();
        let step = Tweak::Chain {
            epoch: 0,
            chain: 0,
            step: 0,
        }
        .elements();
        assert_ne!(message, leaf);
        assert_ne!(leaf, step);
    }

    #[test]
    fn known_answers_with_seven_element_digests() {
        // 155 chain ends of 7 elements, as the one-bit chunk instantiations hash.
        let (hash, a, b, ends) = fixture(b"h7c155", 7, 155);
        assert_eq!(
            canonical(&hash.chain_step(0x1234_5678, 17, 3, &a)),
            [
                429_748_879,
                397_028_764,
                1_117_750_956,
                68_632_921,
                1_642_563_446,
                367_386_777,
                947_413_765
            ]
        );
        assert_eq!(
            canonical(&hash.node(9, 0x00ab_cdef, &a, &b)),
            [
                717_137_055,
                377_706_494,
                172_901_476,
                601_556_512,
                1_953_112_154,
                1_855_733_609,
                1_685_977_287
            ]
        );
        assert_eq!(
            canonical(&hash.leaf(77, &ends)),
            [
                1_418_307_456,
                620_987_370,
                2_071_073_198,
                1_729_105_307,
                1_714_981_710,
                1_244_207_317,
                156_992_750
            ]
        );
    }

    #[test]
    fn known_answers_with_eight_element_digests() {
        // 46 chain ends of 8 elements, as the hypercube instantiation hashes.
        let (hash, a, b, ends) = fixture(b"h8c46", 8, 46);
        assert_eq!(
            canonical(&hash.chain_step(0x1234_5678, 17, 3, &a)),
            [
                890_983_445,
                791_338_933,
                2_042_058_811,
                356_015_955,
                937_279_851,
                45_914_065,
                1_577_796_253,
                1_008_551_226
            ]
        );
        assert_eq!(
            canonical(&hash.node(9, 0x00ab_cdef, &a, &b)),
            [
                1_121_401_165,
                1_780_115_344,
                1_984_950_717,
                233_743_303,
                1_426_117_775,
                660_855_929,
                400_109_102,
                206_057_650
            ]
        );
        assert_eq!(
            canonical(&hash.leaf(77, &ends)),
            [
                1_557_206_208,
                2_104_594_826,
                639_984_824,
                314_843_128,
                1_664_155_420,
                263_674_824,
                1_729_223_712,
                1_741_430_209
            ]
        );
    }

    #[test]
    fn leaf_inputs_that_fill_whole_blocks() {
        // 39 ends of 7 elements: 5 + 2 + 273 = 280 elements, 18 full blocks and 10 left.
        // 20 ends of 8 elements: 5 + 2 + 160 = 167 elements, 11 full blocks and 2 left.
        let (hash, _, _, ends) = fixture(b"h7c39", 7, 39);
        assert_eq!(
            canonical(&hash.leaf(77, &ends)),
            [
                674_373_632,
                2_105_347_220,
                1_384_897_830,
                1_851_347_046,
                623_388_542,
                380_956_403,
                1_988_229_851
            ]
        );
        let (hash, _, _, ends) = fixture(b"h8c20", 8, 20);
        assert_eq!(
            canonical(&hash.leaf(77, &ends)),
            [
                579_292_234,
                2_126_434_272,
                1_892_544_731,
                100_584_638,
                1_027_758_562,
                1_259_192_922,
                1_169_698_277,
                678_574_862
            ]
        );
    }

    #[test]
    fn walking_in_two_legs_equals_one_walk() {
        // Fixture state: a 15-step chain split at every point.
        let (hash, a, ..) = fixture(b"h7c39", 7, 39);
        let whole = hash.walk(9, 20, 0, 15, &a);
        for split in 0..=15 {
            let middle = hash.walk(9, 20, 0, split, &a);
            assert_eq!(hash.walk(9, 20, split as u8, 15 - split, &middle), whole);
        }
    }
}
