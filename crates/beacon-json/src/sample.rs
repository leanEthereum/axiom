//! Random values for the round-trip properties, drawn from a proptest seed.
//!
//! A seed drives a small generator, and each type draws its fields from it.
//! Collections draw at most two elements, which reaches every nesting level cheaply.

use std::fmt::Debug;

use axiom_json::Json;
use axiom_ssz::{
    BitList, BitVector, ByteList, ByteVector, Length, List, ProgressiveBitList, ProgressiveList,
    U256, Vector,
};
use axiom_types::{
    BlobIndex, BlsPubkey, BlsSignature, BuilderIndex, Bytes32, ColumnIndex, CommitteeIndex, Epoch,
    ExecutionAddress, Gwei, Hash32, KzgCommitment, KzgProof, Root, Slot, ValidatorIndex, Version,
    WithdrawalIndex,
};

use crate::ApiJson;

/// Most elements a sampled list holds.
const MAX_ITEMS: usize = 2;

/// Most bytes a sampled byte list holds.
const MAX_BYTES: usize = 8;

/// A deterministic stream of random words, seeded by proptest.
///
/// The steps are SplitMix64.
/// See Steele, Lea, and Flood, "Fast splittable pseudorandom number generators", OOPSLA 2014.
#[derive(Clone, Debug)]
pub(crate) struct Sampler(u64);

impl Sampler {
    /// A stream from a seed.
    pub(crate) const fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// The next random word.
    pub(crate) const fn word(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A count from zero to a bound, inclusive.
    pub(crate) const fn count(&mut self, bound: usize) -> usize {
        (self.word() % (bound as u64 + 1)) as usize
    }

    /// Random bytes into a buffer.
    pub(crate) fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let word = self.word().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
    }

    /// A random value of a type.
    pub(crate) fn draw<T: Sample>(&mut self) -> T {
        T::sample(self)
    }

    /// Checks that a random value of a type survives its JSON form and that form's text.
    pub(crate) fn round_trip<T: ApiJson + Sample + PartialEq + Debug>(
        &mut self,
    ) -> Result<(), String> {
        let value: T = self.draw();
        let json = value.to_json();
        let reparsed = Json::parse(json.to_string()).map_err(|error| error.to_string())?;
        if reparsed != json {
            return Err(format!("text changed the value: {json} became {reparsed}"));
        }
        match T::from_json(&reparsed) {
            Ok(decoded) if decoded == value => Ok(()),
            Ok(decoded) => Err(format!("{value:?} came back as {decoded:?}")),
            Err(error) => Err(format!("{value:?} failed to decode: {error}")),
        }
    }
}

/// A type the sampler can draw.
pub(crate) trait Sample {
    /// A random value.
    fn sample(sampler: &mut Sampler) -> Self;
}

impl Sample for u64 {
    fn sample(sampler: &mut Sampler) -> Self {
        sampler.word()
    }
}

impl Sample for bool {
    fn sample(sampler: &mut Sampler) -> Self {
        sampler.word() & 1 == 1
    }
}

impl<const N: usize> Sample for [u8; N] {
    fn sample(sampler: &mut Sampler) -> Self {
        let mut out = [0; N];
        sampler.fill(&mut out);
        out
    }
}

impl Sample for U256 {
    fn sample(sampler: &mut Sampler) -> Self {
        Self(sampler.draw())
    }
}

impl Sample for Slot {
    fn sample(sampler: &mut Sampler) -> Self {
        Self(sampler.draw())
    }
}

impl Sample for Epoch {
    fn sample(sampler: &mut Sampler) -> Self {
        Self(sampler.draw())
    }
}

impl Sample for Gwei {
    fn sample(sampler: &mut Sampler) -> Self {
        Self(sampler.draw())
    }
}

impl Sample for ValidatorIndex {
    fn sample(sampler: &mut Sampler) -> Self {
        Self(sampler.draw())
    }
}

impl Sample for BuilderIndex {
    fn sample(sampler: &mut Sampler) -> Self {
        Self(sampler.draw())
    }
}

impl Sample for CommitteeIndex {
    fn sample(sampler: &mut Sampler) -> Self {
        Self(sampler.draw())
    }
}

impl Sample for WithdrawalIndex {
    fn sample(sampler: &mut Sampler) -> Self {
        Self(sampler.draw())
    }
}

impl Sample for BlobIndex {
    fn sample(sampler: &mut Sampler) -> Self {
        Self(sampler.draw())
    }
}

impl Sample for ColumnIndex {
    fn sample(sampler: &mut Sampler) -> Self {
        Self(sampler.draw())
    }
}

impl Sample for Root {
    fn sample(sampler: &mut Sampler) -> Self {
        Self(sampler.draw())
    }
}

impl Sample for Hash32 {
    fn sample(sampler: &mut Sampler) -> Self {
        Self(sampler.draw())
    }
}

impl Sample for Bytes32 {
    fn sample(sampler: &mut Sampler) -> Self {
        Self(sampler.draw())
    }
}

impl Sample for Version {
    fn sample(sampler: &mut Sampler) -> Self {
        Self(sampler.draw())
    }
}

impl Sample for ExecutionAddress {
    fn sample(sampler: &mut Sampler) -> Self {
        Self(sampler.draw())
    }
}

impl Sample for BlsPubkey {
    fn sample(sampler: &mut Sampler) -> Self {
        Self(sampler.draw())
    }
}

impl Sample for BlsSignature {
    fn sample(sampler: &mut Sampler) -> Self {
        Self(sampler.draw())
    }
}

impl Sample for KzgCommitment {
    fn sample(sampler: &mut Sampler) -> Self {
        Self(sampler.draw())
    }
}

impl Sample for KzgProof {
    fn sample(sampler: &mut Sampler) -> Self {
        Self(sampler.draw())
    }
}

impl<N: Length> Sample for ByteVector<N> {
    fn sample(sampler: &mut Sampler) -> Self {
        let mut bytes = Self::zeroed();
        sampler.fill(&mut bytes);
        bytes
    }
}

impl<N: Length> Sample for ByteList<N> {
    fn sample(sampler: &mut Sampler) -> Self {
        let mut bytes = vec![0; sampler.count(N::LEN.min(MAX_BYTES))];
        sampler.fill(&mut bytes);
        Self::try_from(bytes).unwrap()
    }
}

impl Sample for ProgressiveList<u8> {
    fn sample(sampler: &mut Sampler) -> Self {
        let mut bytes = vec![0; sampler.count(MAX_BYTES)];
        sampler.fill(&mut bytes);
        Self::from(bytes)
    }
}

impl<N: Length> Sample for BitList<N> {
    fn sample(sampler: &mut Sampler) -> Self {
        // Any length up to the limit, so the sentinel lands in every bit position.
        let mut bits = Self::with_len(sampler.count(N::LEN)).unwrap();
        for index in 0..bits.len() {
            bits.set(index, sampler.draw());
        }
        bits
    }
}

impl<N: Length> Sample for BitVector<N> {
    fn sample(sampler: &mut Sampler) -> Self {
        let mut bits = Self::new();
        for index in 0..N::LEN {
            bits.set(index, sampler.draw());
        }
        bits
    }
}

impl Sample for ProgressiveBitList {
    fn sample(sampler: &mut Sampler) -> Self {
        let mut bits = Self::with_len(sampler.count(4 * MAX_BYTES));
        for index in 0..bits.len() {
            bits.set(index, sampler.draw());
        }
        bits
    }
}

impl<T: Sample, N: Length> Sample for List<T, N> {
    fn sample(sampler: &mut Sampler) -> Self {
        let items = (0..sampler.count(N::LEN.min(MAX_ITEMS)))
            .map(|_| sampler.draw())
            .collect::<Vec<T>>();
        Self::try_from(items).unwrap()
    }
}

impl<T: Sample, N: Length> Sample for Vector<T, N> {
    fn sample(sampler: &mut Sampler) -> Self {
        Self::from_fn(|_| sampler.draw())
    }
}

impl<T: Sample> Sample for ProgressiveList<T> {
    fn sample(sampler: &mut Sampler) -> Self {
        (0..sampler.count(MAX_ITEMS))
            .map(|_| sampler.draw())
            .collect()
    }
}
