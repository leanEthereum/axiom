//! BIP-39 mnemonics: entropy written as English words, and the seed they stretch into.

use std::{fmt, io, str::FromStr};

use axiom_crypto::pbkdf2::Pbkdf2;
use sha2::{Digest, Sha256};

use crate::keys::{MnemonicError, OsEntropy, Seed, nfkd, wipe::Wipe, wordlist::Wordlist};

/// The length of a mnemonic, which fixes its entropy: 128 to 256 bits in steps of 32.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WordCount {
    /// 12 words: 128 bits of entropy.
    Twelve,
    /// 15 words: 160 bits of entropy.
    Fifteen,
    /// 18 words: 192 bits of entropy.
    Eighteen,
    /// 21 words: 224 bits of entropy.
    TwentyOne,
    /// 24 words: 256 bits of entropy.
    TwentyFour,
}

impl WordCount {
    /// Every count, shortest first.
    const ALL: [Self; 5] = [
        Self::Twelve,
        Self::Fifteen,
        Self::Eighteen,
        Self::TwentyOne,
        Self::TwentyFour,
    ];

    /// The number of words.
    #[must_use]
    pub const fn words(self) -> usize {
        match self {
            Self::Twelve => 12,
            Self::Fifteen => 15,
            Self::Eighteen => 18,
            Self::TwentyOne => 21,
            Self::TwentyFour => 24,
        }
    }

    /// Bytes of entropy the words carry.
    ///
    /// Per BIP-39, MS = (ENT + ENT / 32) / 11 words, so ENT = 32 MS / 3 bits = 4 MS / 3 bytes.
    #[must_use]
    pub const fn entropy_len(self) -> usize {
        4 * self.words() / 3
    }

    /// Checksum bits after the entropy: CS = ENT / 32.
    const fn checksum_bits(self) -> usize {
        self.entropy_len() / 4
    }

    /// The count with a number of words, when BIP-39 defines one.
    fn from_words(words: usize) -> Option<Self> {
        Self::ALL.into_iter().find(|count| count.words() == words)
    }

    /// The count carrying a number of entropy bytes, when BIP-39 defines one.
    fn from_entropy_len(len: usize) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|count| count.entropy_len() == len)
    }
}

/// A BIP-39 mnemonic: entropy and checksum, written as words of the English list.
///
/// The phrase and entropy are overwritten with zero on drop, and debug output hides them.
pub struct Mnemonic {
    /// The entropy, in the first bytes the word count fixes.
    entropy: [u8; 32],
    /// The length.
    count: WordCount,
    /// The words, joined by single spaces.
    phrase: String,
}

impl Mnemonic {
    /// PBKDF2 rounds from mnemonic to seed, per BIP-39, section "From mnemonic to seed".
    const SEED_ROUNDS: u32 = 2048;

    /// Prefix of the salt, before the passphrase.
    const SALT_PREFIX: &'static str = "mnemonic";

    /// The mnemonic writing some entropy.
    ///
    /// # Errors
    ///
    /// Fails unless the entropy is 16, 20, 24, 28, or 32 bytes long.
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, MnemonicError> {
        let count = WordCount::from_entropy_len(entropy.len())
            .ok_or(MnemonicError::EntropyLength { len: entropy.len() })?;

        // The bit string ENT || CS: the entropy, then the first CS bits of its digest.
        let mut bits = BitString::new();
        bits.bytes[..entropy.len()].copy_from_slice(entropy);
        bits.bytes[entropy.len()] = Sha256::digest(entropy)[0];

        // Each 11 bits name one word.
        let list = Wordlist::english();
        let mut phrase = String::with_capacity(count.words() * 9);
        for index in 0..count.words() {
            if index > 0 {
                phrase.push(' ');
            }
            phrase.push_str(list.word(bits.word(index)));
        }

        let mut stored = [0; 32];
        stored[..entropy.len()].copy_from_slice(entropy);
        Ok(Self {
            entropy: stored,
            count,
            phrase,
        })
    }

    /// A fresh mnemonic of the given length, from the operating system's entropy.
    ///
    /// # Errors
    ///
    /// Fails when the entropy source cannot be read.
    pub fn generate(count: WordCount) -> io::Result<Self> {
        let mut entropy = [0; 32];
        OsEntropy::fill(&mut entropy[..count.entropy_len()])?;
        let mnemonic = Self::from_entropy(&entropy[..count.entropy_len()]);
        entropy.wipe();
        // Invariant: the length comes from a word count, so it is one BIP-39 defines.
        Ok(mnemonic.expect("the entropy length matches a word count"))
    }

    /// Parses a phrase, checking every word and the checksum.
    ///
    /// The text is normalized to NFKD, and words may be separated by any whitespace.
    /// The stored phrase joins the words with single spaces, and the seed stretches that form.
    ///
    /// # Errors
    ///
    /// Fails on a word count BIP-39 does not define, a word outside the list, or a bad checksum.
    pub fn parse(phrase: &str) -> Result<Self, MnemonicError> {
        let mut normalized = nfkd(phrase);
        let result = Self::parse_normalized(&normalized);
        normalized.wipe();
        result
    }

    /// The words, joined by single spaces.
    #[must_use]
    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    /// The entropy the words carry.
    #[must_use]
    pub fn entropy(&self) -> &[u8] {
        &self.entropy[..self.count.entropy_len()]
    }

    /// The length.
    #[must_use]
    pub const fn word_count(&self) -> WordCount {
        self.count
    }

    /// The seed the mnemonic stretches into under a passphrase, empty when there is none.
    ///
    /// # Overview
    ///
    /// ```text
    /// seed = PBKDF2-HMAC-SHA512(NFKD(phrase), "mnemonic" || NFKD(passphrase), 2048, 64)
    /// ```
    ///
    /// The phrase is English words in ASCII, already in NFKD.
    #[must_use]
    pub fn to_seed(&self, passphrase: &str) -> Seed {
        // Sized up front: a growing buffer would leave copies of the passphrase behind.
        let mut normalized = nfkd(passphrase);
        let mut salt = String::with_capacity(Self::SALT_PREFIX.len() + normalized.len());
        salt.push_str(Self::SALT_PREFIX);
        salt.push_str(&normalized);
        normalized.wipe();
        let mut seed = [0; Seed::LEN];
        // Invariant: 2048 rounds is positive and 64 bytes is one SHA-512 block of output.
        Pbkdf2::sha512(
            self.phrase.as_bytes(),
            salt.as_bytes(),
            Self::SEED_ROUNDS,
            &mut seed,
        )
        .expect("2048 rounds and 64 bytes are within PBKDF2 limits");
        salt.wipe();
        let out = Seed::from_bytes(seed);
        seed.wipe();
        out
    }

    /// Parses a phrase already in NFKD.
    fn parse_normalized(text: &str) -> Result<Self, MnemonicError> {
        let words: Vec<&str> = text.split_whitespace().collect();
        let count = WordCount::from_words(words.len())
            .ok_or(MnemonicError::WordCount { count: words.len() })?;

        // Write each word's 11 bits back into the bit string ENT || CS.
        let list = Wordlist::english();
        let mut bits = BitString::new();
        for (index, word) in words.iter().enumerate() {
            let value = list
                .index_of(word)
                .ok_or_else(|| MnemonicError::UnknownWord {
                    index,
                    word: (*word).to_owned(),
                })?;
            bits.set_word(index, value);
        }

        // The last CS bits must be the first CS bits of the entropy's digest.
        let len = count.entropy_len();
        let unused = 8 - count.checksum_bits();
        let expected = Sha256::digest(&bits.bytes[..len])[0] >> unused;
        let actual = bits.bytes[len] >> unused;
        if expected != actual {
            return Err(MnemonicError::Checksum { expected, actual });
        }
        Self::from_entropy(&bits.bytes[..len])
    }
}

impl FromStr for Mnemonic {
    type Err = MnemonicError;

    fn from_str(phrase: &str) -> Result<Self, Self::Err> {
        Self::parse(phrase)
    }
}

impl Drop for Mnemonic {
    fn drop(&mut self) {
        self.entropy.wipe();
        self.phrase.wipe();
    }
}

impl fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mnemonic")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

/// The bit string ENT || CS of BIP-39, read and written 11 bits at a time.
///
/// At most 256 + 8 bits, so 33 bytes hold it; bits run most significant first.
struct BitString {
    /// The bits, wiped on drop.
    bytes: [u8; 33],
}

impl BitString {
    /// Bits per word: a 2048-word list indexes with 11 bits.
    const WORD_BITS: usize = 11;

    /// A string of zero bits.
    const fn new() -> Self {
        Self { bytes: [0; 33] }
    }

    /// Whether the bit at a position is set.
    const fn bit(&self, position: usize) -> bool {
        self.bytes[position / 8] & (0x80 >> (position % 8)) != 0
    }

    /// The 11-bit value of the word at an index.
    fn word(&self, index: usize) -> u16 {
        let start = index * Self::WORD_BITS;
        (start..start + Self::WORD_BITS).fold(0, |value, position| {
            (value << 1) | u16::from(self.bit(position))
        })
    }

    /// Writes the 11-bit value of the word at an index into zero bits.
    fn set_word(&mut self, index: usize, value: u16) {
        let start = index * Self::WORD_BITS;
        for offset in 0..Self::WORD_BITS {
            // The first bit of the word is its most significant, bit 10.
            if value & (1 << (Self::WORD_BITS - 1 - offset)) != 0 {
                let position = start + offset;
                self.bytes[position / 8] |= 0x80 >> (position % 8);
            }
        }
    }
}

impl Drop for BitString {
    fn drop(&mut self) {
        self.bytes.wipe();
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn zero_entropy_ends_with_its_checksum_word() {
        // 16 zero bytes: eleven words of value 0, then 7 zero bits and checksum 0x3.
        // SHA-256 of 16 zero bytes starts 0x37, whose top 4 bits are 0b0011.
        // The last word is 0b0000000_0011 = 3, which is about.
        let mnemonic = Mnemonic::from_entropy(&[0; 16]).unwrap();
        assert_eq!(
            mnemonic.phrase(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        assert_eq!(mnemonic.word_count(), WordCount::Twelve);
        assert_eq!(mnemonic.entropy(), [0; 16]);
    }

    #[test]
    fn entropy_lengths_outside_bip_39_are_refused() {
        // 15 and 33 bytes sit just outside the range; 18 bytes is inside but not a multiple of 4.
        for len in [0, 15, 18, 33] {
            assert_eq!(
                Mnemonic::from_entropy(&vec![0; len]).err(),
                Some(MnemonicError::EntropyLength { len })
            );
        }
    }

    #[test]
    fn word_counts_outside_bip_39_are_refused() {
        // Eleven valid words: one short of the smallest mnemonic.
        let phrase = "abandon ".repeat(11);
        assert_eq!(
            Mnemonic::parse(&phrase).err(),
            Some(MnemonicError::WordCount { count: 11 })
        );
        assert_eq!(
            Mnemonic::parse("").err(),
            Some(MnemonicError::WordCount { count: 0 })
        );
    }

    #[test]
    fn an_unknown_word_is_named_with_its_index() {
        // Word 4 is misspelled.
        let phrase = "abandon abandon abandon abandon abandn abandon abandon abandon abandon abandon abandon about";
        assert_eq!(
            Mnemonic::parse(phrase).err(),
            Some(MnemonicError::UnknownWord {
                index: 4,
                word: "abandn".to_owned()
            })
        );
    }

    #[test]
    fn a_wrong_last_word_breaks_the_checksum() {
        // Mutation: about (checksum 0b0011) becomes able (value 2, checksum 0b0010).
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon able";
        assert_eq!(
            Mnemonic::parse(phrase).err(),
            Some(MnemonicError::Checksum {
                expected: 0x3,
                actual: 0x2
            })
        );
    }

    #[test]
    fn whitespace_and_normalization_are_forgiven() {
        // Tabs, a newline, and an ideographic space U+3000 separate the words.
        // NFKD maps U+3000 to a plain space before the split.
        let phrase = " abandon\tabandon abandon abandon abandon abandon abandon abandon abandon abandon\u{3000}abandon\nabout ";
        let mnemonic = Mnemonic::parse(phrase).unwrap();
        assert_eq!(
            mnemonic.phrase(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
    }

    #[test]
    fn the_passphrase_is_normalized_before_salting() {
        // U+00C5 and U+212B both decompose to A and a combining ring, U+030A.
        let mnemonic = Mnemonic::from_entropy(&[0; 16]).unwrap();
        let composed = mnemonic.to_seed("\u{00C5}");
        let angstrom = mnemonic.to_seed("\u{212B}");
        let decomposed = mnemonic.to_seed("A\u{030A}");
        assert_eq!(composed.as_bytes(), decomposed.as_bytes());
        assert_eq!(angstrom.as_bytes(), decomposed.as_bytes());
    }

    #[test]
    fn debug_output_hides_the_words() {
        let mnemonic = Mnemonic::from_entropy(&[0; 32]).unwrap();
        assert_eq!(
            format!("{mnemonic:?}"),
            "Mnemonic { count: TwentyFour, .. }"
        );
    }

    proptest! {
        #[test]
        fn phrases_round_trip_to_their_entropy(
            index in 0_usize..5,
            entropy in any::<[u8; 32]>(),
        ) {
            // Every length: write the entropy as words, parse them back, recover the entropy.
            let count = WordCount::ALL[index];
            let written = Mnemonic::from_entropy(&entropy[..count.entropy_len()]).unwrap();
            let parsed = Mnemonic::parse(written.phrase()).unwrap();
            prop_assert_eq!(parsed.entropy(), &entropy[..count.entropy_len()]);
            prop_assert_eq!(parsed.phrase(), written.phrase());
            prop_assert_eq!(parsed.phrase().split(' ').count(), count.words());
        }
    }
}
