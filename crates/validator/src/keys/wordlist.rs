//! The BIP-39 English wordlist.

use std::sync::LazyLock;

/// The words, split once on first use.
static ENGLISH: LazyLock<Wordlist> = LazyLock::new(|| Wordlist {
    words: include_str!("english.txt").lines().collect(),
});

/// A BIP-39 wordlist: 2048 words, sorted, each naming one 11-bit value.
///
/// The data file beside this one is english.txt of the BIP-39 repository, byte for byte.
/// Its SHA-256 is 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda.
#[derive(Debug)]
pub(crate) struct Wordlist {
    /// The words, in value order, which is also alphabetical order.
    words: Vec<&'static str>,
}

impl Wordlist {
    /// The English list.
    pub(crate) fn english() -> &'static Self {
        &ENGLISH
    }

    /// The word of an 11-bit value.
    pub(crate) fn word(&self, index: u16) -> &'static str {
        // Invariant: callers pass 11-bit values, and the list holds 2048 words.
        self.words[usize::from(index)]
    }

    /// The 11-bit value of a word, when the list holds it.
    ///
    /// The list is sorted, so the lookup binary searches.
    pub(crate) fn index_of(&self, word: &str) -> Option<u16> {
        // Invariant: an index below 2048 fits 16 bits.
        self.words
            .binary_search(&word)
            .ok()
            .map(|index| index as u16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_english_list_has_2048_sorted_unique_words() {
        let words = &Wordlist::english().words;
        // One word per 11-bit value: 2^11 = 2048.
        assert_eq!(words.len(), 2048);
        // Strictly increasing means sorted and free of duplicates.
        assert!(words.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(words.first(), Some(&"abandon"));
        assert_eq!(words.last(), Some(&"zoo"));
    }

    #[test]
    fn lookups_invert_each_other() {
        let list = Wordlist::english();
        assert_eq!(list.index_of("abandon"), Some(0));
        assert_eq!(list.index_of("about"), Some(3));
        assert_eq!(list.index_of("zoo"), Some(2047));
        assert_eq!(list.word(2047), "zoo");
        // A prefix of a word is not a word.
        assert_eq!(list.index_of("aband"), None);
    }
}
