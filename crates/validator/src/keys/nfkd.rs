//! Unicode Normalization Form KD, which passwords and mnemonic passphrases go through.
//!
//! # Overview
//!
//! NFKD makes two spellings of one text into the same bytes.
//! A fraktur letter becomes its plain letter, and an accented letter becomes a letter and a mark.
//! The algorithm is Unicode Standard Annex 15, section 3, and chapter 3.11 of the standard.
//!
//! 1. Replace each code point by its full compatibility decomposition, recursively.
//! 2. Decompose each precomposed Hangul syllable arithmetically, per chapter 3.12.
//! 3. Sort each run of marks with nonzero combining class by class, keeping ties in order.
//!
//! # Data
//!
//! The table beside this file derives from UnicodeData.txt of Unicode 16.0.0.
//! That file has SHA-256 ff58e5823bd095166564a006e47d111130813dcf8bf234ef79fa51a870edb48f.
//!
//! It keeps the code points that have a decomposition mapping or a nonzero combining class.
//! Each line holds three fields, separated by semicolons:
//!
//! - the code point, in hex;
//! - its canonical combining class, field 3 of the source, in decimal;
//! - its one-step decomposition mapping, field 5 of the source, as hex code points.
//!
//! A compatibility mapping loses its angle-bracketed tag, since NFKD applies both kinds alike.
//! Every other code point decomposes to itself with class zero.
//! Hangul syllables have no line: their decomposition is arithmetic.

use std::sync::LazyLock;

use crate::keys::wipe::Wipe;

/// The decomposition table, parsed on first use.
static TABLE: LazyLock<Decompositions> = LazyLock::new(Decompositions::parse);

/// The Unicode 16.0.0 decomposition data, one code point per line.
const DATA: &str = include_str!("nfkd.txt");

/// The NFKD form of a text.
///
/// The output buffer is sized before it is filled, so it never reallocates.
/// No partial copy of a secret input is then left behind in freed memory.
#[must_use]
pub fn nfkd(text: &str) -> String {
    let table = &*TABLE;

    // Phase 1: count the output, so both buffers are allocated once at their final size.
    let (mut chars, mut bytes) = (0, 0);
    for c in text.chars() {
        table.decompose(c, &mut |d| {
            chars += 1;
            bytes += d.len_utf8();
        });
    }

    // Phase 2: decompose, holding each run of marks back until a starter closes it.
    let mut out = String::with_capacity(bytes);
    let mut run = MarkRun::with_capacity(chars);
    for c in text.chars() {
        table.decompose(c, &mut |d| match table.class(d) {
            0 => {
                run.flush_into(&mut out);
                out.push(d);
            }
            class => run.push(class, d),
        });
    }
    run.flush_into(&mut out);
    out
}

/// Marks waiting for canonical ordering: their class, arrival order, and code point.
///
/// The buffer is wiped on drop, since the marks may belong to a password.
struct MarkRun {
    /// Pending marks, all of nonzero class.
    marks: Vec<(u8, u32, char)>,
}

impl MarkRun {
    /// An empty run with room for a number of marks.
    fn with_capacity(capacity: usize) -> Self {
        Self {
            marks: Vec::with_capacity(capacity),
        }
    }

    /// Appends a mark of nonzero class.
    fn push(&mut self, class: u8, mark: char) {
        // Invariant: the run never exceeds the input's decomposed length.
        // A text of 2^32 decomposed code points is beyond any password.
        let order = self.marks.len() as u32;
        self.marks.push((class, order, mark));
    }

    /// Writes the run in canonical order, then empties it.
    fn flush_into(&mut self, out: &mut String) {
        // Canonical ordering is a stable sort by class.
        // The arrival order breaks ties, so an unstable sort is stable here and allocates nothing.
        self.marks.sort_unstable();
        out.extend(self.marks.iter().map(|&(_, _, mark)| mark));
        self.marks.wipe();
        self.marks.clear();
    }
}

impl Drop for MarkRun {
    fn drop(&mut self) {
        self.marks.wipe();
    }
}

/// The full decomposition and combining class of every code point that has either.
struct Decompositions {
    /// Entries sorted by code point.
    entries: Vec<Entry>,
    /// The full decompositions, back to back.
    pool: Vec<char>,
}

/// One code point of the table.
#[derive(Clone, Copy)]
struct Entry {
    /// The code point.
    code: char,
    /// Its canonical combining class.
    class: u8,
    /// Start of its full decomposition in the pool.
    start: u32,
    /// Length of its full decomposition; zero when it decomposes to itself.
    len: u32,
}

impl Decompositions {
    /// First precomposed Hangul syllable, per Unicode chapter 3.12.
    const S_BASE: u32 = 0xac00;
    /// First leading consonant jamo.
    const L_BASE: u32 = 0x1100;
    /// First vowel jamo.
    const V_BASE: u32 = 0x1161;
    /// One before the first trailing consonant jamo: index zero means no trailing consonant.
    const T_BASE: u32 = 0x11a7;
    /// Vowels times trailing consonants: 21 * 28.
    const N_COUNT: u32 = 588;
    /// Trailing consonants, counting the absent one.
    const T_COUNT: u32 = 28;
    /// Precomposed syllables: 19 leading consonants times 588.
    const S_COUNT: u32 = 11_172;

    /// Parses the compiled-in data and expands every mapping fully.
    fn parse() -> Self {
        // Step 1: the one-step mappings, in file order, which is code point order.
        let raw: Vec<(char, u8, Vec<char>)> = DATA.lines().map(Self::parse_line).collect();

        // Step 2: expand each mapping recursively into the pool.
        let mut pool = Vec::new();
        let entries = raw
            .iter()
            .map(|&(code, class, ref mapping)| {
                // Invariant: the pool holds well under 2^32 code points, about 20 000.
                let start = pool.len() as u32;
                for &c in mapping {
                    Self::expand(&raw, c, &mut pool);
                }
                Entry {
                    code,
                    class,
                    start,
                    len: pool.len() as u32 - start,
                }
            })
            .collect();
        Self { entries, pool }
    }

    /// Parses one line of the data file.
    fn parse_line(line: &str) -> (char, u8, Vec<char>) {
        // Invariant: the data is compiled in, and a unit test parses every line of it.
        let mut fields = line.split(';');
        let mut field = || fields.next().expect("three fields per line");
        let code = Self::code_point(field());
        let class = field().parse().expect("a class below 256");
        let mapping = field().split_whitespace().map(Self::code_point).collect();
        (code, class, mapping)
    }

    /// A code point written in hex.
    fn code_point(hex: &str) -> char {
        // Invariant: the data names only scalar values, never surrogates.
        u32::from_str_radix(hex, 16)
            .ok()
            .and_then(char::from_u32)
            .expect("a Unicode scalar value")
    }

    /// Appends the full decomposition of a code point, following one-step mappings down.
    fn expand(raw: &[(char, u8, Vec<char>)], c: char, out: &mut Vec<char>) {
        if let Some(jamo) = Self::hangul(c) {
            out.extend(jamo.into_iter().flatten());
            return;
        }
        match raw.binary_search_by_key(&c, |&(code, _, _)| code) {
            Ok(index) if !raw[index].2.is_empty() => {
                for &d in &raw[index].2 {
                    Self::expand(raw, d, out);
                }
            }
            _ => out.push(c),
        }
    }

    /// The jamo of a precomposed Hangul syllable, per Unicode chapter 3.12.
    ///
    /// The trailing consonant is absent when the syllable has none.
    fn hangul(c: char) -> Option<[Option<char>; 3]> {
        let index = u32::from(c).checked_sub(Self::S_BASE)?;
        if index >= Self::S_COUNT {
            return None;
        }
        // index = (L * 21 + V) * 28 + T.
        let leading = Self::L_BASE + index / Self::N_COUNT;
        let vowel = Self::V_BASE + (index % Self::N_COUNT) / Self::T_COUNT;
        let trailing = index % Self::T_COUNT;
        Some([
            char::from_u32(leading),
            char::from_u32(vowel),
            (trailing != 0)
                .then(|| char::from_u32(Self::T_BASE + trailing))
                .flatten(),
        ])
    }

    /// The table entry of a code point, when it has one.
    fn entry(&self, c: char) -> Option<&Entry> {
        self.entries
            .binary_search_by_key(&c, |entry| entry.code)
            .ok()
            .map(|index| &self.entries[index])
    }

    /// The canonical combining class of a code point.
    fn class(&self, c: char) -> u8 {
        self.entry(c).map_or(0, |entry| entry.class)
    }

    /// Calls the sink with each code point of the full decomposition, in mapping order.
    fn decompose(&self, c: char, sink: &mut impl FnMut(char)) {
        if let Some(jamo) = Self::hangul(c) {
            jamo.into_iter().flatten().for_each(sink);
            return;
        }
        match self.entry(c) {
            Some(entry) if entry.len > 0 => {
                let start = entry.start as usize;
                self.pool[start..start + entry.len as usize]
                    .iter()
                    .copied()
                    .for_each(sink);
            }
            _ => sink(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_parses_every_line() {
        // 6843 lines: the code points of Unicode 16.0.0 with a mapping or a nonzero class.
        assert_eq!(TABLE.entries.len(), 6843);
        assert_eq!(DATA.lines().count(), 6843);
        // The file is sorted, so lookups may binary search.
        assert!(TABLE.entries.windows(2).all(|w| w[0].code < w[1].code));
    }

    #[test]
    fn compatibility_mappings_flatten_styled_letters() {
        // MATHEMATICAL FRAKTUR SMALL T, U+1D531, maps to t under compatibility.
        assert_eq!(nfkd("\u{1D531}"), "t");
        // The ligature ffi, U+FB03, becomes three letters.
        assert_eq!(nfkd("\u{FB03}"), "ffi");
        // A key emoji, U+1F511, has no mapping and stays.
        assert_eq!(nfkd("\u{1F511}"), "\u{1F511}");
    }

    #[test]
    fn mappings_expand_recursively() {
        // U+1E9B LATIN SMALL LETTER LONG S WITH DOT ABOVE maps to U+017F U+0307.
        // U+017F LATIN SMALL LETTER LONG S then maps to s under compatibility.
        assert_eq!(nfkd("\u{1E9B}"), "s\u{0307}");

        // Three steps: U+1F82 maps to U+1F02 U+0345, U+1F02 to U+1F00 U+0300.
        // U+1F00 then maps to alpha and a smooth breathing, U+03B1 U+0313.
        assert_eq!(nfkd("\u{1F82}"), "\u{03B1}\u{0313}\u{0300}\u{0345}");
    }

    #[test]
    fn hangul_syllables_decompose_arithmetically() {
        // U+AC00, the first syllable: leading U+1100, vowel U+1161, no trailing consonant.
        assert_eq!(nfkd("\u{AC00}"), "\u{1100}\u{1161}");
        // U+D7A3, the last syllable: index 11171 = (18 * 21 + 20) * 28 + 27.
        assert_eq!(nfkd("\u{D7A3}"), "\u{1112}\u{1175}\u{11C2}");
        // U+320E PARENTHESIZED HANGUL KIYEOK A maps to a syllable, which decomposes again.
        assert_eq!(nfkd("\u{320E}"), "(\u{1100}\u{1161})");
    }

    #[test]
    fn marks_are_ordered_by_class_and_stably() {
        // Fixture state: a, dot below (class 220), acute (230), dot below again (220).
        //
        //     classes in:  0 220 230 220
        //     classes out: 0 220 220 230
        //
        // The two dots keep their relative order, and the starter b closes the run.
        let text = "a\u{0323}\u{0301}\u{0323}b";
        assert_eq!(nfkd(text), "a\u{0323}\u{0323}\u{0301}b");
    }

    #[test]
    fn empty_and_plain_text_pass_through() {
        assert_eq!(nfkd(""), "");
        assert_eq!(nfkd("testpassword"), "testpassword");
    }
}
