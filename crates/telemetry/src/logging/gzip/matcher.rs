//! LZ77 matching over a sliding window, with hash chains to find earlier occurrences.
//!
//! Source: RFC 1951 section 4, which describes this matcher.

/// The farthest back a match may reach.
///
/// Source: RFC 1951 section 3.2.5, where distances run from 1 to 32768.
pub(super) const WINDOW: usize = 1 << 15;

/// The shortest match the length alphabet can name.
///
/// Source: RFC 1951 section 3.2.5, where lengths run from 3 to 258.
const MIN_MATCH: usize = 3;

/// The longest match the length alphabet can name.
const MAX_MATCH: usize = 258;

/// Bytes kept ahead of the cursor before a token is chosen, unless the input has ended.
///
/// A full-length match then fits, and every position it covers can still be hashed.
/// Tokens then depend only on the input, never on how the input was split into writes.
const LOOKAHEAD: usize = MAX_MATCH + MIN_MATCH;

/// The buffer holds one window of history and up to one window of input.
const CAPACITY: usize = 2 * WINDOW;

/// Hash chain heads are indexed by this many bits of a three-byte prefix.
const HASH_BITS: u32 = 15;

/// Earlier occurrences examined per position, trading ratio for time.
const MAX_CHAIN: usize = 128;

/// Knuth's multiplicative hashing constant, the golden ratio scaled to 32 bits.
///
/// Source: Knuth, The Art of Computer Programming, volume 3, section 6.4.
const GOLDEN: u32 = 0x9e37_79b1;

/// One unit of LZ77 output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Token {
    /// A byte copied as is.
    Literal(u8),

    /// A copy of earlier output.
    Match {
        /// How many bytes to copy, from 3 to 258.
        length: u16,

        /// How far back the copy starts, from 1 to 32768.
        distance: u16,
    },
}

/// The window of recent input and the hash chains over it.
///
/// Stream positions are absolute, so chains need no rewriting when the window slides.
#[derive(Debug)]
pub(super) struct Matcher {
    /// Recent history, then input not yet tokenized.
    buffer: Vec<u8>,

    /// The stream position of the buffer's first byte.
    start: u64,

    /// The index of the next byte to tokenize.
    cursor: usize,

    /// For each hash, one plus the latest stream position with that hash, or zero.
    head: Box<[u64]>,

    /// For each position modulo the window, one plus the previous position with its hash, or zero.
    previous: Box<[u64]>,
}

impl Default for Matcher {
    fn default() -> Self {
        Self {
            buffer: Vec::with_capacity(CAPACITY),
            start: 0,
            cursor: 0,
            head: vec![0; 1 << HASH_BITS].into_boxed_slice(),
            previous: vec![0; WINDOW].into_boxed_slice(),
        }
    }
}

impl Matcher {
    /// Takes as much input as the buffer has room for, and returns how much it took.
    ///
    /// Every pending token must have been drawn first, so a full buffer has history to drop.
    pub(super) fn fill(&mut self, input: &[u8]) -> usize {
        if self.buffer.len() == CAPACITY {
            self.slide();
        }
        let taken = input.len().min(CAPACITY - self.buffer.len());
        self.buffer.extend_from_slice(&input[..taken]);
        taken
    }

    /// Drops all but one window of history, making room for more input.
    fn slide(&mut self) {
        // Invariant: tokens are drawn until fewer than the lookahead remain.
        // A full buffer then has its cursor past 65536 - 261, so above one window.
        let dropped = self.cursor - WINDOW;
        self.buffer.copy_within(dropped.., 0);
        self.buffer.truncate(self.buffer.len() - dropped);
        self.cursor -= dropped;
        self.start += dropped as u64;
    }

    /// The next token, or none when more input is needed.
    ///
    /// Once the input has ended, the last bytes are drawn without waiting for a full lookahead.
    pub(super) fn next_token(&mut self, ended: bool) -> Option<Token> {
        let available = self.buffer.len() - self.cursor;
        if available == 0 || (!ended && available < LOOKAHEAD) {
            return None;
        }
        // Fewer than three bytes cannot start a match, and cannot be hashed.
        if available < MIN_MATCH {
            let literal = self.buffer[self.cursor];
            self.cursor += 1;
            return Some(Token::Literal(literal));
        }
        let hash = self.hash(self.cursor);
        let found = self.longest_match(hash, available.min(MAX_MATCH));
        self.insert(self.cursor, hash);
        match found {
            Some((length, distance)) => {
                // Every position inside the match becomes a future match start too.
                for offset in 1..length {
                    let at = self.cursor + offset;
                    if at + MIN_MATCH <= self.buffer.len() {
                        self.insert(at, self.hash(at));
                    }
                }
                self.cursor += length;
                // Bound: lengths stop at 258 and distances at 32768, both within 16 bits.
                Some(Token::Match {
                    length: length as u16,
                    distance: distance as u16,
                })
            }
            None => {
                let literal = self.buffer[self.cursor];
                self.cursor += 1;
                Some(Token::Literal(literal))
            }
        }
    }

    /// The hash of the three bytes at a buffer index.
    fn hash(&self, at: usize) -> usize {
        let prefix =
            u32::from_le_bytes([self.buffer[at], self.buffer[at + 1], self.buffer[at + 2], 0]);
        // The top bits of the product mix every input bit.
        (prefix.wrapping_mul(GOLDEN) >> (32 - HASH_BITS)) as usize
    }

    /// Records a buffer index as the latest position with its hash.
    fn insert(&mut self, at: usize, hash: usize) {
        let position = self.start + at as u64;
        self.previous[position as usize % WINDOW] = self.head[hash];
        self.head[hash] = position + 1;
    }

    /// The longest earlier match at the cursor, as a length and a distance.
    fn longest_match(&self, hash: usize, limit: usize) -> Option<(usize, usize)> {
        let position = self.start + self.cursor as u64;
        let ahead = &self.buffer[self.cursor..self.cursor + limit];
        let mut best = None;
        let mut best_length = MIN_MATCH - 1;
        let mut link = self.head[hash];
        for _ in 0..MAX_CHAIN {
            // Zero ends the chain.
            let Some(earlier) = link.checked_sub(1) else {
                break;
            };
            let distance = (position - earlier) as usize;
            // Chains run from newest to oldest, so the first one out of reach ends the walk.
            if distance > WINDOW {
                break;
            }
            // Invariant: one window of history precedes the cursor, so the index is in the buffer.
            let from = (earlier - self.start) as usize;
            // A match may overlap the cursor; the bytes it reads are all in the buffer.
            let length = self.buffer[from..]
                .iter()
                .zip(ahead)
                .take_while(|(a, b)| a == b)
                .count();
            if length > best_length {
                best_length = length;
                best = Some((length, distance));
                if length == limit {
                    break;
                }
            }
            // Invariant: the slot still holds this position's link.
            // A newer position in the slot would be a full window later, beyond the cursor.
            link = self.previous[earlier as usize % WINDOW];
        }
        best
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every token of an input written at once.
    fn tokens(input: &[u8]) -> Vec<Token> {
        let mut matcher = Matcher::default();
        let mut out = Vec::new();
        let mut rest = input;
        loop {
            let taken = matcher.fill(rest);
            rest = &rest[taken..];
            let ended = rest.is_empty();
            while let Some(token) = matcher.next_token(ended) {
                out.push(token);
            }
            if ended {
                return out;
            }
        }
    }

    #[test]
    fn repeats_become_overlapping_matches() {
        // "abcabcabc": three literals, then one six-byte copy from three back.
        assert_eq!(
            tokens(b"abcabcabc"),
            [
                Token::Literal(b'a'),
                Token::Literal(b'b'),
                Token::Literal(b'c'),
                Token::Match {
                    length: 6,
                    distance: 3
                },
            ]
        );
    }

    #[test]
    fn matches_start_inside_earlier_matches() {
        // "abcdef" twice, then "cdef".
        //
        //     "cdef" occurs at 2, inside the literals, and at 8, inside the first copy
        //
        // The copy's inner positions are indexed too, so the nearer occurrence wins.
        assert_eq!(
            tokens(b"abcdefabcdefcdef")[6..],
            [
                Token::Match {
                    length: 6,
                    distance: 6
                },
                Token::Match {
                    length: 4,
                    distance: 4
                },
            ]
        );
    }

    #[test]
    fn matches_never_reach_beyond_the_window() {
        // Fixture state: "xyz", then 32766 zeros, then "xyz" again.
        //
        //     distance from the second "xyz" to the first = 3 + 32766 = 32769
        //
        // One byte past the window, so the second "xyz" stays literal.
        let mut input = b"xyz".to_vec();
        input.resize(3 + 32766, 0);
        input.extend_from_slice(b"xyz");
        let tail = &tokens(&input)[..];
        assert_eq!(
            tail[tail.len() - 3..],
            [
                Token::Literal(b'x'),
                Token::Literal(b'y'),
                Token::Literal(b'z')
            ]
        );
    }

    #[test]
    fn matches_reach_the_window_edge() {
        // Fixture state: "xyz", then 32765 zeros, then "xyz" again.
        //
        //     distance from the second "xyz" to the first = 3 + 32765 = 32768
        //
        // Exactly the window, so the second "xyz" is one copy.
        let mut input = b"xyz".to_vec();
        input.resize(3 + 32765, 0);
        input.extend_from_slice(b"xyz");
        assert_eq!(
            tokens(&input).last(),
            Some(&Token::Match {
                length: 3,
                distance: 32768
            })
        );
    }
}
