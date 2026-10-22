//! The two bounds of a key range.

use std::ops::Bound;

/// A lower and an upper bound on byte-wise ordered keys, owned by the cursor that walks them.
///
/// Either bound may be inclusive, exclusive, or absent.
/// An inverted range admits no key, since no key passes both checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct KeyRange {
    /// The bound every key must reach from below.
    lower: Bound<Box<[u8]>>,
    /// The bound every key must stay within from above.
    upper: Bound<Box<[u8]>>,
}

impl KeyRange {
    /// Copies two borrowed bounds into a range.
    pub(super) fn new(lower: Bound<&[u8]>, upper: Bound<&[u8]>) -> Self {
        Self {
            lower: lower.map(Box::from),
            upper: upper.map(Box::from),
        }
    }

    /// Returns whether a key respects the lower bound.
    pub(super) fn above_lower(&self, key: &[u8]) -> bool {
        match &self.lower {
            Bound::Included(bound) => key >= &**bound,
            Bound::Excluded(bound) => key > &**bound,
            Bound::Unbounded => true,
        }
    }

    /// Returns whether a key respects the upper bound.
    pub(super) fn below_upper(&self, key: &[u8]) -> bool {
        match &self.upper {
            Bound::Included(bound) => key <= &**bound,
            Bound::Excluded(bound) => key < &**bound,
            Bound::Unbounded => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_admit_keys_by_kind() {
        // The range from "b" inclusive to "d" exclusive.
        let range = KeyRange::new(Bound::Included(b"b"), Bound::Excluded(b"d"));

        // "a" falls below, "b" sits on the inclusive bound, "c" is inside.
        assert!(!range.above_lower(b"a"));
        assert!(range.above_lower(b"b"));
        assert!(range.above_lower(b"c") && range.below_upper(b"c"));

        // "d" sits on the exclusive bound, so it is out.
        assert!(!range.below_upper(b"d"));

        // An unbounded range admits the empty key at both ends.
        let all = KeyRange::new(Bound::Unbounded, Bound::Unbounded);
        assert!(all.above_lower(b"") && all.below_upper(b""));
    }
}
