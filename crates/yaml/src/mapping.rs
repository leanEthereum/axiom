//! An ordered mapping from string keys to values.

use std::{collections::HashMap, fmt, iter::FusedIterator, mem, slice};

use crate::Yaml;

/// Keys and values in document order, with constant-time lookup by key.
///
/// Keys are the text of scalars, so `1`, `'1'`, and `"1"` are the same key.
/// Keys are unique.
#[derive(Clone, Default)]
pub struct Mapping {
    /// The entries, in the order they were inserted.
    entries: Vec<(String, Yaml)>,
    /// Position of each key's entry.
    index: HashMap<String, usize>,
}

impl Mapping {
    /// An empty mapping.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the mapping has no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The value stored under a key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Yaml> {
        self.index.get(key).map(|&i| &self.entries[i].1)
    }

    /// Whether a key is present.
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.index.contains_key(key)
    }

    /// Stores a value under a key and returns the value it replaces.
    ///
    /// A new key goes last.
    /// A present key keeps its position and takes the new value.
    pub fn insert(&mut self, key: impl Into<String>, value: Yaml) -> Option<Yaml> {
        let key = key.into();
        match self.index.get(&key) {
            // The key exists: swap the value in place, so document order holds.
            Some(&i) => Some(mem::replace(&mut self.entries[i].1, value)),
            None => {
                self.index.insert(key.clone(), self.entries.len());
                self.entries.push((key, value));
                None
            }
        }
    }

    /// The entries in document order.
    #[must_use]
    pub fn iter(&self) -> Iter<'_> {
        Iter {
            inner: self.entries.iter(),
        }
    }
}

impl PartialEq for Mapping {
    fn eq(&self, other: &Self) -> bool {
        // The index is derived from the entries, so the entries decide equality.
        // Order is part of a document, so it takes part.
        self.entries == other.entries
    }
}

impl Eq for Mapping {}

impl fmt::Debug for Mapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

impl<'a> IntoIterator for &'a Mapping {
    type Item = (&'a str, &'a Yaml);
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

/// Iterator over the entries of a mapping, in document order.
#[derive(Clone, Debug)]
pub struct Iter<'a> {
    /// The underlying entries.
    inner: slice::Iter<'a, (String, Yaml)>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = (&'a str, &'a Yaml);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(key, value)| (key.as_str(), value))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl DoubleEndedIterator for Iter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner
            .next_back()
            .map(|(key, value)| (key.as_str(), value))
    }
}

impl ExactSizeIterator for Iter<'_> {}

impl FusedIterator for Iter<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_keeps_document_order_and_replaces_in_place() {
        // Fixture state: b then a, inserted in that order.
        let mut mapping = Mapping::new();
        assert_eq!(mapping.insert("b", Yaml::Null), None);
        assert_eq!(mapping.insert("a", Yaml::Bool(true)), None);

        // Replacing b returns the old value and keeps b first.
        //
        //     before: [b: null, a: true]
        //     after:  [b: "x",  a: true]
        let old = mapping.insert("b", Yaml::String("x".into()));
        assert_eq!(old, Some(Yaml::Null));

        let entries: Vec<_> = mapping.iter().collect();
        assert_eq!(
            entries,
            [("b", &Yaml::String("x".into())), ("a", &Yaml::Bool(true))]
        );
        assert_eq!(mapping.len(), 2);
        assert!(mapping.contains_key("a"));
        assert_eq!(mapping.get("c"), None);
    }

    #[test]
    fn equality_depends_on_order() {
        // Same entries, opposite order: two different documents.
        let mut ab = Mapping::new();
        ab.insert("a", Yaml::Null);
        ab.insert("b", Yaml::Null);
        let mut ba = Mapping::new();
        ba.insert("b", Yaml::Null);
        ba.insert("a", Yaml::Null);

        assert_ne!(ab, ba);
        assert_eq!(ab, ab.clone());
    }

    #[test]
    fn iterator_runs_both_ways_with_exact_size() {
        let mut mapping = Mapping::new();
        mapping.insert("x", Yaml::Null);
        mapping.insert("y", Yaml::Null);

        // Two entries: the iterator knows its length and walks from either end.
        let mut iter = mapping.iter();
        assert_eq!(iter.len(), 2);
        assert_eq!(iter.next_back().map(|(k, _)| k), Some("y"));
        assert_eq!(iter.next().map(|(k, _)| k), Some("x"));
        assert_eq!(iter.next(), None);
    }
}
