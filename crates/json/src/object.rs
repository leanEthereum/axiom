//! JSON objects, which keep their members in document order.

use std::{mem, slice};

use crate::Json;

/// The members of a JSON object, in insertion order, with unique names.
///
/// Order is kept so that a value serializes back to the bytes it was parsed from.
/// Lookup is a linear scan, which beats hashing for the few members RPC objects carry.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Object {
    /// Name and value pairs, no two names equal.
    members: Vec<(String, Json)>,
}

impl Object {
    /// An object without members.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            members: Vec::new(),
        }
    }

    /// Number of members.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether the object has no members.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// The value of a member, when present.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Json> {
        // Scan in order; names are unique, so the first match is the only one.
        self.members
            .iter()
            .find(|(member, _)| member == name)
            .map(|(_, value)| value)
    }

    /// The value of a member, for changing it in place.
    #[must_use]
    pub fn get_mut(&mut self, name: &str) -> Option<&mut Json> {
        self.members
            .iter_mut()
            .find(|(member, _)| member == name)
            .map(|(_, value)| value)
    }

    /// Sets a member, keeping its position when it already exists.
    ///
    /// # Returns
    ///
    /// The value the member held before, if any.
    pub fn insert(&mut self, name: impl Into<String>, value: Json) -> Option<Json> {
        let name = name.into();
        // Replace in place so a known member does not move to the end.
        if let Some((_, slot)) = self.members.iter_mut().find(|(member, _)| *member == name) {
            return Some(mem::replace(slot, value));
        }
        // A new name goes last, in insertion order.
        self.members.push((name, value));
        None
    }

    /// Removes a member and returns its value, keeping the order of the rest.
    pub fn remove(&mut self, name: &str) -> Option<Json> {
        // Find the position, then shift the later members down by one.
        let position = self.members.iter().position(|(member, _)| member == name)?;
        Some(self.members.remove(position).1)
    }

    /// The members, in order.
    pub fn iter(&self) -> slice::Iter<'_, (String, Json)> {
        self.members.iter()
    }

    /// Appends a member the caller knows to be new.
    ///
    /// The parser checks names for uniqueness once the object closes.
    pub(crate) fn push_unchecked(&mut self, name: String, value: Json) {
        self.members.push((name, value));
    }

    /// The members as a slice, for the parser's uniqueness check.
    pub(crate) fn members(&self) -> &[(String, Json)] {
        &self.members
    }
}

impl<'a> IntoIterator for &'a Object {
    type Item = &'a (String, Json);
    type IntoIter = slice::Iter<'a, (String, Json)>;

    fn into_iter(self) -> Self::IntoIter {
        self.members.iter()
    }
}

impl<K: Into<String>> FromIterator<(K, Json)> for Object {
    /// Collects members in order; a repeated name keeps its first position and last value.
    fn from_iter<I: IntoIterator<Item = (K, Json)>>(iter: I) -> Self {
        let mut object = Self::new();
        // Insert one by one so that names stay unique.
        for (name, value) in iter {
            object.insert(name, value);
        }
        object
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_replaces_in_place() {
        // Start with members a, b, c in that order.
        let mut object: Object = [("a", Json::Null), ("b", Json::Null), ("c", Json::Null)]
            .into_iter()
            .collect();

        // Setting b again returns the old null and keeps b in the middle.
        assert_eq!(object.insert("b", Json::Bool(true)), Some(Json::Null));
        let names: Vec<&str> = object.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["a", "b", "c"]);
        assert_eq!(object.get("b"), Some(&Json::Bool(true)));

        // Removing a shifts b and c down; the length drops from 3 to 2.
        assert_eq!(object.remove("a"), Some(Json::Null));
        assert_eq!(object.len(), 2);
        assert_eq!(object.get("a"), None);
    }
}
