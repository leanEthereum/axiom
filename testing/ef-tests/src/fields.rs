//! Field names of a container, for readable mismatch reports.

use axiom_ssz::Container;

use crate::Failure;

/// The names of a container's fields, in declaration order.
///
/// A state mismatch printed in full is unreadable.
/// Naming the fields whose roots differ points straight at the faulty step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldNames(pub &'static [&'static str]);

impl FieldNames {
    /// Compares two containers, naming the fields that differ.
    ///
    /// # Errors
    ///
    /// Fails when the containers differ.
    pub fn check<C: Container + PartialEq>(&self, expected: &C, actual: &C) -> Result<(), Failure> {
        if expected == actual {
            return Ok(());
        }
        let differing: Vec<String> = expected
            .field_roots()
            .iter()
            .zip(actual.field_roots())
            .enumerate()
            .filter(|(_, (left, right))| *left != right)
            .map(|(index, _)| {
                self.0
                    .get(index)
                    .map_or_else(|| format!("field {index}"), |name| (*name).to_owned())
            })
            .collect();
        Err(Failure(format!(
            "post-state differs in: {}",
            differing.join(", ")
        )))
    }
}
