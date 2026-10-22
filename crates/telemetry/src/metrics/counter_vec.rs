//! Counters split by label values.

use std::sync::Arc;

use crate::metrics::{Counter, family::Family};

/// A counter per tuple of label values, with a fixed number of labels.
///
/// The label count is part of the type, so a lookup with the wrong arity does not compile.
#[derive(Clone, Debug)]
pub struct CounterVec<const N: usize> {
    /// The children, shared with the registry.
    family: Arc<Family<Counter>>,
}

impl<const N: usize> CounterVec<N> {
    /// Wraps a family the registry built with exactly this many labels.
    pub(crate) const fn new(family: Arc<Family<Counter>>) -> Self {
        Self { family }
    }

    /// The counter for these label values, created at zero on first use.
    #[must_use]
    pub fn with_label_values(&self, values: [&str; N]) -> Counter {
        // The array length matches the label count fixed at registration.
        self.family.child(&values, Counter::new)
    }
}
