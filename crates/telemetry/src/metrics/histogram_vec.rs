//! Histograms split by label values.

use std::sync::Arc;

use crate::metrics::{Buckets, Histogram, family::Family};

/// A histogram per tuple of label values, all over the same buckets.
///
/// The label count is part of the type, so a lookup with the wrong arity does not compile.
#[derive(Clone, Debug)]
pub struct HistogramVec<const N: usize> {
    /// The children, shared with the registry.
    family: Arc<Family<Histogram>>,

    /// The bounds every new child is built over.
    buckets: Buckets,
}

impl<const N: usize> HistogramVec<N> {
    /// Wraps a family the registry built with exactly this many labels.
    pub(crate) const fn new(family: Arc<Family<Histogram>>, buckets: Buckets) -> Self {
        Self { family, buckets }
    }

    /// The histogram for these label values, created empty on first use.
    #[must_use]
    pub fn with_label_values(&self, values: [&str; N]) -> Histogram {
        // New children share the bound list; only the counts are fresh.
        self.family
            .child(&values, || Histogram::new(self.buckets.clone()))
    }
}
