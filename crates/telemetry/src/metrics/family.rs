//! A set of series of one metric, told apart by label values.

use std::{
    cmp::Ordering,
    sync::{PoisonError, RwLock},
};

use crate::metrics::name::LabelName;

/// One child metric per distinct tuple of label values.
///
/// # Overview
///
/// Label names are fixed at registration; values are chosen at each lookup.
///
/// ```text
///     names     topic           outcome
///     child 1   beacon_block    accept     -> its own counter
///     child 2   beacon_block    reject     -> its own counter
/// ```
///
/// # Performance
///
/// Children are kept sorted by values, so a lookup is a binary search under a read lock.
/// A hit allocates nothing.
/// Hot paths should still keep the child handle rather than look it up per event.
#[derive(Debug)]
pub(crate) struct Family<M> {
    /// The label names, in declaration order.
    names: Box<[LabelName]>,

    /// The children, sorted by their label values.
    children: RwLock<Vec<(Box<[String]>, M)>>,
}

impl<M: Clone> Family<M> {
    /// An empty family over these label names.
    pub(crate) const fn new(names: Box<[LabelName]>) -> Self {
        Self {
            names,
            children: RwLock::new(Vec::new()),
        }
    }

    /// The label names, in declaration order.
    pub(crate) fn names(&self) -> &[LabelName] {
        &self.names
    }

    /// The child for these values, created by a constructor on first use.
    ///
    /// The caller guarantees one value per label name.
    pub(crate) fn child(&self, values: &[&str], make: impl FnOnce() -> M) -> M {
        // Fast path: the child exists and a shared lock suffices.
        // A poisoned lock still holds a valid list, since no update panics midway.
        {
            let children = self.children.read().unwrap_or_else(PoisonError::into_inner);
            if let Ok(index) = children.binary_search_by(|(key, _)| compare(key, values)) {
                return children[index].1.clone();
            }
        }

        // Slow path: take the write lock and search again.
        // Another thread may have inserted the same child between the two locks.
        let mut children = self
            .children
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        match children.binary_search_by(|(key, _)| compare(key, values)) {
            Ok(index) => children[index].1.clone(),
            Err(index) => {
                // Insert at the sorted position, keeping later searches valid.
                let key = values.iter().map(|value| (*value).to_owned()).collect();
                let metric = make();
                children.insert(index, (key, metric.clone()));
                metric
            }
        }
    }

    /// A copy of every child with its values, sorted by values.
    pub(crate) fn children(&self) -> Vec<(Box<[String]>, M)> {
        // Clone handles under the lock, so formatting happens without it.
        self.children
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// Orders a stored key against looked-up values, element by element.
fn compare(key: &[String], values: &[&str]) -> Ordering {
    // Lexicographic order over the tuple, matching the order children are stored in.
    key.iter().map(String::as_str).cmp(values.iter().copied())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::Counter;

    #[test]
    fn one_child_per_value_tuple() {
        // A family with two labels.
        let names = LabelName::parse_all(&["topic", "outcome"], &[]).expect("valid labels");
        let family: Family<Counter> = Family::new(names);

        // The same tuple twice yields the same series; the second lookup sees the first add.
        family.child(&["block", "accept"], Counter::new).inc();
        family.child(&["block", "accept"], Counter::new).inc();
        // A different tuple is a separate series.
        family.child(&["attestation", "reject"], Counter::new).inc();

        // Children come back sorted: "attestation" before "block".
        let children: Vec<(Vec<String>, u64)> = family
            .children()
            .into_iter()
            .map(|(key, counter)| (key.into_vec(), counter.get()))
            .collect();
        assert_eq!(
            children,
            vec![
                (vec!["attestation".to_owned(), "reject".to_owned()], 1),
                (vec!["block".to_owned(), "accept".to_owned()], 2),
            ]
        );
    }
}
