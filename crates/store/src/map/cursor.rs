//! In-order traversal of a key range, from both ends.

use std::{ops::Bound, sync::Arc};

use super::{Node, range::KeyRange};

/// A double-ended iterator over the nodes of a map whose keys fall within two bounds.
///
/// The cursor owns reference-counted pointers to the nodes it will visit.
/// It therefore keeps iterating the tree it started on, whatever writes follow.
///
/// # Algorithm
///
/// Each end keeps a stack holding the path of nodes not yet visited.
///
/// Take a tree with root d, children b and f, and c as the right child of b.
/// Seeking the lower bound "c" fills the front stack in three steps:
///
/// 1. At d, d >= c, so push d and go left.
/// 2. At b, b < c, so skip b and go right.
/// 3. At c, c >= c, so push c and go left.
///
/// ```text
///     stack = [d, c]
/// ```
///
/// Advancing then pops c, and pushes the leftmost path of the right subtree of c.
///
/// The two ends stop when they meet: the front never yields a key at or past the back's last key.
///
/// # Performance
///
/// Seeking costs O(log n), each step is amortized O(1), and the stacks hold O(log n) pointers.
pub(crate) struct Cursor<V> {
    /// Unvisited nodes for the ascending end, the next one on top.
    front: Vec<Arc<Node<V>>>,
    /// Unvisited nodes for the descending end, the next one on top.
    back: Vec<Arc<Node<V>>>,
    /// The bounds both ends must respect.
    range: KeyRange,
    /// Last node yielded by the ascending end.
    last_front: Option<Arc<Node<V>>>,
    /// Last node yielded by the descending end.
    last_back: Option<Arc<Node<V>>>,
}

impl<V> Cursor<V> {
    /// Seeks both ends of the range in a tree.
    pub(super) fn new(
        root: Option<&Arc<Node<V>>>,
        lower: Bound<&[u8]>,
        upper: Bound<&[u8]>,
    ) -> Self {
        let range = KeyRange::new(lower, upper);

        let mut front = Vec::new();
        let mut node = root;
        while let Some(current) = node {
            if range.above_lower(&current.key) {
                // In range from below: visit it after everything on its left.
                front.push(Arc::clone(current));
                node = current.left.as_ref();
            } else {
                // Below the range: only its right subtree can hold keys in range.
                node = current.right.as_ref();
            }
        }

        let mut back = Vec::new();
        let mut node = root;
        while let Some(current) = node {
            if range.below_upper(&current.key) {
                // Mirror image: visit it after everything on its right.
                back.push(Arc::clone(current));
                node = current.right.as_ref();
            } else {
                node = current.left.as_ref();
            }
        }

        Self {
            front,
            back,
            range,
            last_front: None,
            last_back: None,
        }
    }

    /// Ends the traversal at both ends.
    fn finish(&mut self) {
        self.front.clear();
        self.back.clear();
    }

    /// Pushes a subtree's path of left children, its smallest keys last.
    fn push_left_spine(&mut self, mut link: Option<&Arc<Node<V>>>) {
        while let Some(node) = link {
            self.front.push(Arc::clone(node));
            link = node.left.as_ref();
        }
    }

    /// Pushes a subtree's path of right children, its largest keys last.
    fn push_right_spine(&mut self, mut link: Option<&Arc<Node<V>>>) {
        while let Some(node) = link {
            self.back.push(Arc::clone(node));
            link = node.right.as_ref();
        }
    }
}

impl<V> Iterator for Cursor<V> {
    type Item = Arc<Node<V>>;

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.front.pop()?;
        // The in-order successor is the smallest key of the right subtree.
        self.push_left_spine(node.right.as_ref());

        // Stop past the upper bound, or where the descending end already went.
        let past_upper = !self.range.below_upper(&node.key);
        let met_back = self
            .last_back
            .as_ref()
            .is_some_and(|back| node.key >= back.key);
        if past_upper || met_back {
            self.finish();
            return None;
        }
        self.last_front = Some(Arc::clone(&node));
        Some(node)
    }
}

impl<V> DoubleEndedIterator for Cursor<V> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let node = self.back.pop()?;
        // The in-order predecessor is the largest key of the left subtree.
        self.push_right_spine(node.left.as_ref());

        let past_lower = !self.range.above_lower(&node.key);
        let met_front = self
            .last_front
            .as_ref()
            .is_some_and(|front| node.key <= front.key);
        if past_lower || met_front {
            self.finish();
            return None;
        }
        self.last_back = Some(Arc::clone(&node));
        Some(node)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use proptest::prelude::*;

    use super::{super::Map, *};

    fn bound() -> impl Strategy<Value = Bound<Vec<u8>>> {
        let key = proptest::collection::vec(0u8..4, 0..3);
        prop_oneof![
            key.clone().prop_map(Bound::Included),
            key.prop_map(Bound::Excluded),
            Just(Bound::Unbounded),
        ]
    }

    proptest! {
        #[test]
        fn range_matches_btreemap_from_both_ends(
            keys in proptest::collection::btree_set(proptest::collection::vec(0u8..4, 0..3), 0..40),
            lower in bound(),
            upper in bound(),
            directions in proptest::collection::vec(any::<bool>(), 0..50),
        ) {
            // Build the same key set in the map and the reference.
            let mut map = Map::new();
            let mut model = BTreeMap::new();
            for (i, key) in keys.iter().enumerate() {
                map.insert(key, i);
                model.insert(key.clone(), i);
            }

            // An inverted or empty range must yield nothing rather than panic.
            let lower = lower.as_ref().map(Vec::as_slice);
            let upper = upper.as_ref().map(Vec::as_slice);
            let valid = match (lower, upper) {
                (Bound::Included(a), Bound::Included(b)) => a <= b,
                (Bound::Included(a) | Bound::Excluded(a), Bound::Included(b) | Bound::Excluded(b)) => a < b,
                _ => true,
            };
            let expected: Vec<Vec<u8>> = if valid {
                model.range::<[u8], _>((lower, upper)).map(|(k, _)| k.clone()).collect()
            } else {
                Vec::new()
            };

            // Interleave front and back steps in a random pattern.
            //
            //     directions [true, false, true] -> next, next_back, next, then drain fronts
            let mut cursor = map.range(lower, upper);
            let mut from_front = Vec::new();
            let mut from_back = Vec::new();
            for forward in directions {
                let step = if forward { cursor.next() } else { cursor.next_back() };
                match step {
                    Some(node) if forward => from_front.push(node.key().to_vec()),
                    Some(node) => from_back.push(node.key().to_vec()),
                    None => break,
                }
            }
            from_front.extend(cursor.map(|node| node.key().to_vec()));
            from_back.reverse();
            from_front.extend(from_back);

            // Every key of the range appears exactly once, in ascending order.
            prop_assert_eq!(from_front, expected);
        }
    }
}
