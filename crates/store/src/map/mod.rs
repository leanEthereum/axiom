//! A persistent ordered map from byte keys to values.
//!
//! # Overview
//!
//! The map is an AVL tree whose nodes are reference-counted and shared between copies.
//! Cloning the map clones one pointer, so a snapshot of the whole index costs O(1).
//!
//! A write never changes a node that another copy can see.
//! It copies the nodes on the path from the root to the change, "path copying".
//! A node nobody else holds is mutated in place instead, so writes without snapshots allocate nothing.
//!
//! ```text
//!     insert "e" while a snapshot holds the old root
//!
//!        snapshot             live
//!           |                   |
//!          (d)                 (d')       d' and f' are fresh copies
//!         /   \               /    \
//!       (b)   (f)          (b)     (f')   b is one node, shared by both trees
//!                                  /
//!                                (e)
//! ```
//!
//! The copied path has O(log n) nodes, so a write after a snapshot costs O(log n) allocations.
//!
//! # Invariants
//!
//! - Keys are strictly increasing in in-order traversal.
//! - Each node's height is one more than the taller child's, leaves at one.
//! - Sibling subtree heights differ by at most one, so the height is below 1.45 log_2(n + 2).
//!
//! See Adelson-Velsky and Landis, "An algorithm for the organization of information", 1962.
//! See Driscoll, Sarnak, Sleator and Tarjan, "Making data structures persistent", 1989.

mod cursor;
mod range;

use std::{cmp::Ordering, fmt, mem, ops::Bound, sync::Arc};

pub(crate) use cursor::Cursor;

/// An optional shared subtree.
type Link<V> = Option<Arc<Node<V>>>;

/// One key and its value, with its two subtrees.
#[derive(Clone)]
pub(crate) struct Node<V> {
    /// The key, ordered byte-wise.
    key: Box<[u8]>,
    /// The value bound to the key.
    value: V,
    /// Height of the subtree rooted here, one for a leaf.
    height: u8,
    /// Subtree of smaller keys.
    left: Link<V>,
    /// Subtree of larger keys.
    right: Link<V>,
}

impl<V> Node<V> {
    /// Returns the key of this node.
    pub(crate) fn key(&self) -> &[u8] {
        &self.key
    }

    /// Returns the value of this node.
    pub(crate) const fn value(&self) -> &V {
        &self.value
    }

    /// Returns the height of a possibly empty subtree.
    fn height(link: Option<&Arc<Self>>) -> u8 {
        link.as_ref().map_or(0, |node| node.height)
    }

    /// Recomputes this node's height from its children.
    fn fix_height(&mut self) {
        self.height = 1 + Self::height(self.left.as_ref()).max(Self::height(self.right.as_ref()));
    }

    /// Returns the left height minus the right height.
    fn balance(&self) -> i16 {
        i16::from(Self::height(self.left.as_ref())) - i16::from(Self::height(self.right.as_ref()))
    }
}

impl<V: Clone> Node<V> {
    /// Inserts into a subtree, returning the value the key had.
    fn insert(link: &mut Link<V>, key: &[u8], value: V) -> Option<V> {
        // An empty subtree becomes a single leaf.
        let Some(node) = link else {
            *link = Some(Arc::new(Self {
                key: key.into(),
                value,
                height: 1,
                left: None,
                right: None,
            }));
            return None;
        };

        // Take ownership of this node: in place if unshared, otherwise a copy.
        let inner = Arc::make_mut(node);
        let previous = match key.cmp(&inner.key) {
            Ordering::Less => Self::insert(&mut inner.left, key, value),
            Ordering::Greater => Self::insert(&mut inner.right, key, value),
            // Same key: swap the value, the shape does not change.
            Ordering::Equal => return Some(mem::replace(&mut inner.value, value)),
        };

        // A new leaf may have grown this subtree by one level.
        Self::rebalance(node);
        previous
    }

    /// Removes a key known to be present from a subtree, returning its value.
    fn remove(link: &mut Link<V>, key: &[u8]) -> Option<V> {
        let node = link.as_mut()?;
        let inner = Arc::make_mut(node);
        match key.cmp(&inner.key) {
            Ordering::Less => {
                let removed = Self::remove(&mut inner.left, key);
                Self::rebalance(node);
                removed
            }
            Ordering::Greater => {
                let removed = Self::remove(&mut inner.right, key);
                Self::rebalance(node);
                removed
            }
            Ordering::Equal => {
                // Detach both children, then decide what takes this node's place.
                let replacement = match (inner.left.take(), inner.right.take()) {
                    // Zero or one child: the child itself moves up.
                    (None, child) | (child, None) => child,
                    // Two children: the in-order successor moves up.
                    //
                    //         (k)               (s)
                    //        /   \     ->      /   \
                    //      (a)   (r)         (a)   (r without s)
                    //            /
                    //          (s)  smallest key above k
                    (Some(left), right) => {
                        let mut right = right;
                        let mut successor = Self::take_min(&mut right)?;
                        let lifted = Arc::make_mut(&mut successor);
                        lifted.left = Some(left);
                        lifted.right = right;
                        Self::rebalance(&mut successor);
                        Some(successor)
                    }
                };
                let removed = mem::replace(link, replacement)?;
                // The detached node has no children left, so unwrapping it is cheap.
                Some(
                    Arc::try_unwrap(removed)
                        .map_or_else(|shared| shared.value.clone(), |own| own.value),
                )
            }
        }
    }

    /// Detaches the node with the smallest key of a non-empty subtree.
    ///
    /// The returned node keeps no left child; its right child is spliced into its place.
    fn take_min(link: &mut Link<V>) -> Option<Arc<Self>> {
        let node = link.as_mut()?;
        if node.left.is_some() {
            // The minimum lies further left; recurse, then restore balance on the way up.
            let minimum = Self::take_min(&mut Arc::make_mut(node).left);
            Self::rebalance(node);
            return minimum;
        }

        // This node is the minimum: its right subtree takes its place.
        let mut minimum = link.take()?;
        *link = Arc::make_mut(&mut minimum).right.take();
        Some(minimum)
    }

    /// Restores the height and balance of a subtree whose children are balanced.
    fn rebalance(node: &mut Arc<Self>) {
        let inner = Arc::make_mut(node);
        inner.fix_height();
        let balance = inner.balance();

        if balance > 1 {
            // Left-heavy. A right-leaning left child needs a first rotation.
            //
            //     left-right case:   (c)          (c)          (b)
            //                        /            /            / \
            //                      (a)    ->    (b)    ->    (a) (c)
            //                        \          /
            //                        (b)      (a)
            if let Some(left) = inner.left.as_mut()
                && left.balance() < 0
            {
                Self::rotate_left(left);
            }
            Self::rotate_right(node);
        } else if balance < -1 {
            // Right-heavy, the mirror image.
            if let Some(right) = inner.right.as_mut()
                && right.balance() > 0
            {
                Self::rotate_right(right);
            }
            Self::rotate_left(node);
        }
    }

    /// Lifts the left child above this node.
    ///
    /// ```text
    ///         (y)              (x)
    ///         / \              / \
    ///       (x)  C    ->      A  (y)
    ///       / \                  / \
    ///      A   B                B   C
    /// ```
    fn rotate_right(node: &mut Arc<Self>) {
        let inner = Arc::make_mut(node);
        // Invariant: a left-heavy node has a left child, so this never returns early.
        let Some(mut pivot) = inner.left.take() else {
            return;
        };
        // Subtree B changes parent from x to y.
        inner.left = Arc::make_mut(&mut pivot).right.take();
        inner.fix_height();
        // Swap so that x is the subtree root and y hangs on its right.
        mem::swap(node, &mut pivot);
        let top = Arc::make_mut(node);
        top.right = Some(pivot);
        top.fix_height();
    }

    /// Lifts the right child above this node, the mirror of the right rotation.
    fn rotate_left(node: &mut Arc<Self>) {
        let inner = Arc::make_mut(node);
        // Invariant: a right-heavy node has a right child, so this never returns early.
        let Some(mut pivot) = inner.right.take() else {
            return;
        };
        inner.right = Arc::make_mut(&mut pivot).left.take();
        inner.fix_height();
        mem::swap(node, &mut pivot);
        let top = Arc::make_mut(node);
        top.left = Some(pivot);
        top.fix_height();
    }
}

/// A persistent ordered map from byte keys to values.
pub(crate) struct Map<V> {
    /// The root of the tree.
    root: Link<V>,
    /// Number of keys.
    len: usize,
}

impl<V> Map<V> {
    /// Creates an empty map.
    pub(crate) const fn new() -> Self {
        Self { root: None, len: 0 }
    }

    /// Returns the number of keys.
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    /// Returns the value bound to a key.
    pub(crate) fn get(&self, key: &[u8]) -> Option<&V> {
        // Descend one level per comparison: at most 1.45 log_2(n) steps.
        let mut link = &self.root;
        while let Some(node) = link {
            link = match key.cmp(&node.key) {
                Ordering::Less => &node.left,
                Ordering::Greater => &node.right,
                Ordering::Equal => return Some(&node.value),
            };
        }
        None
    }

    /// Returns a double-ended cursor over the keys within two bounds.
    pub(crate) fn range(&self, lower: Bound<&[u8]>, upper: Bound<&[u8]>) -> Cursor<V> {
        Cursor::new(self.root.as_ref(), lower, upper)
    }
}

impl<V: Clone> Map<V> {
    /// Binds a key to a value, returning the value it had.
    pub(crate) fn insert(&mut self, key: &[u8], value: V) -> Option<V> {
        let previous = Node::insert(&mut self.root, key, value);
        if previous.is_none() {
            self.len += 1;
        }
        previous
    }

    /// Removes a key, returning the value it had.
    pub(crate) fn remove(&mut self, key: &[u8]) -> Option<V> {
        // Searching first avoids copying a shared path for a key that is absent.
        self.get(key)?;
        let removed = Node::remove(&mut self.root, key);
        if removed.is_some() {
            self.len -= 1;
        }
        removed
    }
}

impl<V> Clone for Map<V> {
    fn clone(&self) -> Self {
        // One reference count increment: the whole tree is shared.
        Self {
            root: self.root.clone(),
            len: self.len,
        }
    }
}

impl<V> Default for Map<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> fmt::Debug for Map<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Map")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use proptest::prelude::*;

    use super::*;

    /// Checks ordering, heights and balance of every subtree, returning its height.
    fn check_subtree(
        link: Option<&Arc<Node<u32>>>,
        lower: Option<&[u8]>,
        upper: Option<&[u8]>,
    ) -> u8 {
        let Some(node) = link else { return 0 };
        // Ordering: every key sits strictly between the bounds inherited from ancestors.
        assert!(lower.is_none_or(|bound| node.key() > bound));
        assert!(upper.is_none_or(|bound| node.key() < bound));
        let left = check_subtree(node.left.as_ref(), lower, Some(node.key()));
        let right = check_subtree(node.right.as_ref(), Some(node.key()), upper);
        // Balance: sibling heights differ by at most one.
        assert!(left.abs_diff(right) <= 1);
        // Height: one above the taller child.
        assert_eq!(node.height, 1 + left.max(right));
        node.height
    }

    #[derive(Clone, Debug)]
    enum Op {
        Insert(Vec<u8>, u32),
        Remove(Vec<u8>),
        Snapshot,
    }

    fn op() -> impl Strategy<Value = Op> {
        // Two-byte keys over a small alphabet make collisions and removals of present keys common.
        let key = proptest::collection::vec(0u8..4, 0..3);
        prop_oneof![
            4 => (key.clone(), any::<u32>()).prop_map(|(k, v)| Op::Insert(k, v)),
            3 => key.prop_map(Op::Remove),
            1 => Just(Op::Snapshot),
        ]
    }

    proptest! {
        #[test]
        fn matches_btreemap_and_snapshots_never_change(ops in proptest::collection::vec(op(), 0..200)) {
            // The live map and a reference model receive the same operations.
            let mut map = Map::new();
            let mut model = BTreeMap::new();
            // Each snapshot is frozen next to a copy of the model at the same moment.
            let mut snapshots = Vec::new();

            for op in ops {
                match op {
                    Op::Insert(key, value) => {
                        prop_assert_eq!(map.insert(&key, value), model.insert(key, value));
                    }
                    Op::Remove(key) => {
                        prop_assert_eq!(map.remove(&key), model.remove(&key));
                    }
                    Op::Snapshot => snapshots.push((map.clone(), model.clone())),
                }
                // Structure: the tree stays a balanced search tree after every write.
                check_subtree(map.root.as_ref(), None, None);
                prop_assert_eq!(map.len(), model.len());
            }

            // Persistence: every snapshot still holds exactly what the model held then.
            snapshots.push((map, model));
            for (snapshot, frozen) in &snapshots {
                let entries: Vec<_> = snapshot
                    .range(Bound::Unbounded, Bound::Unbounded)
                    .map(|node| (node.key().to_vec(), *node.value()))
                    .collect();
                let expected: Vec<_> = frozen.iter().map(|(k, v)| (k.clone(), *v)).collect();
                prop_assert_eq!(entries, expected);
            }
        }
    }

    #[test]
    fn sequential_inserts_stay_logarithmic() {
        // 100_000 ascending keys: the worst case for an unbalanced tree.
        let mut map = Map::new();
        for i in 0u32..100_000 {
            map.insert(&i.to_be_bytes(), i);
        }
        // AVL bound: height < 1.45 log_2(100_002) ~ 24.1.
        let height = check_subtree(map.root.as_ref(), None, None);
        assert!(height <= 24, "height {height}");
        assert_eq!(map.get(&77_777u32.to_be_bytes()), Some(&77_777));
    }
}
