//! The storage behind every persistent collection: shared packs with cached roots.

use std::{
    fmt,
    hash::{Hash, Hasher},
    mem,
    ops::{Bound, Index, RangeBounds},
    sync::{Arc, OnceLock},
    vec,
};

use super::{
    iter::{Iter, IterMut},
    layout::{Layout, Shape},
    pack::Pack,
    threads::Threads,
};
use crate::{
    BYTES_PER_LENGTH_OFFSET, GeneralizedIndex, MerkleProof, Merkleizer, Root, Ssz,
    collections::Elements, offset::Offset,
};

/// A run of same-typed elements, stored as shared packs that each cache their subtree root.
///
/// It reads like a slice: length, indexing, and iteration.
/// Edits reach it only through the collection that owns it.
///
/// # Invariants
///
/// Every pack holds exactly its capacity, except the last, which is not empty.
/// The cached root, when set, is the root of the elements as they are now.
/// Every edit passes through one method, which clears it first.
pub struct Sequence<T> {
    /// The table of packs, shared with clones until one of them edits it.
    table: Arc<Table<T>>,
}

/// The packs of a sequence, with its length, layout, and cached root.
///
/// One pointer to it is the whole sequence, so a sequence is one word wide.
struct Table<T> {
    /// The packs, in order.
    packs: Vec<Arc<Pack<T>>>,
    /// Number of elements.
    len: usize,
    /// Pack boundaries and the tree shape, fixed by the owning collection.
    layout: Layout,
    /// Root of the elements' tree, before any length mix-in, computed on first use.
    root: OnceLock<Root>,
}

impl<T> Clone for Table<T> {
    /// Copies the pack pointers, sharing every pack.
    fn clone(&self) -> Self {
        Self {
            packs: self.packs.clone(),
            len: self.len,
            layout: self.layout,
            root: self.root.clone(),
        }
    }
}

impl<T> Sequence<T> {
    /// An empty sequence.
    pub(crate) fn empty(layout: Layout) -> Self {
        Self::from_packs(layout, Vec::new(), 0)
    }

    /// A sequence holding the given elements, moved into packs.
    pub(crate) fn from_vec(layout: Layout, items: Vec<T>) -> Self {
        let len = items.len();
        let mut packs = Vec::new();
        let mut rest = items.into_iter();
        loop {
            let pack: Vec<T> = rest.by_ref().take(layout.capacity(packs.len())).collect();
            if pack.is_empty() {
                break;
            }
            packs.push(Arc::new(Pack::new(pack)));
        }
        Self::from_packs(layout, packs, len)
    }

    /// A sequence over packs holding that many elements in total.
    fn from_packs(layout: Layout, packs: Vec<Arc<Pack<T>>>, len: usize) -> Self {
        Self {
            table: Arc::new(Table {
                packs,
                len,
                layout,
                root: OnceLock::new(),
            }),
        }
    }

    /// Number of elements.
    #[must_use]
    pub fn len(&self) -> usize {
        self.table.len
    }

    /// Whether there are no elements.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.table.len == 0
    }

    /// The element at an index, if there is one.
    #[inline]
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&T> {
        if index >= self.table.len {
            return None;
        }
        let (pack, position) = self.table.layout.locate(index);
        self.table.packs.get(pack)?.items().get(position)
    }

    /// The first element, if there is one.
    #[must_use]
    pub fn first(&self) -> Option<&T> {
        self.get(0)
    }

    /// The last element, if there is one.
    #[must_use]
    pub fn last(&self) -> Option<&T> {
        self.table
            .len
            .checked_sub(1)
            .and_then(|index| self.get(index))
    }

    /// Iterator over the elements, in order.
    #[must_use]
    pub fn iter(&self) -> Iter<'_, T> {
        Iter::new(&self.table.packs, self.table.len)
    }

    /// Whether some element equals the given one.
    pub fn contains(&self, value: &T) -> bool
    where
        T: PartialEq,
    {
        self.iter().any(|item| item == value)
    }

    /// The elements, copied into a fresh buffer.
    #[must_use]
    pub fn to_vec(&self) -> Vec<T>
    where
        T: Clone,
    {
        let mut items = Vec::with_capacity(self.table.len);
        for pack in &self.table.packs {
            items.extend_from_slice(pack.items());
        }
        items
    }

    /// Whether two sequences share their whole table, so they hold the same elements.
    pub(crate) fn shares_packs_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.table, &other.table)
    }
}

impl<T: Clone> Sequence<T> {
    /// A sequence of one value repeated, whose full packs are all one shared pack.
    pub(crate) fn repeat(layout: Layout, value: &T, len: usize) -> Self {
        let mut packs: Vec<Arc<Pack<T>>> = Vec::new();
        let mut full: Option<Arc<Pack<T>>> = None;
        let mut start = 0;
        while start < len {
            let capacity = layout.capacity(packs.len());
            let count = capacity.min(len - start);
            // Invariant: only full packs of one capacity are shared, so each sits at an aligned subtree.
            let pack = match &full {
                Some(shared) if shared.items().len() == count && count == capacity => {
                    Arc::clone(shared)
                }
                _ => Arc::new(Pack::new(vec![value.clone(); count])),
            };
            if count == capacity {
                full = Some(Arc::clone(&pack));
            }
            packs.push(pack);
            start += count;
        }
        Self::from_packs(layout, packs, len)
    }

    /// The element at an index, for an edit.
    #[inline]
    pub(crate) fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        if index >= self.table.len {
            return None;
        }
        let (pack, position) = self.table.layout.locate(index);
        let pack = self.table_mut().packs.get_mut(pack)?;
        Arc::make_mut(pack).items_mut().get_mut(position)
    }

    /// Overwrites every element with the matching one of another sequence of the same length.
    ///
    /// Two sequences of one layout then share every pack, cached roots included.
    ///
    /// # Panics
    ///
    /// Panics when the lengths differ, as copying between slices would.
    pub(crate) fn copy_from(&mut self, source: &Self) {
        assert_eq!(
            self.table.len, source.table.len,
            "source length {} differs from destination length {}",
            source.table.len, self.table.len
        );
        if self.table.layout == source.table.layout {
            *self = source.clone();
        } else {
            for (target, item) in self.iter_mut().zip(source) {
                target.clone_from(item);
            }
        }
    }

    /// Overwrites every element with one value, sharing one pack across all full packs.
    pub(crate) fn fill(&mut self, value: &T) {
        *self = Self::repeat(self.table.layout, value, self.table.len);
    }

    /// Iterator over the elements for edits, in order.
    pub(crate) fn iter_mut(&mut self) -> IterMut<'_, T> {
        let table = self.table_mut();
        IterMut::new(&mut table.packs, table.len)
    }

    /// Appends an element.
    pub(crate) fn push(&mut self, item: T) {
        let table = self.table_mut();
        let (pack, _) = table.layout.locate(table.len);
        if pack == table.packs.len() {
            let capacity = table.layout.capacity(pack);
            table
                .packs
                .push(Arc::new(Pack::new(Vec::with_capacity(capacity))));
        }
        // Invariant: the element after the last one lands in the last pack or a new one.
        if let Some(last) = table.packs.last_mut() {
            Arc::make_mut(last).items_mut().push(item);
        }
        table.len += 1;
    }

    /// Removes and returns the last element.
    pub(crate) fn pop(&mut self) -> Option<T> {
        let table = self.table_mut();
        let last = table.packs.last_mut()?;
        let items = Arc::make_mut(last).items_mut();
        let item = items.pop();
        if items.is_empty() {
            table.packs.pop();
        }
        table.len -= 1;
        item
    }

    /// Shortens the sequence to at most the given length.
    ///
    /// Packs wholly before the cut keep their cached roots.
    pub(crate) fn truncate(&mut self, length: usize) {
        if length >= self.table.len {
            return;
        }
        let table = self.table_mut();
        let (pack, position) = table.layout.locate(length);
        if position == 0 {
            table.packs.truncate(pack);
        } else {
            table.packs.truncate(pack + 1);
            if let Some(last) = table.packs.last_mut() {
                Arc::make_mut(last).items_mut().truncate(position);
            }
        }
        table.len = length;
    }

    /// Removes every element.
    pub(crate) fn clear(&mut self) {
        *self = Self::empty(self.table.layout);
    }

    /// Keeps only the elements the predicate accepts, preserving order.
    ///
    /// The predicate sees every element once, in order.
    /// Packs before the first rejected element keep their cached roots.
    pub(crate) fn retain(&mut self, mut keep: impl FnMut(&T) -> bool) {
        let Some(first) = self.iter().position(|item| !keep(item)) else {
            return;
        };
        let kept: Vec<T> = self
            .iter()
            .skip(first + 1)
            .filter(|item| keep(item))
            .cloned()
            .collect();
        self.truncate(first);
        for item in kept {
            self.push(item);
        }
    }

    /// Removes a range of elements and yields them.
    ///
    /// Removing a tail keeps the packs before it.
    /// Any other range shifts later elements, so the sequence is rebuilt.
    ///
    /// # Panics
    ///
    /// Panics when the range is out of bounds or decreasing, as a slice range would.
    pub(crate) fn drain(&mut self, range: impl RangeBounds<usize>) -> vec::IntoIter<T> {
        let start = match range.start_bound() {
            Bound::Included(&start) => start,
            Bound::Excluded(&start) => start + 1,
            Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            Bound::Included(&end) => end + 1,
            Bound::Excluded(&end) => end,
            Bound::Unbounded => self.table.len,
        };
        assert!(
            start <= end && end <= self.table.len,
            "drain range {start}..{end} is out of bounds for length {}",
            self.table.len
        );
        if end == self.table.len {
            let tail: Vec<T> = self.iter().skip(start).cloned().collect();
            self.truncate(start);
            return tail.into_iter();
        }
        let mut items = self.take_vec();
        let drained: Vec<T> = items.drain(start..end).collect();
        *self = Self::from_vec(self.table.layout, items);
        drained.into_iter()
    }

    /// The elements, moved out where no clone shares them and copied otherwise.
    pub(crate) fn into_vec(self) -> Vec<T> {
        let mut items = Vec::with_capacity(self.table.len);
        for pack in Arc::unwrap_or_clone(self.table).packs {
            match Arc::try_unwrap(pack) {
                Ok(pack) => items.extend(pack.into_items()),
                Err(shared) => items.extend_from_slice(shared.items()),
            }
        }
        items
    }

    /// The elements, leaving the sequence empty.
    fn take_vec(&mut self) -> Vec<T> {
        mem::replace(self, Self::empty(self.table.layout)).into_vec()
    }

    /// The pack table, for an edit, which drops the cached root.
    ///
    /// Copy on write: a table shared with a clone is copied first, sharing its packs.
    fn table_mut(&mut self) -> &mut Table<T> {
        let table = Arc::make_mut(&mut self.table);
        // Invariant: the root is cleared before any element can change.
        table.root.take();
        table
    }
}

impl<T: Ssz + Sync> Sequence<T> {
    /// Root of the elements' tree, before any length mix-in.
    ///
    /// # Performance
    ///
    /// The root is cached, and so is every pack's root.
    /// After an edit, only the edited packs re-hash, then one fold over the pack roots runs.
    /// Many cold packs, as after a decode, hash on all cores.
    pub(crate) fn root(&self) -> Root {
        *self
            .table
            .root
            .get_or_init(|| match self.table.layout.shape {
                Shape::Binary { depth } => self.binary_root(depth),
                Shape::Progressive => self.progressive_root(),
            })
    }

    /// Length of the elements' encoding, in bytes.
    pub(crate) fn encoded_len(&self) -> usize {
        match T::FIXED_SIZE {
            Some(size) => size * self.table.len,
            None => self
                .iter()
                .map(|item| BYTES_PER_LENGTH_OFFSET + item.encoded_len())
                .sum(),
        }
    }

    /// Appends the elements' encoding, the same as a slice's.
    pub(crate) fn encode_to(&self, out: &mut Vec<u8>) {
        if T::FIXED_SIZE.is_some() {
            for pack in &self.table.packs {
                Elements::encode_to(pack.items(), out);
            }
            return;
        }

        // Phase 1: the offset table, each offset counting the bodies before it.
        let mut offset = BYTES_PER_LENGTH_OFFSET * self.table.len;
        for item in self {
            out.extend_from_slice(&Offset::encode(offset));
            offset += item.encoded_len();
        }

        // Phase 2: the bodies, in order.
        for item in self {
            item.encode_to(out);
        }
    }

    /// Proves a node of the elements' binary tree, sized for the limit.
    pub(crate) fn prove(
        &self,
        limit: usize,
        index: GeneralizedIndex,
    ) -> Option<(Root, MerkleProof)> {
        let items: Vec<&T> = self.iter().collect();
        Elements::<T>::prove(&items, limit, index)
    }

    /// Root of a binary tree: one fold over the cached pack roots.
    fn binary_root(&self, depth: usize) -> Root {
        let height = self.table.layout.pack_height;
        self.hash_cold_packs(&self.table.packs);
        // Invariant: the layout caps the pack height at the depth.
        let mut top = Merkleizer::over_subtrees(depth - height, height);
        for pack in &self.table.packs {
            top.push(pack.root(height));
        }
        top.finish()
    }

    /// Root of a progressive tree: small subtrees from the first pack, then folds of packs.
    ///
    /// # Algorithm
    ///
    /// 1. Hash each subtree inside the first pack directly from its elements.
    /// 2. Fold each later subtree from the cached roots of the packs it spans.
    /// 3. Fold the subtree roots along the spine, from its zero end.
    ///
    /// See EIP-7916.
    fn progressive_root(&self) -> Root {
        let leaves = Elements::<T>::leaf_count(self.table.len);
        let per_leaf = self.table.layout.per_leaf;
        let height = self.table.layout.pack_height;
        let head = Layout::head_subtrees();
        let mut subtrees = Vec::new();

        // Phase 1: the subtrees smaller than a pack, all inside the first pack.
        let first = self
            .table
            .packs
            .first()
            .map_or(&[][..], |pack| pack.items());
        for subtree in 0..head {
            let start = Layout::subtree_offset(subtree);
            if start >= leaves {
                break;
            }
            let end = (Layout::subtree_offset(subtree + 1) * per_leaf).min(first.len());
            subtrees.push(Elements::subtree_root(
                &first[start * per_leaf..end],
                2 * subtree,
            ));
        }

        // Phase 2: every later subtree spans whole packs, aligned to its start.
        if let Some(rest) = self.table.packs.get(1..) {
            self.hash_cold_packs(rest);
        }
        let mut subtree = head;
        while Layout::subtree_offset(subtree) < leaves {
            let leaves_before = Layout::subtree_offset(subtree) - Layout::subtree_offset(head);
            let first_pack = 1 + (leaves_before >> height);
            // Invariant: the first subtree past the first pack has at least 2^height leaves.
            let depth = 2 * subtree - height;
            let mut top = Merkleizer::over_subtrees(depth, height);
            for pack in self.table.packs.iter().skip(first_pack).take(1 << depth) {
                top.push(pack.root(height));
            }
            subtrees.push(top.finish());
            subtree += 1;
        }

        // Phase 3: the spine, from its zero end back to the root.
        subtrees
            .iter()
            .rev()
            .fold(Root::ZERO, |rest, subtree| Root::hash_pair(subtree, &rest))
    }

    /// Hashes every pack whose root is not cached, on all cores when there are many.
    fn hash_cold_packs(&self, packs: &[Arc<Pack<T>>]) {
        let height = self.table.layout.pack_height;
        let cold: Vec<&Pack<T>> = packs
            .iter()
            .filter(|pack| !pack.is_hashed())
            .map(|pack| &**pack)
            .collect();
        Threads::available().for_each(&cold, |pack| {
            pack.root(height);
        });
    }
}

impl<T> Clone for Sequence<T> {
    /// Shares the pack table, so a clone costs one reference count.
    fn clone(&self) -> Self {
        Self {
            table: Arc::clone(&self.table),
        }
    }
}

impl<T> Index<usize> for Sequence<T> {
    type Output = T;

    /// The element at an index.
    ///
    /// # Panics
    ///
    /// Panics when the index is out of bounds, as a slice would.
    fn index(&self, index: usize) -> &T {
        match self.get(index) {
            Some(item) => item,
            None => panic!(
                "index out of bounds: the len is {} but the index is {index}",
                self.table.len
            ),
        }
    }
}

impl<'a, T> IntoIterator for &'a Sequence<T> {
    type Item = &'a T;
    type IntoIter = Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, T: Clone> IntoIterator for &'a mut Sequence<T> {
    type Item = &'a mut T;
    type IntoIter = IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

impl<T: fmt::Debug> fmt::Debug for Sequence<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<T: PartialEq> PartialEq for Sequence<T> {
    /// Compares elements, skipping packs the two sequences share.
    fn eq(&self, other: &Self) -> bool {
        if self.table.len != other.table.len {
            return false;
        }
        if self.shares_packs_with(other) {
            return true;
        }
        if self.table.layout == other.table.layout {
            return self
                .table
                .packs
                .iter()
                .zip(other.table.packs.iter())
                .all(|(left, right)| Arc::ptr_eq(left, right) || left.items() == right.items());
        }
        self.iter().eq(other.iter())
    }
}

impl<T: Eq> Eq for Sequence<T> {}

impl<T: Hash> Hash for Sequence<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.table.len.hash(state);
        for item in self {
            item.hash(state);
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::{Const, List, PersistentList};

    /// Number of packs two sequences hold at the same address.
    fn shared_packs<T>(left: &Sequence<T>, right: &Sequence<T>) -> usize {
        left.table
            .packs
            .iter()
            .zip(right.table.packs.iter())
            .filter(|(left, right)| Arc::ptr_eq(left, right))
            .count()
    }

    #[test]
    fn a_clone_shares_the_whole_table() {
        // Fixture state: 10000 u64 in 40 packs of 256.
        let list =
            PersistentList::<u64, Const<65536>>::try_from((0..10_000).collect::<Vec<_>>()).unwrap();

        let copy = list.clone();

        assert!(copy.shares_packs_with(&list));
        assert_eq!(shared_packs(&copy, &list), 40);
    }

    #[test]
    fn an_edit_copies_only_the_pack_it_touches() {
        // Fixture state: 10000 u64 in 40 packs of 256, cloned before one edit.
        let list =
            PersistentList::<u64, Const<65536>>::try_from((0..10_000).collect::<Vec<_>>()).unwrap();
        let mut copy = list.clone();

        // Mutation: element 5000 sits in pack 19, the only pack the edit copies.
        copy[5000] = 7;

        assert!(!copy.shares_packs_with(&list));
        assert_eq!(shared_packs(&copy, &list), 39);
        assert_eq!(list[5000], 5000);
        assert_eq!(copy[5000], 7);
    }

    #[test]
    fn an_edit_keeps_every_other_pack_root() {
        // Fixture state: 10000 u64 in 40 packs, hashed once so every pack root is cached.
        let mut list =
            PersistentList::<u64, Const<65536>>::try_from((0..10_000).collect::<Vec<_>>()).unwrap();
        list.hash_tree_root();

        // Mutation: one element of pack 19 changes, so only that pack loses its root.
        list[5000] = 7;

        let cold: Vec<usize> = list
            .table
            .packs
            .iter()
            .enumerate()
            .filter(|(_, pack)| !pack.is_hashed())
            .map(|(index, _)| index)
            .collect();
        assert_eq!(cold, [19]);
        assert!(list.table.root.get().is_none());
    }

    #[test]
    fn many_cold_packs_hash_in_parallel_to_the_same_root() {
        // Fixture state: 100000 u64 in 391 packs, all cold after a decode, so threads share them.
        let values: Vec<u64> = (0..100_000).map(|value| value * 3).collect();
        let plain = List::<u64, Const<1_099_511_627_776>>::try_from(values).unwrap();

        let persistent = PersistentList::<u64, Const<1_099_511_627_776>>::decode(&plain.encode());

        assert_eq!(
            persistent.map(|list| list.hash_tree_root()),
            Ok(plain.hash_tree_root())
        );
    }

    #[test]
    fn equality_ignores_sharing_and_caches() {
        // Two lists built apart, one hashed and one not, hold equal elements.
        let left = PersistentList::<u64, Const<1024>>::try_from(vec![1, 2, 3]).unwrap();
        let right = PersistentList::<u64, Const<1024>>::try_from(vec![1, 2, 3]).unwrap();
        left.hash_tree_root();

        assert_eq!(left, right);
    }

    proptest! {
        #[test]
        fn iteration_from_both_ends_matches_a_slice(
            length in 0_usize..2000,
            steps in proptest::collection::vec((0_u8..3, 0_usize..700), 0..20),
        ) {
            // Fixture state: u64 in packs of 256, walked by next, next_back, and long skips.
            let values: Vec<u64> = (0..length as u64).collect();
            let list = PersistentList::<u64, Const<4096>>::try_from(values.clone()).unwrap();
            let mut persistent = list.iter();
            let mut plain = values.iter();

            for (kind, skip) in steps {
                match kind {
                    0 => prop_assert_eq!(persistent.next(), plain.next()),
                    1 => prop_assert_eq!(persistent.next_back(), plain.next_back()),
                    _ => prop_assert_eq!(persistent.nth(skip), plain.nth(skip)),
                }
                prop_assert_eq!(persistent.len(), plain.len());
            }
            prop_assert!(persistent.eq(plain));
        }
    }
}
