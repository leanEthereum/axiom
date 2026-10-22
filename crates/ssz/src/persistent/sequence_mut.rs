//! A fixed-length view for editing a persistent collection's elements in place.

use std::ops::{Deref, Index, IndexMut};

use super::{iter::IterMut, sequence::Sequence};

/// Elements of a persistent collection, editable in place but never grown or shrunk.
///
/// It plays the part of a mutable slice.
/// The collection's length and limit stay its own, so no edit through the view breaks them.
#[derive(Debug)]
pub struct SequenceMut<'a, T> {
    /// The collection's elements.
    sequence: &'a mut Sequence<T>,
}

impl<'a, T> SequenceMut<'a, T> {
    /// A view of a collection's elements.
    pub(crate) const fn new(sequence: &'a mut Sequence<T>) -> Self {
        Self { sequence }
    }
}

impl<'a, T: Clone> SequenceMut<'a, T> {
    /// The element at an index, for an edit.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.sequence.get_mut(index)
    }

    /// The element at an index, for an edit that outlives the view.
    #[must_use]
    pub fn into_mut(self, index: usize) -> Option<&'a mut T> {
        self.sequence.get_mut(index)
    }

    /// Overwrites every element with the matching one of a sequence of the same length.
    ///
    /// The two collections then share their storage until either is edited.
    ///
    /// # Panics
    ///
    /// Panics when the lengths differ, as copying between slices would.
    pub fn copy_from(&mut self, source: &Sequence<T>) {
        self.sequence.copy_from(source);
    }

    /// Overwrites every element with one value.
    pub fn fill(&mut self, value: &T) {
        self.sequence.fill(value);
    }

    /// Iterator over the elements for edits, in order.
    pub fn iter_mut(&mut self) -> IterMut<'_, T> {
        self.sequence.iter_mut()
    }

    /// Iterator over the elements for edits, outliving the view.
    #[must_use]
    pub fn into_iter_mut(self) -> IterMut<'a, T> {
        self.sequence.iter_mut()
    }
}

impl<'b, T: Clone> IntoIterator for &'b mut SequenceMut<'_, T> {
    type Item = &'b mut T;
    type IntoIter = IterMut<'b, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

impl<T> Deref for SequenceMut<'_, T> {
    type Target = Sequence<T>;

    fn deref(&self) -> &Sequence<T> {
        self.sequence
    }
}

impl<T> Index<usize> for SequenceMut<'_, T> {
    type Output = T;

    fn index(&self, index: usize) -> &T {
        &self.sequence[index]
    }
}

impl<T: Clone> IndexMut<usize> for SequenceMut<'_, T> {
    /// The element at an index, for an edit.
    ///
    /// # Panics
    ///
    /// Panics when the index is out of bounds, as a slice would.
    fn index_mut(&mut self, index: usize) -> &mut T {
        let len = self.sequence.len();
        match self.sequence.get_mut(index) {
            Some(item) => item,
            None => panic!("index out of bounds: the len is {len} but the index is {index}"),
        }
    }
}
