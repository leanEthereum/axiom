//! Iterators over the elements of a persistent sequence, pack by pack.

use std::{iter::FusedIterator, slice, sync::Arc};

use super::pack::Pack;

/// Iterator over a sequence's elements, in order.
#[derive(Clone, Debug)]
pub struct Iter<'a, T> {
    /// Packs not yet entered from either end.
    packs: slice::Iter<'a, Arc<Pack<T>>>,
    /// Elements left in the pack entered from the front.
    front: slice::Iter<'a, T>,
    /// Elements left in the pack entered from the back.
    back: slice::Iter<'a, T>,
    /// Elements left in total.
    remaining: usize,
}

impl<'a, T> Iter<'a, T> {
    /// Iterator over the elements of the given packs, which hold that many in total.
    pub(super) fn new(packs: &'a [Arc<Pack<T>>], remaining: usize) -> Self {
        Self {
            packs: packs.iter(),
            front: [].iter(),
            back: [].iter(),
            remaining,
        }
    }
}

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        loop {
            if let Some(item) = self.front.next() {
                self.remaining -= 1;
                return Some(item);
            }
            match self.packs.next() {
                Some(pack) => self.front = pack.items().iter(),
                None => {
                    // The middle is spent, so the rest sits in the pack entered from the back.
                    let item = self.back.next()?;
                    self.remaining -= 1;
                    return Some(item);
                }
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<T> DoubleEndedIterator for Iter<'_, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(item) = self.back.next_back() {
                self.remaining -= 1;
                return Some(item);
            }
            match self.packs.next_back() {
                Some(pack) => self.back = pack.items().iter(),
                None => {
                    let item = self.front.next_back()?;
                    self.remaining -= 1;
                    return Some(item);
                }
            }
        }
    }
}

impl<T> ExactSizeIterator for Iter<'_, T> {}

impl<T> FusedIterator for Iter<'_, T> {}

/// Iterator over a sequence's elements for edits, in order.
///
/// Entering a pack makes it private to this sequence and drops its cached root.
/// Packs the iterator never reaches keep their roots.
#[derive(Debug)]
pub struct IterMut<'a, T> {
    /// Packs not yet entered from either end.
    packs: slice::IterMut<'a, Arc<Pack<T>>>,
    /// Elements left in the pack entered from the front.
    front: slice::IterMut<'a, T>,
    /// Elements left in the pack entered from the back.
    back: slice::IterMut<'a, T>,
    /// Elements left in total.
    remaining: usize,
}

impl<'a, T> IterMut<'a, T> {
    /// Iterator over the elements of the given packs, which hold that many in total.
    pub(super) fn new(packs: &'a mut [Arc<Pack<T>>], remaining: usize) -> Self {
        Self {
            packs: packs.iter_mut(),
            front: [].iter_mut(),
            back: [].iter_mut(),
            remaining,
        }
    }
}

impl<'a, T: Clone> Iterator for IterMut<'a, T> {
    type Item = &'a mut T;

    fn next(&mut self) -> Option<&'a mut T> {
        loop {
            if let Some(item) = self.front.next() {
                self.remaining -= 1;
                return Some(item);
            }
            match self.packs.next() {
                // Copy on write: a pack shared with a clone is copied before its first edit.
                Some(pack) => self.front = Arc::make_mut(pack).items_mut().iter_mut(),
                None => {
                    let item = self.back.next()?;
                    self.remaining -= 1;
                    return Some(item);
                }
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<T: Clone> DoubleEndedIterator for IterMut<'_, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(item) = self.back.next_back() {
                self.remaining -= 1;
                return Some(item);
            }
            match self.packs.next_back() {
                Some(pack) => self.back = Arc::make_mut(pack).items_mut().iter_mut(),
                None => {
                    let item = self.front.next_back()?;
                    self.remaining -= 1;
                    return Some(item);
                }
            }
        }
    }
}

impl<T: Clone> ExactSizeIterator for IterMut<'_, T> {}

impl<T: Clone> FusedIterator for IterMut<'_, T> {}
