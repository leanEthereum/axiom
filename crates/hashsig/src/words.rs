//! Short strings of field elements: hash outputs, encoding randomness, and the public parameter.

use std::fmt;

use crate::{entropy::Entropy, field::KoalaBear};

/// Field elements in the public parameter of the tweakable hash.
pub(crate) const PARAMETER_LEN: usize = 5;

/// Up to CAP field elements, of a length fixed by the instantiation.
///
/// # Invariants
///
/// Elements past the length are zero, so equality compares only the used ones.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Words<const CAP: usize> {
    /// The elements, zero past the length.
    elements: [KoalaBear; CAP],
    /// How many elements are used.
    len: u8,
}

/// A tweakable hash output: a chain value, a leaf, or a tree node.
pub type Digest = Words<8>;

/// The randomness that steers the message encoding.
pub type Randomness = Words<7>;

impl<const CAP: usize> Words<CAP> {
    /// The words of a slice of at most CAP elements.
    ///
    /// # Panics
    ///
    /// Panics when the slice is longer than CAP, which instantiations rule out at compile time.
    #[must_use]
    pub(crate) fn from_slice(slice: &[KoalaBear]) -> Self {
        let mut elements = [KoalaBear::ZERO; CAP];
        elements[..slice.len()].copy_from_slice(slice);
        Self {
            elements,
            len: slice.len() as u8,
        }
    }

    /// The words built element by element.
    pub(crate) fn from_fn(len: usize, mut element: impl FnMut(usize) -> KoalaBear) -> Self {
        assert!(len <= CAP, "at most {CAP} words");
        let mut elements = [KoalaBear::ZERO; CAP];
        for (i, slot) in elements[..len].iter_mut().enumerate() {
            *slot = element(i);
        }
        Self {
            elements,
            len: len as u8,
        }
    }

    /// Uniform words drawn from entropy.
    pub(crate) fn sample(len: usize, entropy: &mut impl Entropy) -> Self {
        Self::from_fn(len, |_| entropy.element())
    }

    /// The used elements.
    #[must_use]
    pub fn elements(&self) -> &[KoalaBear] {
        &self.elements[..usize::from(self.len)]
    }
}

impl<const CAP: usize> Default for Words<CAP> {
    fn default() -> Self {
        Self {
            elements: [KoalaBear::ZERO; CAP],
            len: 0,
        }
    }
}

impl<const CAP: usize> fmt::Debug for Words<CAP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.elements()).finish()
    }
}

/// The public parameter that keys every tweakable hash call of one key pair.
///
/// It separates the hash functions of different keys, so multi-target attacks gain nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PublicParameter(pub(crate) [KoalaBear; PARAMETER_LEN]);

impl PublicParameter {
    /// A uniform parameter drawn from entropy.
    pub(crate) fn sample(entropy: &mut impl Entropy) -> Self {
        Self(std::array::from_fn(|_| entropy.element()))
    }

    /// The elements.
    #[must_use]
    pub const fn elements(&self) -> &[KoalaBear; PARAMETER_LEN] {
        &self.0
    }
}
