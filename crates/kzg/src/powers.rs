//! The successive powers of a field element, as an endless iterator.

use std::iter::FusedIterator;

use axiom_bls12_381::Scalar;

/// The powers x^0, x^1, x^2, ... of a field element, one multiplication each.
///
/// Taking the first n gives compute_powers of the Deneb spec.
/// Zipped with a slice, it scales entry i by x^i without one exponentiation per entry.
#[derive(Clone, Debug)]
pub(crate) struct Powers {
    /// The power the next call yields.
    next: Scalar,
    /// The element whose powers these are.
    base: Scalar,
}

impl Powers {
    /// Starts at x^0 = 1.
    pub(crate) const fn new(base: Scalar) -> Self {
        Self {
            next: Scalar::ONE,
            base,
        }
    }
}

impl Iterator for Powers {
    type Item = Scalar;

    #[inline]
    fn next(&mut self) -> Option<Scalar> {
        let current = self.next;
        self.next *= self.base;
        Some(current)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::MAX, None)
    }
}

impl FusedIterator for Powers {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn powers_of_three() {
        // 3^0, 3^1, 3^2, 3^3 = 1, 3, 9, 27.
        let powers: Vec<Scalar> = Powers::new(Scalar::from_u64(3)).take(4).collect();
        assert_eq!(powers, [1, 3, 9, 27].map(Scalar::from_u64));
    }
}
