//! The bit-reversal permutation, the order in which the specs store evaluations.

/// The permutation of 2^k positions that reverses the k bits of each index.
///
/// ```text
///     k = 3:   1 = 001  ->  100 = 4,     6 = 110  ->  011 = 3
/// ```
///
/// The permutation is an involution, so applying it twice restores the input.
/// See reverse_bits and bit_reversal_permutation in the Deneb polynomial commitments spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BitReversal {
    /// Number of index bits, the base-two logarithm of the length.
    log_size: u32,
}

impl BitReversal {
    /// The permutation of 2^k positions.
    pub(crate) const fn new(log_size: u32) -> Self {
        Self { log_size }
    }

    /// The permutation of a slice of this length.
    ///
    /// # Panics
    ///
    /// Panics when the length is not a power of two.
    pub(crate) const fn of_length(length: usize) -> Self {
        assert!(
            length.is_power_of_two(),
            "bit reversal needs a power-of-two length"
        );
        Self::new(length.trailing_zeros())
    }

    /// The position an index moves to.
    pub(crate) const fn index(self, index: usize) -> usize {
        // Reverse the whole word, then drop the low bits that were the high zeros of the index.
        if self.log_size == 0 {
            0
        } else {
            index.reverse_bits() >> (usize::BITS - self.log_size)
        }
    }

    /// Applies the permutation in place.
    ///
    /// # Panics
    ///
    /// Panics when the length differs from 2^k.
    pub(crate) fn permute<T>(self, values: &mut [T]) {
        assert_eq!(
            values.len(),
            1 << self.log_size,
            "bit reversal length must match"
        );
        // Swap each pair once, from its smaller index.
        for i in 0..values.len() {
            let j = self.index(i);
            if i < j {
                values.swap(i, j);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_reversal_of_eight() {
        // Fixture state: n = 8, three index bits.
        //
        //     index   0    1    2    3    4    5    6    7
        //     binary  000  001  010  011  100  101  110  111
        //     reverse 000  100  010  110  001  101  011  111
        let mut values = [0, 1, 2, 3, 4, 5, 6, 7];
        BitReversal::of_length(values.len()).permute(&mut values);
        assert_eq!(values, [0, 4, 2, 6, 1, 5, 3, 7]);
        // A domain of one point has no bits to reverse.
        assert_eq!(BitReversal::new(0).index(0), 0);
    }
}
