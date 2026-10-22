//! The hash table of recent positions that finds match candidates.

/// Largest hash table, 2^14 entries of 2 bytes: 32 KiB, which stays in L1 cache.
const MAX_BITS: u32 = 14;

/// Smallest hash table, so tiny inputs do not pay for clearing a large one.
const MIN_BITS: u32 = 8;

/// Multiplier of the hash: odd, with well-mixed bits, from the reference.
const MULTIPLIER: u32 = 0x1e35_a7bd;

/// The last fragment position seen for each hash of 4 bytes.
///
/// Positions fit 16 bits because fragments hold at most 64 KiB.
pub(super) struct HashTable<'a> {
    /// One position per hash value, all zero at the start of a fragment.
    slots: &'a mut [u16],
    /// Right shift that keeps the top bits of the product: 32 minus the table's bits.
    shift: u32,
}

impl<'a> HashTable<'a> {
    /// A cleared table sized for a fragment, carved from the front of the given storage.
    ///
    /// # Panics
    ///
    /// Panics when the storage is shorter than the slots the fragment needs.
    pub(super) fn new(storage: &'a mut [u16], fragment_len: usize) -> Self {
        let bits = Self::bits(fragment_len);
        // Only the slots this fragment's hash can reach are used and cleared.
        let slots = &mut storage[..1 << bits];
        slots.fill(0);
        Self {
            slots,
            shift: 32 - bits,
        }
    }

    /// Number of slots a fragment of the given length uses.
    pub(super) const fn slots_for(fragment_len: usize) -> usize {
        1 << Self::bits(fragment_len)
    }

    /// Number of hash bits for a fragment of the given length.
    ///
    /// The table grows with the input up to its cap, rounded up to a power of two.
    const fn bits(len: usize) -> u32 {
        let bits = len.saturating_sub(1).bit_width();
        if bits < MIN_BITS {
            MIN_BITS
        } else if bits > MAX_BITS {
            MAX_BITS
        } else {
            bits
        }
    }

    /// Hash of 4 bytes, keeping the top bits of a multiplicative hash.
    ///
    /// The shift leaves a value below the slot count, a valid index.
    #[inline]
    pub(super) const fn hash(&self, word: u32) -> usize {
        (word.wrapping_mul(MULTIPLIER) >> self.shift) as usize
    }

    /// Records a position under a hash.
    #[inline]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "positions in a fragment are below 2^16 and fit the u16 table"
    )]
    pub(super) const fn insert(&mut self, hash: usize, position: usize) {
        self.slots[hash] = position as u16;
    }

    /// Records a position under a hash and returns the one it displaces.
    #[inline]
    pub(super) fn replace(&mut self, hash: usize, position: usize) -> usize {
        let candidate = usize::from(self.slots[hash]);
        self.insert(hash, position);
        candidate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_grows_with_the_fragment_up_to_its_cap() {
        // Below 256 bytes: the floor; then the next power of two; then the cap.
        assert_eq!(HashTable::bits(0), MIN_BITS);
        assert_eq!(HashTable::bits(256), 8);
        assert_eq!(HashTable::bits(257), 9);
        assert_eq!(HashTable::bits(1 << 14), 14);
        assert_eq!(HashTable::bits(1 << 16), MAX_BITS);
    }

    #[test]
    fn replace_returns_the_displaced_position() {
        // A fresh table holds zero everywhere, then hands back what it stored.
        let mut storage = vec![9; 512];
        let mut table = HashTable::new(&mut storage, 300);
        assert_eq!(table.replace(3, 100), 0);
        assert_eq!(table.replace(3, 200), 100);

        // 300 bytes need 9 bits: 512 slots, all cleared.
        assert_eq!(table.slots.len(), 512);
    }
}
