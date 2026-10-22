//! The Grain LFSR that derives Poseidon's round constants, run at compile time.
//!
//! # Overview
//!
//! Poseidon draws its round constants from a self-shrinking Grain LFSR seeded by the instance.
//! The seed encodes the field, the S-box, the word size, the width, and the round counts.
//! Generating the table from that seed, instead of pasting it, lets anyone re-derive every constant.
//!
//! Grassi, Khovratovich, Rechberger, Roy, Schofnegger, "Poseidon", USENIX Security 2021, appendix F.

use crate::field::KoalaBear;

/// Bits of LFSR state.
const STATE_BITS: u32 = 80;

/// Output bits discarded after seeding, so the first constant is far from the seed.
const WARM_UP: u32 = 160;

/// Bits drawn per field element candidate: the bit length of p.
const ELEMENT_BITS: u32 = 31;

/// A Grain LFSR in the self-shrinking mode of the Poseidon paper.
///
/// # Invariants
///
/// Bit i of the word is state bit i, and bit 0 is the oldest.
#[derive(Clone, Copy, Debug)]
pub(super) struct Grain {
    /// The 80 state bits.
    state: u128,
}

impl Grain {
    /// The LFSR seeded for one Poseidon instance over a prime field with the x^alpha S-box.
    ///
    /// The seed is these fields, most significant bit first, then thirty ones.
    ///
    /// ```text
    /// field type   2 bits   1 for a prime field
    /// S-box        4 bits   0 for x^alpha
    /// word size   12 bits   31
    /// width       12 bits   t
    /// full rounds 10 bits   R_F
    /// partial     10 bits   R_P
    /// padding     30 bits   all ones
    /// ```
    pub(super) const fn new(width: u32, full_rounds: u32, partial_rounds: u32) -> Self {
        let fields: [(u32, u32); 6] = [
            (1, 2),
            (0, 4),
            (ELEMENT_BITS, 12),
            (width, 12),
            (full_rounds, 10),
            (partial_rounds, 10),
        ];
        let mut state = 0_u128;
        let mut position = 0;
        let mut field = 0;
        while field < fields.len() {
            let (value, bits) = fields[field];
            let mut bit = bits;
            while bit > 0 {
                bit -= 1;
                state |= (((value >> bit) & 1) as u128) << position;
                position += 1;
            }
            field += 1;
        }
        while position < STATE_BITS {
            state |= 1 << position;
            position += 1;
        }

        let mut grain = Self { state };
        let mut discarded = 0;
        while discarded < WARM_UP {
            grain.step();
            discarded += 1;
        }
        grain
    }

    /// Shifts in one new bit and returns it.
    ///
    /// The feedback taps are bits 0, 13, 23, 38, 51 and 62.
    const fn step(&mut self) -> u32 {
        let s = self.state;
        let bit = ((s >> 62) ^ (s >> 51) ^ (s >> 38) ^ (s >> 23) ^ (s >> 13) ^ s) & 1;
        self.state = (s >> 1) | (bit << (STATE_BITS - 1));
        bit as u32
    }

    /// The next output bit of the self-shrinking generator.
    ///
    /// Bits come in pairs: a pair starting with 1 outputs its second bit, any other is dropped.
    const fn next_bit(&mut self) -> u32 {
        loop {
            let keep = self.step();
            let bit = self.step();
            if keep == 1 {
                return bit;
            }
        }
    }

    /// The next field element: 31 bits most significant first, rejected until below p.
    pub(super) const fn next_element(&mut self) -> KoalaBear {
        loop {
            let mut value = 0;
            let mut bit = 0;
            while bit < ELEMENT_BITS {
                value = (value << 1) | self.next_bit();
                bit += 1;
            }
            if let Some(element) = KoalaBear::from_canonical(value) {
                return element;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_constants_of_the_width_16_instance() {
        // The first four constants of the R_F = 8, R_P = 20 instance, as Poseidon's script prints them.
        let mut grain = Grain::new(16, 8, 20);
        let first: [u32; 4] = std::array::from_fn(|_| grain.next_element().to_canonical());
        assert_eq!(first, [0x7ee5_6a48, 0x1136_7045, 0x12e4_1941, 0x7ebb_c12b]);
    }
}
