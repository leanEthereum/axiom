//! The AES-128 key schedule and the portable cipher, the fallback and the oracle of every hardware path.
//!
//! # Overview
//!
//! The S-box is a bitsliced Boolean circuit, so no step indexes a table by a secret byte.
//! Every step runs the same instructions whatever the key and the data.

mod sbox;
mod state;

use state::State;

use crate::ct::wipe;

/// Rounds of AES-128, per FIPS 197, section 5.
pub(super) const ROUNDS: usize = 10;

/// Round constants of the key schedule, per FIPS 197, section 5.2.
///
/// They are the successive powers of x in GF(2^8).
pub(super) const RCON: [u8; ROUNDS] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// The eleven round keys of one AES-128 key, in the byte order of the state.
///
/// The keys are cleared from memory when dropped.
#[derive(Clone)]
pub(super) struct RoundKeys([[u8; 16]; ROUNDS + 1]);

impl RoundKeys {
    /// Expands a 128-bit key into eleven round keys, per FIPS 197, section 5.2.
    ///
    /// ```text
    /// w[i] = w[i - 4] ^ SubWord(RotWord(w[i - 1])) ^ Rcon   when i = 0 mod 4
    /// w[i] = w[i - 4] ^ w[i - 1]                            otherwise
    /// ```
    pub(super) fn expand(key: &[u8; 16]) -> Self {
        // Round key 0 is the key itself.
        let mut keys = [[0_u8; 16]; ROUNDS + 1];
        keys[0] = *key;
        for round in 1..=ROUNDS {
            let previous = keys[round - 1];

            // RotWord then SubWord on the last word of the previous round key.
            //
            // The S-box circuit works on 16 bytes at once.
            // The other 12 lanes are idle.
            let mut rotated = [0_u8; 16];
            rotated[..4].copy_from_slice(&[previous[13], previous[14], previous[15], previous[12]]);
            let mut state = State::from_bytes(rotated);
            state.sub_bytes();
            let mut word = state.to_bytes();
            word[0] ^= RCON[round - 1];

            // Each word chains off the word before it.
            let mut next = [0_u8; 16];
            for i in 0..4 {
                next[i] = previous[i] ^ word[i];
            }
            for i in 4..16 {
                next[i] = previous[i] ^ next[i - 4];
            }
            keys[round] = next;
        }
        Self::from_blocks(keys)
    }

    /// Round keys a hardware key schedule expanded.
    pub(super) const fn from_blocks(keys: [[u8; 16]; ROUNDS + 1]) -> Self {
        Self(keys)
    }

    /// The round keys as raw blocks, the form the hardware paths load.
    pub(super) const fn as_blocks(&self) -> &[[u8; 16]; ROUNDS + 1] {
        &self.0
    }

    /// Encrypts one block in place, per FIPS 197, section 5.1.
    pub(super) fn encrypt_block(&self, block: &mut [u8; 16]) {
        // Initial whitening, then nine full rounds.
        let keys = self.as_blocks();
        let mut state = State::from_bytes(*block);
        state.add_round_key(&keys[0]);
        for key in &keys[1..ROUNDS] {
            state.sub_bytes();
            state.shift_rows();
            state.mix_columns();
            state.add_round_key(key);
        }
        // The last round skips MixColumns.
        state.sub_bytes();
        state.shift_rows();
        state.add_round_key(&keys[ROUNDS]);
        *block = state.to_bytes();
    }
}

impl Drop for RoundKeys {
    fn drop(&mut self) {
        wipe(self.0.as_flattened_mut());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fips_197_key_expansion() {
        // FIPS 197, appendix A.1: round keys 1 and 10 of 2b7e1516...
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let keys = RoundKeys::expand(&key);
        assert_eq!(
            keys.0[1],
            [
                0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c,
                0x76, 0x05
            ]
        );
        assert_eq!(
            keys.0[10],
            [
                0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63,
                0x0c, 0xa6
            ]
        );
    }
}
