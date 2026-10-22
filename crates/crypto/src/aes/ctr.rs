//! AES-128 in counter mode with a full 128-bit counter, per NIST SP 800-38A, section 6.5.

use std::fmt;

use super::{Aes128, BLOCK_LEN};
use crate::ct::wipe;

/// An AES-128-CTR keystream, applied by XOR.
///
/// # Overview
///
/// ```text
/// keystream block i = AES_K(IV + i mod 2^128)
/// ```
///
/// The whole 16-byte block is one big-endian counter.
/// That is the standard incrementing function of SP 800-38A, appendix B.1.
/// discv5 masks packet headers this way, with the masking IV of each packet as the initial counter.
#[derive(Clone)]
pub struct Aes128Ctr {
    /// The block cipher.
    cipher: Aes128,
    /// The next counter block, as a big-endian integer.
    counter: u128,
    /// Keystream left over from a block a previous call cut short.
    leftover: [u8; BLOCK_LEN],
    /// Bytes of the leftover block already used, or 16 when none remain.
    used: usize,
}

impl Aes128Ctr {
    /// A keystream under the key, starting from the initial counter block.
    #[must_use]
    pub fn new(key: &[u8; Aes128::KEY_LEN], iv: &[u8; BLOCK_LEN]) -> Self {
        Self {
            cipher: Aes128::new(key),
            counter: u128::from_be_bytes(*iv),
            leftover: [0; BLOCK_LEN],
            used: BLOCK_LEN,
        }
    }

    /// XORs the next keystream bytes into the data.
    ///
    /// Successive calls continue the stream where the last one stopped.
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        // Phase 1: spend keystream left over from the previous call.
        let take = (BLOCK_LEN - self.used).min(data.len());
        let (head, rest) = data.split_at_mut(take);
        for (byte, key) in head.iter_mut().zip(&self.leftover[self.used..]) {
            *byte ^= key;
        }
        self.used += take;

        // Phase 2: whole blocks in batches.
        let whole = rest.len() - rest.len() % BLOCK_LEN;
        let (blocks, tail) = rest.split_at_mut(whole);
        let mut counter = self.counter;
        self.cipher.xor_keystream(blocks, || {
            let block = counter.to_be_bytes();
            counter = counter.wrapping_add(1);
            block
        });
        self.counter = counter;

        // Phase 3: one more block for the tail, keeping its unused part.
        if !tail.is_empty() {
            self.leftover = self.counter.to_be_bytes();
            self.counter = self.counter.wrapping_add(1);
            self.cipher.encrypt_block(&mut self.leftover);
            for (byte, key) in tail.iter_mut().zip(&self.leftover) {
                *byte ^= key;
            }
            self.used = tail.len();
        }
    }
}

impl Drop for Aes128Ctr {
    fn drop(&mut self) {
        wipe(&mut self.leftover);
    }
}

impl fmt::Debug for Aes128Ctr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Key and keystream are secret: never print them.
        f.debug_struct("Aes128Ctr").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Decodes a hex string in a test vector.
    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn sp_800_38a_ctr_vector() {
        // SP 800-38A, appendix F.5.1: CTR-AES128.Encrypt, four blocks.
        let key: [u8; 16] = hex("2b7e151628aed2a6abf7158809cf4f3c").try_into().unwrap();
        let iv: [u8; 16] = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").try_into().unwrap();
        let mut data = hex(concat!(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        ));
        Aes128Ctr::new(&key, &iv).apply_keystream(&mut data);
        assert_eq!(
            data,
            hex(concat!(
                "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff",
                "5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee",
            ))
        );
    }

    #[test]
    fn counter_carries_across_the_whole_block() {
        // IV = 2^128 - 1: the next counter wraps to 0, carrying through all 16 bytes.
        let key = [5; 16];
        let mut two_blocks = [0_u8; 32];
        Aes128Ctr::new(&key, &[0xff; 16]).apply_keystream(&mut two_blocks);

        // The second keystream block is AES(0).
        let mut zero = [0_u8; 16];
        Aes128::new(&key).encrypt_block(&mut zero);
        assert_eq!(two_blocks[16..], zero);
    }

    proptest! {
        #[test]
        fn pieces_encrypt_like_the_whole(
            key in any::<[u8; 16]>(),
            iv in any::<[u8; 16]>(),
            data in prop::collection::vec(any::<u8>(), 0..400),
            cuts in prop::collection::vec(any::<prop::sample::Index>(), 0..5),
        ) {
            // Any split of the stream across calls gives the one-shot ciphertext.
            let mut whole = data.clone();
            Aes128Ctr::new(&key, &iv).apply_keystream(&mut whole);

            let mut points: Vec<usize> = cuts.iter().map(|c| c.index(data.len() + 1)).collect();
            points.sort_unstable();
            let mut pieces = data;
            let mut ctr = Aes128Ctr::new(&key, &iv);
            let mut start = 0;
            for point in points {
                ctr.apply_keystream(&mut pieces[start..point]);
                start = point;
            }
            ctr.apply_keystream(&mut pieces[start..]);
            prop_assert_eq!(pieces, whole);
        }
    }
}
