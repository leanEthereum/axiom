//! AES-128-GCM with 96-bit nonces, per NIST SP 800-38D.

use std::fmt;

use super::{Aes128, BLOCK_LEN, ghash::Ghash};
use crate::{
    aead::AeadError,
    ct::{Mask, wipe},
};

/// Longest plaintext one nonce may seal: 2^32 - 2 blocks, per SP 800-38D, section 5.2.1.1.
///
/// The 32-bit block counter starts at 2 for the payload, so 2^32 - 2 blocks remain before it wraps.
const MAX_PLAINTEXT_LEN: u64 = ((1 << 32) - 2) * BLOCK_LEN as u64;

/// The AES-128-GCM authenticated cipher under one key.
///
/// # Overview
///
/// With a 96-bit nonce, per SP 800-38D, section 7.1:
///
/// ```text
/// H  = AES_K(0^128)
/// J0 = nonce || 0x00000001
/// C  = P ^ AES_K(J0 + 1), AES_K(J0 + 2), ...      counter in the low 32 bits
/// T  = AES_K(J0) ^ GHASH_H(A | pad | C | pad | bits(A) | bits(C))
/// ```
///
/// A nonce must never repeat under one key.
/// A repeat reveals the XOR of two plaintexts and lets an attacker solve for H.
#[derive(Clone)]
pub struct Aes128Gcm {
    /// The block cipher.
    cipher: Aes128,
    /// The hash key H.
    hash_key: [u8; BLOCK_LEN],
}

impl Aes128Gcm {
    /// Bytes in a key.
    pub const KEY_LEN: usize = 16;

    /// Bytes in a nonce: the 96-bit form every protocol uses.
    pub const NONCE_LEN: usize = 12;

    /// Bytes in a tag.
    pub const TAG_LEN: usize = 16;

    /// A cipher under one key.
    #[must_use]
    pub fn new(key: &[u8; Self::KEY_LEN]) -> Self {
        Self::with_cipher(Aes128::new(key))
    }

    /// A cipher around an existing block cipher.
    fn with_cipher(cipher: Aes128) -> Self {
        // The hash key is the encryption of the zero block, per SP 800-38D, section 6.4.
        let mut hash_key = [0_u8; BLOCK_LEN];
        cipher.encrypt_block(&mut hash_key);
        Self { cipher, hash_key }
    }

    /// Encrypts and authenticates, returning the ciphertext followed by the tag.
    ///
    /// # Panics
    ///
    /// Panics when the plaintext exceeds 2^32 - 2 blocks, about 64 GiB.
    #[must_use]
    pub fn seal(&self, nonce: &[u8; Self::NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        // Copy the plaintext, encrypt it in place, then append the tag.
        let mut sealed = Vec::with_capacity(plaintext.len() + Self::TAG_LEN);
        sealed.extend_from_slice(plaintext);
        let tag = self.seal_in_place_detached(nonce, aad, &mut sealed);
        sealed.extend_from_slice(&tag);
        sealed
    }

    /// Checks and decrypts a ciphertext followed by its tag.
    ///
    /// # Errors
    ///
    /// Fails when the input is shorter than a tag or the tag does not authenticate.
    pub fn open(
        &self,
        nonce: &[u8; Self::NONCE_LEN],
        aad: &[u8],
        sealed: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        // The tag is the last 16 bytes.
        // Anything shorter cannot be a sealed message.
        let Some(split) = sealed.len().checked_sub(Self::TAG_LEN) else {
            return Err(AeadError);
        };
        let (ciphertext, tag) = sealed.split_at(split);
        let tag = tag.try_into().map_err(|_| AeadError)?;
        let mut plaintext = ciphertext.to_vec();
        self.open_in_place_detached(nonce, aad, &mut plaintext, tag)?;
        Ok(plaintext)
    }

    /// Encrypts the buffer in place and returns the tag.
    ///
    /// # Panics
    ///
    /// Panics when the buffer exceeds 2^32 - 2 blocks, about 64 GiB.
    pub fn seal_in_place_detached(
        &self,
        nonce: &[u8; Self::NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> [u8; Self::TAG_LEN] {
        // Encrypt first, then authenticate the ciphertext, as GCM specifies.
        assert!(
            buffer.len() as u64 <= MAX_PLAINTEXT_LEN,
            "AES-GCM plaintext too long"
        );
        self.apply_counter(nonce, buffer);
        self.tag(nonce, aad, buffer)
    }

    /// Checks the tag, then decrypts the buffer in place.
    ///
    /// The buffer is left untouched on failure, so no unauthenticated plaintext escapes.
    ///
    /// # Errors
    ///
    /// Fails when the buffer is too long for GCM or the tag does not authenticate.
    pub fn open_in_place_detached(
        &self,
        nonce: &[u8; Self::NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; Self::TAG_LEN],
    ) -> Result<(), AeadError> {
        // A buffer past the GCM limit cannot have come from a valid sealer.
        if buffer.len() as u64 > MAX_PLAINTEXT_LEN {
            return Err(AeadError);
        }

        // Timing: the comparison reads all 16 bytes whatever the first difference.
        let expected = self.tag(nonce, aad, buffer);
        if !Mask::bytes_equal(&expected, tag).reveal() {
            return Err(AeadError);
        }
        self.apply_counter(nonce, buffer);
        Ok(())
    }

    /// XORs the payload keystream, from counter J0 + 1, into the buffer.
    fn apply_counter(&self, nonce: &[u8; Self::NONCE_LEN], buffer: &mut [u8]) {
        // inc32: only the low 32 bits count, per SP 800-38D, section 6.2.
        let mut counter = 2_u32;
        self.cipher.xor_keystream(buffer, || {
            let block = Self::counter_block(nonce, counter);
            counter = counter.wrapping_add(1);
            block
        });
    }

    /// The tag over the AAD and the ciphertext.
    fn tag(
        &self,
        nonce: &[u8; Self::NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> [u8; Self::TAG_LEN] {
        // S = GHASH(A | pad | C | pad | [len(A)]_64 | [len(C)]_64), lengths in bits.
        let mut ghash = Ghash::new(&self.hash_key);
        ghash.update_padded(aad);
        ghash.update_padded(ciphertext);
        let mut lengths = [0_u8; BLOCK_LEN];
        lengths[..8].copy_from_slice(&(aad.len() as u64 * 8).to_be_bytes());
        lengths[8..].copy_from_slice(&(ciphertext.len() as u64 * 8).to_be_bytes());
        ghash.update_blocks(&[lengths]);

        // T = AES_K(J0) ^ S.
        let mut tag = Self::counter_block(nonce, 1);
        self.cipher.encrypt_block(&mut tag);
        for (byte, s) in tag.iter_mut().zip(ghash.finalize()) {
            *byte ^= s;
        }
        tag
    }

    /// The counter block nonce || counter, the counter big-endian.
    fn counter_block(nonce: &[u8; Self::NONCE_LEN], counter: u32) -> [u8; BLOCK_LEN] {
        // The 96-bit nonce fills the first 12 bytes, the counter the last 4.
        let mut block = [0_u8; BLOCK_LEN];
        block[..Self::NONCE_LEN].copy_from_slice(nonce);
        block[Self::NONCE_LEN..].copy_from_slice(&counter.to_be_bytes());
        block
    }
}

impl Drop for Aes128Gcm {
    fn drop(&mut self) {
        wipe(&mut self.hash_key);
    }
}

impl fmt::Debug for Aes128Gcm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The key and H are secret: never print them.
        f.debug_struct("Aes128Gcm").finish_non_exhaustive()
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

    /// Seals with both the dispatched and the portable cipher, checks both, and returns one.
    fn seal_both(key: &[u8; 16], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let fast = Aes128Gcm::new(key).seal(nonce, aad, plaintext);
        let portable = Aes128Gcm::with_cipher(Aes128::portable(key)).seal(nonce, aad, plaintext);
        assert_eq!(fast, portable);
        fast
    }

    #[test]
    fn sp_800_38d_test_cases() {
        // AES-128 GCM test cases 1 to 4 of McGrew and Viega, adopted by NIST's suite.
        let zero_key = [0_u8; 16];
        let zero_nonce = [0_u8; 12];

        // Case 1: empty plaintext and AAD.
        // The tag is AES_0(J0) alone.
        assert_eq!(
            seal_both(&zero_key, &zero_nonce, &[], &[]),
            hex("58e2fccefa7e3061367f1d57a4e7455a")
        );

        // Case 2: one zero block.
        assert_eq!(
            seal_both(&zero_key, &zero_nonce, &[], &[0; 16]),
            hex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")
        );

        // Cases 3 and 4 share key, nonce, and plaintext.
        // Case 4 drops 4 bytes and adds AAD.
        let key: [u8; 16] = hex("feffe9928665731c6d6a8f9467308308").try_into().unwrap();
        let nonce: [u8; 12] = hex("cafebabefacedbaddecaf888").try_into().unwrap();
        let plaintext = hex(concat!(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        ));
        let ciphertext = hex(concat!(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e",
            "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
        ));

        let sealed = seal_both(&key, &nonce, &[], &plaintext);
        assert_eq!(sealed[..64], ciphertext[..]);
        assert_eq!(sealed[64..], hex("4d5c2af327cd64a62cf35abd2ba6fab4")[..]);

        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let sealed = seal_both(&key, &nonce, &aad, &plaintext[..60]);
        assert_eq!(sealed[..60], ciphertext[..60]);
        assert_eq!(sealed[60..], hex("5bc94fbc3221a5db94fae95ae7121a47")[..]);
        assert_eq!(
            Aes128Gcm::new(&key).open(&nonce, &aad, &sealed).unwrap(),
            plaintext[..60]
        );
    }

    #[test]
    fn every_tampering_is_rejected() {
        // Fixture state: 40-byte plaintext, 5-byte AAD, a 56-byte sealed message.
        let cipher = Aes128Gcm::new(&[3; 16]);
        let nonce = [9; 12];
        let sealed = cipher.seal(&nonce, b"route", &[0x5a; 40]);
        assert_eq!(sealed.len(), 56);

        // Mutation: one flipped bit anywhere in ciphertext or tag.
        for position in [0, 39, 40, 55] {
            let mut forged = sealed.clone();
            forged[position] ^= 1;
            assert_eq!(cipher.open(&nonce, b"route", &forged), Err(AeadError));
        }

        // Mutation: AAD, nonce, key, and length.
        assert_eq!(cipher.open(&nonce, b"Route", &sealed), Err(AeadError));
        assert_eq!(cipher.open(&[8; 12], b"route", &sealed), Err(AeadError));
        assert_eq!(
            Aes128Gcm::new(&[4; 16]).open(&nonce, b"route", &sealed),
            Err(AeadError)
        );
        assert_eq!(cipher.open(&nonce, b"route", &sealed[..15]), Err(AeadError));
    }

    #[test]
    fn failed_open_leaves_the_buffer_untouched() {
        // A forged tag must not release any decrypted byte.
        let cipher = Aes128Gcm::new(&[1; 16]);
        let mut buffer = *b"ciphertext bytes";
        let original = buffer;
        assert_eq!(
            cipher.open_in_place_detached(&[0; 12], b"", &mut buffer, &[0; 16]),
            Err(AeadError)
        );
        assert_eq!(buffer, original);
    }

    proptest! {
        #[test]
        fn open_inverts_seal_on_both_paths(
            key in any::<[u8; 16]>(),
            nonce in any::<[u8; 12]>(),
            aad in prop::collection::vec(any::<u8>(), 0..70),
            plaintext in prop::collection::vec(any::<u8>(), 0..600),
        ) {
            // Law: open(seal(m)) == m, and the hardware and portable paths agree byte for byte.
            let sealed = seal_both(&key, &nonce, &aad, &plaintext);
            prop_assert_eq!(sealed.len(), plaintext.len() + 16);
            prop_assert_eq!(Aes128Gcm::new(&key).open(&nonce, &aad, &sealed), Ok(plaintext));
        }
    }
}
