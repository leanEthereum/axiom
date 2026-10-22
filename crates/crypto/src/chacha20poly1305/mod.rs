//! ChaCha20-Poly1305, the AEAD of RFC 8439 that seals libp2p Noise transport messages.

#[cfg(target_arch = "x86_64")]
mod avx2;
mod chacha20;
mod poly1305;

use std::fmt;

pub use chacha20::ChaCha20;
pub use poly1305::Poly1305;

use crate::{
    aead::AeadError,
    ct::{Mask, wipe},
};

/// The ChaCha20-Poly1305 authenticated cipher under one key.
///
/// # Overview
///
/// Sealing follows RFC 8439, section 2.8.
///
/// ```text
/// otk        = ChaCha20(key, nonce, counter 0)[0..32]
/// ciphertext = plaintext ^ ChaCha20(key, nonce, counter 1 ..)
/// tag        = Poly1305(otk, aad | pad16 | ciphertext | pad16 | len(aad) | len(ciphertext))
/// ```
///
/// A nonce must never repeat under one key.
/// A repeat reveals the XOR of two plaintexts and the Poly1305 key.
#[derive(Clone)]
pub struct ChaCha20Poly1305 {
    /// The 256-bit key.
    key: [u8; Self::KEY_LEN],
}

impl ChaCha20Poly1305 {
    /// Bytes in a key.
    pub const KEY_LEN: usize = 32;

    /// Bytes in a nonce: the 96-bit IETF variant.
    pub const NONCE_LEN: usize = 12;

    /// Bytes in a tag.
    pub const TAG_LEN: usize = 16;

    /// A cipher under one key.
    #[must_use]
    pub const fn new(key: &[u8; Self::KEY_LEN]) -> Self {
        Self { key: *key }
    }

    /// Encrypts and authenticates, returning the ciphertext followed by the tag.
    ///
    /// # Panics
    ///
    /// Panics when the plaintext exceeds 256 GiB, the ChaCha20 counter range.
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
        let mut plaintext = ciphertext.to_vec();
        let tag = tag.try_into().map_err(|_| AeadError)?;
        self.open_in_place_detached(nonce, aad, &mut plaintext, tag)?;
        Ok(plaintext)
    }

    /// Encrypts the buffer in place and returns the tag.
    ///
    /// # Panics
    ///
    /// Panics when the buffer exceeds 256 GiB, the ChaCha20 counter range.
    pub fn seal_in_place_detached(
        &self,
        nonce: &[u8; Self::NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> [u8; Self::TAG_LEN] {
        // Encrypt first, then authenticate the ciphertext.
        let (mut mac, mut stream) = self.start(nonce);
        stream.apply_keystream(buffer);
        Self::finish(&mut mac, aad, buffer);
        mac.finalize()
    }

    /// Checks the tag, then decrypts the buffer in place.
    ///
    /// The buffer is left untouched on failure, so no unauthenticated plaintext escapes.
    ///
    /// # Errors
    ///
    /// Fails when the tag does not authenticate.
    pub fn open_in_place_detached(
        &self,
        nonce: &[u8; Self::NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; Self::TAG_LEN],
    ) -> Result<(), AeadError> {
        let (mut mac, mut stream) = self.start(nonce);

        // Authenticate the ciphertext as received, before any decryption.
        Self::finish(&mut mac, aad, buffer);
        let expected = mac.finalize();

        // Timing: the comparison reads all 16 bytes whatever the first difference.
        if !Mask::bytes_equal(&expected, tag).reveal() {
            return Err(AeadError);
        }
        stream.apply_keystream(buffer);
        Ok(())
    }

    /// The Poly1305 instance keyed by block 0, and the keystream from block 1.
    fn start(&self, nonce: &[u8; Self::NONCE_LEN]) -> (Poly1305, ChaCha20) {
        // Block 0 yields the one-time key, per RFC 8439, section 2.6.
        let mut stream = ChaCha20::new(&self.key, nonce, 0);
        let mut block = stream.next_block();
        let mut one_time_key = [0_u8; Poly1305::KEY_LEN];
        one_time_key.copy_from_slice(&block[..Poly1305::KEY_LEN]);
        let mac = Poly1305::new(&one_time_key);

        // Both copies of the one-time key are secret.
        wipe(&mut block);
        wipe(&mut one_time_key);

        // The stream now sits at block 1, where the payload keystream begins.
        (mac, stream)
    }

    /// Feeds the padded AAD, the padded ciphertext, and both lengths.
    fn finish(mac: &mut Poly1305, aad: &[u8], ciphertext: &[u8]) {
        // Each variable-length field is padded so the next starts on a block boundary.
        mac.update_padded(aad);
        mac.update_padded(ciphertext);
        mac.update(&(aad.len() as u64).to_le_bytes());
        mac.update(&(ciphertext.len() as u64).to_le_bytes());
    }
}

impl Drop for ChaCha20Poly1305 {
    fn drop(&mut self) {
        wipe(&mut self.key);
    }
}

impl fmt::Debug for ChaCha20Poly1305 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The key is secret: never print it.
        f.debug_struct("ChaCha20Poly1305").finish_non_exhaustive()
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

    /// The sunscreen plaintext of RFC 8439, 114 bytes.
    const SUNSCREEN: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    #[test]
    fn rfc_8439_one_time_key_generation() {
        // RFC 8439, section 2.6.2: the Poly1305 key is the head of block 0.
        let key: [u8; 32] = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .try_into()
            .unwrap();
        let nonce: [u8; 12] = hex("000000000001020304050607").try_into().unwrap();
        let block = ChaCha20::new(&key, &nonce, 0).next_block();
        assert_eq!(
            block[..32].to_vec(),
            hex("8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646")
        );
    }

    #[test]
    fn rfc_8439_aead_vector() {
        // RFC 8439, section 2.8.2: sunscreen with 12 bytes of AAD.
        let key: [u8; 32] = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .try_into()
            .unwrap();
        let nonce: [u8; 12] = hex("070000004041424344454647").try_into().unwrap();
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let cipher = ChaCha20Poly1305::new(&key);

        let sealed = cipher.seal(&nonce, &aad, SUNSCREEN);
        let expected_ciphertext = hex(concat!(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc",
            "3ff4def08e4b7a9de576d26586cec64b6116",
        ));
        assert_eq!(sealed[..114].to_vec(), expected_ciphertext);
        assert_eq!(
            sealed[114..].to_vec(),
            hex("1ae10b594f09e26a7e902ecbd0600691")
        );

        // And back.
        assert_eq!(cipher.open(&nonce, &aad, &sealed).unwrap(), SUNSCREEN);
    }

    #[test]
    fn rfc_8439_decryption_vector() {
        // RFC 8439, appendix A.5: a 265-byte ciphertext with 12 bytes of AAD.
        let key: [u8; 32] = hex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0")
            .try_into()
            .unwrap();
        let nonce: [u8; 12] = hex("000000000102030405060708").try_into().unwrap();
        let aad = hex("f33388860000000000004e91");
        let mut sealed = hex(concat!(
            "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2",
            "4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf",
            "332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855",
            "9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4",
            "b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e",
            "af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a",
            "0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10",
            "49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29",
            "a6ad5cb4022b02709b",
        ));
        sealed.extend(hex("eead9d67890cbb22392336fea1851f38"));
        let plaintext = ChaCha20Poly1305::new(&key)
            .open(&nonce, &aad, &sealed)
            .unwrap();
        assert!(
            plaintext.starts_with(
                b"Internet-Drafts are draft documents valid for a maximum of six months"
            )
        );
        assert_eq!(plaintext.len(), 265);
    }

    #[test]
    fn every_tampering_is_rejected() {
        // Fixture state: 114-byte plaintext, 3-byte AAD, a 130-byte sealed message.
        let cipher = ChaCha20Poly1305::new(&[9; 32]);
        let nonce = [4; 12];
        let sealed = cipher.seal(&nonce, b"aad", SUNSCREEN);
        assert_eq!(sealed.len(), 130);

        // Mutation: flip one bit in the ciphertext, then in the tag.
        for position in [0, 113, 114, 129] {
            let mut forged = sealed.clone();
            forged[position] ^= 0x80;
            assert_eq!(cipher.open(&nonce, b"aad", &forged), Err(AeadError));
        }

        // Mutation: a different AAD, nonce, or key.
        assert_eq!(cipher.open(&nonce, b"aaD", &sealed), Err(AeadError));
        assert_eq!(cipher.open(&[5; 12], b"aad", &sealed), Err(AeadError));
        assert_eq!(
            ChaCha20Poly1305::new(&[8; 32]).open(&nonce, b"aad", &sealed),
            Err(AeadError)
        );

        // Mutation: inputs shorter than a tag, and a truncated message.
        assert_eq!(cipher.open(&nonce, b"aad", &sealed[..15]), Err(AeadError));
        assert_eq!(cipher.open(&nonce, b"aad", &sealed[1..]), Err(AeadError));
    }

    #[test]
    fn failed_open_leaves_the_buffer_untouched() {
        // A forged tag must not release any decrypted byte.
        let cipher = ChaCha20Poly1305::new(&[1; 32]);
        let mut buffer = *b"ciphertext bytes";
        let original = buffer;
        let result = cipher.open_in_place_detached(&[0; 12], b"", &mut buffer, &[0; 16]);
        assert_eq!(result, Err(AeadError));
        assert_eq!(buffer, original);
    }

    proptest! {
        #[test]
        fn open_inverts_seal(
            key in any::<[u8; 32]>(),
            nonce in any::<[u8; 12]>(),
            aad in prop::collection::vec(any::<u8>(), 0..70),
            plaintext in prop::collection::vec(any::<u8>(), 0..1100),
        ) {
            // Law: open(seal(m)) == m, with ciphertext as long as the plaintext plus 16.
            let cipher = ChaCha20Poly1305::new(&key);
            let sealed = cipher.seal(&nonce, &aad, &plaintext);
            prop_assert_eq!(sealed.len(), plaintext.len() + 16);
            prop_assert_eq!(cipher.open(&nonce, &aad, &sealed), Ok(plaintext));
        }
    }
}
