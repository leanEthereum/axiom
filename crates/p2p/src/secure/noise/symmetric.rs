//! The Noise symmetric state: transcript hash, chaining key, and cipher states.
//!
//! Sections 5.1 and 5.2 of the Noise Protocol Framework, with SHA-256 and ChaCha20-Poly1305.

use std::fmt;

use axiom_crypto::{chacha20poly1305::ChaCha20Poly1305, hmac::HmacSha256};
use sha2::{Digest, Sha256};

use super::{PROTOCOL_NAME, TAG_LEN};
use crate::secure::SecureError;

/// Bytes of a hash output, a chaining key, and a cipher key.
const HASH_LEN: usize = 32;

/// A key and its nonce counter.
#[derive(Clone, Default)]
pub(super) struct CipherState {
    /// The cipher, absent until the first key mixing.
    cipher: Option<ChaCha20Poly1305>,
    /// The next nonce.
    nonce: u64,
}

impl fmt::Debug for CipherState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Keys stay out of logs; the nonce is public.
        f.debug_struct("CipherState")
            .field("keyed", &self.cipher.is_some())
            .field("nonce", &self.nonce)
            .finish()
    }
}

impl CipherState {
    /// A cipher state holding a key, at nonce zero.
    pub(super) const fn new(key: &[u8; HASH_LEN]) -> Self {
        Self {
            cipher: Some(ChaCha20Poly1305::new(key)),
            nonce: 0,
        }
    }

    /// Encrypts, or copies when no key is set yet.
    pub(super) fn encrypt(
        &mut self,
        ad: &[u8],
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SecureError> {
        let Some(cipher) = &self.cipher else {
            out.extend_from_slice(plaintext);
            return Ok(());
        };
        let nonce = Self::encode_nonce(Self::advance(&mut self.nonce)?);
        // Encrypt in place behind what the buffer already holds, then append the tag.
        let start = out.len();
        out.extend_from_slice(plaintext);
        let tag = cipher.seal_in_place_detached(&nonce, ad, &mut out[start..]);
        out.extend_from_slice(&tag);
        Ok(())
    }

    /// Decrypts, or copies when no key is set yet.
    pub(super) fn decrypt(
        &mut self,
        ad: &[u8],
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SecureError> {
        let Some(cipher) = &self.cipher else {
            out.extend_from_slice(ciphertext);
            return Ok(());
        };
        // The tag is the last 16 bytes.
        let (body, tag) =
            ciphertext
                .split_last_chunk::<TAG_LEN>()
                .ok_or(SecureError::MessageTooShort {
                    needed: TAG_LEN,
                    len: ciphertext.len(),
                })?;
        let counter = Self::advance(&mut self.nonce)?;
        let nonce = Self::encode_nonce(counter);
        let start = out.len();
        out.extend_from_slice(body);
        // On failure the unauthenticated bytes are removed before returning.
        if cipher
            .open_in_place_detached(&nonce, ad, &mut out[start..], tag)
            .is_err()
        {
            out.truncate(start);
            return Err(SecureError::DecryptionFailed { nonce: counter });
        }
        Ok(())
    }

    /// Whether a key is set, so ciphertexts carry a tag.
    pub(super) const fn has_key(&self) -> bool {
        self.cipher.is_some()
    }

    /// Takes the current nonce and advances the counter.
    const fn advance(nonce: &mut u64) -> Result<u64, SecureError> {
        // Nonce 2^64 - 1 is reserved by the framework, so it is never used.
        if *nonce == u64::MAX {
            return Err(SecureError::NonceExhausted);
        }
        let current = *nonce;
        *nonce += 1;
        Ok(current)
    }

    /// The 96-bit ChaCha20-Poly1305 nonce: 4 zero bytes, then the counter little-endian.
    ///
    /// See the Noise specification, section 12.3.
    fn encode_nonce(counter: u64) -> [u8; ChaCha20Poly1305::NONCE_LEN] {
        let mut nonce = [0u8; ChaCha20Poly1305::NONCE_LEN];
        nonce[4..].copy_from_slice(&counter.to_le_bytes());
        nonce
    }
}

/// The running handshake transcript and key schedule.
#[derive(Clone, Debug)]
pub(super) struct SymmetricState {
    /// The chaining key, folding in every DH output.
    chaining_key: [u8; HASH_LEN],
    /// The transcript hash, authenticated as associated data.
    hash: [u8; HASH_LEN],
    /// The handshake cipher.
    cipher: CipherState,
}

impl SymmetricState {
    /// The state after initialization and the prologue.
    pub(super) fn new(prologue: &[u8]) -> Self {
        // A 32-byte protocol name equals the hash length, so it is used verbatim.
        let hash = *PROTOCOL_NAME;
        let mut state = Self {
            chaining_key: hash,
            hash,
            cipher: CipherState::default(),
        };
        // An empty prologue, as libp2p uses, still updates the hash.
        state.mix_hash(prologue);
        state
    }

    /// The transcript hash, which both sides agree on after the handshake.
    #[cfg(test)]
    pub(super) const fn handshake_hash(&self) -> &[u8; HASH_LEN] {
        &self.hash
    }

    /// Folds data into the transcript hash: h = SHA256(h || data).
    pub(super) fn mix_hash(&mut self, data: &[u8]) {
        self.hash = Sha256::new()
            .chain_update(self.hash)
            .chain_update(data)
            .finalize()
            .into();
    }

    /// Folds a DH output into the chaining key and installs a fresh cipher key.
    pub(super) fn mix_key(&mut self, ikm: &[u8]) {
        let (chaining_key, key) = Self::hkdf(&self.chaining_key, ikm);
        self.chaining_key = chaining_key;
        self.cipher = CipherState::new(&key);
    }

    /// Encrypts under the transcript hash, then folds the ciphertext into it.
    pub(super) fn encrypt_and_hash(
        &mut self,
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SecureError> {
        let start = out.len();
        let hash = self.hash;
        self.cipher.encrypt(&hash, plaintext, out)?;
        self.mix_hash(&out[start..]);
        Ok(())
    }

    /// Decrypts under the transcript hash, then folds the ciphertext into it.
    pub(super) fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, SecureError> {
        let mut plaintext = Vec::new();
        let hash = self.hash;
        self.cipher.decrypt(&hash, ciphertext, &mut plaintext)?;
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }

    /// Bytes an encrypted field of a given plaintext length takes on the wire.
    pub(super) const fn sealed_len(&self, plaintext_len: usize) -> usize {
        if self.cipher.has_key() {
            plaintext_len + TAG_LEN
        } else {
            plaintext_len
        }
    }

    /// Derives the two transport ciphers: initiator-to-responder first.
    pub(super) fn split(&self) -> (CipherState, CipherState) {
        let (first, second) = Self::hkdf(&self.chaining_key, &[]);
        (CipherState::new(&first), CipherState::new(&second))
    }

    /// HKDF with two outputs, as Noise defines it in section 4.3.
    ///
    /// ```text
    /// temp = HMAC(chaining_key, input_key_material)
    /// out1 = HMAC(temp, 0x01)
    /// out2 = HMAC(temp, out1 || 0x02)
    /// ```
    ///
    /// That is RFC 5869 with the chaining key as salt, empty info, and 64 output bytes.
    fn hkdf(chaining_key: &[u8; HASH_LEN], ikm: &[u8]) -> ([u8; HASH_LEN], [u8; HASH_LEN]) {
        // Extract: the pseudorandom key.
        let temp = HmacSha256::mac(chaining_key, ikm);
        // Expand: two blocks, each chained into the next.
        let out1 = HmacSha256::mac(&temp, &[0x01]);
        let mut second = HmacSha256::new(&temp);
        second.update(&out1);
        second.update(&[0x02]);
        (out1, second.finalize())
    }
}

#[cfg(test)]
mod tests {
    use axiom_crypto::hkdf::Hkdf;

    use super::*;

    #[test]
    fn hkdf_equals_rfc_5869_with_the_chaining_key_as_salt() {
        // RFC 5869 extract-then-expand of 64 bytes, for ck = 0x01.. and ikm = "dh".
        let chaining_key = [1u8; 32];
        let mut okm = [0u8; 64];
        Hkdf::extract(&chaining_key, b"dh")
            .expand(&[], &mut okm)
            .unwrap();
        let (out1, out2) = SymmetricState::hkdf(&chaining_key, b"dh");
        assert_eq!(out1, okm[..32]);
        assert_eq!(out2, okm[32..]);
    }

    #[test]
    fn initial_hash_is_the_protocol_name_mixed_with_the_prologue() {
        // h = SHA256(name || "") and ck = name.
        let state = SymmetricState::new(&[]);
        assert_eq!(state.hash, <[u8; 32]>::from(Sha256::digest(PROTOCOL_NAME)));
        assert_eq!(&state.chaining_key, PROTOCOL_NAME);
    }

    #[test]
    fn nonce_is_four_zero_bytes_then_the_counter_little_endian() {
        // Counter 0x0102 encodes as 00 00 00 00 | 02 01 00 00 00 00 00 00.
        assert_eq!(
            CipherState::encode_nonce(0x0102),
            [0, 0, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn nonce_exhaustion_is_an_error() {
        // Fixture state: the counter sits at the reserved value 2^64 - 1.
        let mut cipher = CipherState {
            cipher: Some(ChaCha20Poly1305::new(&[0; 32])),
            nonce: u64::MAX,
        };
        let mut out = Vec::new();
        assert_eq!(
            cipher.encrypt(&[], b"x", &mut out),
            Err(SecureError::NonceExhausted)
        );
    }

    #[test]
    fn failed_decryption_leaves_the_output_untouched() {
        // Seal "hello" at nonce 0, then flip the first ciphertext bit.
        let mut sender = CipherState::new(&[9; 32]);
        let mut receiver = CipherState::new(&[9; 32]);
        let mut sealed = Vec::new();
        sender.encrypt(b"ad", b"hello", &mut sealed).unwrap();
        sealed[0] ^= 1;
        let mut out = b"kept".to_vec();
        assert_eq!(
            receiver.decrypt(b"ad", &sealed, &mut out),
            Err(SecureError::DecryptionFailed { nonce: 0 })
        );
        assert_eq!(out, b"kept");
    }
}
