//! The Noise symmetric state: transcript hash, chaining key, and cipher states.
//!
//! Section 5.1 and 5.2 of the Noise Protocol Framework, with SHA-256 as the hash.

use sha2::{Digest, Sha256};

use super::{NoiseCrypto, PROTOCOL_NAME, TAG_LEN};
use crate::secure::SecureError;

/// SHA-256 block size, the HMAC padding width.
const BLOCK_LEN: usize = 64;

/// HMAC-SHA256 of a message under a 32-byte key, RFC 2104.
pub(super) fn hmac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    // Pad the key to one block; a 32-byte key never needs hashing first.
    let mut block = [0u8; BLOCK_LEN];
    block[..32].copy_from_slice(key);
    // Inner hash: H((K ^ ipad) || message).
    let mut inner = Sha256::new();
    inner.update(block.map(|byte| byte ^ 0x36));
    for part in parts {
        inner.update(part);
    }
    // Outer hash: H((K ^ opad) || inner).
    let mut outer = Sha256::new();
    outer.update(block.map(|byte| byte ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// HKDF with two outputs, as Noise defines it.
///
/// ```text
/// temp = HMAC(chaining_key, input_key_material)
/// out1 = HMAC(temp, 0x01)
/// out2 = HMAC(temp, out1 || 0x02)
/// ```
pub(super) fn hkdf(chaining_key: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let temp = hmac(chaining_key, &[ikm]);
    let out1 = hmac(&temp, &[&[0x01]]);
    let out2 = hmac(&temp, &[&out1, &[0x02]]);
    (out1, out2)
}

/// A key and its nonce counter.
#[derive(Clone, Debug, Default)]
pub(super) struct CipherState {
    /// The key, absent until the first key mixing.
    key: Option<[u8; 32]>,
    /// The next nonce.
    nonce: u64,
}

impl CipherState {
    /// A cipher state holding a key, at nonce zero.
    pub(super) const fn new(key: [u8; 32]) -> Self {
        Self {
            key: Some(key),
            nonce: 0,
        }
    }

    /// Encrypts, or copies when no key is set yet.
    pub(super) fn encrypt(
        &mut self,
        crypto: &dyn NoiseCrypto,
        ad: &[u8],
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SecureError> {
        match self.key {
            Some(key) => {
                let nonce = self.next_nonce()?;
                crypto.encrypt(&key, nonce, ad, plaintext, out);
            }
            None => out.extend_from_slice(plaintext),
        }
        Ok(())
    }

    /// Decrypts, or copies when no key is set yet.
    pub(super) fn decrypt(
        &mut self,
        crypto: &dyn NoiseCrypto,
        ad: &[u8],
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SecureError> {
        match self.key {
            Some(key) => {
                if ciphertext.len() < TAG_LEN {
                    return Err(SecureError::MessageTooShort);
                }
                let nonce = self.next_nonce()?;
                crypto.decrypt(&key, nonce, ad, ciphertext, out)
            }
            None => {
                out.extend_from_slice(ciphertext);
                Ok(())
            }
        }
    }

    /// Whether a key is set, so ciphertexts carry a tag.
    pub(super) const fn has_key(&self) -> bool {
        self.key.is_some()
    }

    /// Takes the current nonce and advances the counter.
    const fn next_nonce(&mut self) -> Result<u64, SecureError> {
        // Nonce 2^64 - 1 is reserved by the framework, so it is never used.
        if self.nonce == u64::MAX {
            return Err(SecureError::NonceExhausted);
        }
        let nonce = self.nonce;
        self.nonce += 1;
        Ok(nonce)
    }
}

/// The running handshake transcript and key schedule.
#[derive(Clone, Debug)]
pub(super) struct SymmetricState {
    /// The chaining key, folding in every DH output.
    chaining_key: [u8; 32],
    /// The transcript hash, authenticated as associated data.
    hash: [u8; 32],
    /// The handshake cipher.
    cipher: CipherState,
}

impl SymmetricState {
    /// The state after initialization with an empty prologue.
    pub(super) fn new() -> Self {
        // A 32-byte protocol name equals the hash length, so it is used verbatim.
        let hash = *PROTOCOL_NAME;
        let mut state = Self {
            chaining_key: hash,
            hash,
            cipher: CipherState::default(),
        };
        // libp2p uses an empty prologue, which still updates the hash.
        state.mix_hash(&[]);
        state
    }

    /// Folds data into the transcript hash: h = SHA256(h || data).
    pub(super) fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(self.hash);
        hasher.update(data);
        self.hash = hasher.finalize().into();
    }

    /// Folds a DH output into the chaining key and installs a fresh cipher key.
    pub(super) fn mix_key(&mut self, ikm: &[u8]) {
        let (chaining_key, key) = hkdf(&self.chaining_key, ikm);
        self.chaining_key = chaining_key;
        self.cipher = CipherState::new(key);
    }

    /// Encrypts under the transcript hash, then folds the ciphertext into it.
    pub(super) fn encrypt_and_hash(
        &mut self,
        crypto: &dyn NoiseCrypto,
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SecureError> {
        let start = out.len();
        self.cipher
            .encrypt(crypto, &self.hash.clone(), plaintext, out)?;
        let ciphertext = out[start..].to_vec();
        self.mix_hash(&ciphertext);
        Ok(())
    }

    /// Decrypts under the transcript hash, then folds the ciphertext into it.
    pub(super) fn decrypt_and_hash(
        &mut self,
        crypto: &dyn NoiseCrypto,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SecureError> {
        let mut plaintext = Vec::new();
        self.cipher
            .decrypt(crypto, &self.hash.clone(), ciphertext, &mut plaintext)?;
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
        let (first, second) = hkdf(&self.chaining_key, &[]);
        (CipherState::new(first), CipherState::new(second))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::hex;

    #[test]
    fn hmac_sha256_rfc4231_case_2() {
        // RFC 4231 test case 2 uses the 4-byte key "Jefe"; zero-padding to 32 bytes is equivalent.
        let mut key = [0u8; 32];
        key[..4].copy_from_slice(b"Jefe");
        let mac = hmac(&key, &[b"what do ya want ", b"for nothing?"]);
        assert_eq!(
            mac.to_vec(),
            hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
    }

    #[test]
    fn initial_hash_is_the_protocol_name_mixed_with_an_empty_prologue() {
        // h = SHA256(name || "") and ck = name.
        let state = SymmetricState::new();
        assert_eq!(state.hash, <[u8; 32]>::from(Sha256::digest(PROTOCOL_NAME)));
        assert_eq!(&state.chaining_key, PROTOCOL_NAME);
    }

    #[test]
    fn nonce_exhaustion_is_an_error() {
        // Fixture state: the counter sits at the reserved value 2^64 - 1.
        let mut cipher = CipherState {
            key: Some([0; 32]),
            nonce: u64::MAX,
        };
        assert_eq!(cipher.next_nonce(), Err(SecureError::NonceExhausted));
    }
}
