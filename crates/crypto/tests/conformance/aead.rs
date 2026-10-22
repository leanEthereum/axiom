//! Wycheproof AEAD suites: ChaCha20-Poly1305, AES-128-GCM, and AES-128-GMAC.
//!
//! Every case opens the published ciphertext, then reseals the plaintext.
//! A valid case must open to the message and reseal to the same bytes.
//! An invalid case, always a forged tag, must fail to open.
//!
//! The crate serves AES with 128-bit keys and both AEADs with 96-bit nonces and 128-bit tags.
//! Other key, nonce, and tag sizes are counted as unsupported.

use axiom_crypto::{AeadError, aes::Aes128Gcm, chacha20poly1305::ChaCha20Poly1305};

use crate::wycheproof::{Case, Outcome, Tally, VectorFile};

/// An AEAD under one key.
enum Cipher {
    /// ChaCha20-Poly1305 of RFC 8439.
    ChaCha(ChaCha20Poly1305),
    /// AES-128-GCM of SP 800-38D.
    Aes(Aes128Gcm),
}

impl Cipher {
    /// ChaCha20-Poly1305 under a key, unsupported unless it is 32 bytes.
    fn chacha(key: &[u8]) -> Result<Self, Outcome> {
        let key = key
            .try_into()
            .map_err(|_| Outcome::Unsupported("ChaCha20 key other than 256 bits"))?;
        Ok(Self::ChaCha(ChaCha20Poly1305::new(key)))
    }

    /// AES-128-GCM under a key, unsupported unless it is 16 bytes.
    fn aes(key: &[u8]) -> Result<Self, Outcome> {
        let key = key
            .try_into()
            .map_err(|_| Outcome::Unsupported("AES key other than 128 bits"))?;
        Ok(Self::Aes(Aes128Gcm::new(key)))
    }

    /// Encrypts and authenticates.
    fn seal(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        match self {
            Self::ChaCha(cipher) => cipher.seal(nonce, aad, plaintext),
            Self::Aes(cipher) => cipher.seal(nonce, aad, plaintext),
        }
    }

    /// Authenticates and decrypts.
    fn open(&self, nonce: &[u8; 12], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, AeadError> {
        match self {
            Self::ChaCha(cipher) => cipher.open(nonce, aad, sealed),
            Self::Aes(cipher) => cipher.open(nonce, aad, sealed),
        }
    }

    /// Runs one case: open the published bytes, then reseal the plaintext.
    ///
    /// The message field is the plaintext and the AAD field the associated data.
    /// For GMAC the message is all associated data, and the plaintext is empty.
    fn check(&self, case: &Case<'_>, aad: &[u8], plaintext: &[u8], ciphertext: &[u8]) -> Outcome {
        let Ok(nonce) = <[u8; 12]>::try_from(case.hex("iv").as_slice()) else {
            return Outcome::Unsupported("nonce other than 96 bits");
        };
        let tag = case.hex("tag");
        if tag.len() != 16 {
            return Outcome::Unsupported("tag other than 128 bits");
        }
        let sealed = [ciphertext, &tag].concat();

        // Phase 1: the published ciphertext and tag must open to the message, or fail.
        match self.open(&nonce, aad, &sealed) {
            Err(AeadError) => Outcome::Rejected,
            Ok(opened) if opened != plaintext => {
                Outcome::WrongOutput(format!("opened to {opened:02x?}"))
            }
            // Phase 2: sealing the message again must give the very same bytes.
            Ok(_) => {
                let resealed = self.seal(&nonce, aad, plaintext);
                if resealed == sealed {
                    Outcome::Accepted
                } else {
                    Outcome::WrongOutput(format!("sealed to {resealed:02x?}"))
                }
            }
        }
    }
}

/// Runs an AEAD file whose cases carry key, iv, aad, msg, ct, and tag.
fn run_aead(file: &VectorFile, cipher: fn(&[u8]) -> Result<Cipher, Outcome>) -> Tally {
    file.run(|case| match cipher(&case.hex("key")) {
        Err(unsupported) => unsupported,
        Ok(cipher) => cipher.check(case, &case.hex("aad"), &case.hex("msg"), &case.hex("ct")),
    })
}

#[test]
fn chacha20_poly1305() {
    let Some(file) = VectorFile::load("chacha20_poly1305_test.json") else {
        return;
    };
    // 316 cases use a 96-bit nonce: 256 valid, 60 with a modified tag.
    // 9 cases use another nonce size, which the 12-byte nonce type cannot express.
    // Wycheproof marks those 9 invalid, and the type system already refuses them.
    let tally = run_aead(&file, Cipher::chacha);
    assert_eq!(
        tally,
        Tally {
            valid: 256,
            invalid: 60,
            unsupported: 9,
            ..Tally::default()
        }
    );
}

#[test]
fn aes_gcm() {
    let Some(file) = VectorFile::load("aes_gcm_test.json") else {
        return;
    };
    // Of 316 cases, 67 use a 128-bit key and a 96-bit nonce: 40 valid, 27 with a modified tag.
    // The other 249 use AES-192, AES-256, or a nonce of another size.
    let tally = run_aead(&file, Cipher::aes);
    assert_eq!(
        tally,
        Tally {
            valid: 40,
            invalid: 27,
            unsupported: 249,
            ..Tally::default()
        }
    );
}

#[test]
fn aes_gmac() {
    let Some(file) = VectorFile::load("aes_gmac_test.json") else {
        return;
    };
    // GMAC is GCM with an empty plaintext and the message as associated data.
    // Of 414 cases, 69 use a 128-bit key and a 96-bit nonce: 15 valid, 54 with a modified tag.
    let tally = file.run(|case| match Cipher::aes(&case.hex("key")) {
        Err(unsupported) => unsupported,
        Ok(cipher) => cipher.check(case, &case.hex("msg"), &[], &[]),
    });
    assert_eq!(
        tally,
        Tally {
            valid: 15,
            invalid: 54,
            unsupported: 345,
            ..Tally::default()
        }
    );
}
