//! Transport messages after the handshake: framed, encrypted chunks.
//!
//! ```text
//! wire:  [ length: u16 BE ][ ciphertext || tag ]   length <= 65535
//!
//! 100 000 plaintext bytes → two frames:
//!   65519 plaintext + 16 tag = 65535
//!   34481 plaintext + 16 tag = 34497
//! ```

use std::fmt;

use super::{MAX_PLAINTEXT_LEN, symmetric::CipherState};
use crate::secure::{Open, Seal, SecureError};

/// Bytes of the frame length prefix.
const PREFIX_LEN: usize = 2;

/// The sending half of a Noise transport.
pub(super) struct NoiseSealer {
    /// The sending key and nonce.
    cipher: CipherState,
}

impl NoiseSealer {
    /// A sealer over a split cipher state.
    pub(super) const fn new(cipher: CipherState) -> Self {
        Self { cipher }
    }
}

impl fmt::Debug for NoiseSealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Keys stay out of logs.
        f.write_str("NoiseSealer")
    }
}

impl Seal for NoiseSealer {
    fn seal(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> Result<(), SecureError> {
        // One frame per 65519 plaintext bytes, each with its own nonce.
        for chunk in plaintext.chunks(MAX_PLAINTEXT_LEN) {
            // Reserve the prefix, encrypt behind it, then fill in the length.
            let start = out.len();
            out.extend_from_slice(&[0; PREFIX_LEN]);
            self.cipher.encrypt(&[], chunk, out)?;
            // Invariant: chunk <= 65519, so chunk + tag <= 65535 fits in a u16.
            let len = (out.len() - start - PREFIX_LEN) as u16;
            out[start..start + PREFIX_LEN].copy_from_slice(&len.to_be_bytes());
        }
        Ok(())
    }
}

/// The receiving half of a Noise transport.
pub(super) struct NoiseOpener {
    /// The receiving key and nonce.
    cipher: CipherState,
    /// Wire bytes of an incomplete frame.
    buffer: Vec<u8>,
}

impl NoiseOpener {
    /// An opener over a split cipher state.
    pub(super) const fn new(cipher: CipherState) -> Self {
        Self {
            cipher,
            buffer: Vec::new(),
        }
    }
}

impl fmt::Debug for NoiseOpener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoiseOpener")
            .field("buffered", &self.buffer.len())
            .finish_non_exhaustive()
    }
}

impl Open for NoiseOpener {
    fn open(&mut self, wire: &[u8], out: &mut Vec<u8>) -> Result<(), SecureError> {
        self.buffer.extend_from_slice(wire);
        let mut offset = 0;
        // Decrypt every complete frame; keep the tail for the next call.
        while let Some(prefix) = self.buffer.get(offset..offset + PREFIX_LEN) {
            let len = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
            let Some(frame) = self
                .buffer
                .get(offset + PREFIX_LEN..offset + PREFIX_LEN + len)
            else {
                break;
            };
            self.cipher.decrypt(&[], frame, out)?;
            offset += PREFIX_LEN + len;
        }
        self.buffer.drain(..offset);
        Ok(())
    }
}
