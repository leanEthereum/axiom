//! Record protection: sealing and opening one direction's records under its current keys.
//!
//! # Overview
//!
//! TLS 1.3 encrypts every record as application data, hiding the real type inside, per RFC 8446, section 5.2.
//!
//! ```text
//! nonce     = iv XOR sequence number, left-padded to 12 bytes
//! plaintext = content || type || zero padding
//! aad       = the 5-byte record header
//! ```
//!
//! TLS 1.2 keeps the type in the header and authenticates it, per RFC 5246, section 6.2.3.3.
//!
//! ```text
//! aad = sequence number (8) || type (1) || version (2) || plaintext length (2)
//! AES-GCM nonce = 4-byte fixed IV || 8-byte explicit nonce sent in the record, RFC 5288
//! ChaCha20-Poly1305 nonce = 12-byte IV XOR sequence number, RFC 7905
//! ```
//!
//! Each record takes the next sequence number; one may never repeat under a key.

use std::fmt;

use axiom_crypto::{aes::Aes128Gcm, chacha20poly1305::ChaCha20Poly1305};

use super::{ContentType, LEGACY_RECORD_VERSION};
use crate::{CipherSuite, ProtocolError, Tls12Key, TrafficSecret};

/// Bytes of an AEAD tag, for both ciphers.
pub(crate) const TAG_LEN: usize = 16;

/// Bytes of the explicit nonce of a TLS 1.2 AES-GCM record.
const EXPLICIT_NONCE_LEN: usize = 8;

/// Bytes of a nonce and IV.
const IV_LEN: usize = 12;

/// The authenticated cipher of a key.
#[derive(Clone)]
enum Aead {
    /// AES-128-GCM.
    Aes128Gcm(Box<Aes128Gcm>),
    /// ChaCha20-Poly1305.
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl Aead {
    /// Encrypts in place, returning the tag.
    fn seal(&self, nonce: &[u8; IV_LEN], aad: &[u8], data: &mut [u8]) -> [u8; TAG_LEN] {
        match self {
            Self::Aes128Gcm(aead) => aead.seal_in_place_detached(nonce, aad, data),
            Self::ChaCha20Poly1305(aead) => aead.seal_in_place_detached(nonce, aad, data),
        }
    }

    /// Checks and decrypts in place.
    fn open(
        &self,
        nonce: &[u8; IV_LEN],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), ProtocolError> {
        let result = match self {
            Self::Aes128Gcm(aead) => aead.open_in_place_detached(nonce, aad, data, tag),
            Self::ChaCha20Poly1305(aead) => aead.open_in_place_detached(nonce, aad, data, tag),
        };
        result.map_err(|_| ProtocolError::BadRecordMac)
    }
}

/// The record format a key belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Format {
    /// TLS 1.3: inner content type, header as associated data.
    Tls13,
    /// TLS 1.2 AES-GCM: explicit nonce in the record.
    Tls12ExplicitNonce,
    /// TLS 1.2 ChaCha20-Poly1305: nonce from the sequence number.
    Tls12,
}

/// One direction's keys and record counter.
#[derive(Clone)]
pub(crate) struct Protection {
    /// The cipher.
    aead: Aead,
    /// The IV the sequence number is folded into.
    iv: [u8; IV_LEN],
    /// The next record's sequence number.
    sequence: u64,
    /// The record format.
    format: Format,
}

impl Protection {
    /// The protection of a TLS 1.3 traffic secret, per RFC 8446, section 7.3.
    pub(crate) fn tls13(secret: &TrafficSecret) -> Self {
        let mut iv = [0; IV_LEN];
        secret.expand_label(b"iv", &[], &mut iv);
        let aead = match secret.suite() {
            CipherSuite::Aes128GcmSha256 => {
                let mut key = [0; 16];
                secret.expand_label(b"key", &[], &mut key);
                let aead = Aead::Aes128Gcm(Box::new(Aes128Gcm::new(&key)));
                key.fill(0);
                aead
            }
            CipherSuite::ChaCha20Poly1305Sha256 => {
                let mut key = [0; 32];
                secret.expand_label(b"key", &[], &mut key);
                let aead = Aead::ChaCha20Poly1305(ChaCha20Poly1305::new(&key));
                key.fill(0);
                aead
            }
        };
        Self {
            aead,
            iv,
            sequence: 0,
            format: Format::Tls13,
        }
    }

    /// The protection of a TLS 1.2 record key.
    pub(crate) fn tls12(key: &Tls12Key) -> Self {
        let (aead, format) = if key.suite.is_aes_gcm() {
            let mut bytes = [0; 16];
            bytes.copy_from_slice(&key.key[..16]);
            let aead = Aead::Aes128Gcm(Box::new(Aes128Gcm::new(&bytes)));
            bytes.fill(0);
            (aead, Format::Tls12ExplicitNonce)
        } else {
            (
                Aead::ChaCha20Poly1305(ChaCha20Poly1305::new(&key.key)),
                Format::Tls12,
            )
        };
        Self {
            aead,
            iv: key.iv,
            sequence: 0,
            format,
        }
    }

    /// Records sealed so far under this key.
    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Seals one record of a content type, returning the whole record, header included.
    pub(crate) fn seal(
        &mut self,
        kind: ContentType,
        content: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        let sequence = self.next_sequence()?;
        let nonce = self.nonce(sequence);
        match self.format {
            Format::Tls13 => {
                let length = content.len() + 1 + TAG_LEN;
                let header = Self::header(ContentType::APPLICATION_DATA, length);
                let mut record = Vec::with_capacity(header.len() + length);
                record.extend_from_slice(&header);
                record.extend_from_slice(content);
                record.push(kind.0);
                let tag = self.aead.seal(&nonce, &header, &mut record[header.len()..]);
                record.extend_from_slice(&tag);
                Ok(record)
            }
            Format::Tls12 | Format::Tls12ExplicitNonce => {
                let explicit = if self.format == Format::Tls12ExplicitNonce {
                    EXPLICIT_NONCE_LEN
                } else {
                    0
                };
                let length = explicit + content.len() + TAG_LEN;
                let header = Self::header(kind, length);
                let aad = Self::tls12_aad(sequence, kind, content.len());
                let mut record = Vec::with_capacity(header.len() + length);
                record.extend_from_slice(&header);
                record.extend_from_slice(&nonce[IV_LEN - explicit..]);
                let start = record.len();
                record.extend_from_slice(content);
                let tag = self.aead.seal(&nonce, &aad, &mut record[start..]);
                record.extend_from_slice(&tag);
                Ok(record)
            }
        }
    }

    /// Opens one protected record body, returning the content type and the content.
    pub(crate) fn open(
        &mut self,
        header: [u8; 5],
        body: &mut Vec<u8>,
    ) -> Result<ContentType, ProtocolError> {
        let sequence = self.next_sequence()?;
        match self.format {
            Format::Tls13 => {
                let tag = Self::split_tag(body)?;
                let nonce = self.nonce(sequence);
                self.aead.open(&nonce, &header, body, &tag)?;
                // RFC 8446, section 5.4: strip the zero padding; the last nonzero byte is the type.
                let end = body
                    .iter()
                    .rposition(|&byte| byte != 0)
                    .ok_or(ProtocolError::MissingContentType)?;
                let kind = ContentType(body[end]);
                body.truncate(end);
                Ok(kind)
            }
            Format::Tls12 | Format::Tls12ExplicitNonce => {
                let kind = ContentType(header[0]);
                let mut nonce = self.nonce(sequence);
                if self.format == Format::Tls12ExplicitNonce {
                    if body.len() < EXPLICIT_NONCE_LEN {
                        return Err(ProtocolError::BadRecordMac);
                    }
                    nonce[IV_LEN - EXPLICIT_NONCE_LEN..]
                        .copy_from_slice(&body[..EXPLICIT_NONCE_LEN]);
                    body.drain(..EXPLICIT_NONCE_LEN);
                }
                let tag = Self::split_tag(body)?;
                let aad = Self::tls12_aad(sequence, kind, body.len());
                self.aead.open(&nonce, &aad, body, &tag)?;
                Ok(kind)
            }
        }
    }

    /// The nonce of a sequence number.
    ///
    /// TLS 1.3 and TLS 1.2 ChaCha20 XOR it into the IV.
    /// TLS 1.2 AES-GCM appends it to the 4-byte fixed IV as the explicit nonce.
    fn nonce(&self, sequence: u64) -> [u8; IV_LEN] {
        let mut nonce = self.iv;
        let tail = &mut nonce[IV_LEN - 8..];
        if self.format == Format::Tls12ExplicitNonce {
            tail.copy_from_slice(&sequence.to_be_bytes());
        } else {
            for (byte, counter) in tail.iter_mut().zip(sequence.to_be_bytes()) {
                *byte ^= counter;
            }
        }
        nonce
    }

    /// Takes the next sequence number, refusing to wrap.
    const fn next_sequence(&mut self) -> Result<u64, ProtocolError> {
        let sequence = self.sequence;
        match sequence.checked_add(1) {
            Some(next) => {
                self.sequence = next;
                Ok(sequence)
            }
            None => Err(ProtocolError::SequenceExhausted),
        }
    }

    /// Removes and returns the trailing tag.
    fn split_tag(body: &mut Vec<u8>) -> Result<[u8; TAG_LEN], ProtocolError> {
        let start = body
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(ProtocolError::BadRecordMac)?;
        let mut tag = [0; TAG_LEN];
        tag.copy_from_slice(&body[start..]);
        body.truncate(start);
        Ok(tag)
    }

    /// The TLS 1.2 associated data of a record.
    fn tls12_aad(sequence: u64, kind: ContentType, length: usize) -> [u8; 13] {
        let mut aad = [0; 13];
        aad[..8].copy_from_slice(&sequence.to_be_bytes());
        aad[8] = kind.0;
        aad[9..11].copy_from_slice(&LEGACY_RECORD_VERSION.to_be_bytes());
        aad[11..].copy_from_slice(&(length as u16).to_be_bytes());
        aad
    }

    /// A record header.
    fn header(kind: ContentType, length: usize) -> [u8; 5] {
        let mut header = [kind.0, 0, 0, 0, 0];
        header[1..3].copy_from_slice(&LEGACY_RECORD_VERSION.to_be_bytes());
        header[3..].copy_from_slice(&(length as u16).to_be_bytes());
        header
    }
}

impl fmt::Debug for Protection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Keys and IVs are never printed.
        f.debug_struct("Protection")
            .field("sequence", &self.sequence)
            .field("format", &self.format)
            .finish_non_exhaustive()
    }
}
