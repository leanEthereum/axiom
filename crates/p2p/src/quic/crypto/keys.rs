//! Packet protection: the AEAD over payloads and the mask over headers.
//!
//! # Overview
//!
//! Each traffic secret expands into three values, per RFC 9001, section 5.1:
//!
//! - the AEAD key, under the label "quic key"
//! - the IV, under "quic iv"
//! - the header protection key, under "quic hp"
//!
//! The nonce is the IV with the packet number XORed into its low bytes.
//! The AEAD's associated data is the whole header, packet number included.
//!
//! Header protection then masks the low bits of the first byte and the packet number bytes.
//! The mask comes from a 16-byte sample of ciphertext taken four bytes after the number starts.
//! See RFC 9001, sections 5.3 and 5.4.

use axiom_crypto::{
    AeadError,
    aes::{Aes128, Aes128Gcm},
    chacha20poly1305::{ChaCha20, ChaCha20Poly1305},
};

use super::super::{DecodeError, packet::PacketNumber};
use crate::tls::{CipherSuite, TrafficSecret};

/// Bytes of an AEAD tag, the same for both suites.
pub(crate) const TAG_LEN: usize = 16;

/// Bytes of the header protection sample.
pub(crate) const SAMPLE_LEN: usize = 16;

/// Bytes of an AEAD nonce and IV.
const IV_LEN: usize = 12;

/// The authenticated cipher of a suite.
#[derive(Clone)]
enum Aead {
    /// AEAD_AES_128_GCM.
    Aes128Gcm(Box<Aes128Gcm>),
    /// AEAD_CHACHA20_POLY1305.
    ChaCha20Poly1305(ChaCha20Poly1305),
}

/// Seals and opens payloads in one direction at one level.
#[derive(Clone)]
pub(crate) struct PacketKey {
    /// The cipher.
    aead: Aead,
    /// The IV the packet number is folded into.
    iv: [u8; IV_LEN],
}

impl PacketKey {
    /// The key and IV a secret expands into.
    pub(crate) fn new(secret: &TrafficSecret) -> Self {
        let mut iv = [0; IV_LEN];
        secret.expand_label(b"quic iv", &[], &mut iv);
        let aead = match secret.suite() {
            CipherSuite::Aes128GcmSha256 => {
                let mut key = [0; 16];
                secret.expand_label(b"quic key", &[], &mut key);
                let aead = Aead::Aes128Gcm(Box::new(Aes128Gcm::new(&key)));
                key.fill(0);
                aead
            }
            CipherSuite::ChaCha20Poly1305Sha256 => {
                let mut key = [0; 32];
                secret.expand_label(b"quic key", &[], &mut key);
                let aead = Aead::ChaCha20Poly1305(ChaCha20Poly1305::new(&key));
                key.fill(0);
                aead
            }
        };
        Self { aead, iv }
    }

    /// The nonce of a packet: the IV with the 62-bit number XORed into its tail.
    fn nonce(&self, pn: PacketNumber) -> [u8; IV_LEN] {
        let mut nonce = self.iv;
        for (byte, pn_byte) in nonce[IV_LEN - 8..].iter_mut().zip(pn.0.to_be_bytes()) {
            *byte ^= pn_byte;
        }
        nonce
    }

    /// Encrypts a payload in place, returning the tag to append.
    pub(crate) fn seal(
        &self,
        pn: PacketNumber,
        header: &[u8],
        payload: &mut [u8],
    ) -> [u8; TAG_LEN] {
        let nonce = self.nonce(pn);
        match &self.aead {
            Aead::Aes128Gcm(aead) => aead.seal_in_place_detached(&nonce, header, payload),
            Aead::ChaCha20Poly1305(aead) => aead.seal_in_place_detached(&nonce, header, payload),
        }
    }

    /// Checks and decrypts a payload in place.
    pub(crate) fn open(
        &self,
        pn: PacketNumber,
        header: &[u8],
        payload: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), AeadError> {
        let nonce = self.nonce(pn);
        match &self.aead {
            Aead::Aes128Gcm(aead) => aead.open_in_place_detached(&nonce, header, payload, tag),
            Aead::ChaCha20Poly1305(aead) => {
                aead.open_in_place_detached(&nonce, header, payload, tag)
            }
        }
    }
}

impl core::fmt::Debug for PacketKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PacketKey").finish_non_exhaustive()
    }
}

/// Masks and unmasks packet headers in one direction.
#[derive(Clone)]
pub(crate) enum HeaderKey {
    /// AES-128 in ECB mode over the sample.
    Aes(Box<Aes128>),
    /// ChaCha20 keyed by the header key, with counter and nonce taken from the sample.
    ChaCha([u8; 32]),
}

impl HeaderKey {
    /// The header key a secret expands into.
    pub(crate) fn new(secret: &TrafficSecret) -> Self {
        match secret.suite() {
            CipherSuite::Aes128GcmSha256 => {
                let mut key = [0; 16];
                secret.expand_label(b"quic hp", &[], &mut key);
                let cipher = Self::Aes(Box::new(Aes128::new(&key)));
                key.fill(0);
                cipher
            }
            CipherSuite::ChaCha20Poly1305Sha256 => {
                let mut key = [0; 32];
                secret.expand_label(b"quic hp", &[], &mut key);
                Self::ChaCha(key)
            }
        }
    }

    /// The five mask bytes a sample yields, per RFC 9001, sections 5.4.3 and 5.4.4.
    fn mask(&self, sample: &[u8; SAMPLE_LEN]) -> [u8; 5] {
        let mut mask = [0; 5];
        match self {
            Self::Aes(cipher) => {
                let mut block = *sample;
                cipher.encrypt_block(&mut block);
                mask.copy_from_slice(&block[..5]);
            }
            Self::ChaCha(key) => {
                // counter = sample[0..4] little-endian, nonce = sample[4..16].
                let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
                let mut nonce = [0; 12];
                nonce.copy_from_slice(&sample[4..]);
                ChaCha20::new(key, &nonce, counter).apply_keystream(&mut mask);
            }
        }
        mask
    }

    /// The sample four bytes past the start of the packet number.
    fn sample(packet: &[u8], pn_offset: usize) -> Result<[u8; SAMPLE_LEN], DecodeError> {
        let start = pn_offset + 4;
        let Some(bytes) = packet.get(start..start + SAMPLE_LEN) else {
            return Err(DecodeError::Truncated {
                needed: start + SAMPLE_LEN,
                available: packet.len(),
            });
        };
        let mut sample = [0; SAMPLE_LEN];
        sample.copy_from_slice(bytes);
        Ok(sample)
    }

    /// Masks a sealed packet's first byte and packet number.
    ///
    /// The packet must be long enough to sample, which padding guarantees.
    pub(crate) fn protect(
        &self,
        packet: &mut [u8],
        pn_offset: usize,
        pn_len: usize,
    ) -> Result<(), DecodeError> {
        let mask = self.mask(&Self::sample(packet, pn_offset)?);
        packet[0] ^= mask[0] & Self::first_byte_bits(packet[0]);
        for (byte, mask) in packet[pn_offset..pn_offset + pn_len]
            .iter_mut()
            .zip(&mask[1..])
        {
            *byte ^= mask;
        }
        Ok(())
    }

    /// Unmasks a received packet's first byte and packet number.
    ///
    /// # Returns
    ///
    /// The packet number length and its truncated value.
    pub(crate) fn unprotect(
        &self,
        packet: &mut [u8],
        pn_offset: usize,
    ) -> Result<(usize, u32), DecodeError> {
        let mask = self.mask(&Self::sample(packet, pn_offset)?);
        packet[0] ^= mask[0] & Self::first_byte_bits(packet[0]);
        let pn_len = usize::from(packet[0] & 0x03) + 1;
        let mut truncated = 0_u32;
        for (byte, mask) in packet[pn_offset..pn_offset + pn_len]
            .iter_mut()
            .zip(&mask[1..])
        {
            *byte ^= mask;
            truncated = (truncated << 8) | u32::from(*byte);
        }
        Ok((pn_len, truncated))
    }

    /// The first-byte bits header protection covers: four for long headers, five for short.
    const fn first_byte_bits(first: u8) -> u8 {
        if first & 0x80 == 0 { 0x1f } else { 0x0f }
    }
}

impl core::fmt::Debug for HeaderKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HeaderKey").finish_non_exhaustive()
    }
}

/// The packet and header keys of one direction at one level.
#[derive(Clone, Debug)]
pub(crate) struct Keys {
    /// The payload key.
    pub(crate) packet: PacketKey,
    /// The header key.
    pub(crate) header: HeaderKey,
}

impl Keys {
    /// The keys a traffic secret expands into.
    pub(crate) fn new(secret: &TrafficSecret) -> Self {
        Self {
            packet: PacketKey::new(secret),
            header: HeaderKey::new(secret),
        }
    }
}

/// The keys of both directions at one level.
#[derive(Clone, Debug)]
pub(crate) struct KeyPair {
    /// Protects what this side sends.
    pub(crate) local: Keys,
    /// Removes the protection of what the peer sends.
    pub(crate) remote: Keys,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::testing::hex;

    #[test]
    fn rfc_9001_appendix_a5_chacha20_short_header() {
        // The server's application secret of RFC 9001, appendix A.5.
        let secret = TrafficSecret::new(
            CipherSuite::ChaCha20Poly1305Sha256,
            hex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")
                .try_into()
                .unwrap(),
        );
        let keys = Keys::new(&secret);

        // Packet number 654360564, encoded on three bytes as 49140 (0xbff4).
        let pn = PacketNumber(654_360_564);
        assert_eq!(
            keys.packet.nonce(pn).to_vec(),
            hex("e0459b3474bdd0e46d417eb0")
        );

        // A single PING frame under the unprotected header 4200bff4.
        let mut packet = hex("4200bff401");
        let (header, payload) = packet.split_at_mut(4);
        let tag = keys.packet.seal(pn, header, payload);
        packet.extend_from_slice(&tag);
        assert_eq!(packet[4..], hex("655e5cd55c41f69080575d7999c25a5bfb"));

        // The sample skips one byte past the three-byte number; the mask is aefefe7d03.
        assert_eq!(
            HeaderKey::sample(&packet, 1).unwrap().to_vec(),
            hex("5e5cd55c41f69080575d7999c25a5bfb")
        );
        assert_eq!(
            keys.header
                .mask(&HeaderKey::sample(&packet, 1).unwrap())
                .to_vec(),
            hex("aefefe7d03")
        );
        keys.header.protect(&mut packet, 1, 3).unwrap();
        assert_eq!(packet, hex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb"));

        // Unprotecting restores the header and yields the three-byte number.
        assert_eq!(keys.header.unprotect(&mut packet, 1), Ok((3, 0x00bf_f4)));
        let (header, rest) = packet.split_at_mut(4);
        let (payload, tag) = rest.split_at_mut(1);
        let tag: [u8; TAG_LEN] = (&*tag).try_into().unwrap();
        assert_eq!(keys.packet.open(pn, header, payload, &tag), Ok(()));
        assert_eq!(payload, [0x01]);
    }

    #[test]
    fn tampering_fails_authentication() {
        let secret = TrafficSecret::new(CipherSuite::Aes128GcmSha256, [7; 32]);
        let key = PacketKey::new(&secret);
        let mut payload = *b"hello";
        let tag = key.seal(PacketNumber(9), b"hdr", &mut payload);

        // Another packet number gives another nonce, so the tag fails.
        let mut copy = payload;
        assert_eq!(
            key.open(PacketNumber(10), b"hdr", &mut copy, &tag),
            Err(AeadError)
        );
        // So does another header.
        let mut copy = payload;
        assert_eq!(
            key.open(PacketNumber(9), b"hdX", &mut copy, &tag),
            Err(AeadError)
        );
        // The right inputs restore the plaintext.
        assert_eq!(
            key.open(PacketNumber(9), b"hdr", &mut payload, &tag),
            Ok(())
        );
        assert_eq!(&payload, b"hello");
    }
}
