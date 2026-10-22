//! The TLS 1.2 client, for the servers that still negotiate it.
//!
//! # Overview
//!
//! Some public endpoints, such as older load balancers in front of relays, still stop at TLS 1.2.
//! The client offers it beside TLS 1.3, and a server that picks it gets the full handshake of RFC 5246:
//!
//! 1. the server sends ServerHello, Certificate, ServerKeyExchange, and ServerHelloDone;
//! 2. the client sends ClientKeyExchange, ChangeCipherSpec, and Finished;
//! 3. the server sends ChangeCipherSpec and Finished.
//!
//! Only forward-secret AEAD suites are offered: ECDHE with AES-128-GCM or ChaCha20-Poly1305.
//! The extended master secret of RFC 7627 is offered, and used when the server accepts it.
//! There is no resumption and no renegotiation.
//!
//! # Timing
//!
//! The key exchange, the PRF, and the record keys run in constant time; parsing touches public data.

mod client;
mod message;
mod prf;

use std::{fmt, hint::black_box};

pub(crate) use client::Tls12Client;

/// A TLS 1.2 cipher suite this stack offers.
///
/// All four use the SHA-256 PRF, so the transcript hash is the same as TLS 1.3's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Tls12Suite {
    /// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0xc02b, RFC 5289.
    EcdheEcdsaAes128GcmSha256,
    /// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 0xc02f, RFC 5289.
    EcdheRsaAes128GcmSha256,
    /// TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 0xcca9, RFC 7905.
    EcdheEcdsaChaCha20Poly1305Sha256,
    /// TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 0xcca8, RFC 7905.
    EcdheRsaChaCha20Poly1305Sha256,
}

impl Tls12Suite {
    /// Every suite, in the client's order of preference.
    pub const ALL: [Self; 4] = [
        Self::EcdheEcdsaAes128GcmSha256,
        Self::EcdheRsaAes128GcmSha256,
        Self::EcdheEcdsaChaCha20Poly1305Sha256,
        Self::EcdheRsaChaCha20Poly1305Sha256,
    ];

    /// The code point.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::EcdheEcdsaAes128GcmSha256 => 0xc02b,
            Self::EcdheRsaAes128GcmSha256 => 0xc02f,
            Self::EcdheEcdsaChaCha20Poly1305Sha256 => 0xcca9,
            Self::EcdheRsaChaCha20Poly1305Sha256 => 0xcca8,
        }
    }

    /// The suite of a code point, if offered here.
    #[must_use]
    pub fn from_code(code: u16) -> Option<Self> {
        Self::ALL.into_iter().find(|suite| suite.code() == code)
    }

    /// Whether the server authenticates with an ECDSA key, rather than an RSA one.
    #[must_use]
    pub const fn is_ecdsa(self) -> bool {
        matches!(
            self,
            Self::EcdheEcdsaAes128GcmSha256 | Self::EcdheEcdsaChaCha20Poly1305Sha256
        )
    }

    /// Whether records use AES-GCM, with its explicit nonce, rather than ChaCha20-Poly1305.
    #[must_use]
    pub const fn is_aes_gcm(self) -> bool {
        matches!(
            self,
            Self::EcdheEcdsaAes128GcmSha256 | Self::EcdheRsaAes128GcmSha256
        )
    }

    /// Bytes of the record key.
    #[must_use]
    pub const fn key_len(self) -> usize {
        if self.is_aes_gcm() { 16 } else { 32 }
    }

    /// Bytes of the fixed IV taken from the key block.
    ///
    /// AES-GCM takes 4 and sends 8 more with each record, per RFC 5288, section 3.
    /// ChaCha20-Poly1305 takes 12 and XORs the sequence number in, per RFC 7905, section 2.
    #[must_use]
    pub const fn iv_len(self) -> usize {
        if self.is_aes_gcm() { 4 } else { 12 }
    }
}

/// One direction's TLS 1.2 record key: the AEAD key and its fixed IV.
///
/// The key clears itself when dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct Tls12Key {
    /// The suite, which fixes the AEAD and nonce rule.
    pub suite: Tls12Suite,
    /// The AEAD key; the first 16 bytes for AES-128-GCM.
    pub key: [u8; 32],
    /// The fixed IV; the first 4 bytes for AES-GCM.
    pub iv: [u8; 12],
}

impl Drop for Tls12Key {
    fn drop(&mut self) {
        self.key.fill(0);
        black_box(&mut self.key);
    }
}

impl fmt::Debug for Tls12Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The key is never printed.
        f.debug_struct("Tls12Key")
            .field("suite", &self.suite)
            .finish_non_exhaustive()
    }
}

/// The TLS 1.2 record keys of both directions, by this side's view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tls12Secrets {
    /// Protects what this side sends.
    pub local: Tls12Key,
    /// Protects what the peer sends.
    pub remote: Tls12Key,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_points_round_trip() {
        for suite in Tls12Suite::ALL {
            assert_eq!(Tls12Suite::from_code(suite.code()), Some(suite));
        }
        // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 needs the SHA-384 PRF, which is not offered.
        assert_eq!(Tls12Suite::from_code(0xc030), None);
    }
}
