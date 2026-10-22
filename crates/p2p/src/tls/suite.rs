//! The cipher suites this stack negotiates, and the encryption levels of QUIC.

/// A TLS 1.3 cipher suite this stack negotiates.
///
/// Both hash with SHA-256, so the transcript and key schedule are the same for either.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CipherSuite {
    /// TLS_AES_128_GCM_SHA256, code point 0x1301.
    Aes128GcmSha256,
    /// TLS_CHACHA20_POLY1305_SHA256, code point 0x1303.
    ChaCha20Poly1305Sha256,
}

impl CipherSuite {
    /// Every suite, in the server's order of preference.
    ///
    /// AES-GCM comes first: most hosts run it in hardware.
    pub const ALL: [Self; 2] = [Self::Aes128GcmSha256, Self::ChaCha20Poly1305Sha256];

    /// The code point, per RFC 8446, appendix B.4.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Aes128GcmSha256 => 0x1301,
            Self::ChaCha20Poly1305Sha256 => 0x1303,
        }
    }

    /// The suite of a code point, if this stack supports it.
    #[must_use]
    pub const fn from_code(code: u16) -> Option<Self> {
        match code {
            0x1301 => Some(Self::Aes128GcmSha256),
            0x1303 => Some(Self::ChaCha20Poly1305Sha256),
            _ => None,
        }
    }
}

/// The QUIC encryption level a handshake message travels at, per RFC 9001, section 4.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Level {
    /// Initial packets, keyed from the destination connection id.
    Initial,
    /// Handshake packets.
    Handshake,
    /// 1-RTT packets.
    Application,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_points_round_trip() {
        for suite in CipherSuite::ALL {
            assert_eq!(CipherSuite::from_code(suite.code()), Some(suite));
        }
        // TLS_AES_256_GCM_SHA384 hashes with SHA-384, which this stack does not run.
        assert_eq!(CipherSuite::from_code(0x1302), None);
    }
}
