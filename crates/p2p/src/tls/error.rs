//! Reasons a TLS handshake aborts, and the alert each one sends.

use thiserror::Error;

use super::{CertificateError, Level};
use crate::identity::PeerId;

/// A handshake failure, with the TLS alert it maps to.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TlsError {
    /// A message ends before a field it announces.
    #[error("message truncated: {needed} bytes needed, {available} available")]
    Truncated {
        /// Bytes the field needs.
        needed: usize,
        /// Bytes left in the message.
        available: usize,
    },

    /// A message or vector has bytes left after its last field.
    #[error("{count} trailing bytes after the last field")]
    TrailingBytes {
        /// Bytes left over.
        count: usize,
    },

    /// A vector length is outside the range its definition allows, or not a whole number of items.
    #[error("vector of {length} bytes is outside {min}..={max} or not a multiple of {item}")]
    InvalidVectorLength {
        /// Bytes announced.
        length: usize,
        /// Fewest bytes allowed.
        min: usize,
        /// Most bytes allowed.
        max: usize,
        /// Bytes per item.
        item: usize,
    },

    /// A handshake message is longer than this stack accepts.
    #[error("handshake message of {length} bytes exceeds {max}")]
    MessageTooLong {
        /// Length announced.
        length: usize,
        /// Longest message accepted.
        max: usize,
    },

    /// A handshake message arrives that the current state does not expect.
    #[error("unexpected handshake message type {found} while {state}")]
    UnexpectedMessage {
        /// The message type received.
        found: u8,
        /// What the state machine was waiting for.
        state: &'static str,
    },

    /// Handshake bytes arrive at an encryption level other than the expected one.
    #[error("handshake bytes at level {found:?}, expected {expected:?}")]
    WrongLevel {
        /// The level the state machine reads at.
        expected: Level,
        /// The level the bytes arrived at.
        found: Level,
    },

    /// Bytes of a level remain unprocessed when the keys change, per RFC 9001, section 4.1.3.
    #[error("{count} unprocessed bytes at level {level:?} when keys change")]
    DataAfterKeyChange {
        /// The level being left.
        level: Level,
        /// Bytes left in it.
        count: usize,
    },

    /// An extension appears twice in one message.
    #[error("extension {0:#06x} appears twice")]
    DuplicateExtension(u16),

    /// A response carries an extension this side never offered, or one the message cannot carry.
    #[error("extension {0:#06x} was not offered or is not allowed here")]
    UnsupportedExtension(u16),

    /// A required extension is absent.
    #[error("required extension {0:#06x} is missing")]
    MissingExtension(u16),

    /// The legacy version field is not 0x0303, the value TLS 1.3 requires.
    #[error("legacy version {0:#06x} is not 0x0303")]
    InvalidLegacyVersion(u16),

    /// The peer does not offer or select TLS 1.3.
    #[error("peer does not speak TLS 1.3")]
    UnsupportedVersion,

    /// A legacy session id is not empty, which QUIC forbids, per RFC 9001, section 8.4.
    #[error("legacy session id of {0} bytes, QUIC requires none")]
    NonEmptySessionId(usize),

    /// The compression methods are not exactly the null method.
    #[error("compression methods are not exactly the null method")]
    InvalidCompression,

    /// No cipher suite is supported by both sides.
    #[error("no common cipher suite")]
    NoCommonCipherSuite,

    /// The server selected a cipher suite the client did not offer.
    #[error("server selected cipher suite {0:#06x}, which was not offered")]
    UnofferedCipherSuite(u16),

    /// No X25519 key share was offered; a hello retry is not supported.
    ///
    /// Both sides of this stack always send an X25519 share, so a retry never helps them.
    #[error("no X25519 key share, and hello retry is not supported")]
    NoKeyShare,

    /// The server answered with a HelloRetryRequest, which this stack does not support.
    #[error("server sent a HelloRetryRequest, which is not supported")]
    HelloRetryRequest,

    /// A key share has the wrong group or length.
    #[error("key share for group {group:#06x} with {length} bytes is not a 32-byte X25519 share")]
    InvalidKeyShare {
        /// The group named.
        group: u16,
        /// The key share length.
        length: usize,
    },

    /// A key share has small order, so the shared secret would be all zeros.
    #[error("key share has low order")]
    LowOrderKeyShare,

    /// The peer does not accept ecdsa_secp256r1_sha256 signatures.
    #[error("no common signature scheme")]
    NoCommonSignatureScheme,

    /// The client does not offer the libp2p application protocol.
    #[error("libp2p application protocol not offered")]
    NoApplicationProtocol,

    /// The server selected an application protocol other than libp2p.
    #[error("server selected another application protocol")]
    UnofferedApplicationProtocol,

    /// The server echoed another session id than the client sent.
    #[error("session id echo differs from the session id sent")]
    SessionIdMismatch,

    /// A certificate request context is not empty, as the initial handshake requires.
    #[error("certificate request context of {0} bytes, expected none")]
    NonEmptyRequestContext(usize),

    /// A certificate entry carries extensions this side never requested.
    #[error("certificate entry carries unrequested extensions")]
    CertificateExtensions,

    /// The client sent no certificate, which libp2p requires.
    #[error("peer sent no certificate")]
    CertificateRequired,

    /// The peer sent more than one certificate, which libp2p forbids.
    #[error("peer sent {0} certificates, expected exactly one")]
    MultipleCertificates(usize),

    /// The peer certificate is not a valid libp2p certificate.
    #[error("invalid certificate: {0}")]
    Certificate(#[from] CertificateError),

    /// The certificate authenticates another peer than the one dialed.
    #[error("certificate authenticates {actual}, expected {expected}")]
    PeerIdMismatch {
        /// The peer the dialer meant to reach.
        expected: PeerId,
        /// The peer the certificate names.
        actual: PeerId,
    },

    /// A CertificateVerify uses a signature scheme other than ecdsa_secp256r1_sha256.
    #[error("signature scheme {0:#06x} was not offered")]
    UnofferedSignatureScheme(u16),

    /// A CertificateVerify signature does not verify under the certificate key.
    #[error("certificate verify signature does not verify")]
    InvalidCertificateVerify,

    /// A Finished message does not match the transcript.
    #[error("finished verify data does not match")]
    InvalidFinished,

    /// A certificate seed is zero or not below the P-256 group order.
    #[error("certificate seed gives no valid P-256 key")]
    InvalidSeed,
}

impl TlsError {
    /// The TLS alert description, per RFC 8446, section 6.
    ///
    /// QUIC closes with the crypto error 0x100 plus this value, per RFC 9001, section 4.8.
    #[must_use]
    pub const fn alert(&self) -> u8 {
        match self {
            // unexpected_message.
            Self::UnexpectedMessage { .. }
            | Self::WrongLevel { .. }
            | Self::DataAfterKeyChange { .. } => 10,
            // handshake_failure.
            Self::NoCommonCipherSuite
            | Self::NoKeyShare
            | Self::HelloRetryRequest
            | Self::NoCommonSignatureScheme => 40,
            // The certificate error picks its own alert.
            Self::Certificate(error) => error.alert(),
            // bad_certificate.
            Self::MultipleCertificates(_) | Self::PeerIdMismatch { .. } => 42,
            // illegal_parameter.
            Self::DuplicateExtension(_)
            | Self::NonEmptySessionId(_)
            | Self::InvalidCompression
            | Self::UnofferedCipherSuite(_)
            | Self::InvalidKeyShare { .. }
            | Self::LowOrderKeyShare
            | Self::UnofferedApplicationProtocol
            | Self::SessionIdMismatch
            | Self::NonEmptyRequestContext(_)
            | Self::UnofferedSignatureScheme(_) => 47,
            // decode_error.
            Self::Truncated { .. }
            | Self::TrailingBytes { .. }
            | Self::InvalidVectorLength { .. }
            | Self::MessageTooLong { .. } => 50,
            // decrypt_error.
            Self::InvalidCertificateVerify | Self::InvalidFinished => 51,
            // protocol_version.
            Self::InvalidLegacyVersion(_) | Self::UnsupportedVersion => 70,
            // internal_error.
            Self::InvalidSeed => 80,
            // missing_extension.
            Self::MissingExtension(_) => 109,
            // unsupported_extension.
            Self::UnsupportedExtension(_) | Self::CertificateExtensions => 110,
            // certificate_required.
            Self::CertificateRequired => 116,
            // no_application_protocol.
            Self::NoApplicationProtocol => 120,
        }
    }
}
