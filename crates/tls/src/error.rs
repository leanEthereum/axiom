//! Reasons a TLS connection aborts, and the alert each one sends.

use thiserror::Error;

use crate::{Alert, CertificateError, CertificateRejection, Level};

/// A failure of a TLS connection: a broken protocol rule, or a refused certificate.
///
/// The certificate reason is generic: the checker that refused the chain defines it.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum TlsError<C = CertificateError> {
    /// The peer broke a rule of the protocol.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    /// The peer's certificate chain was refused.
    #[error("invalid certificate: {0}")]
    Certificate(C),
}

impl<C: CertificateRejection> TlsError<C> {
    /// The alert sent to the peer, per RFC 8446, section 6.
    ///
    /// QUIC closes with the crypto error 0x100 plus this value, per RFC 9001, section 4.8.
    #[must_use]
    pub fn alert(&self) -> Alert {
        match self {
            Self::Protocol(error) => error.alert(),
            Self::Certificate(error) => error.alert(),
        }
    }
}

/// A broken protocol rule, with the TLS alert it maps to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ProtocolError {
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

    /// Bytes of a level remain unprocessed when the keys change.
    ///
    /// RFC 8446, section 5.1, and RFC 9001, section 4.1.3, both forbid a message across a key change.
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

    /// An extension body does not hold the value its definition requires.
    #[error("extension {0:#06x} carries an invalid value")]
    InvalidExtension(u16),

    /// The legacy version field is not 0x0303, the value both TLS 1.2 and 1.3 hellos carry.
    #[error("legacy version {0:#06x} is not 0x0303")]
    InvalidLegacyVersion(u16),

    /// The peer offers or selects no version this side speaks.
    #[error("no common protocol version")]
    UnsupportedVersion,

    /// A TLS 1.2 server answered a client that offered TLS 1.3, and its random says so.
    ///
    /// RFC 8446, section 4.1.3: the sentinel reveals an attacker who stripped TLS 1.3 from the hello.
    #[error("server random carries the TLS 1.3 downgrade sentinel")]
    Downgrade,

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

    /// No key share in a group this side supports; a hello retry is not supported.
    #[error("no key share in a supported group, and hello retry is not supported")]
    NoKeyShare,

    /// The server answered with a HelloRetryRequest, which this stack does not support.
    #[error("server sent a HelloRetryRequest, which is not supported")]
    HelloRetryRequest,

    /// A TLS 1.2 key exchange names its curve explicitly, which RFC 8422, section 5.4, deprecates.
    #[error("ECDHE curve type {0} is not named_curve")]
    UnsupportedCurveType(u8),

    /// The peer chose a key exchange group this side did not offer.
    #[error("group {0:#06x} was not offered")]
    UnofferedGroup(u16),

    /// A key share has the wrong group or length, or is not a valid public value.
    #[error("key share for group {group:#06x} with {length} bytes is not a valid public value")]
    InvalidKeyShare {
        /// The group named.
        group: u16,
        /// The key share length.
        length: usize,
    },

    /// An X25519 key share has small order, so the shared secret would be all zeros.
    #[error("key share has low order")]
    LowOrderKeyShare,

    /// No signature scheme is acceptable to both sides.
    #[error("no common signature scheme")]
    NoCommonSignatureScheme,

    /// The client offers no application protocol this server accepts.
    #[error("no common application protocol")]
    NoApplicationProtocol,

    /// The server selected an application protocol the client did not offer.
    #[error("server selected an application protocol that was not offered")]
    UnofferedApplicationProtocol,

    /// The server echoed another session id than the client sent.
    #[error("session id echo differs from the session id sent")]
    SessionIdMismatch,

    /// A TLS 1.2 server answered secure renegotiation with a non-empty value.
    ///
    /// RFC 5746, section 3.4: an initial handshake carries an empty renegotiated_connection.
    #[error("renegotiation info is not empty")]
    InvalidRenegotiationInfo,

    /// A certificate request context is not empty, as the initial handshake requires.
    #[error("certificate request context of {0} bytes, expected none")]
    NonEmptyRequestContext(usize),

    /// A certificate entry carries extensions this side never requested.
    #[error("certificate entry carries unrequested extensions")]
    CertificateExtensions,

    /// The peer sent no certificate where one is required.
    #[error("peer sent no certificate")]
    CertificateRequired,

    /// A signature uses a scheme this side did not offer, or one its key cannot make.
    #[error("signature scheme {0:#06x} was not offered or does not fit the key")]
    UnofferedSignatureScheme(u16),

    /// The server's certificate key does not fit the authentication of the TLS 1.2 suite.
    #[error("server key type does not match the cipher suite")]
    KeyTypeMismatch,

    /// A CertificateVerify signature does not verify under the certificate key.
    #[error("certificate verify signature does not verify")]
    InvalidCertificateVerify,

    /// A TLS 1.2 ServerKeyExchange signature does not verify under the certificate key.
    #[error("server key exchange signature does not verify")]
    InvalidKeyExchangeSignature,

    /// A Finished message does not match the transcript.
    #[error("finished verify data does not match")]
    InvalidFinished,

    /// A KeyUpdate request field is neither 0 nor 1.
    #[error("key update request {0} is neither 0 nor 1")]
    InvalidKeyUpdate(u8),

    /// A record is longer than the protocol allows.
    #[error("record of {length} bytes exceeds {max}")]
    RecordOverflow {
        /// Bytes announced or decrypted.
        length: usize,
        /// Most bytes allowed.
        max: usize,
    },

    /// A record header does not carry a TLS version.
    #[error("record version {0:#06x} is not TLS")]
    InvalidRecordVersion(u16),

    /// A record fails authentication.
    #[error("record fails authentication")]
    BadRecordMac,

    /// A record has a content type the current state does not accept.
    #[error("unexpected record of content type {0}")]
    UnexpectedRecord(u8),

    /// A protected record holds only padding, with no content type.
    #[error("protected record has no content type")]
    MissingContentType,

    /// A handshake or alert record is empty, which RFC 8446, section 5.1, forbids.
    #[error("empty record of content type {0}")]
    EmptyRecord(u8),

    /// An alert record is not one level byte and one description byte.
    #[error("malformed alert record")]
    InvalidAlert,

    /// The peer sent a fatal alert.
    #[error("peer sent {0}")]
    AlertReceived(Alert),

    /// This side's signature failed its own consistency check.
    #[error("signing failed its consistency check")]
    SigningFailed,

    /// The record sequence number would wrap, which RFC 8446, section 5.3, forbids.
    #[error("record sequence number exhausted")]
    SequenceExhausted,

    /// A side sent data after its close_notify alert.
    #[error("data after close_notify")]
    DataAfterClose,
}

impl ProtocolError {
    /// The alert sent to the peer, per RFC 8446, section 6.
    #[must_use]
    pub const fn alert(&self) -> Alert {
        match self {
            Self::UnexpectedMessage { .. }
            | Self::WrongLevel { .. }
            | Self::DataAfterKeyChange { .. }
            | Self::UnexpectedRecord(_)
            | Self::EmptyRecord(_)
            | Self::DataAfterClose => Alert::UNEXPECTED_MESSAGE,
            Self::BadRecordMac => Alert::BAD_RECORD_MAC,
            Self::RecordOverflow { .. } => Alert::RECORD_OVERFLOW,
            Self::NoCommonCipherSuite
            | Self::NoKeyShare
            | Self::HelloRetryRequest
            | Self::NoCommonSignatureScheme
            // RFC 5746, section 3.4: a bad renegotiation value aborts with handshake_failure.
            | Self::InvalidRenegotiationInfo => Alert::HANDSHAKE_FAILURE,
            Self::DuplicateExtension(_)
            | Self::InvalidExtension(_)
            | Self::NonEmptySessionId(_)
            | Self::InvalidCompression
            | Self::UnofferedCipherSuite(_)
            | Self::UnofferedGroup(_)
            | Self::UnsupportedCurveType(_)
            | Self::KeyTypeMismatch
            | Self::InvalidKeyShare { .. }
            | Self::LowOrderKeyShare
            | Self::UnofferedApplicationProtocol
            | Self::SessionIdMismatch
            | Self::NonEmptyRequestContext(_)
            | Self::UnofferedSignatureScheme(_)
            | Self::Downgrade
            | Self::InvalidKeyUpdate(_)
            | Self::MissingContentType => Alert::ILLEGAL_PARAMETER,
            Self::Truncated { .. }
            | Self::TrailingBytes { .. }
            | Self::InvalidVectorLength { .. }
            | Self::MessageTooLong { .. }
            | Self::InvalidAlert
            | Self::InvalidRecordVersion(_) => Alert::DECODE_ERROR,
            Self::InvalidCertificateVerify
            | Self::InvalidKeyExchangeSignature
            | Self::InvalidFinished => Alert::DECRYPT_ERROR,
            Self::InvalidLegacyVersion(_) | Self::UnsupportedVersion => Alert::PROTOCOL_VERSION,
            Self::SequenceExhausted | Self::SigningFailed => Alert::INTERNAL_ERROR,
            Self::MissingExtension(_) => Alert::MISSING_EXTENSION,
            Self::UnsupportedExtension(_) | Self::CertificateExtensions => {
                Alert::UNSUPPORTED_EXTENSION
            }
            Self::CertificateRequired => Alert::CERTIFICATE_REQUIRED,
            Self::NoApplicationProtocol => Alert::NO_APPLICATION_PROTOCOL,
            // The peer already closed; this side answers nothing new.
            Self::AlertReceived(alert) => *alert,
        }
    }
}
