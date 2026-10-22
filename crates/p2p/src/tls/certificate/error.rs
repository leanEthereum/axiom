//! Reasons a libp2p certificate is refused.

use axiom_crypto::p256::P256Error;
use thiserror::Error;

use crate::{identity::KeyType, protobuf::ProtobufError, tls::der::DerError};

/// A certificate that does not authenticate a libp2p peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum CertificateError {
    /// The certificate, or a structure inside it, is not strict DER of the expected shape.
    #[error("malformed DER: {0}")]
    Der(#[from] DerError),

    /// The certificate is not version 3, the only one that carries extensions.
    #[error("certificate version field {0} is not 2, meaning v3")]
    UnsupportedVersion(u64),

    /// A signature algorithm is not ecdsa-with-SHA256.
    #[error("signature algorithm is not ecdsa-with-SHA256")]
    UnsupportedSignatureAlgorithm,

    /// The outer and inner signature algorithms differ, which RFC 5280, section 4.1.1.2, forbids.
    #[error("outer and inner signature algorithms differ")]
    AlgorithmMismatch,

    /// A subject public key is not an EC key on P-256.
    #[error("subject public key is not on P-256")]
    UnsupportedKeyAlgorithm,

    /// A P-256 public key or signature value is invalid.
    #[error("invalid P-256 key or signature: {0}")]
    P256(#[from] P256Error),

    /// A deprecated issuer or subject unique identifier is present.
    #[error("certificate carries a unique identifier")]
    UniqueIdentifier,

    /// The self-signature does not verify under the certificate's own key.
    #[error("self-signature does not verify")]
    InvalidSelfSignature,

    /// An extension appears twice, which RFC 5280, section 4.2, forbids.
    #[error("duplicate extension")]
    DuplicateExtension,

    /// An extension marked critical is not understood.
    #[error("unknown critical extension")]
    UnknownCriticalExtension,

    /// A critical flag is written as an explicit false, which DER forbids for a default.
    #[error("explicit default critical flag")]
    ExplicitDefault,

    /// The libp2p public key extension is absent.
    #[error("libp2p public key extension is missing")]
    MissingExtension,

    /// The current time is before the start of the validity window.
    #[error("not valid before {not_before}, now is {now} (Unix seconds)")]
    NotYetValid {
        /// Start of the window.
        not_before: i64,
        /// The current time.
        now: i64,
    },

    /// The current time is after the end of the validity window.
    #[error("expired at {not_after}, now is {now} (Unix seconds)")]
    Expired {
        /// End of the window.
        not_after: i64,
        /// The current time.
        now: i64,
    },

    /// The host public key in the extension is not a valid protobuf key.
    #[error("malformed host public key: {0}")]
    HostKey(#[from] ProtobufError),

    /// The host key's scheme is one this node does not verify.
    #[error("host key type {0:?} is not supported")]
    UnsupportedHostKey(KeyType),

    /// The host signature over the certificate key does not verify.
    #[error("host key signature does not verify")]
    InvalidHostSignature,
}

impl CertificateError {
    /// The TLS alert description, per RFC 8446, section 6.2.
    #[must_use]
    pub const fn alert(&self) -> u8 {
        match self {
            // certificate_expired: expired or not yet valid.
            Self::NotYetValid { .. } | Self::Expired { .. } => 45,
            // unsupported_certificate: a type this node cannot check.
            Self::UnsupportedSignatureAlgorithm
            | Self::UnsupportedKeyAlgorithm
            | Self::UnsupportedHostKey(_) => 43,
            // bad_certificate: everything else.
            _ => 42,
        }
    }
}
