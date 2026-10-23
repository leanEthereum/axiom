//! Reasons a libp2p certificate is refused.

use axiom_tls::{Alert, CertificateRejection, x509::X509Error};
use thiserror::Error;

use crate::{
    identity::{KeyType, PeerId},
    protobuf::ProtobufError,
};

/// A certificate that does not authenticate a libp2p peer.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum CertificateError {
    /// The certificate, or a structure inside it, is malformed.
    #[error("malformed certificate: {0}")]
    X509(#[from] X509Error),

    /// A signature algorithm is not ecdsa-with-SHA256.
    #[error("signature algorithm is not ecdsa-with-SHA256")]
    UnsupportedSignatureAlgorithm,

    /// The certificate key is not an EC key on P-256.
    #[error("subject public key is not on P-256")]
    UnsupportedKeyAlgorithm,

    /// A deprecated issuer or subject unique identifier is present.
    #[error("certificate carries a unique identifier")]
    UniqueIdentifier,

    /// The self-signature does not verify under the certificate's own key.
    #[error("self-signature does not verify")]
    InvalidSelfSignature,

    /// An extension marked critical is not understood.
    #[error("unknown critical extension")]
    UnknownCriticalExtension,

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

    /// The peer sent more or fewer than one certificate, which libp2p forbids.
    #[error("peer sent {0} certificates, expected exactly one")]
    MultipleCertificates(usize),

    /// The certificate authenticates another peer than the one dialed.
    #[error("certificate authenticates {actual}, expected {expected}")]
    PeerIdMismatch {
        /// The peer the dialer meant to reach.
        expected: PeerId,
        /// The peer the certificate names.
        actual: PeerId,
    },

    /// A certificate seed is zero or not below the P-256 group order.
    #[error("certificate seed gives no valid P-256 key")]
    InvalidSeed,
}

impl CertificateRejection for CertificateError {
    fn alert(&self) -> Alert {
        match self {
            Self::NotYetValid { .. } | Self::Expired { .. } => Alert::CERTIFICATE_EXPIRED,
            // A type this node cannot check.
            Self::UnsupportedSignatureAlgorithm
            | Self::UnsupportedKeyAlgorithm
            | Self::UnsupportedHostKey(_) => Alert::UNSUPPORTED_CERTIFICATE,
            Self::InvalidSeed => Alert::INTERNAL_ERROR,
            _ => Alert::BAD_CERTIFICATE,
        }
    }
}
