//! Reasons a server's certificate chain is refused.

use thiserror::Error;

use crate::{Alert, CertificateRejection, x509::X509Error};

/// A server certificate chain that does not authenticate the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum CertificateError {
    /// A certificate, key, or signature in the chain is malformed or unsupported.
    #[error("certificate at depth {depth}: {source}")]
    X509 {
        /// Position in the path: 0 for the server's own certificate.
        depth: usize,
        /// What is wrong with it.
        #[source]
        source: X509Error,
    },

    /// A certificate is not version 3.
    #[error("certificate at depth {depth} is not version 3")]
    UnsupportedVersion {
        /// Position in the path.
        depth: usize,
    },

    /// The current time is before a certificate's validity window.
    #[error(
        "certificate at depth {depth} not valid before {not_before}, now is {now} (Unix seconds)"
    )]
    NotYetValid {
        /// Position in the path.
        depth: usize,
        /// Start of the window.
        not_before: i64,
        /// The current time.
        now: i64,
    },

    /// The current time is after a certificate's validity window.
    #[error("certificate at depth {depth} expired at {not_after}, now is {now} (Unix seconds)")]
    Expired {
        /// Position in the path.
        depth: usize,
        /// End of the window.
        not_after: i64,
        /// The current time.
        now: i64,
    },

    /// A certificate carries a critical extension this stack does not process.
    #[error("certificate at depth {depth} has an unsupported critical extension")]
    UnsupportedCriticalExtension {
        /// Position in the path.
        depth: usize,
    },

    /// The server's certificate is a CA certificate.
    #[error("server certificate is a CA certificate")]
    CaUsedAsEndEntity,

    /// An issuing certificate is not marked as a CA.
    #[error("issuer at depth {depth} is not a CA")]
    EndEntityUsedAsCa {
        /// Position in the path.
        depth: usize,
    },

    /// An issuing certificate's key usage does not allow signing certificates.
    #[error("issuer at depth {depth} may not sign certificates")]
    MissingKeyCertSign {
        /// Position in the path.
        depth: usize,
    },

    /// More CAs follow an issuer than its path length constraint allows.
    #[error("issuer at depth {depth} allows {allowed} CAs below it, the path has {actual}")]
    PathLenExceeded {
        /// Position in the path.
        depth: usize,
        /// The path length constraint.
        allowed: u64,
        /// Intermediate CAs below it.
        actual: usize,
    },

    /// A certificate's extended key usage does not include server authentication.
    #[error("certificate at depth {depth} is not valid for server authentication")]
    RequiredEkuNotFound {
        /// Position in the path.
        depth: usize,
    },

    /// A name in the path falls outside a CA's name constraints.
    #[error("a name violates the constraints of the issuer at depth {depth}")]
    NameConstraintViolation {
        /// Position of the constraining CA in the path.
        depth: usize,
    },

    /// The server's certificate does not name the server.
    #[error("certificate is not valid for the server name")]
    NotValidForName,

    /// No path leads from the server's certificate to a trusted root.
    #[error("no path to a trusted root")]
    UnknownIssuer,

    /// The path would hold more intermediates than the limit.
    #[error("path exceeds {max} intermediates")]
    MaxDepthExceeded {
        /// Most intermediates allowed.
        max: usize,
    },

    /// Path building spent its budget of signature checks or steps.
    #[error("path building exceeded its budget")]
    BudgetExceeded,

    /// The peer sent an empty certificate list.
    #[error("empty certificate chain")]
    EmptyChain,
}

impl CertificateRejection for CertificateError {
    fn alert(&self) -> Alert {
        match self {
            Self::NotYetValid { .. } | Self::Expired { .. } => Alert::CERTIFICATE_EXPIRED,
            Self::UnknownIssuer => Alert::UNKNOWN_CA,
            Self::X509 {
                source:
                    X509Error::UnsupportedSignatureAlgorithm
                    | X509Error::UnsupportedKeyAlgorithm
                    | X509Error::RsaKeyTooSmall { .. },
                ..
            }
            | Self::UnsupportedCriticalExtension { .. } => Alert::UNSUPPORTED_CERTIFICATE,
            Self::X509 {
                source: X509Error::InvalidSignature,
                ..
            } => Alert::DECRYPT_ERROR,
            _ => Alert::BAD_CERTIFICATE,
        }
    }
}
