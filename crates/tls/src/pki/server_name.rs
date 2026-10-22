//! The name a client expects the server to prove, and matching it against a certificate.
//!
//! # Overview
//!
//! The client knows the server by the host of its URL: a DNS name or an IP address.
//! The certificate names the server in its subject alternative names.
//! The common name is never consulted, per RFC 9525, section 6.3.
//!
//! - A DNS name matches a dNSName entry, ignoring ASCII case.
//! - A wildcard entry stands for exactly one label, and only as the whole leftmost label.
//! - An IP address matches an iPAddress entry of the same family, byte for byte.

use std::{
    fmt,
    net::IpAddr,
    str::{self, FromStr},
};

use thiserror::Error;

use crate::x509::{Certificate, GeneralName, X509Error};

/// Longest DNS name, in bytes without a trailing dot, per RFC 1035, section 2.3.4.
const MAX_NAME_LEN: usize = 253;

/// Longest DNS label, per RFC 1035, section 2.3.4.
const MAX_LABEL_LEN: usize = 63;

/// A host name that is neither a valid DNS name nor an IP address.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("invalid server name {0:?}")]
pub struct InvalidServerName(pub String);

/// The identity a client checks the server's certificate against.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ServerName {
    /// A DNS name: lowercase ASCII, without a trailing dot.
    Dns(String),
    /// An IP address, written as a literal in the URL.
    Ip(IpAddr),
}

impl ServerName {
    /// The DNS name, if the server is named by one.
    ///
    /// Only a DNS name travels in the server_name extension, per RFC 6066, section 3.
    #[must_use]
    pub fn dns_name(&self) -> Option<&str> {
        match self {
            Self::Dns(name) => Some(name),
            Self::Ip(_) => None,
        }
    }

    /// Whether a certificate's subject alternative names include this name.
    ///
    /// # Errors
    ///
    /// Fails when the extension is malformed.
    pub fn is_named_by(&self, certificate: &Certificate<'_>) -> Result<bool, X509Error> {
        let Some(names) = certificate.extensions().subject_alt_names()? else {
            return Ok(false);
        };
        for name in names {
            let matched = match (self, name?) {
                (Self::Dns(reference), GeneralName::DnsName(presented)) => {
                    Self::dns_matches(reference, presented)
                }
                (Self::Ip(IpAddr::V4(reference)), GeneralName::IpAddress(presented)) => {
                    presented == reference.octets()
                }
                (Self::Ip(IpAddr::V6(reference)), GeneralName::IpAddress(presented)) => {
                    presented == reference.octets()
                }
                _ => false,
            };
            if matched {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether a presented dNSName matches a reference DNS name.
    ///
    /// A presented name must be a valid host name, or one whose leftmost label is exactly "*".
    /// The wildcard needs two labels after it, so it never covers a top-level domain.
    fn dns_matches(reference: &str, presented: &[u8]) -> bool {
        let Ok(presented) = str::from_utf8(presented) else {
            return false;
        };
        let presented = presented.to_ascii_lowercase();
        if let Some(rest) = presented.strip_prefix("*.") {
            if !Self::is_valid_host(rest, false) || rest.split('.').count() < 2 {
                return false;
            }
            // The wildcard stands for exactly one non-empty label.
            return reference
                .split_once('.')
                .is_some_and(|(first, tail)| !first.is_empty() && tail == rest);
        }
        Self::is_valid_host(&presented, false) && presented == reference
    }

    /// Whether text is a valid host name: labels of letters, digits and hyphens.
    ///
    /// A reference name may also carry underscores, which some private names use.
    pub(crate) fn is_valid_host(name: &str, allow_underscore: bool) -> bool {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return false;
        }
        name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= MAX_LABEL_LEN
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || byte == b'-'
                        || (allow_underscore && byte == b'_')
                })
        })
    }
}

impl FromStr for ServerName {
    type Err = InvalidServerName;

    /// Reads a host: an IP literal, else a DNS name.
    ///
    /// A DNS name is lowercased and loses a trailing dot; IPv6 literals come without brackets.
    fn from_str(host: &str) -> Result<Self, Self::Err> {
        if let Ok(address) = host.parse::<IpAddr>() {
            return Ok(Self::Ip(address));
        }
        let name = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
        // A name of digits and dots alone would read as a malformed address.
        let numeric = name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.');
        if !Self::is_valid_host(&name, true) || numeric {
            return Err(InvalidServerName(host.to_owned()));
        }
        Ok(Self::Dns(name))
    }
}

impl fmt::Display for ServerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(name) => f.write_str(name),
            Self::Ip(address) => write!(f, "{address}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_parse() {
        assert_eq!(
            "Example.COM.".parse(),
            Ok(ServerName::Dns("example.com".to_owned()))
        );
        assert_eq!(
            "::1".parse(),
            Ok(ServerName::Ip(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1])))
        );
        assert_eq!(
            "beacon_node".parse(),
            Ok(ServerName::Dns("beacon_node".to_owned()))
        );
        // Mutation: an empty label, a leading hyphen, and a malformed address.
        for host in ["a..b", "-a.b", "1.2.3.256", ""] {
            assert_eq!(
                host.parse::<ServerName>(),
                Err(InvalidServerName(host.to_owned())),
                "{host}"
            );
        }
    }

    #[test]
    fn dns_matching() {
        // Each tuple: reference, presented, whether they match.
        let cases = [
            ("example.com", "example.com", true),
            ("example.com", "EXAMPLE.com", true),
            ("foo.example.com", "*.example.com", true),
            // The wildcard covers exactly one label.
            ("example.com", "*.example.com", false),
            ("a.b.example.com", "*.example.com", false),
            // Only a whole leftmost label may be a wildcard.
            ("foo.example.com", "f*.example.com", false),
            ("foo.bar.example.com", "foo.*.example.com", false),
            // A wildcard over a top-level domain, a lone wildcard, and an underscore.
            ("example.com", "*.com", false),
            ("example.com", "*", false),
            ("foo_bar.example.com", "foo_bar.example.com", false),
        ];
        for (reference, presented, expected) in cases {
            assert_eq!(
                ServerName::dns_matches(reference, presented.as_bytes()),
                expected,
                "{reference} against {presented}"
            );
        }
    }
}
