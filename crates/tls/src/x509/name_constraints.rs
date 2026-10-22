//! Name constraints: the subtrees of names a CA may certify, and checking names against them.
//!
//! # Overview
//!
//! A CA's name constraints bound every certificate below it, per RFC 5280, section 4.2.1.10.
//! Each presented name is checked against the subtrees of its own form:
//!
//! - an excluded subtree that matches refuses the name;
//! - when permitted subtrees of the form exist, one of them must match.
//!
//! Forms without subtrees are unconstrained.
//! A constraint form this stack does not evaluate refuses any name of that form.

use std::{mem, str};

use super::{Certificate, GeneralName, X509Error};
use crate::der::{DerReader, Tag};

/// The permitted and excluded subtrees of a CA's name constraints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameConstraints<'a> {
    /// Names below the CA must fall in one of these, per form.
    pub permitted: Option<Vec<GeneralName<'a>>>,
    /// Names below the CA must fall in none of these.
    pub excluded: Option<Vec<GeneralName<'a>>>,
}

impl<'a> NameConstraints<'a> {
    /// Decodes the extension value.
    ///
    /// ```text
    /// NameConstraints ::= SEQUENCE { permittedSubtrees [0] GeneralSubtrees OPTIONAL,
    ///                                excludedSubtrees  [1] GeneralSubtrees OPTIONAL }
    /// GeneralSubtree  ::= SEQUENCE { base GeneralName, minimum [0] DEFAULT 0, maximum [1] OPTIONAL }
    /// ```
    ///
    /// RFC 5280 requires a minimum of zero and no maximum, and forbids an empty sequence.
    pub(crate) fn from_der(value: &'a [u8]) -> Result<Self, X509Error> {
        let mut outer = DerReader::new(value);
        let mut fields = outer.sequence()?;
        outer.finish()?;
        let permitted = fields
            .optional(Tag::explicit(0))?
            .map(Self::subtrees)
            .transpose()?;
        let excluded = fields
            .optional(Tag::explicit(1))?
            .map(Self::subtrees)
            .transpose()?;
        fields.finish()?;
        if permitted.is_none() && excluded.is_none() {
            return Err(X509Error::InvalidExtension);
        }
        Ok(Self {
            permitted,
            excluded,
        })
    }

    /// The number of subtrees, permitted and excluded.
    #[must_use]
    pub fn subtree_count(&self) -> usize {
        self.permitted.as_ref().map_or(0, Vec::len) + self.excluded.as_ref().map_or(0, Vec::len)
    }

    /// Whether every name a certificate presents satisfies the constraints.
    ///
    /// The names are the subject, unless empty, and each subject alternative name.
    ///
    /// # Errors
    ///
    /// Fails on a malformed constraint or extension.
    pub fn permits(&self, certificate: &Certificate<'_>) -> Result<bool, X509Error> {
        let subject = certificate.subject();
        if !subject.is_empty() && !self.permits_name(GeneralName::DirectoryName(*subject))? {
            return Ok(false);
        }
        if let Some(names) = certificate.extensions().subject_alt_names()? {
            for name in names {
                if !self.permits_name(name?)? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// Whether one presented name satisfies the constraints.
    fn permits_name(&self, name: GeneralName<'_>) -> Result<bool, X509Error> {
        for base in self.excluded.iter().flatten() {
            if Self::same_form(base, &name) && Self::matches(base, &name, Subtree::Excluded)? {
                return Ok(false);
            }
        }
        let Some(permitted) = &self.permitted else {
            return Ok(true);
        };
        let mut constrained = false;
        for base in permitted.iter().filter(|base| Self::same_form(base, &name)) {
            constrained = true;
            if Self::matches(base, &name, Subtree::Permitted)? {
                return Ok(true);
            }
        }
        Ok(!constrained)
    }

    /// Whether a subtree base and a presented name are of one form.
    fn same_form(base: &GeneralName<'_>, name: &GeneralName<'_>) -> bool {
        match (base, name) {
            (GeneralName::Other(a), GeneralName::Other(b)) => a == b,
            _ => mem::discriminant(base) == mem::discriminant(name),
        }
    }

    /// Whether a presented name falls in a subtree of its own form.
    fn matches(
        base: &GeneralName<'_>,
        name: &GeneralName<'_>,
        subtree: Subtree,
    ) -> Result<bool, X509Error> {
        match (base, name) {
            (GeneralName::DnsName(base), GeneralName::DnsName(name)) => {
                Self::dns_matches(base, name, subtree)
            }
            (GeneralName::IpAddress(base), GeneralName::IpAddress(name)) => {
                Self::ip_matches(base, name)
            }
            (GeneralName::DirectoryName(base), GeneralName::DirectoryName(name)) => {
                name.starts_with(base)
            }
            (GeneralName::Rfc822Name(base), GeneralName::Rfc822Name(name)) => {
                Ok(Self::email_matches(base, name))
            }
            // URI and the other forms are not evaluated; a name of such a form is refused.
            _ => Err(X509Error::UnsupportedNameConstraint),
        }
    }

    /// Whether a dNSName falls under a DNS constraint.
    ///
    /// A constraint matches the name itself and every name with labels added on the left.
    /// A wildcard name matches a permitted subtree when all its expansions do.
    /// It matches an excluded subtree when any expansion might.
    fn dns_matches(base: &[u8], name: &[u8], subtree: Subtree) -> Result<bool, X509Error> {
        let base = Self::dns_text(base)?.to_ascii_lowercase();
        // A leading period, read as subdomains only, is common though RFC 5280 does not define it.
        let (base, subdomains_only) = match base.strip_prefix('.') {
            Some(rest) => (rest.to_owned(), true),
            None => (base, false),
        };
        if !base.is_empty() && !Self::is_host(&base) {
            return Err(X509Error::InvalidExtension);
        }
        let Ok(name) = Self::dns_text(name) else {
            return Ok(false);
        };
        let name = name.to_ascii_lowercase();
        let within = |candidate: &str| {
            base.is_empty()
                || (!subdomains_only && candidate == base)
                || candidate
                    .strip_suffix(base.as_str())
                    .is_some_and(|head| head.ends_with('.') && head.len() > 1)
        };
        if let Some(rest) = name.strip_prefix("*.") {
            if !Self::is_host(rest) {
                return Ok(subtree == Subtree::Excluded);
            }
            // Every expansion adds one label to the rest, so all fall inside when the rest does.
            let all_within = base.is_empty()
                || rest == base
                || rest
                    .strip_suffix(base.as_str())
                    .is_some_and(|head| head.ends_with('.'));
            // One expansion equals the base when the base is one label longer than the rest.
            let one_within = !subdomains_only
                && base
                    .strip_suffix(rest)
                    .and_then(|head| head.strip_suffix('.'))
                    .is_some_and(|label| !label.is_empty() && !label.contains('.'));
            return Ok(match subtree {
                Subtree::Permitted => all_within,
                Subtree::Excluded => all_within || one_within,
            });
        }
        // A presented name that is not a host name satisfies no subtree, and must not slip past.
        if !Self::is_host(&name) {
            return Ok(subtree == Subtree::Excluded);
        }
        Ok(within(&name))
    }

    /// Whether an iPAddress falls in an address and mask constraint of its family.
    fn ip_matches(base: &[u8], name: &[u8]) -> Result<bool, X509Error> {
        // The constraint is an address then a mask: 8 bytes for IPv4, 32 for IPv6.
        if base.len() != 8 && base.len() != 32 {
            return Err(X509Error::InvalidExtension);
        }
        let (address, mask) = base.split_at(base.len() / 2);
        // The mask must be a run of ones then a run of zeros.
        let bits = mask.iter().fold(Vec::new(), |mut bits, byte| {
            bits.extend((0..8).rev().map(|shift| byte >> shift & 1));
            bits
        });
        if bits.windows(2).any(|pair| pair == [0, 1]) {
            return Err(X509Error::InvalidExtension);
        }
        if name.len() != address.len() {
            return Ok(false);
        }
        Ok(name
            .iter()
            .zip(address)
            .zip(mask)
            .all(|((name, address), mask)| name & mask == address & mask))
    }

    /// Whether an rfc822Name falls under an email constraint.
    ///
    /// A constraint with an "@" names one mailbox.
    /// One with a leading period names every subdomain of a host, and otherwise one host.
    fn email_matches(base: &[u8], name: &[u8]) -> bool {
        let Some((local, host)) = Self::split_email(name) else {
            return false;
        };
        if let Some((base_local, base_host)) = Self::split_email(base) {
            return local == base_local && host.eq_ignore_ascii_case(base_host);
        }
        if let Some(domain) = base.strip_prefix(b".") {
            return host.len() > domain.len()
                && host[host.len() - domain.len()..].eq_ignore_ascii_case(domain)
                && host[host.len() - domain.len() - 1] == b'.';
        }
        host.eq_ignore_ascii_case(base)
    }

    /// The local part and host of a mailbox with exactly one "@".
    fn split_email(text: &[u8]) -> Option<(&[u8], &[u8])> {
        let at = text.iter().position(|&byte| byte == b'@')?;
        let (local, rest) = text.split_at(at);
        let host = &rest[1..];
        (!local.is_empty() && !host.is_empty() && !host.contains(&b'@')).then_some((local, host))
    }

    /// A DNS name or constraint as text.
    fn dns_text(bytes: &[u8]) -> Result<&str, X509Error> {
        str::from_utf8(bytes).map_err(|_| X509Error::InvalidExtension)
    }

    /// Whether text is a host name: non-empty labels of letters, digits and hyphens.
    fn is_host(text: &str) -> bool {
        !text.is_empty()
            && text.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
    }

    /// Reads a GeneralSubtrees list.
    fn subtrees(content: &'a [u8]) -> Result<Vec<GeneralName<'a>>, X509Error> {
        let mut list = DerReader::new(content);
        // GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree.
        if list.is_empty() {
            return Err(X509Error::InvalidExtension);
        }
        let mut bases = Vec::new();
        while !list.is_empty() {
            let mut subtree = list.sequence()?;
            bases.push(GeneralName::read(&mut subtree)?);
            if !subtree.is_empty() {
                return Err(X509Error::UnsupportedNameConstraint);
            }
        }
        Ok(bases)
    }
}

/// Which list a subtree comes from, since a wildcard name matches the two lists differently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Subtree {
    /// A permitted subtree.
    Permitted,
    /// An excluded subtree.
    Excluded,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        der::DerWriter,
        x509::{Name, oid},
    };

    #[test]
    fn decoding_forms() {
        // permitted dNSName "a.com".
        let permitted = [
            0x30, 0x0b, 0xa0, 0x09, 0x30, 0x07, 0x82, 0x05, b'a', b'.', b'c', b'o', b'm',
        ];
        assert_eq!(
            NameConstraints::from_der(&permitted),
            Ok(NameConstraints {
                permitted: Some(vec![GeneralName::DnsName(b"a.com")]),
                excluded: None,
            })
        );
        // Mutation: a maximum field, then an empty sequence.
        let bounded = [
            0x30, 0x0e, 0xa0, 0x0c, 0x30, 0x0a, 0x82, 0x05, b'a', b'.', b'c', b'o', b'm', 0x81,
            0x01, 0x01,
        ];
        assert_eq!(
            NameConstraints::from_der(&bounded),
            Err(X509Error::UnsupportedNameConstraint)
        );
        assert_eq!(
            NameConstraints::from_der(&[0x30, 0x00]),
            Err(X509Error::InvalidExtension)
        );
    }

    #[test]
    fn dns_subtrees() {
        let permitted = Subtree::Permitted;
        let excluded = Subtree::Excluded;
        // Each tuple: constraint, presented name, subtree, verdict.
        let cases: [(&str, &str, Subtree, bool); 12] = [
            ("example.com", "example.com", permitted, true),
            ("example.com", "foo.example.com", permitted, true),
            ("example.com", "fooexample.com", permitted, false),
            (".example.com", "example.com", permitted, false),
            (".example.com", "foo.example.com", permitted, true),
            ("", "anything.org", permitted, true),
            // A wildcard sits wholly inside the domain it extends.
            ("foo.com", "*.foo.com", permitted, true),
            ("bar.foo.com", "*.foo.com", permitted, false),
            // An excluded name the wildcard could expand to refuses it.
            ("bar.example.com", "*.example.com", excluded, true),
            ("x.bar.example.com", "*.example.com", excluded, false),
            // An invalid presented name satisfies no permitted subtree and every excluded one.
            ("example.com", "foo_bar.example.com", permitted, false),
            ("example.com", "foo_bar.example.com", excluded, true),
        ];
        for (base, name, subtree, expected) in cases {
            assert_eq!(
                NameConstraints::dns_matches(base.as_bytes(), name.as_bytes(), subtree),
                Ok(expected),
                "{base} {name} {subtree:?}"
            );
        }
        // Mutation: a wildcard in the constraint is malformed.
        assert_eq!(
            NameConstraints::dns_matches(b"*.example.com", b"a.example.com", permitted),
            Err(X509Error::InvalidExtension)
        );
    }

    #[test]
    fn ip_and_email_subtrees() {
        // 192.0.2.0/24 holds 192.0.2.1, not 192.0.3.1, and no IPv6 address.
        let base = [192, 0, 2, 0, 255, 255, 255, 0];
        assert_eq!(
            NameConstraints::ip_matches(&base, &[192, 0, 2, 1]),
            Ok(true)
        );
        assert_eq!(
            NameConstraints::ip_matches(&base, &[192, 0, 3, 1]),
            Ok(false)
        );
        assert_eq!(NameConstraints::ip_matches(&base, &[0; 16]), Ok(false));
        // Mutation: a mask with a hole, and a 5-byte constraint.
        assert_eq!(
            NameConstraints::ip_matches(&[192, 0, 2, 0, 255, 0, 255, 0], &[192, 0, 2, 1]),
            Err(X509Error::InvalidExtension)
        );
        assert_eq!(
            NameConstraints::ip_matches(&[1, 2, 3, 4, 5], &[1, 2, 3, 4]),
            Err(X509Error::InvalidExtension)
        );

        // A mailbox, a host, and the subdomains of a host.
        assert!(NameConstraints::email_matches(b"a@x.com", b"a@X.com"));
        assert!(!NameConstraints::email_matches(b"a@x.com", b"b@x.com"));
        assert!(NameConstraints::email_matches(b"x.com", b"b@x.com"));
        assert!(!NameConstraints::email_matches(b"x.com", b"b@y.x.com"));
        assert!(NameConstraints::email_matches(b".x.com", b"b@y.x.com"));
        assert!(!NameConstraints::email_matches(b".x.com", b"b@x.com"));
    }

    #[test]
    fn subjects_are_directory_names() {
        // Fixture state: a constraint permitting the name CN=a, and a subject CN=a, CN=b.
        let rdn = |value: &[u8]| {
            let mut writer = DerWriter::new();
            writer.nested(Tag::SET, |set| {
                set.sequence(|attribute| {
                    attribute.element(Tag::OBJECT_IDENTIFIER, oid::COMMON_NAME);
                    attribute.element(Tag::UTF8_STRING, value);
                });
            });
            writer.into_bytes()
        };
        let name = |rdns: &[&[u8]]| {
            let mut writer = DerWriter::new();
            writer.nested(Tag::SEQUENCE, |sequence| {
                for value in rdns {
                    sequence.encoded(&rdn(value));
                }
            });
            writer.into_bytes()
        };
        let base = name(&[b"a"]);
        let subject = name(&[b"a", b"b"]);
        let other = name(&[b"c"]);
        let base = Name::from_der(&base).unwrap();
        let matches = |subject: &[u8]| {
            NameConstraints::matches(
                &GeneralName::DirectoryName(base),
                &GeneralName::DirectoryName(Name::from_der(subject).unwrap()),
                Subtree::Permitted,
            )
        };
        assert_eq!(matches(&subject), Ok(true));
        assert_eq!(matches(&other), Ok(false));
    }
}
