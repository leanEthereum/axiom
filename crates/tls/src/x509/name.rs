//! Names: the distinguished names of issuers and subjects, and the general names of extensions.

use std::iter;

use super::{X509Error, oid};
use crate::der::{DerReader, Tag};

/// A distinguished name, kept as its whole DER encoding.
///
/// Path building matches an issuer to a subject by comparing these encodings byte for byte.
/// RFC 5280, section 7.1, allows that simple comparison when both come from one issuer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Name<'a> {
    /// The SEQUENCE encoding, tag and length included.
    encoding: &'a [u8],
    /// The content of the SEQUENCE: the relative distinguished names in order.
    rdns: &'a [u8],
}

impl<'a> Name<'a> {
    /// Reads a Name from a reader, checking that each relative name is a SET.
    pub(crate) fn read(reader: &mut DerReader<'a>) -> Result<Self, X509Error> {
        let (rdns, encoding) = reader.element_with_encoding(Tag::SEQUENCE)?;
        let name = Self { encoding, rdns };
        for rdn in name.relative_names() {
            rdn?;
        }
        Ok(name)
    }

    /// Decodes a Name from its whole encoding.
    pub(crate) fn from_der(encoding: &'a [u8]) -> Result<Self, X509Error> {
        let mut reader = DerReader::new(encoding);
        let name = Self::read(&mut reader)?;
        reader.finish()?;
        Ok(name)
    }

    /// The whole encoding.
    #[must_use]
    pub const fn encoding(&self) -> &'a [u8] {
        self.encoding
    }

    /// The relative distinguished names, each as its whole SET encoding.
    pub fn relative_names(&self) -> impl Iterator<Item = Result<&'a [u8], X509Error>> + use<'a> {
        let mut reader = DerReader::new(self.rdns);
        iter::from_fn(move || {
            if reader.is_empty() {
                return None;
            }
            Some(
                reader
                    .element_with_encoding(Tag::SET)
                    .map(|(_, encoding)| encoding)
                    .map_err(X509Error::from),
            )
        })
    }

    /// The values of every commonName attribute, in order.
    pub fn common_names(&self) -> Result<Vec<&'a [u8]>, X509Error> {
        let mut names = Vec::new();
        for rdn in self.relative_names() {
            let mut set = DerReader::new(rdn?);
            // The SET content follows a one-byte tag and a length; skip the header.
            let content = set.element(Tag::SET)?;
            let mut attributes = DerReader::new(content);
            while !attributes.is_empty() {
                let mut attribute = attributes.sequence()?;
                let kind = attribute.object_identifier()?;
                let (_, value) = attribute.any()?;
                attribute.finish()?;
                if kind == oid::COMMON_NAME {
                    names.push(value);
                }
            }
        }
        Ok(names)
    }

    /// Whether this name begins with every relative name of another, in order.
    ///
    /// RFC 5280, section 4.2.1.10: a directoryName constraint matches the names below it.
    pub fn starts_with(&self, prefix: &Self) -> Result<bool, X509Error> {
        let mut mine = self.relative_names();
        for wanted in prefix.relative_names() {
            match mine.next() {
                Some(found) if found? == wanted? => {}
                _ => return Ok(false),
            }
        }
        Ok(true)
    }

    /// Whether the name has no relative names at all.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rdns.is_empty()
    }
}

/// One GeneralName, per RFC 5280, section 4.2.1.6.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GeneralName<'a> {
    /// rfc822Name [1]: an email address, or in a constraint a host or domain.
    Rfc822Name(&'a [u8]),
    /// dNSName [2]: a host name, or in a constraint a domain.
    DnsName(&'a [u8]),
    /// directoryName [4]: a distinguished name.
    DirectoryName(Name<'a>),
    /// uniformResourceIdentifier [6].
    Uri(&'a [u8]),
    /// iPAddress [7]: 4 or 16 bytes, or in a constraint an address then a mask.
    IpAddress(&'a [u8]),
    /// otherName, x400Address, ediPartyName or registeredID, with its tag.
    Other(Tag),
}

impl<'a> GeneralName<'a> {
    /// Reads the next GeneralName.
    pub(crate) fn read(reader: &mut DerReader<'a>) -> Result<Self, X509Error> {
        let (tag, content) = reader.any()?;
        Ok(match tag.0 {
            // IMPLICIT primitive forms: [1] IA5String, [2] IA5String, [6] IA5String, [7] OCTET STRING.
            0x81 => Self::Rfc822Name(Self::ia5(content)?),
            0x82 => Self::DnsName(Self::ia5(content)?),
            0x86 => Self::Uri(Self::ia5(content)?),
            0x87 => Self::IpAddress(content),
            // [4] is EXPLICIT, since Name is a CHOICE.
            0xa4 => Self::DirectoryName(Name::from_der(content)?),
            0xa0 | 0x83 | 0xa3 | 0xa5 | 0x88 => Self::Other(tag),
            _ => return Err(X509Error::InvalidExtension),
        })
    }

    /// Checks an IA5String holds only 7-bit characters.
    fn ia5(content: &'a [u8]) -> Result<&'a [u8], X509Error> {
        if content.is_ascii() {
            Ok(content)
        } else {
            Err(X509Error::InvalidExtension)
        }
    }
}

/// A SEQUENCE of GeneralName, read lazily.
#[derive(Clone, Copy, Debug)]
pub struct GeneralNames<'a> {
    /// The names not yet read.
    reader: DerReader<'a>,
}

impl<'a> GeneralNames<'a> {
    /// The names in the content of a GeneralNames SEQUENCE, checking each one.
    pub(crate) fn new(content: &'a [u8]) -> Result<Self, X509Error> {
        let names = Self {
            reader: DerReader::new(content),
        };
        for name in names {
            name?;
        }
        Ok(names)
    }
}

impl<'a> Iterator for GeneralNames<'a> {
    type Item = Result<GeneralName<'a>, X509Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.is_empty() {
            return None;
        }
        let name = GeneralName::read(&mut self.reader);
        if name.is_err() {
            // Stop after a malformed entry; its length cannot be trusted.
            self.reader = DerReader::new(&[]);
        }
        Some(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::der::DerWriter;

    /// A name of common names, one per relative name.
    fn name(common_names: &[&str]) -> Vec<u8> {
        let mut writer = DerWriter::new();
        writer.sequence(|rdns| {
            for value in common_names {
                rdns.nested(Tag::SET, |set| {
                    set.sequence(|attribute| {
                        attribute.element(Tag::OBJECT_IDENTIFIER, oid::COMMON_NAME);
                        attribute.element(Tag::UTF8_STRING, value.as_bytes());
                    });
                });
            }
        });
        writer.into_bytes()
    }

    #[test]
    fn prefixes_follow_relative_names() {
        let full = name(&["a", "b", "c"]);
        let prefix = name(&["a", "b"]);
        let other = name(&["a", "x"]);
        let full = Name::from_der(&full).unwrap();
        assert_eq!(
            full.common_names(),
            Ok(vec![&b"a"[..], &b"b"[..], &b"c"[..]])
        );
        assert_eq!(
            full.starts_with(&Name::from_der(&prefix).unwrap()),
            Ok(true)
        );
        assert_eq!(
            full.starts_with(&Name::from_der(&other).unwrap()),
            Ok(false)
        );
        // A longer name is never a prefix of a shorter one.
        assert_eq!(
            Name::from_der(&prefix).unwrap().starts_with(&full),
            Ok(false)
        );
    }

    #[test]
    fn general_names_by_tag() {
        // dNSName "a.b", iPAddress 127.0.0.1, then registeredID 1.2.
        let bytes = [
            0x82, 0x03, b'a', b'.', b'b', 0x87, 0x04, 127, 0, 0, 1, 0x88, 0x01, 0x2a,
        ];
        let names: Vec<_> = GeneralNames::new(&bytes).unwrap().collect();
        assert_eq!(
            names,
            [
                Ok(GeneralName::DnsName(b"a.b")),
                Ok(GeneralName::IpAddress(&[127, 0, 0, 1])),
                Ok(GeneralName::Other(Tag(0x88))),
            ]
        );

        // Mutation: a non-ASCII byte in a dNSName.
        assert_eq!(
            GeneralNames::new(&[0x82, 0x01, 0xe9]).unwrap_err(),
            X509Error::InvalidExtension
        );
    }
}
