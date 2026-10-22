//! Certificate extensions: the raw list, and typed readers for the ones path validation needs.

use super::{GeneralNames, NameConstraints, X509Error, oid};
use crate::der::{DerError, DerReader, Tag};

/// One extension: its identifier, criticality, and the DER inside its OCTET STRING.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extension<'a> {
    /// The extension's OID, as encoded content bytes.
    pub oid: &'a [u8],
    /// Whether a verifier that does not understand it must refuse the certificate.
    pub critical: bool,
    /// The extension value.
    pub value: &'a [u8],
}

/// The extensions of one certificate, in order, each identifier at most once.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Extensions<'a> {
    /// The extensions as written.
    entries: Vec<Extension<'a>>,
}

impl<'a> Extensions<'a> {
    /// Reads the content of an Extensions SEQUENCE.
    ///
    /// ```text
    /// Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
    /// ```
    ///
    /// RFC 5280, section 4.2: an extension appears at most once.
    pub(crate) fn read(content: &'a [u8]) -> Result<Self, X509Error> {
        let mut list = DerReader::new(content);
        if list.is_empty() {
            return Err(X509Error::EmptyExtensions);
        }
        let mut entries: Vec<Extension<'a>> = Vec::new();
        while !list.is_empty() {
            let mut extension = list.sequence()?;
            let oid = extension.object_identifier()?;
            // DER omits a default value, so a written flag must be true.
            let critical = match extension.optional(Tag::BOOLEAN)? {
                None => false,
                Some([0xff]) => true,
                Some([0x00]) => return Err(X509Error::ExplicitDefault),
                Some(_) => return Err(DerError::InvalidBoolean.into()),
            };
            let value = extension.octet_string()?;
            extension.finish()?;
            if entries.iter().any(|seen| seen.oid == oid) {
                return Err(X509Error::DuplicateExtension);
            }
            entries.push(Extension {
                oid,
                critical,
                value,
            });
        }
        Ok(Self { entries })
    }

    /// Every extension, in order.
    pub fn iter(&self) -> impl Iterator<Item = &Extension<'a>> {
        self.entries.iter()
    }

    /// The extension with an identifier, if present.
    #[must_use]
    pub fn get(&self, oid: &[u8]) -> Option<&Extension<'a>> {
        self.entries.iter().find(|extension| extension.oid == oid)
    }

    /// The basic constraints, if present, per RFC 5280, section 4.2.1.9.
    ///
    /// ```text
    /// BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER (0..MAX) OPTIONAL }
    /// ```
    pub fn basic_constraints(&self) -> Result<Option<BasicConstraints>, X509Error> {
        let Some(extension) = self.get(oid::BASIC_CONSTRAINTS) else {
            return Ok(None);
        };
        let mut outer = DerReader::new(extension.value);
        let mut fields = outer.sequence()?;
        outer.finish()?;
        let ca = match fields.optional(Tag::BOOLEAN)? {
            None => false,
            Some([0xff]) => true,
            Some([0x00]) => return Err(X509Error::ExplicitDefault),
            Some(_) => return Err(DerError::InvalidBoolean.into()),
        };
        let path_len = if fields.peek_tag() == Some(Tag::INTEGER) {
            Some(fields.small_integer()?)
        } else {
            None
        };
        fields.finish()?;
        Ok(Some(BasicConstraints { ca, path_len }))
    }

    /// The key usage bits, if present, per RFC 5280, section 4.2.1.3.
    pub fn key_usage(&self) -> Result<Option<KeyUsage>, X509Error> {
        let Some(extension) = self.get(oid::KEY_USAGE) else {
            return Ok(None);
        };
        let mut reader = DerReader::new(extension.value);
        let (bytes, _) = reader.named_bits()?;
        reader.finish()?;
        // Nine named bits fit in two bytes; bit 0 is the top bit of the first byte.
        let bits = match bytes {
            [] => 0,
            [first] => u16::from(*first) << 8,
            [first, second] => (u16::from(*first) << 8) | u16::from(*second),
            _ => return Err(X509Error::InvalidExtension),
        };
        Ok(Some(KeyUsage(bits)))
    }

    /// The extended key usage purposes, if present, per RFC 5280, section 4.2.1.12.
    pub fn extended_key_usage(&self) -> Result<Option<Vec<&'a [u8]>>, X509Error> {
        let Some(extension) = self.get(oid::EXTENDED_KEY_USAGE) else {
            return Ok(None);
        };
        let mut outer = DerReader::new(extension.value);
        let mut list = outer.sequence()?;
        outer.finish()?;
        let mut purposes = Vec::new();
        // KeyPurposeId SEQUENCE SIZE (1..MAX).
        if list.is_empty() {
            return Err(X509Error::InvalidExtension);
        }
        while !list.is_empty() {
            purposes.push(list.object_identifier()?);
        }
        Ok(Some(purposes))
    }

    /// The subject alternative names, if present, per RFC 5280, section 4.2.1.6.
    pub fn subject_alt_names(&self) -> Result<Option<GeneralNames<'a>>, X509Error> {
        let Some(extension) = self.get(oid::SUBJECT_ALT_NAME) else {
            return Ok(None);
        };
        let mut outer = DerReader::new(extension.value);
        let content = outer.element(Tag::SEQUENCE)?;
        outer.finish()?;
        // GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName.
        if content.is_empty() {
            return Err(X509Error::InvalidExtension);
        }
        GeneralNames::new(content).map(Some)
    }

    /// The name constraints, if present, per RFC 5280, section 4.2.1.10.
    pub fn name_constraints(&self) -> Result<Option<NameConstraints<'a>>, X509Error> {
        self.get(oid::NAME_CONSTRAINTS)
            .map(|extension| NameConstraints::from_der(extension.value))
            .transpose()
    }
}

/// Whether a certificate is a CA, and how many CAs may follow it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BasicConstraints {
    /// Whether the subject is a certificate authority.
    pub ca: bool,
    /// Most intermediate CAs that may follow this one in a path.
    pub path_len: Option<u64>,
}

/// The key usage bits, bit 0 most significant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyUsage(u16);

impl KeyUsage {
    /// digitalSignature, bit 0.
    pub const DIGITAL_SIGNATURE: u8 = 0;
    /// keyCertSign, bit 5.
    pub const KEY_CERT_SIGN: u8 = 5;

    /// Whether a named bit is set.
    #[must_use]
    pub const fn contains(self, bit: u8) -> bool {
        self.0 & (0x8000 >> bit) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::der::DerWriter;

    /// An extension list from (oid, critical, value) triples.
    fn list(entries: &[(&[u8], Option<bool>, &[u8])]) -> Vec<u8> {
        let mut writer = DerWriter::new();
        for (oid, critical, value) in entries {
            writer.sequence(|extension| {
                extension.element(Tag::OBJECT_IDENTIFIER, oid);
                if let Some(flag) = critical {
                    extension.boolean(*flag);
                }
                extension.element(Tag::OCTET_STRING, value);
            });
        }
        writer.into_bytes()
    }

    #[test]
    fn typed_readers() {
        // cA true with a path length of 1; keyCertSign alone, bits 00000100 with 2 unused.
        let constraints = [0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x01];
        let usage = [0x03, 0x02, 0x02, 0x04];
        let bytes = list(&[
            (oid::BASIC_CONSTRAINTS, Some(true), &constraints),
            (oid::KEY_USAGE, None, &usage),
        ]);
        let extensions = Extensions::read(&bytes).unwrap();
        assert_eq!(
            extensions.basic_constraints(),
            Ok(Some(BasicConstraints {
                ca: true,
                path_len: Some(1)
            }))
        );
        let key_usage = extensions.key_usage().unwrap().unwrap();
        assert!(key_usage.contains(KeyUsage::KEY_CERT_SIGN));
        assert!(!key_usage.contains(KeyUsage::DIGITAL_SIGNATURE));
        assert_eq!(extensions.extended_key_usage(), Ok(None));
    }

    #[test]
    fn list_rules() {
        // Mutation: the same OID twice, an explicit false flag, and an empty list.
        let twice = list(&[(oid::KEY_USAGE, None, &[]), (oid::KEY_USAGE, None, &[])]);
        assert_eq!(Extensions::read(&twice), Err(X509Error::DuplicateExtension));
        let explicit = list(&[(oid::KEY_USAGE, Some(false), &[])]);
        assert_eq!(Extensions::read(&explicit), Err(X509Error::ExplicitDefault));
        assert_eq!(Extensions::read(&[]), Err(X509Error::EmptyExtensions));
    }
}
