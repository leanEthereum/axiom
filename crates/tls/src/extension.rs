//! Hello extensions: the block of typed fields that carries every negotiated parameter.

use super::{
    ProtocolError,
    codec::{Reader, Width, Writer},
};

/// A TLS extension code point, per RFC 8446, section 4.2, and RFC 9001, section 8.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ExtensionType(pub(crate) u16);

impl ExtensionType {
    /// server_name, RFC 6066.
    pub(crate) const SERVER_NAME: Self = Self(0);
    /// supported_groups, RFC 8446.
    pub(crate) const SUPPORTED_GROUPS: Self = Self(10);
    /// ec_point_formats, RFC 8422, TLS 1.2 only.
    pub(crate) const EC_POINT_FORMATS: Self = Self(11);
    /// signature_algorithms, RFC 8446.
    pub(crate) const SIGNATURE_ALGORITHMS: Self = Self(13);
    /// application_layer_protocol_negotiation, RFC 7301.
    pub(crate) const ALPN: Self = Self(16);
    /// extended_master_secret, RFC 7627, TLS 1.2 only.
    pub(crate) const EXTENDED_MASTER_SECRET: Self = Self(23);
    /// supported_versions, RFC 8446.
    pub(crate) const SUPPORTED_VERSIONS: Self = Self(43);
    /// key_share, RFC 8446.
    pub(crate) const KEY_SHARE: Self = Self(51);
    /// quic_transport_parameters, RFC 9001.
    pub(crate) const QUIC_TRANSPORT_PARAMETERS: Self = Self(0x39);
    /// renegotiation_info, RFC 5746, TLS 1.2 only.
    pub(crate) const RENEGOTIATION_INFO: Self = Self(0xff01);
}

/// A key share: a group and its public value.
pub(crate) type KeyShare<'a> = (u16, &'a [u8]);

/// The extensions of one message, in order, each type at most once.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Extensions<'a> {
    /// Each extension's type and body.
    entries: Vec<(ExtensionType, &'a [u8])>,
}

impl<'a> Extensions<'a> {
    /// Reads an extension block, refusing a type that appears twice.
    ///
    /// RFC 8446, section 4.2: "There MUST NOT be more than one extension of the same type."
    pub(crate) fn read(reader: &mut Reader<'a>, min: usize) -> Result<Self, ProtocolError> {
        let mut block = reader.vector(Width::U16, min, 0xffff, 1)?;
        let mut entries: Vec<(ExtensionType, &'a [u8])> = Vec::new();
        while !block.is_empty() {
            let kind = ExtensionType(block.u16()?);
            let body = block.vector(Width::U16, 0, 0xffff, 1)?.rest();
            if entries.iter().any(|(seen, _)| *seen == kind) {
                return Err(ProtocolError::DuplicateExtension(kind.0));
            }
            entries.push((kind, body));
        }
        Ok(Self { entries })
    }

    /// Writes one extension whose body the closure fills.
    pub(crate) fn write(writer: &mut Writer, kind: ExtensionType, body: impl FnOnce(&mut Writer)) {
        writer.u16(kind.0);
        writer.vector(Width::U16, body);
    }

    /// The body of an extension, if present.
    pub(crate) fn get(&self, kind: ExtensionType) -> Option<&'a [u8]> {
        self.entries
            .iter()
            .find(|(found, _)| *found == kind)
            .map(|&(_, body)| body)
    }

    /// The body of an extension that must be present.
    pub(crate) fn require(&self, kind: ExtensionType) -> Result<&'a [u8], ProtocolError> {
        self.get(kind)
            .ok_or(ProtocolError::MissingExtension(kind.0))
    }

    /// Refuses any extension outside the allowed set.
    ///
    /// A response may only carry extensions its request offered, per RFC 8446, section 4.2.
    pub(crate) fn allow_only(&self, allowed: &[ExtensionType]) -> Result<(), ProtocolError> {
        match self
            .entries
            .iter()
            .find(|(kind, _)| !allowed.contains(kind))
        {
            Some((kind, _)) => Err(ProtocolError::UnsupportedExtension(kind.0)),
            None => Ok(()),
        }
    }

    /// The versions a ClientHello offers, a u8 vector of u16.
    pub(crate) fn supported_versions(&self) -> Result<Option<Vec<u16>>, ProtocolError> {
        self.u16_list(ExtensionType::SUPPORTED_VERSIONS, Width::U8, 2, 254)
    }

    /// The version a ServerHello selects, a single u16.
    pub(crate) fn selected_version(&self) -> Result<u16, ProtocolError> {
        let mut body = Reader::new(self.require(ExtensionType::SUPPORTED_VERSIONS)?);
        let version = body.u16()?;
        body.finish()?;
        Ok(version)
    }

    /// The named groups offered.
    pub(crate) fn supported_groups(&self) -> Result<Option<Vec<u16>>, ProtocolError> {
        self.u16_list(ExtensionType::SUPPORTED_GROUPS, Width::U16, 2, 0xfffe)
    }

    /// The signature schemes accepted.
    pub(crate) fn signature_algorithms(&self) -> Result<Option<Vec<u16>>, ProtocolError> {
        self.u16_list(ExtensionType::SIGNATURE_ALGORITHMS, Width::U16, 2, 0xfffe)
    }

    /// The key shares a ClientHello offers, in order.
    pub(crate) fn client_key_shares(&self) -> Result<Option<Vec<KeyShare<'a>>>, ProtocolError> {
        let Some(body) = self.get(ExtensionType::KEY_SHARE) else {
            return Ok(None);
        };
        let mut outer = Reader::new(body);
        let mut list = outer.vector(Width::U16, 0, 0xffff, 1)?;
        outer.finish()?;
        let mut shares = Vec::new();
        while !list.is_empty() {
            shares.push(Self::key_share(&mut list)?);
        }
        Ok(Some(shares))
    }

    /// The key share a ServerHello selects.
    pub(crate) fn server_key_share(&self) -> Result<KeyShare<'a>, ProtocolError> {
        let mut body = Reader::new(self.require(ExtensionType::KEY_SHARE)?);
        let share = Self::key_share(&mut body)?;
        body.finish()?;
        Ok(share)
    }

    /// The application protocol names, in order.
    pub(crate) fn alpn(&self) -> Result<Option<Vec<&'a [u8]>>, ProtocolError> {
        let Some(body) = self.get(ExtensionType::ALPN) else {
            return Ok(None);
        };
        // RFC 7301, section 3.1: ProtocolName protocol_name_list<2..2^16-1>, names <1..2^8-1>.
        let mut outer = Reader::new(body);
        let mut list = outer.vector(Width::U16, 2, 0xffff, 1)?;
        outer.finish()?;
        let mut names = Vec::new();
        while !list.is_empty() {
            names.push(list.vector(Width::U8, 1, 0xff, 1)?.rest());
        }
        Ok(Some(names))
    }

    /// Writes an ALPN extension naming protocols in preference order.
    pub(crate) fn write_alpn<P: AsRef<[u8]>>(writer: &mut Writer, protocols: &[P]) {
        Self::write(writer, ExtensionType::ALPN, |body| {
            body.vector(Width::U16, |list| {
                for protocol in protocols {
                    list.vector(Width::U8, |name| name.bytes(protocol.as_ref()));
                }
            });
        });
    }

    /// Writes a server_name extension naming one DNS host, per RFC 6066, section 3.
    ///
    /// ```text
    /// ServerNameList: server_name_list <1..2^16-1> of { name_type: u8 = host_name(0), HostName <1..2^16-1> }
    /// ```
    pub(crate) fn write_server_name(writer: &mut Writer, host: &[u8]) {
        Self::write(writer, ExtensionType::SERVER_NAME, |body| {
            body.vector(Width::U16, |list| {
                list.u8(0);
                list.vector(Width::U16, |name| name.bytes(host));
            });
        });
    }

    /// Fails unless an extension, when present, has an empty body.
    ///
    /// A server acknowledges server_name, and TLS 1.2 extended_master_secret, with an empty body.
    pub(crate) fn require_empty(&self, kind: ExtensionType) -> Result<(), ProtocolError> {
        match self.get(kind) {
            Some(body) if !body.is_empty() => Err(ProtocolError::InvalidExtension(kind.0)),
            _ => Ok(()),
        }
    }

    /// Writes a key share entry: the group, then the public value.
    pub(crate) fn write_key_share(writer: &mut Writer, group: u16, key: &[u8]) {
        writer.u16(group);
        writer.vector(Width::U16, |value| value.bytes(key));
    }

    /// Reads one key share entry.
    fn key_share(reader: &mut Reader<'a>) -> Result<KeyShare<'a>, ProtocolError> {
        let group = reader.u16()?;
        let key = reader.vector(Width::U16, 1, 0xffff, 1)?.rest();
        Ok((group, key))
    }

    /// A list of u16 values in one extension, if present.
    fn u16_list(
        &self,
        kind: ExtensionType,
        width: Width,
        min: usize,
        max: usize,
    ) -> Result<Option<Vec<u16>>, ProtocolError> {
        let Some(body) = self.get(kind) else {
            return Ok(None);
        };
        let mut outer = Reader::new(body);
        let mut list = outer.vector(width, min, max, 2)?;
        outer.finish()?;
        let mut values = Vec::new();
        while !list.is_empty() {
            values.push(list.u16()?);
        }
        Ok(Some(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicates_are_refused() {
        // Two empty ALPN extensions: 00 08 | 00 10 00 00 | 00 10 00 00.
        let bytes = [0x00, 0x08, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00];
        assert_eq!(
            Extensions::read(&mut Reader::new(&bytes), 0),
            Err(ProtocolError::DuplicateExtension(0x10))
        );
    }

    #[test]
    fn typed_bodies() {
        // ALPN "libp2p", and a key share for X25519 with a one-byte key.
        let mut writer = Writer::new();
        writer.vector(Width::U16, |block| {
            Extensions::write_alpn(block, &[b"libp2p"]);
            Extensions::write(block, ExtensionType::KEY_SHARE, |body| {
                Extensions::write_key_share(body, 0x001d, &[7]);
            });
        });
        let bytes = writer.into_bytes();
        let extensions = Extensions::read(&mut Reader::new(&bytes), 0).unwrap();
        assert_eq!(extensions.alpn(), Ok(Some(vec![&b"libp2p"[..]])));
        assert_eq!(extensions.server_key_share(), Ok((0x001d, &[7][..])));
        assert_eq!(extensions.supported_versions(), Ok(None));
        assert_eq!(
            extensions.require(ExtensionType::SUPPORTED_VERSIONS),
            Err(ProtocolError::MissingExtension(43))
        );
        assert_eq!(
            extensions.allow_only(&[ExtensionType::ALPN]),
            Err(ProtocolError::UnsupportedExtension(51))
        );
    }
}
