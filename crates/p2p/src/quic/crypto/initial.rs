//! Initial packet keys, derived from the client's first destination connection id.
//!
//! Initial packets are protected, but anyone who sees the client's first packet can derive the keys.
//! The protection resists off-path tampering and blind injection, not observation.
//! See RFC 9001, section 5.2.

use axiom_crypto::hkdf::Hkdf;

use super::{KeyPair, Keys};
use crate::{
    quic::ConnectionId,
    tls::{CipherSuite, TrafficSecret},
};

/// The version 1 salt, per RFC 9001, section 5.2.
const INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// The two Initial traffic secrets of a connection.
#[derive(Debug)]
pub(crate) struct InitialSecrets {
    /// Protects what the client sends.
    pub(crate) client: TrafficSecret,
    /// Protects what the server sends.
    pub(crate) server: TrafficSecret,
}

impl InitialSecrets {
    /// The secrets for a client's first destination connection id.
    ///
    /// Initial packets always use AES-128-GCM with SHA-256.
    pub(crate) fn new(dcid: &ConnectionId) -> Self {
        let initial = Hkdf::extract(&INITIAL_SALT, dcid.as_bytes());
        let initial = TrafficSecret::new(CipherSuite::Aes128GcmSha256, *initial.prk());
        Self {
            client: initial.derive(b"client in"),
            server: initial.derive(b"server in"),
        }
    }

    /// The key pair one side uses.
    pub(crate) fn keys(&self, is_client: bool) -> KeyPair {
        let (local, remote) = if is_client {
            (&self.client, &self.server)
        } else {
            (&self.server, &self.client)
        };
        KeyPair {
            local: Keys::new(local),
            remote: Keys::new(remote),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::{
        packet::PacketNumber,
        testing::{RFC9001_CLIENT_CRYPTO_FRAME, RFC9001_CLIENT_INITIAL, hex},
    };

    /// The client's first destination connection id in RFC 9001, appendix A.
    fn dcid() -> ConnectionId {
        ConnectionId::new(&hex("8394c8f03e515708")).unwrap()
    }

    /// Seals a payload under a header and masks the header, as a sender does.
    fn protect(keys: &Keys, header: &str, payload: &[u8], pn: u64, pn_len: usize) -> Vec<u8> {
        let mut packet = hex(header);
        let pn_offset = packet.len() - pn_len;
        let header_len = packet.len();
        packet.extend_from_slice(payload);
        let (head, body) = packet.split_at_mut(header_len);
        let tag = keys.packet.seal(PacketNumber(pn), head, body);
        packet.extend_from_slice(&tag);
        keys.header.protect(&mut packet, pn_offset, pn_len).unwrap();
        packet
    }

    #[test]
    fn rfc_9001_appendix_a1_secrets() {
        let secrets = InitialSecrets::new(&dcid());
        assert_eq!(
            secrets.client.as_bytes().to_vec(),
            hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
        );
        assert_eq!(
            secrets.server.as_bytes().to_vec(),
            hex("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
        );

        // The key, IV and header key of each side.
        let expand = |secret: &TrafficSecret, label: &[u8], len: usize| {
            let mut out = vec![0; len];
            secret.expand_label(label, &[], &mut out);
            out
        };
        assert_eq!(
            expand(&secrets.client, b"quic key", 16),
            hex("1f369613dd76d5467730efcbe3b1a22d")
        );
        assert_eq!(
            expand(&secrets.client, b"quic iv", 12),
            hex("fa044b2f42a3fd3b46fb255c")
        );
        assert_eq!(
            expand(&secrets.client, b"quic hp", 16),
            hex("9f50449e04a0e810283a1e9933adedd2")
        );
        assert_eq!(
            expand(&secrets.server, b"quic key", 16),
            hex("cf3a5331653c364c88f0f379b6067e37")
        );
        assert_eq!(
            expand(&secrets.server, b"quic iv", 12),
            hex("0ac1493ca1905853b0bba03e")
        );
        assert_eq!(
            expand(&secrets.server, b"quic hp", 16),
            hex("c206b8d9b9f0f37644430b490eeaa314")
        );
    }

    #[test]
    fn rfc_9001_appendix_a2_client_initial() {
        // The CRYPTO frame carrying the ClientHello, padded with zeros to 1162 bytes.
        let mut payload = hex(RFC9001_CLIENT_CRYPTO_FRAME);
        payload.resize(1162, 0);

        // Packet number 2 on four bytes; the length field says 1182.
        let keys = InitialSecrets::new(&dcid()).keys(true);
        let packet = protect(
            &keys.local,
            "c300000001088394c8f03e5157080000449e00000002",
            &payload,
            2,
            4,
        );
        assert_eq!(packet, hex(RFC9001_CLIENT_INITIAL));

        // The server removes the protection with its remote keys.
        let server = InitialSecrets::new(&dcid()).keys(false);
        let mut received = packet;
        assert_eq!(
            server.remote.header.unprotect(&mut received, 18),
            Ok((4, 2))
        );
        let (header, rest) = received.split_at_mut(22);
        let (body, tag) = rest.split_at_mut(1162);
        let tag = (&*tag).try_into().unwrap();
        assert_eq!(
            server
                .remote
                .packet
                .open(PacketNumber(2), header, body, &tag),
            Ok(())
        );
        assert_eq!(body, payload.as_slice());
    }

    #[test]
    fn rfc_9001_appendix_a3_server_initial() {
        // An ACK frame and a CRYPTO frame carrying the ServerHello, without padding.
        let payload = hex(concat!(
            "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739",
            "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94",
            "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00",
            "020304",
        ));
        let keys = InitialSecrets::new(&dcid()).keys(false);
        let packet = protect(
            &keys.local,
            "c1000000010008f067a5502a4262b50040750001",
            &payload,
            1,
            2,
        );
        assert_eq!(
            packet,
            hex(concat!(
                "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a",
                "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3",
                "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84",
                "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4",
                "2158407dd074ee",
            ))
        );
    }

    #[test]
    fn keys_are_typed_per_direction() {
        // A client's local keys are the server's remote keys.
        let client = InitialSecrets::new(&dcid()).keys(true);
        let server = InitialSecrets::new(&dcid()).keys(false);
        let mut payload = *b"ping";
        let tag = client.local.packet.seal(PacketNumber(0), b"", &mut payload);
        assert_eq!(
            server
                .remote
                .packet
                .open(PacketNumber(0), b"", &mut payload, &tag),
            Ok(())
        );
    }
}
