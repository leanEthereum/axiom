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
    use crate::quic::{packet::PacketNumber, testing::hex};

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
        let mut payload = hex(CLIENT_CRYPTO_FRAME);
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
        assert_eq!(packet, hex(CLIENT_INITIAL_PACKET));

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

    /// The CRYPTO frame of RFC 9001, appendix A.2.
    const CLIENT_CRYPTO_FRAME: &str = concat!(
        "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868",
        "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578",
        "616d706c652e636f6dff01000100000a00080006001d00170018001000070005",
        "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba",
        "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400",
        "0d0010000e0403050306030203080408050806002d00020101001c0002400100",
        "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000",
        "75300901100f088394c8f03e51570806048000ffff",
    );

    /// The protected client Initial packet of RFC 9001, appendix A.2.
    const CLIENT_INITIAL_PACKET: &str = concat!(
        "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11",
        "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399",
        "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c",
        "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212",
        "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5",
        "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208",
        "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec",
        "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3",
        "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db",
        "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c",
        "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8",
        "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556",
        "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74",
        "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a",
        "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00",
        "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632",
        "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964",
        "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd",
        "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff",
        "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198",
        "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd",
        "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73",
        "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f",
        "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e",
        "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade",
        "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047",
        "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2",
        "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4",
        "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0",
        "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e",
        "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0",
        "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400",
        "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab",
        "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9",
        "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4",
        "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064",
        "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241",
        "e221af44860018ab0856972e194cd934",
    );
}
