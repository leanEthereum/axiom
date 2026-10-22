//! The simple 1-RTT handshake of RFC 8448, section 3, through this stack's parsers and key schedule.
//!
//! The trace authenticates its server with RSA, which this stack does not verify.
//! It therefore pins the framing, the parsers, the transcript, every derived secret, and both Finished messages.
//! Record headers are stripped: QUIC carries handshake messages without them.

use axiom_crypto::x25519::SecretKey as KeyShareSecret;

use super::{
    CertificateError, CipherSuite, Level, TlsError, TrafficSecret, VerifiedPeer,
    buffer::HandshakeBuffer,
    extension::ExtensionType,
    key_schedule::{HandshakeSecret, Transcript},
    message::{
        CertificateMessage, CertificateVerify, ClientHello, EncryptedExtensions, Finished,
        HandshakeType, Message, NewSessionTicket, ServerHello,
    },
    session::Context,
};
use crate::testing::hex;

/// The client X25519 private key.
const CLIENT_PRIVATE: &str = "49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005";

/// The server X25519 private key.
const SERVER_PRIVATE: &str = "b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e";

/// The ClientHello, 196 bytes.
const CLIENT_HELLO: &str = concat!(
    "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113",
    "031302010000910000000b0009000006736572766572ff01000100000a00140012001d001700180019010001",
    "0101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae",
    "4d5413691e529aaf2c002b0003020304000d0020001e04030503060302030804080508060401050106010201",
    "0402050206020202002d00020101001c00024001",
);

/// The ServerHello, 90 bytes.
const SERVER_HELLO: &str = concat!(
    "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e",
    "00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b0002",
    "0304",
);

/// The EncryptedExtensions, 40 bytes.
const ENCRYPTED_EXTENSIONS: &str =
    "080000240022000a00140012001d00170018001901000101010201030104001c0002400100000000";

/// The server Certificate, 445 bytes, an RSA certificate.
const CERTIFICATE: &str = concat!(
    "0b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e",
    "310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335",
    "395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902",
    "818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a",
    "95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda43",
    "0846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f02",
    "03010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d0101",
    "0b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a5",
    "8c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a",
    "99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b4",
    "2b4de10000",
);

/// The server CertificateVerify, 136 bytes, an RSA-PSS signature.
const CERTIFICATE_VERIFY: &str = concat!(
    "0f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff52f1fda8477b0b7abc90",
    "db78e2d33a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac",
    "027671459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea20d53dfac",
    "d42f74f3",
);

/// The server Finished, 36 bytes.
const SERVER_FINISHED: &str =
    "140000209b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718";

/// The client Finished, 36 bytes.
const CLIENT_FINISHED: &str =
    "14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61";

/// The NewSessionTicket the server sends after the handshake, 205 bytes.
const NEW_SESSION_TICKET: &str = concat!(
    "040000c90000001efad6aac502000000b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb",
    "33fa90bf1b0070ad3c498883c9367c09a2be785abc55cd226097a3a982117283f82a03a143efd3ff5dd36d64",
    "e861be7fd61d2827db279cce145077d454a3664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529513e3da2",
    "677fa5906c5b3f7d8f92f228bda40dda721470f9fbf297b5aea617646fac5c03272e970727c621a79141ef5f",
    "7de6505e5bfbc388e93343694093934ae4d3570008002a000400000400",
);

/// Decodes a 32-byte hex string.
fn bytes32(text: &str) -> [u8; 32] {
    hex(text).try_into().unwrap()
}

/// Frames one hex message through the handshake buffer, as it would arrive at a level.
fn message(level: Level, text: &str) -> Message {
    let mut buffer = HandshakeBuffer::new(level);
    // Split in two, so the buffer joins pieces as it must for CRYPTO frames.
    let raw = hex(text);
    let (head, tail) = raw.split_at(raw.len() / 2);
    buffer.push(level, head).unwrap();
    assert_eq!(buffer.next_message(), Ok(None));
    buffer.push(level, tail).unwrap();
    buffer.next_message().unwrap().unwrap()
}

/// HKDF-Expand-Label of a secret with an empty context, as a vector of a given length.
fn expand(secret: &TrafficSecret, label: &[u8], length: usize) -> Vec<u8> {
    let mut out = vec![0; length];
    secret.expand_label(label, &[], &mut out);
    out
}

#[test]
#[expect(clippy::too_many_lines, reason = "one trace, read top to bottom")]
fn rfc_8448_simple_handshake() {
    let suite = CipherSuite::Aes128GcmSha256;
    let mut transcript = Transcript::new();

    // Phase 1: the ClientHello offers three suites and one X25519 share.
    let client_secret = KeyShareSecret::from_bytes(bytes32(CLIENT_PRIVATE));
    let client_hello = message(Level::Initial, CLIENT_HELLO);
    let hello = ClientHello::parse(client_hello.body()).unwrap();
    assert_eq!(hello.cipher_suites, [0x1301, 0x1303, 0x1302]);
    assert_eq!(
        hello.extensions.supported_versions(),
        Ok(Some(vec![0x0304]))
    );
    let client_public = client_secret.public_key().to_bytes();
    assert_eq!(
        client_public,
        bytes32("99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c")
    );
    assert_eq!(
        hello.extensions.client_key_shares(),
        Ok(Some(vec![(0x001d, &client_public[..])]))
    );
    // The trace client offers no ALPN, so a libp2p server would refuse it.
    assert_eq!(hello.extensions.alpn(), Ok(None));
    transcript.update(client_hello.raw());

    // Phase 2: the ServerHello picks AES-128-GCM and answers with its share.
    let server_secret = KeyShareSecret::from_bytes(bytes32(SERVER_PRIVATE));
    let server_hello = message(Level::Initial, SERVER_HELLO);
    let hello = ServerHello::parse(server_hello.body()).unwrap();
    assert_eq!(hello.cipher_suite, 0x1301);
    assert_eq!(hello.extensions.selected_version(), Ok(0x0304));
    let (group, share) = hello.extensions.server_key_share().unwrap();
    assert_eq!(share, server_secret.public_key().to_bytes());
    transcript.update(server_hello.raw());

    // Phase 3: both sides reach the same X25519 secret, then the handshake secrets.
    let shared = Context::agree(&client_secret, group, share).unwrap();
    assert_eq!(
        Context::agree(&server_secret, 0x001d, &client_public),
        Ok(shared)
    );
    assert_eq!(
        shared,
        bytes32("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d")
    );
    let handshake = HandshakeSecret::new(suite, &shared);
    assert_eq!(
        handshake.secret().as_bytes(),
        &bytes32("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
    );
    let hello_hash = transcript.hash();
    assert_eq!(
        hello_hash,
        bytes32("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8")
    );
    let traffic = handshake.traffic(&hello_hash);
    assert_eq!(
        traffic.client.as_bytes(),
        &bytes32("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
    );
    assert_eq!(
        traffic.server.as_bytes(),
        &bytes32("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
    );

    // The record-layer key and iv of both directions, through the same label expansion.
    assert_eq!(
        expand(&traffic.server, b"key", 16),
        hex("3fce516009c21727d0f2e4e86ee403bc")
    );
    assert_eq!(
        expand(&traffic.server, b"iv", 12),
        hex("5d313eb2671276ee13000b30")
    );
    assert_eq!(
        expand(&traffic.client, b"key", 16),
        hex("dbfaa693d1762c5b666af5d950258d01")
    );
    assert_eq!(
        expand(&traffic.client, b"iv", 12),
        hex("5bd3c71b836e0b76bb73265f")
    );

    // Phase 4: the server flight parses, though a libp2p client refuses its contents.
    let encrypted = message(Level::Handshake, ENCRYPTED_EXTENSIONS);
    let extensions = EncryptedExtensions::parse(encrypted.body())
        .unwrap()
        .extensions;
    // Groups are allowed; record_size_limit, type 0x1c, was never offered.
    assert_eq!(
        extensions.allow_only(&[
            ExtensionType::ALPN,
            ExtensionType::QUIC_TRANSPORT_PARAMETERS,
            ExtensionType::SUPPORTED_GROUPS,
        ]),
        Err(TlsError::UnsupportedExtension(0x1c))
    );
    transcript.update(encrypted.raw());

    let certificate = message(Level::Handshake, CERTIFICATE);
    let chain = CertificateMessage::parse(certificate.body()).unwrap();
    assert_eq!(chain.context, &[] as &[u8]);
    assert_eq!(chain.entries.len(), 1);
    // The RSA certificate is signed with sha256WithRSAEncryption, outside the libp2p profile.
    assert_eq!(
        VerifiedPeer::from_certificate(chain.entries[0].0, 1_500_000_000),
        Err(TlsError::Certificate(
            CertificateError::UnsupportedSignatureAlgorithm
        ))
    );
    transcript.update(certificate.raw());

    let verify = message(Level::Handshake, CERTIFICATE_VERIFY);
    let signature = CertificateVerify::parse(verify.body()).unwrap();
    // rsa_pss_rsae_sha256, 0x0804, with a 128-byte signature.
    assert_eq!((signature.scheme, signature.signature.len()), (0x0804, 128));
    transcript.update(verify.raw());

    // Phase 5: the server Finished, then the master and application secrets.
    let server_finished = message(Level::Handshake, SERVER_FINISHED);
    let finished = Finished::parse(server_finished.body()).unwrap();
    let expected = bytes32("9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718");
    assert_eq!(finished.verify_data, expected);
    assert_eq!(traffic.server.finished(&transcript.hash()), expected);
    assert!(
        traffic
            .server
            .verify_finished(&transcript.hash(), &expected)
    );
    transcript.update(server_finished.raw());

    let master = handshake.master();
    assert_eq!(
        master.secret().as_bytes(),
        &bytes32("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919")
    );
    let finished_hash = transcript.hash();
    assert_eq!(
        finished_hash,
        bytes32("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13")
    );
    let application = master.traffic(&finished_hash);
    assert_eq!(
        application.client.as_bytes(),
        &bytes32("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")
    );
    assert_eq!(
        application.server.as_bytes(),
        &bytes32("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")
    );
    let mut exporter = [0; 32];
    master
        .secret()
        .expand_label(b"exp master", &finished_hash, &mut exporter);
    assert_eq!(
        exporter,
        bytes32("fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50")
    );
    assert_eq!(
        expand(&application.server, b"key", 16),
        hex("9f02283b6c9c07efc26bb9f2ac92e356")
    );
    assert_eq!(
        expand(&application.server, b"iv", 12),
        hex("cf782b88dd83549aadf1e984")
    );
    assert_eq!(
        expand(&application.client, b"key", 16),
        hex("17422dda596ed5d9acd890e3c63f5051")
    );
    assert_eq!(
        expand(&application.client, b"iv", 12),
        hex("5b78923dee08579033e523d9")
    );

    // Phase 6: the client Finished, over the transcript through the server Finished.
    let client_finished = message(Level::Handshake, CLIENT_FINISHED);
    let finished = Finished::parse(client_finished.body()).unwrap();
    let expected = bytes32("a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61");
    assert_eq!(finished.verify_data, expected);
    assert_eq!(traffic.client.finished(&finished_hash), expected);
    transcript.update(client_finished.raw());

    // Mutation: one flipped bit of the verify data fails the check.
    let mut forged = expected;
    forged[31] ^= 1;
    assert!(!traffic.client.verify_finished(&finished_hash, &forged));

    // Phase 7: the resumption master secret covers the client Finished too.
    let full_hash = transcript.hash();
    assert_eq!(
        full_hash,
        bytes32("209145a96ee8e2a122ff810047cc952684658d6049e86429426db87c54ad143d")
    );
    let mut resumption = [0; 32];
    master
        .secret()
        .expand_label(b"res master", &full_hash, &mut resumption);
    assert_eq!(
        resumption,
        bytes32("7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c")
    );

    // Phase 8: the session ticket that follows is well formed, and this stack would drop it.
    let ticket = message(Level::Application, NEW_SESSION_TICKET);
    assert_eq!(ticket.kind(), HandshakeType::NEW_SESSION_TICKET);
    assert_eq!(NewSessionTicket::check(ticket.body()), Ok(()));
}
