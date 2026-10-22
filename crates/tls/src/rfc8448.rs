//! The simple 1-RTT handshake of RFC 8448, section 3, through this stack.
//!
//! The trace pins, in order:
//!
//! - the framing, the parsers, the transcript, and every derived secret;
//! - the server's RSA-PSS CertificateVerify, verified, then signed again byte for byte;
//! - every protected record of both directions, opened and sealed again byte for byte;
//! - the server state machine's ServerHello and handshake keys.
//!
//! The trace's server also sends groups and record_size_limit, which this server does not.
//! Its flight therefore differs from the trace after the ServerHello, as does a client's hello.

use std::{iter, sync::Arc};

use axiom_crypto::rsa::{RsaHash, RsaPrivateKey};

use crate::{
    CertificateError, CertifiedKey, CipherSuite, Connection, Handshake, HashAlgorithm, Level,
    NamedGroup, ProtocolError, Randomness, ServerConfig, SignatureScheme, SigningKey, TlsOutput,
    TrafficSecret, Verifier,
    buffer::HandshakeBuffer,
    extension::ExtensionType,
    group::KeyShareSecret,
    key_schedule::{HandshakeSecret, Transcript},
    message::{
        CertificateMessage, CertificateVerify, ClientHello, EncryptedExtensions, Finished,
        HandshakeType, Message, NewSessionTicket, ServerHello,
    },
    record::{ContentType, Protection},
    testing::hex,
    x509::{Certificate, PublicKey, SignatureAlgorithm, X509Error},
};

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

/// The client hello record, 201 bytes.
const CLIENT_HELLO_RECORD: &str = concat!(
    "16030100c4010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece700",
    "0006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d00170018",
    "00190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c0",
    "6e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e0403050306030203080408050806040105",
    "01060102010402050206020202002d00020101001c00024001",
);

/// The server hello record, 95 bytes.
const SERVER_HELLO_RECORD: &str = concat!(
    "160303005a020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800",
    "130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f",
    "0f002b00020304",
);

/// The server flight record, 679 bytes.
const SERVER_FLIGHT_RECORD: &str = concat!(
    "17030302a2d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35edf7869fcf40aa40aa2b8ea73",
    "f848a7ca07612ef9f945cb960b4068905123ea78b111b429ba9191cd05d2a389280f526134aadc7fc78c4b72",
    "9df828b5ecf7b13bd9aefb0e57f271585b8ea9bb355c7c79020716cfb9b1183ef3ab20e37d57a6b9d7477609",
    "aee6e122a4cf51427325250c7d0e509289444c9b3a648f1d71035d2ed65b0e3cdd0cbae8bf2d0b227812cbb3",
    "60987255cc744110c453baa4fcd610928d809810e4b7ed1a8fd991f06aa6248204797e36a6a73b70a2559c09",
    "ead686945ba246ab66e5edd8044b4c6de3fcf2a89441ac66272fd8fb330ef8190579b3684596c960bd596eea",
    "520a56a8d650f563aad27409960dca63d3e688611ea5e22f4415cf9538d51a200c27034272968a264ed6540c",
    "84838d89f72c24461aad6d26f59ecaba9acbbb317b66d902f4f292a36ac1b639c637ce343117b65962224531",
    "7b49eeda0c6258f100d7d961ffb138647e92ea330faeea6dfa31c7a84dc3bd7e1b7a6c7178af36879018e3f2",
    "52107f243d243dc7339d5684c8b0378bf30244da8c87c843f5e56eb4c5e8280a2b48052cf93b16499a66db7c",
    "ca71e4599426f7d461e66f99882bd89fc50800becca62d6c74116dbd2972fda1fa80f85df881edbe5a376689",
    "36b335583b599186dc5c6918a396fa48a181d6b6fa4f9d62d513afbb992f2b992f67f8afe67f76913fa388cb",
    "5630c8ca01e0c65d11c66a1e2ac4c85977b7c7a6999bbf10dc35ae69f5515614636c0b9b68c19ed2e31c0b3b",
    "66763038ebba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f60f0504de93b5b845e275592c12335ee",
    "340bbc4fddd502784016e4b3be7ef04dda49f4b440a30cb5d2af939828fd4ae3794e44f94df5a631ede42c17",
    "19bfdabf0253fe5175be898e750edc53370d2b",
);

/// The client finished record, 58 bytes.
const CLIENT_FINISHED_RECORD: &str = concat!(
    "170303003575ec4dc238cce60b298044a71e219c56cc77b0517fe9b93c7a4bfc44d87f38f80338ac98fc46de",
    "b384bd1caeacab6867d726c40546",
);

/// The ticket record, 227 bytes.
const TICKET_RECORD: &str = concat!(
    "17030300de3a6b8f90414a97d6959c3487680de5134a2b240e6cffac116e95d41d6af8f6b580dcf3d11d63c7",
    "58db289a015940252f55713e061dc13e078891a38efbcf5753ad8ef170ad3c7353d16d9da773b9ca7f2b9fa1",
    "b6c0d4a3d03f75e09c30ba1e62972ac46f75f7b981be63439b2999ce13064615139891d5e4c5b406f16e3fc1",
    "81a77ca475840025db2f0a77f81b5ab05b94c01346755f69232c86519d86cbeeac87aac347d143f9605d64f6",
    "50db4d023e70e952ca49fe5137121c74bc2697687e248746d6df353005f3bce18696129c8153556b3b6c6779",
    "b37bf15985684f",
);

/// The client data record, 72 bytes.
const CLIENT_DATA_RECORD: &str = concat!(
    "1703030043a23f7054b62c94d0affafe8228ba55cbefacea42f914aa66bcab3f2b9819a8a5b46b395bd54a9a",
    "20441e2b62974e1f5a6292a2977014bd1e3deae63aeebb21694915e4",
);

/// The server data record, 72 bytes.
const SERVER_DATA_RECORD: &str = concat!(
    "17030300432e937e11ef4ac740e538ad36005fc4a46932fc3225d05f82aa1b36e30efaf97d90e6dffc602dcb",
    "501a59a8fcc49c4bf2e5f0a21c0047c2abf332540dd032e167c2955d",
);

/// The client alert record, 24 bytes.
const CLIENT_ALERT_RECORD: &str = concat!("1703030013c9872760655666b74d7ff1153efd6db6d0b0e3",);

/// The server alert record, 24 bytes.
const SERVER_ALERT_RECORD: &str = concat!("1703030013b58fd67166ebf599d24720cfbe7efa7a8864a9",);

/// The plaintext of the client data record, 50 bytes.
const CLIENT_DATA_PAYLOAD: &str = concat!(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b",
    "2c2d2e2f3031",
);

/// The plaintext of the server data record, 50 bytes.
const SERVER_DATA_PAYLOAD: &str = concat!(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b",
    "2c2d2e2f3031",
);

/// The server key's modulus, from RFC 8448, section 2.
const RSA_MODULUS: &str = concat!(
    "b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137a",
    "ce6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda43084674",
    "8030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f",
);

/// The server key's public exponent, from RFC 8448, section 2.
const RSA_PUBLIC_EXPONENT: &str = concat!("010001",);

/// The server key's private exponent, from RFC 8448, section 2.
const RSA_PRIVATE_EXPONENT: &str = concat!(
    "04dea705d43a6ea7209dd8072111a83c81e322a59278b33480641eaf7c0a6985b8e31c44f6de62e1b4c2309f",
    "6126e77b7c41e923314bbfa3881305dc1217f16c819ce538e922f369828d0e57195d8c8488460207b2faa726",
    "bcf708bbd7db7f679f893492fc2a622e08970aac441ce4e0c3088df25ae679233df8a3bda2ff9941",
);

/// The server key's prime1, from RFC 8448, section 2.
const RSA_PRIME1: &str = concat!(
    "e435fb7cc83737756dacea96ab7f59a2cc1069db7deb190e17e33a532b273f30a327aa0aaabc58cd67466af9",
    "845fadc675fe094af92c4bd1f2c1bc33dd2e0515",
);

/// The server key's prime2, from RFC 8448, section 2.
const RSA_PRIME2: &str = concat!(
    "cabd3bc0e0438664c8d4cc9f99977a94d9bbfead8e43870abae3f7eb8b4e0eee8af1d9b4719ba6196cf2cbba",
    "eeebf8b3490afe9e9ffa74a88aa51fc645629303",
);

/// The server key's exponent1, from RFC 8448, section 2.
const RSA_EXPONENT1: &str = concat!(
    "3f57345c27fe1b687e6e761627b78b1b826433dd760fa0bea6a6acf39490aa1b47cda4869d68f584dd5b5029",
    "bd32093b8258661fe715025e5d70a45a08d3d319",
);

/// The server key's exponent2, from RFC 8448, section 2.
const RSA_EXPONENT2: &str = concat!(
    "183da01363bd2f2885cacbdc9964bf4764f1517636f86401286f71893c52ccfe40a6c23d0d086b47c6fb10d8",
    "fd1041e04def7e9a40ce957c417794e10412d139",
);

/// The server key's coefficient, from RFC 8448, section 2.
const RSA_COEFFICIENT: &str = concat!(
    "839ca9a085e4286b2c90e466997a2c681f21339aa3477814e4dec11833050ed50dd13cc038048a43c59b2acc",
    "416889c037665fe5afa605969f8c01dfa5ca969d",
);

/// The RSA-PSS salt of the server's CertificateVerify.
///
/// Recovered from the trace's signature by inverting EMSA-PSS, RFC 8017, section 9.1.2, steps 7 to 12.
const PSS_SALT: &str = "9e796c6cae552f4bbda874d33bb9f5a7b98172441b7954b463cee3f3b1818826";

/// The client application traffic secret, from section 3.
const CLIENT_APPLICATION: &str = "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5";

/// The server application traffic secret, from section 3.
const SERVER_APPLICATION: &str = "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643";

/// The client handshake traffic secret, from section 3.
const CLIENT_HANDSHAKE: &str = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21";

/// The server handshake traffic secret, from section 3.
const SERVER_HANDSHAKE: &str = "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38";

/// Decodes a 32-byte hex string.
fn bytes32(text: &str) -> [u8; 32] {
    hex(text).try_into().unwrap()
}

/// A traffic secret of the trace's suite.
fn secret(text: &str) -> TrafficSecret {
    TrafficSecret::new(CipherSuite::Aes128GcmSha256, bytes32(text))
}

/// Frames one hex message through the handshake buffer, as it would arrive at a level.
fn message(level: Level, text: &str) -> Message {
    let mut buffer = HandshakeBuffer::new(level);
    // Split in two, so the buffer joins pieces as it must for CRYPTO frames and records.
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

/// The server's RSA key, from section 2.
fn server_key() -> SigningKey {
    let key = RsaPrivateKey::from_components(
        &hex(RSA_MODULUS),
        &hex(RSA_PUBLIC_EXPONENT),
        &hex(RSA_PRIVATE_EXPONENT),
        &hex(RSA_PRIME1),
        &hex(RSA_PRIME2),
        &hex(RSA_EXPONENT1),
        &hex(RSA_EXPONENT2),
        &hex(RSA_COEFFICIENT),
    )
    .unwrap();
    SigningKey::Rsa(Box::new(key))
}

/// The server's certificate, the one entry of its Certificate message.
fn server_certificate() -> Vec<u8> {
    let raw = hex(CERTIFICATE);
    CertificateMessage::parse(&raw[4..]).unwrap().entries[0]
        .0
        .to_vec()
}

/// The trace server's randomness: its random and X25519 secret.
fn server_randomness() -> Randomness {
    let server_hello = hex(SERVER_HELLO);
    let mut randomness = Randomness::from_seed([0; 32]);
    randomness.random.copy_from_slice(&server_hello[6..38]);
    randomness.x25519 = bytes32(SERVER_PRIVATE);
    randomness
}

/// The trace server's configuration: its certificate, one suite, one group, no ALPN.
fn server_config() -> ServerConfig {
    let identity = CertifiedKey::new(vec![server_certificate()], server_key()).unwrap();
    ServerConfig {
        suites: vec![CipherSuite::Aes128GcmSha256],
        groups: vec![NamedGroup::X25519],
        alpn: Vec::new(),
        ..ServerConfig::https(Arc::new(identity))
    }
}

#[test]
#[expect(clippy::too_many_lines, reason = "one trace, read top to bottom")]
fn key_schedule_and_messages() {
    let suite = CipherSuite::Aes128GcmSha256;
    let mut transcript = Transcript::new();

    // Phase 1: the ClientHello offers three suites and one X25519 share.
    let client_secret = KeyShareSecret::new(NamedGroup::X25519, bytes32(CLIENT_PRIVATE)).unwrap();
    let client_hello = message(Level::Initial, CLIENT_HELLO);
    let hello = ClientHello::parse(client_hello.body()).unwrap();
    assert_eq!(hello.cipher_suites, [0x1301, 0x1303, 0x1302]);
    assert_eq!(
        hello.extensions.supported_versions(),
        Ok(Some(vec![0x0304]))
    );
    let client_public = client_secret.public();
    assert_eq!(
        client_public,
        hex("99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c")
    );
    assert_eq!(
        hello.extensions.client_key_shares(),
        Ok(Some(vec![(0x001d, &client_public[..])]))
    );
    transcript.update(client_hello.raw());

    // Phase 2: the ServerHello picks AES-128-GCM and answers with its share.
    let server_secret = KeyShareSecret::new(NamedGroup::X25519, bytes32(SERVER_PRIVATE)).unwrap();
    let server_hello = message(Level::Initial, SERVER_HELLO);
    let hello = ServerHello::parse(server_hello.body()).unwrap();
    assert_eq!(hello.cipher_suite, 0x1301);
    assert_eq!(hello.extensions.selected_version(), Ok(0x0304));
    let (group, share) = hello.extensions.server_key_share().unwrap();
    assert_eq!((group, share), (0x001d, &server_secret.public()[..]));
    transcript.update(server_hello.raw());

    // Phase 3: both sides reach the same X25519 secret, then the handshake secrets.
    let shared = client_secret.agree(share).unwrap();
    assert_eq!(server_secret.agree(&client_public), Ok(shared));
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
    assert_eq!(traffic.client, secret(CLIENT_HANDSHAKE));
    assert_eq!(traffic.server, secret(SERVER_HANDSHAKE));

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

    // Phase 4: the server flight parses, and its RSA-PSS signature verifies under its certificate.
    let encrypted = message(Level::Handshake, ENCRYPTED_EXTENSIONS);
    let extensions = EncryptedExtensions::parse(encrypted.body())
        .unwrap()
        .extensions;
    // Groups, record_size_limit 0x1c, and the empty server_name acknowledgment.
    assert_eq!(extensions.require_empty(ExtensionType::SERVER_NAME), Ok(()));
    assert_eq!(
        extensions.allow_only(&[ExtensionType::SERVER_NAME, ExtensionType::SUPPORTED_GROUPS]),
        Err(ProtocolError::UnsupportedExtension(0x1c))
    );
    transcript.update(encrypted.raw());

    let certificate = message(Level::Handshake, CERTIFICATE);
    let chain = CertificateMessage::parse(certificate.body()).unwrap();
    assert_eq!(chain.context, &[] as &[u8]);
    assert_eq!(chain.entries.len(), 1);
    let parsed = Certificate::parse(chain.entries[0].0).unwrap();
    let subject_key = parsed.public_key().unwrap();
    let PublicKey::Rsa(key) = &subject_key else {
        panic!("the trace server holds an RSA key");
    };
    // The trace key has 1024 bits, below what web PKI accepts, so the raw RSA check runs here.
    assert_eq!(key.bits(), 1024);
    assert_eq!(
        subject_key.verify(SignatureAlgorithm::RsaPssSha256, b"", &[0; 128]),
        Err(X509Error::RsaKeyTooSmall {
            bits: 1024,
            min: 2048
        })
    );
    transcript.update(certificate.raw());

    let verify = message(Level::Handshake, CERTIFICATE_VERIFY);
    let signature = CertificateVerify::parse(verify.body()).unwrap();
    assert_eq!(signature.scheme, SignatureScheme::RSA_PSS_RSAE_SHA256);
    let content =
        CertificateVerify::signed_content(CertificateVerify::SERVER_CONTEXT, &transcript.hash());
    let digest = HashAlgorithm::Sha256.digest(&content);
    assert_eq!(
        key.verify_pss(RsaHash::Sha256, &digest, signature.signature, 32),
        Ok(())
    );
    // The server path: signing the same content with the recovered salt gives the same bytes.
    let mut salt = [0; 64];
    salt[..32].copy_from_slice(&hex(PSS_SALT));
    assert_eq!(
        server_key().sign(SignatureScheme::RSA_PSS_RSAE_SHA256, &content, &salt),
        Ok(signature.signature.to_vec())
    );
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
    assert_eq!(application.client, secret(CLIENT_APPLICATION));
    assert_eq!(application.server, secret(SERVER_APPLICATION));
    let mut exporter = [0; 32];
    master
        .secret()
        .expand_label(b"exp master", &finished_hash, &mut exporter);
    assert_eq!(
        exporter,
        bytes32("fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50")
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

    // Phase 8: the session ticket that follows is well formed, and this stack drops it.
    let ticket = message(Level::Application, NEW_SESSION_TICKET);
    assert_eq!(ticket.kind(), HandshakeType::NEW_SESSION_TICKET);
    assert_eq!(NewSessionTicket::check(ticket.body()), Ok(()));
}

#[test]
fn records_reproduce_the_trace() {
    let server_flight = [
        ENCRYPTED_EXTENSIONS,
        CERTIFICATE,
        CERTIFICATE_VERIFY,
        SERVER_FINISHED,
    ]
    .map(hex)
    .concat();
    // Each tuple: the record, its traffic secret, its sequence number, its content type, its content.
    // The alerts are close_notify, a warning: 01 00.
    let cases: [(&str, &str, u64, ContentType, Vec<u8>); 7] = [
        (
            SERVER_FLIGHT_RECORD,
            SERVER_HANDSHAKE,
            0,
            ContentType::HANDSHAKE,
            server_flight,
        ),
        (
            CLIENT_FINISHED_RECORD,
            CLIENT_HANDSHAKE,
            0,
            ContentType::HANDSHAKE,
            hex(CLIENT_FINISHED),
        ),
        (
            TICKET_RECORD,
            SERVER_APPLICATION,
            0,
            ContentType::HANDSHAKE,
            hex(NEW_SESSION_TICKET),
        ),
        (
            CLIENT_DATA_RECORD,
            CLIENT_APPLICATION,
            0,
            ContentType::APPLICATION_DATA,
            hex(CLIENT_DATA_PAYLOAD),
        ),
        (
            SERVER_DATA_RECORD,
            SERVER_APPLICATION,
            1,
            ContentType::APPLICATION_DATA,
            hex(SERVER_DATA_PAYLOAD),
        ),
        (
            CLIENT_ALERT_RECORD,
            CLIENT_APPLICATION,
            1,
            ContentType::ALERT,
            vec![1, 0],
        ),
        (
            SERVER_ALERT_RECORD,
            SERVER_APPLICATION,
            2,
            ContentType::ALERT,
            vec![1, 0],
        ),
    ];
    for (record, traffic, sequence, kind, content) in cases {
        let record = hex(record);
        let header: [u8; 5] = record[..5].try_into().unwrap();

        // A key whose counter sits at the record's position.
        let at_position = || {
            let mut protection = Protection::tls13(&secret(traffic));
            for _ in 0..sequence {
                protection.seal(ContentType::APPLICATION_DATA, &[]).unwrap();
            }
            protection
        };

        // Opening: the receiver's view.
        let mut body = record[5..].to_vec();
        assert_eq!(at_position().open(&header, &mut body), Ok(kind));
        assert_eq!(body, content);

        // Sealing: the sender's view gives the trace record byte for byte.
        assert_eq!(at_position().seal(kind, &content), Ok(record.clone()));

        // Mutation: one flipped bit of the tag fails authentication.
        let mut body = record[5..].to_vec();
        let last = body.len() - 1;
        body[last] ^= 1;
        assert_eq!(
            at_position().open(&header, &mut body),
            Err(ProtocolError::BadRecordMac)
        );
    }
}

#[test]
fn server_reproduces_the_server_hello() {
    // Fixture state: the trace server's certificate and key, random, and X25519 secret.
    let mut connection: Connection<NoClientAuth> =
        Connection::server(server_config(), None, server_randomness(), 1_500_000_000);
    connection.read_tls(&hex(CLIENT_HELLO_RECORD)).unwrap();

    // The first record out is the trace's ServerHello record, byte for byte.
    let out = connection.take_tls();
    let expected = hex(SERVER_HELLO_RECORD);
    assert_eq!(out[..expected.len()], expected);

    // The handshake keys are the trace's.
    let mut handshake =
        Handshake::<NoClientAuth>::server(server_config(), None, server_randomness(), 0);
    handshake
        .read_handshake(Level::Initial, &hex(CLIENT_HELLO))
        .unwrap();
    let keys: Vec<_> = iter::from_fn(|| handshake.poll_output())
        .filter_map(|output| match output {
            TlsOutput::Keys { level, secrets } => Some((level, secrets)),
            _ => None,
        })
        .collect();
    assert_eq!(keys[0].0, Level::Handshake);
    assert_eq!(keys[0].1.local, secret(SERVER_HANDSHAKE));
    assert_eq!(keys[0].1.remote, secret(CLIENT_HANDSHAKE));
    assert_eq!(keys[1].0, Level::Application);
}

/// A verifier for servers that ask for no client certificate; it is never called.
#[derive(Clone, Debug)]
struct NoClientAuth;

impl Verifier for NoClientAuth {
    type Peer = ();
    type Error = CertificateError;

    fn verify(&self, _: &[&[u8]], _: u64) -> Result<((), PublicKey), CertificateError> {
        Err(CertificateError::EmptyChain)
    }
}
