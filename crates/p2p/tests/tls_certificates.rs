//! The certificate test vectors of the libp2p TLS spec, through the public verifier.
//!
//! The four certificates share one P-256 certificate key and the window 1975 to 4096.
//! They differ in the host key their extension carries.

use axiom_p2p::{
    KeyType,
    tls::{CertificateError, TlsError, VerifiedPeer},
};

/// An instant inside every vector's window: 2026-10-14, in Unix seconds.
const NOW: u64 = 1_792_000_000;

/// Decodes hex without a prefix.
fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digits"))
        .collect()
}

/// Vector 1: an Ed25519 host key.
const ED25519: &str = concat!(
    "308201ae30820156a0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a1309",
    "6c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936",
    "303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301",
    "313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132",
    "721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37",
    "e381569ea37c307a3078060a2b0601040183a25a0101046a3068042408011220a77f1d92fedb59dddaea5a1c",
    "4abd1ac2fbde7d7b879ed364501809923d7c11b90440d90d2769db992d5e6195dbb08e706b6651e024fda6cf",
    "b8846694a435519941cac215a8207792e42849cccc6cd8136c6e4bde92a58c5e08cfd4206eb5fe0bf909300a",
    "06082a8648ce3d0403020346003043021f50f6b6c52711a881778718238f650c9fb48943ae6ee6d28427dc60",
    "71ae55e702203625f116a7a454db9c56986c82a25682f7248ea1cb764d322ea983ed36a31b77",
);

/// Vector 2: an ECDSA P-256 host key.
const ECDSA: &str = concat!(
    "308201f63082019da0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a1309",
    "6c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936",
    "303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301",
    "313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132",
    "721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37",
    "e381569ea381c23081bf3081bc060a2b0601040183a25a01010481ad3081aa045f0803125b3059301306072a",
    "8648ce3d020106082a8648ce3d03010703420004bf30511f909414ebdd3242178fd290f093a551cf75c97315",
    "5de0bb5a96fedf6cb5d52da7563e794b512f66e60c7f55ba8a3acf3dd72a801980d205e8a1ad29f204473045",
    "0220064ea8124774caf8f50e57f436aa62350ce652418c019df5d98a3ac666c9386a022100aa59d704a931b5",
    "f72fb9222cb6cc51f954d04a4e2e5450f8805fe8918f71eaae300a06082a8648ce3d04030203470030440220",
    "799395b0b6c1e940a7e4484705f610ab51ed376f19ff9d7c16757cfbf61b8d4302206205c03fbb0f95205c77",
    "9be86581d3e31c01871ad5d1f3435bcf375cb0e5088a",
);

/// Vector 3: a secp256k1 host key, the kind Ethereum nodes use.
const SECP256K1: &str = concat!(
    "308201ba3082015fa0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a1309",
    "6c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936",
    "303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301",
    "313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132",
    "721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37",
    "e381569ea38184308181307f060a2b0601040183a25a01010471306f0425080212210206dc6968726765b820",
    "f050263ececf7f71e4955892776c0970542efd689d2382044630440220145e15a991961f0d08cd15425bb95e",
    "c93f6ffa03c5a385eedc34ecf464c7a8ab022026b3109b8a3f40ef833169777eb2aa337cfb6282f188de0666",
    "d1bcec2a4690dd300a06082a8648ce3d0403020349003046022100e1a217eeef9ec9204b3f774a08b7084964",
    "6b6a1e6b8b27f93dc00ed58545d9fe022100b00dafa549d0f03547878338c7b15e7502888f6d45db387e5ae6",
    "b5d46899cef0",
);

/// Vector 4: a host signature made by another key than the one the extension names.
const INVALID: &str = concat!(
    "308201f73082019da0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a1309",
    "6c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936",
    "303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301",
    "313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132",
    "721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37",
    "e381569ea381c23081bf3081bc060a2b0601040183a25a01010481ad3081aa045f0803125b3059301306072a",
    "8648ce3d020106082a8648ce3d03010703420004bf30511f909414ebdd3242178fd290f093a551cf75c97315",
    "5de0bb5a96fedf6cb5d52da7563e794b512f66e60c7f55ba8a3acf3dd72a801980d205e8a1ad29f204473045",
    "022100bb6e03577b7cc7a3cd1558df0da2b117dfdcc0399bc2504ebe7de6f65cade72802206de96e2a5be9b6",
    "202adba24ee0362e490641ac45c240db71fe955f2c5cf8df6e300a06082a8648ce3d04030203480030450221",
    "00e847f267f43717358f850355bdcabbefb2cfbf8a3c043b203a14788a092fe8db022027c1d04a2d41fd6b57",
    "a7e8b3989e470325de4406e52e084e34a3fd56eef0d0df",
);

#[test]
fn secp256k1_host_key_vector() {
    // Vector 3 authenticates the secp256k1 peer the spec names.
    let peer = VerifiedPeer::from_certificate(&hex(SECP256K1), NOW).unwrap();
    assert_eq!(
        peer.peer_id.to_string(),
        "16Uiu2HAkutTMoTzDw1tCvSRtu6YoixJwS46S1ZFxW8hSx9fWHiPs"
    );
    assert_eq!(peer.public_key.key_type, KeyType::Secp256k1);
}

#[test]
fn ecdsa_host_key_vector() {
    // Vector 2: a 95-byte protobuf key is hashed into a SHA-256 peer id, shown as "Qm...".
    let peer = VerifiedPeer::from_certificate(&hex(ECDSA), NOW).unwrap();
    assert_eq!(
        peer.peer_id.to_string(),
        "QmfXbAwNjJLXfesgztEHe8HwgVDCMMpZ9Eax1HYq6hn9uE"
    );
    assert_eq!(peer.public_key.key_type, KeyType::Ecdsa);
}

#[test]
fn ed25519_host_key_is_unsupported() {
    // Vector 1 is valid, but this node verifies no Ed25519 host signature.
    assert_eq!(
        VerifiedPeer::from_certificate(&hex(ED25519), NOW),
        Err(TlsError::Certificate(CertificateError::UnsupportedHostKey(
            KeyType::Ed25519
        )))
    );
}

#[test]
fn mismatched_host_signature_is_refused() {
    // Vector 4: the certificate itself is sound; its host signature is not.
    assert_eq!(
        VerifiedPeer::from_certificate(&hex(INVALID), NOW),
        Err(TlsError::Certificate(
            CertificateError::InvalidHostSignature
        ))
    );
}

#[test]
fn validity_window_is_enforced() {
    // 1975-01-01 13:00:00 is 157813200; one second earlier is too soon.
    assert_eq!(
        VerifiedPeer::from_certificate(&hex(SECP256K1), 157_813_199),
        Err(TlsError::Certificate(CertificateError::NotYetValid {
            not_before: 157_813_200,
            now: 157_813_199
        }))
    );
    // 4096-01-01 13:00:00 is the last valid second.
    assert!(VerifiedPeer::from_certificate(&hex(SECP256K1), 67_090_165_200).is_ok());
    assert_eq!(
        VerifiedPeer::from_certificate(&hex(SECP256K1), 67_090_165_201),
        Err(TlsError::Certificate(CertificateError::Expired {
            not_after: 67_090_165_200,
            now: 67_090_165_201
        }))
    );
}
