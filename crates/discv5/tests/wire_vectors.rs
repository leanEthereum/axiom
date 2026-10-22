//! The discv5 wire test vectors, byte for byte.
//!
//! Source: `ethereum/devp2p`, branch `master`, file `discv5/discv5-wire-test-vectors.md`.

use axiom_crypto::{
    aes::Aes128Gcm,
    secp256k1::{PublicKey, SecretKey},
};
use axiom_discv5::{
    Enr, NodeId,
    message::{Message, RequestId},
    packet::{AuthData, Header, IdNonce, MaskingIv, Nonce, Packet},
    session::{ChallengeData, IdSignature, Session, SessionKeys},
};

/// Decodes a hex string, ignoring whitespace and an optional 0x prefix.
fn hex(text: &str) -> Vec<u8> {
    let digits: String = text
        .trim_start_matches("0x")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).expect("hex digit"))
        .collect()
}

/// Decodes a hex string of exactly N bytes.
fn hex_array<const N: usize>(text: &str) -> [u8; N] {
    hex(text).try_into().expect("length")
}

const NODE_A_KEY: &str = "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f";
const NODE_B_KEY: &str = "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628";
const NODE_A_ID: &str = "aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb";
const NODE_B_ID: &str = "bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9";
const EPHEMERAL_KEY: &str = "0288ef00023598499cb6c940146d050d2b1fb914198c327f76aad590bead68b6";
const EPHEMERAL_PUBKEY: &str = "039a003ba6517b473fa0cd74aefe99dadfdb34627f90fec6362df85803908f53a5";
const ID_NONCE: &str = "0102030405060708090a0b0c0d0e0f10";
const REQUEST_NONCE: &str = "0102030405060708090a0b0c";

/// Challenge data of a WHOAREYOU with the given record sequence number.
fn challenge(enr_seq: u8) -> ChallengeData {
    let mut data = hex(
        "000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000",
    );
    *data.last_mut().expect("nonempty") = enr_seq;
    ChallengeData(data)
}

fn node_a() -> SecretKey {
    SecretKey::from_bytes(&hex_array(NODE_A_KEY)).expect("valid key")
}

fn node_b() -> SecretKey {
    SecretKey::from_bytes(&hex_array(NODE_B_KEY)).expect("valid key")
}

fn ping(enr_seq: u64) -> Message {
    Message::Ping {
        request_id: RequestId::new(&[0, 0, 0, 1]).expect("4 bytes fit"),
        enr_seq,
    }
}

#[test]
fn vector_node_ids_derive_from_the_keys() {
    // The vectors' ids are keccak256 of the keys' uncompressed points.
    assert_eq!(
        NodeId::from_public_key(&node_a().public_key()).to_string(),
        NODE_A_ID
    );
    assert_eq!(
        NodeId::from_public_key(&node_b().public_key()).to_string(),
        NODE_B_ID
    );
}

#[test]
fn ping_message_packet() {
    let expected = hex(
        "00000000000000000000000000000000088b3d4342774649325f313964a39e55
         ea96c005ad52be8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d3
         4c4f53245d08dab84102ed931f66d1492acb308fa1c6715b9d139b81acbdcc",
    );
    let node_b_id = NodeId(hex_array(NODE_B_ID));
    // Fixture state: zero masking IV, all-ones nonce, read key zero.
    let session = Session::new(&[0; 16], &[0; 16]);
    let packet = session.seal(
        MaskingIv([0; 16]),
        Nonce([0xff; 12]),
        AuthData::Message {
            src_id: NodeId(hex_array(NODE_A_ID)),
        },
        &ping(2),
        &node_b_id,
    );
    assert_eq!(packet, expected);
    // Node B unmasks with its id and opens with the read key.
    let decoded = Packet::decode(&node_b_id, &expected).unwrap();
    assert_eq!(
        decoded.header.auth,
        AuthData::Message {
            src_id: NodeId(hex_array(NODE_A_ID))
        }
    );
    assert_eq!(session.open(&decoded), Ok(ping(2)));
}

#[test]
fn whoareyou_packet() {
    let expected = hex(
        "00000000000000000000000000000000088b3d434277464933a1ccc59f5967ad
         1d6035f15e528627dde75cd68292f9e6c27d6b66c8100a873fcbaed4e16b8d",
    );
    let node_b_id = NodeId(hex_array(NODE_B_ID));
    let packet = Packet {
        masking_iv: MaskingIv([0; 16]),
        header: Header {
            nonce: Nonce(hex_array(REQUEST_NONCE)),
            auth: AuthData::WhoAreYou {
                id_nonce: IdNonce(hex_array(ID_NONCE)),
                enr_seq: 0,
            },
        },
        message: Vec::new(),
    };
    assert_eq!(packet.encode(&node_b_id), expected);
    // The unmasked packet is the challenge data the handshake signs over.
    let decoded = Packet::decode(&node_b_id, &expected).unwrap();
    assert_eq!(decoded, packet);
    assert_eq!(ChallengeData(decoded.message_ad()), challenge(0));
}

#[test]
fn ping_handshake_packet() {
    let expected = hex(
        "00000000000000000000000000000000088b3d4342774649305f313964a39e55
         ea96c005ad521d8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d3
         4c4f53245d08da4bb252012b2cba3f4f374a90a75cff91f142fa9be3e0a5f3ef
         268ccb9065aeecfd67a999e7fdc137e062b2ec4a0eb92947f0d9a74bfbf44dfb
         a776b21301f8b65efd5796706adff216ab862a9186875f9494150c4ae06fa4d1
         f0396c93f215fa4ef524f1eadf5f0f4126b79336671cbcf7a885b1f8bd2a5d83
         9cf8",
    );
    handshake_case(&expected, 1, None, "4f9fac6de7567d1e3b1241dffe90f662");
}

#[test]
fn ping_handshake_packet_with_record() {
    let expected = hex(
        "00000000000000000000000000000000088b3d4342774649305f313964a39e55
         ea96c005ad539c8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d3
         4c4f53245d08da4bb23698868350aaad22e3ab8dd034f548a1c43cd246be9856
         2fafa0a1fa86d8e7a3b95ae78cc2b988ded6a5b59eb83ad58097252188b902b2
         1481e30e5e285f19735796706adff216ab862a9186875f9494150c4ae06fa4d1
         f0396c93f215fa4ef524e0ed04c3c21e39b1868e1ca8105e585ec17315e755e6
         cfc4dd6cb7fd8e1a1f55e49b4b5eb024221482105346f3c82b15fdaae36a3bb1
         2a494683b4a3c7f2ae41306252fed84785e2bbff3b022812d0882f06978df84a
         80d443972213342d04b9048fc3b1d5fcb1df0f822152eced6da4d3f6df27e70e
         4539717307a0208cd208d65093ccab5aa596a34d7511401987662d8cf62b1394
         71",
    );
    // The record rides in the authdata; take it from the packet, then rebuild byte for byte.
    let node_b_id = NodeId(hex_array(NODE_B_ID));
    let decoded = Packet::decode(&node_b_id, &expected).unwrap();
    let AuthData::Handshake {
        record: Some(record),
        ..
    } = decoded.header.auth
    else {
        panic!("a handshake with a record");
    };
    // The record is node A's own, sequence 1, signed by its key.
    assert_eq!(record.node_id(), NodeId(hex_array(NODE_A_ID)));
    assert_eq!(record.seq(), 1);
    handshake_case(
        &expected,
        0,
        Some(record),
        "53b1c075f41876423154e157470c2f48",
    );
}

/// Rebuilds a handshake vector from its inputs, then checks node B's side.
fn handshake_case(expected: &[u8], challenge_seq: u8, record: Option<Box<Enr>>, read_key: &str) {
    let node_a_id = NodeId(hex_array(NODE_A_ID));
    let node_b_id = NodeId(hex_array(NODE_B_ID));
    let challenge = challenge(challenge_seq);
    let ephemeral = SecretKey::from_bytes(&hex_array(EPHEMERAL_KEY)).expect("valid key");
    let ephemeral_public = ephemeral.public_key();
    assert_eq!(
        ephemeral_public.to_compressed().to_vec(),
        hex(EPHEMERAL_PUBKEY)
    );

    // Phase 1: node A derives keys and proves its identity.
    let keys = SessionKeys::initiate(
        &ephemeral,
        &node_b().public_key(),
        &challenge,
        &node_a_id,
        &node_b_id,
    );
    assert_eq!(keys.initiator_key.to_vec(), hex(read_key));
    let id_signature = IdSignature::sign(&node_a(), &challenge, &ephemeral_public, &node_b_id);

    // Phase 2: node A seals PING under the new initiator key.
    let auth = AuthData::Handshake {
        src_id: node_a_id,
        id_signature: id_signature.0,
        ephemeral_key: ephemeral_public,
        record,
    };
    let packet = Session::initiator(&keys).seal(
        MaskingIv([0; 16]),
        Nonce([0xff; 12]),
        auth.clone(),
        &ping(1),
        &node_b_id,
    );
    assert_eq!(packet, expected);

    // Phase 3: node B checks the proof, derives the same keys, and opens the message.
    let decoded = Packet::decode(&node_b_id, expected).expect("vector decodes");
    assert_eq!(decoded.header.auth, auth);
    assert!(id_signature.verify(
        &node_a().public_key(),
        &challenge,
        &ephemeral_public,
        &node_b_id
    ));
    let accepted = SessionKeys::accept(
        &node_b(),
        &ephemeral_public,
        &challenge,
        &node_a_id,
        &node_b_id,
    );
    assert_eq!(accepted, keys);
    assert_eq!(Session::recipient(&accepted).open(&decoded), Ok(ping(1)));
}

#[test]
fn ecdh() {
    // The shared secret is the compressed point: parity byte, then x.
    let public = PublicKey::from_compressed(&hex_array(
        "039961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231",
    ))
    .unwrap();
    let secret = SecretKey::from_bytes(&hex_array(
        "fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736",
    ))
    .unwrap();
    assert_eq!(
        secret.diffie_hellman(&public).to_compressed().to_vec(),
        hex("033b11a2a1f214567e1537ce5e509ffd9b21373247f2a3ff6841f4976f53165e7e")
    );
}

#[test]
fn key_derivation() {
    // The full handshake derivation from ephemeral key and destination key.
    let ephemeral = SecretKey::from_bytes(&hex_array(
        "fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736",
    ))
    .unwrap();
    let dest = PublicKey::from_compressed(&hex_array(
        "0317931e6e0840220642f230037d285d122bc59063221ef3226b1f403ddc69ca91",
    ))
    .unwrap();
    let keys = SessionKeys::initiate(
        &ephemeral,
        &dest,
        &challenge(0),
        &NodeId(hex_array(NODE_A_ID)),
        &NodeId(hex_array(NODE_B_ID)),
    );
    assert_eq!(
        keys.initiator_key.to_vec(),
        hex("dccc82d81bd610f4f76d3ebe97a40571")
    );
    assert_eq!(
        keys.recipient_key.to_vec(),
        hex("ac74bb8773749920b0d3a8881c173ec5")
    );
}

#[test]
fn id_nonce_signing() {
    // RFC 6979 nonces make the signature reproducible.
    let key = SecretKey::from_bytes(&hex_array(
        "fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736",
    ))
    .unwrap();
    let ephemeral = PublicKey::from_compressed(&hex_array(
        "039961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231",
    ))
    .unwrap();
    let node_b_id = NodeId(hex_array(NODE_B_ID));
    let signature = IdSignature::sign(&key, &challenge(0), &ephemeral, &node_b_id);
    assert_eq!(
        signature.0.to_vec(),
        hex(
            "94852a1e2318c4e5e9d422c98eaf19d1d90d876b29cd06ca7cb7546d0fff7b484fe86c09a064fe72bdbef73ba8e9c34df0cd2b53e9d65528c2c7f336d5dfc6e6"
        )
    );
    // The vector also runs in reverse: the signature verifies.
    assert!(signature.verify(&key.public_key(), &challenge(0), &ephemeral, &node_b_id));
    // A different challenger id breaks it.
    assert!(!signature.verify(
        &key.public_key(),
        &challenge(0),
        &ephemeral,
        &NodeId([0; 32])
    ));
}

#[test]
fn aes_gcm_encryption() {
    // The 16-byte tag follows the ciphertext.
    let cipher = Aes128Gcm::new(&hex_array("9f2d77db7004bf8a1a85107ac686990b"));
    let nonce = hex_array("27b5af763c446acd2749fe8e");
    let ad = hex("93a7400fa0d6a694ebc24d5cf570f65d04215b6ac00757875e3f3a5f42107903");
    let sealed = cipher.seal(&nonce, &ad, &hex("01c20101"));
    assert_eq!(sealed, hex("a5d12a2d94b8ccb3ba55558229867dc13bfa3648"));
    assert_eq!(cipher.open(&nonce, &ad, &sealed), Ok(hex("01c20101")));
}
