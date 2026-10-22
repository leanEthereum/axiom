//! The cacophony test vector for `Noise_XX_25519_ChaChaPoly_SHA256`.
//!
//! Source: `haskell-cryptography/cacophony`, file `vectors/cacophony.txt` on the master branch.
//! The file fetched had SHA-256 3bde7c09a6f349ee11c825c50fcc02649f8f02a47c857a459206b357f9386cae.
//! Messages alternate initiator, responder; the first three are the handshake.

use axiom_crypto::x25519::SecretKey;

use super::xx::XxState;
use crate::{secure::Role, testing::hex};

/// The prologue both sides use: "John Galt".
const PROLOGUE: &str = "4a6f686e2047616c74";

/// Initiator static secret.
const INIT_STATIC: &str = "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1";

/// Initiator ephemeral secret.
const INIT_EPHEMERAL: &str = "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a";

/// Responder static secret.
const RESP_STATIC: &str = "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893";

/// Responder ephemeral secret.
const RESP_EPHEMERAL: &str = "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b";

/// The transcript hash both sides end with.
const HANDSHAKE_HASH: &str = "c8e5f64e846193be2a834104c2a009868d6c9f3bd3c186299888b488b2f1f58e";

/// Payload and expected ciphertext of each message, in order.
const MESSAGES: [(&str, &str); 6] = [
    (
        "4c756477696720766f6e204d69736573",
        "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573",
    ),
    (
        "4d757272617920526f746862617264",
        concat!(
            "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f14480884381cbad1f276e038c48378ffce2b65285",
            "e08d6b68aaa3629a5a8639392490e5b9bd5269c2f1e4f488ed8831161f19b7815528f8982ffe09be9b5c412f8a0db50f",
            "8814c7194e83f23dbd8d162c9326ad"
        ),
    ),
    (
        "462e20412e20486179656b",
        concat!(
            "c7195ffacac1307ff99046f219750fc47693e23c3cb08b89c2af808b444850a80ae475b9df0f169ae80a89be0865b57f",
            "58c9fea0d4ec82a286427402f113e4b6ae769a1d95941d49b25030"
        ),
    ),
    (
        "4361726c204d656e676572",
        "96763ed773f8e47bb3712f0e29b3060ffc956ffc146cee53d5e1df",
    ),
    (
        "4a65616e2d426170746973746520536179",
        "3e40f15f6f3a46ae446b253bf8b1d9ffb6ed9b174d272328ff91a7e2e5c79c07f5",
    ),
    (
        "457567656e2042f6686d20766f6e2042617765726b",
        "eb3f3515110702e047a6c9da4478b6ead94873c11c0f2d710ddb3f09fce024b3a58502ae3f",
    ),
];

/// An X25519 secret from hex.
fn secret(text: &str) -> SecretKey {
    SecretKey::from_bytes(hex(text).try_into().unwrap())
}

#[test]
fn cacophony_xx_25519_chachapoly_sha256() {
    let prologue = hex(PROLOGUE);
    let mut initiator = XxState::new(Role::Initiator, &prologue, secret(INIT_STATIC));
    let mut responder = XxState::new(Role::Responder, &prologue, secret(RESP_STATIC));
    let payload = |index: usize| hex(MESSAGES[index].0);
    let expected = |index: usize| hex(MESSAGES[index].1);

    // Message 1: e (32) and the 16-byte payload in the clear, 48 bytes.
    let mut message = Vec::new();
    initiator
        .write_message1(secret(INIT_EPHEMERAL), &payload(0), &mut message)
        .unwrap();
    assert_eq!(message, expected(0));
    assert_eq!(responder.read_message1(&message).unwrap(), payload(0));

    // Message 2: e (32), sealed s (48), sealed 15-byte payload (31): 111 bytes.
    let mut message = Vec::new();
    responder
        .write_message2(secret(RESP_EPHEMERAL), &payload(1), &mut message)
        .unwrap();
    assert_eq!(message.len(), 111);
    assert_eq!(message, expected(1));
    assert_eq!(initiator.read_message2(&message).unwrap(), payload(1));

    // Message 3: sealed s (48), sealed 11-byte payload (27): 75 bytes.
    let mut message = Vec::new();
    initiator.write_message3(&payload(2), &mut message).unwrap();
    assert_eq!(message, expected(2));
    assert_eq!(responder.read_message3(&message).unwrap(), payload(2));

    // Both transcripts end on the published hash.
    assert_eq!(initiator.handshake_hash().to_vec(), hex(HANDSHAKE_HASH));
    assert_eq!(responder.handshake_hash().to_vec(), hex(HANDSHAKE_HASH));

    // Each side learned the other's static key.
    assert_eq!(
        initiator.remote_static(),
        Some(&secret(RESP_STATIC).public_key())
    );
    assert_eq!(
        responder.remote_static(),
        Some(&secret(INIT_STATIC).public_key())
    );

    // Transport: messages 4 and 6 go responder to initiator, message 5 the other way.
    let (mut initiator_send, mut initiator_receive) = initiator.split();
    let (mut responder_send, mut responder_receive) = responder.split();
    for index in 3..6 {
        let (sender, receiver) = if index % 2 == 1 {
            (&mut responder_send, &mut initiator_receive)
        } else {
            (&mut initiator_send, &mut responder_receive)
        };
        let mut ciphertext = Vec::new();
        sender
            .encrypt(&[], &payload(index), &mut ciphertext)
            .unwrap();
        assert_eq!(ciphertext, expected(index));
        let mut plaintext = Vec::new();
        receiver.decrypt(&[], &ciphertext, &mut plaintext).unwrap();
        assert_eq!(plaintext, payload(index));
    }
}
