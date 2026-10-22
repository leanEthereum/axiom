//! The XX handshake state machine.

use std::{fmt, mem, sync::Arc};

use super::{
    DH_LEN, DhKeypair, MAX_MESSAGE_LEN, NoiseCrypto, NoiseHandshakePayload, NoiseIdentity,
    STATIC_KEY_DOMAIN,
    symmetric::SymmetricState,
    transport::{NoiseOpener, NoiseSealer},
};
use crate::{
    identity::{PeerId, PublicKey},
    protobuf::ProtoMessage,
    secure::{Handshake, Open, Role, SecureError, SecureSession},
};

/// Bytes of the length prefix on every handshake message.
const PREFIX_LEN: usize = 2;

/// Where the handshake stands, from this side's point of view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    /// Initiator: message 1 sent, waiting for message 2.
    AwaitMessage2,
    /// Responder: waiting for message 1.
    AwaitMessage1,
    /// Responder: message 2 sent, waiting for message 3.
    AwaitMessage3,
    /// The session was handed out.
    Done,
}

/// One run of the XX pattern.
pub struct NoiseHandshake {
    /// The side this node plays.
    role: Role,
    /// The current step.
    step: Step,
    /// DH and AEAD primitives.
    crypto: Arc<dyn NoiseCrypto>,
    /// Signature verification for the remote identity.
    identity: Arc<dyn NoiseIdentity>,
    /// Transcript hash, chaining key, and handshake cipher.
    symmetric: SymmetricState,
    /// The static key pair.
    static_keypair: DhKeypair,
    /// The ephemeral key pair, generated when this side sends its e token.
    ephemeral: Option<DhKeypair>,
    /// The remote ephemeral public key.
    remote_ephemeral: [u8; DH_LEN],
    /// This side's identity proof.
    payload: NoiseHandshakePayload,
    /// The peer the dialer meant to reach.
    expected: Option<PeerId>,
    /// The identity the remote payload proved.
    remote: Option<(PeerId, PublicKey)>,
    /// Bytes waiting to be written.
    outbound: Vec<u8>,
    /// Bytes received but not yet parsed.
    inbound: Vec<u8>,
}

impl fmt::Debug for NoiseHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoiseHandshake")
            .field("role", &self.role)
            .field("step", &self.step)
            .finish_non_exhaustive()
    }
}

impl NoiseHandshake {
    /// Starts a handshake; the initiator's message 1 is queued at once.
    pub fn new(
        role: Role,
        crypto: Arc<dyn NoiseCrypto>,
        identity: Arc<dyn NoiseIdentity>,
        static_keypair: DhKeypair,
        payload: NoiseHandshakePayload,
        expected: Option<PeerId>,
    ) -> Self {
        let mut handshake = Self {
            role,
            step: Step::AwaitMessage1,
            crypto,
            identity,
            symmetric: SymmetricState::new(),
            static_keypair,
            ephemeral: None,
            remote_ephemeral: [0; DH_LEN],
            payload,
            expected,
            remote: None,
            outbound: Vec::new(),
            inbound: Vec::new(),
        };
        if role == Role::Initiator {
            handshake.write_message1();
            handshake.step = Step::AwaitMessage2;
        }
        handshake
    }

    /// Message 1, tokens "e": the ephemeral key in the clear, and an empty payload.
    fn write_message1(&mut self) {
        let ephemeral = self.crypto.generate_keypair();
        let mut message = Vec::with_capacity(DH_LEN);
        // e: send the ephemeral public key and fold it into the transcript.
        message.extend_from_slice(&ephemeral.public);
        self.symmetric.mix_hash(&ephemeral.public);
        // No key yet, so the empty payload is hashed in the clear.
        self.symmetric.mix_hash(&[]);
        self.ephemeral = Some(ephemeral);
        self.frame(&message);
    }

    /// Reads message 1 as responder.
    fn read_message1(&mut self, message: &[u8]) -> Result<(), SecureError> {
        // e: the initiator's ephemeral key.
        let (remote_ephemeral, payload) = split_key(message)?;
        self.remote_ephemeral = remote_ephemeral;
        self.symmetric.mix_hash(&remote_ephemeral);
        // The payload is plaintext and, for libp2p, empty; it still enters the transcript.
        self.symmetric
            .decrypt_and_hash(self.crypto.as_ref(), payload)?;
        Ok(())
    }

    /// Message 2, tokens "e, ee, s, es", then the encrypted payload.
    fn write_message2(&mut self) -> Result<(), SecureError> {
        let crypto = Arc::clone(&self.crypto);
        let ephemeral = crypto.generate_keypair();
        let mut message = Vec::new();
        // e: the responder's ephemeral key, in the clear.
        message.extend_from_slice(&ephemeral.public);
        self.symmetric.mix_hash(&ephemeral.public);
        // ee: both ephemerals; from here on every field is encrypted.
        let shared = crypto.dh(&ephemeral.secret, &self.remote_ephemeral)?;
        self.symmetric.mix_key(&shared);
        // s: the responder's static key, encrypted: 32 + 16 tag bytes.
        self.symmetric.encrypt_and_hash(
            crypto.as_ref(),
            &self.static_keypair.public,
            &mut message,
        )?;
        // es: initiator ephemeral with responder static.
        let shared = crypto.dh(&self.static_keypair.secret, &self.remote_ephemeral)?;
        self.symmetric.mix_key(&shared);
        // The identity proof.
        self.symmetric
            .encrypt_and_hash(crypto.as_ref(), &self.payload.encode(), &mut message)?;
        self.ephemeral = Some(ephemeral);
        self.frame(&message);
        Ok(())
    }

    /// Reads message 2 as initiator.
    fn read_message2(&mut self, message: &[u8]) -> Result<(), SecureError> {
        let crypto = Arc::clone(&self.crypto);
        let ephemeral = self.ephemeral.clone().ok_or(SecureError::InvalidKey)?;
        // e: the responder's ephemeral key.
        let (remote_ephemeral, rest) = split_key(message)?;
        self.remote_ephemeral = remote_ephemeral;
        self.symmetric.mix_hash(&remote_ephemeral);
        // ee.
        let shared = crypto.dh(&ephemeral.secret, &remote_ephemeral)?;
        self.symmetric.mix_key(&shared);
        // s: the responder's encrypted static key.
        let sealed_len = self.symmetric.sealed_len(DH_LEN);
        if rest.len() < sealed_len {
            return Err(SecureError::MessageTooShort);
        }
        let (sealed_static, payload) = rest.split_at(sealed_len);
        let remote_static = to_key(
            &self
                .symmetric
                .decrypt_and_hash(crypto.as_ref(), sealed_static)?,
        )?;
        // es: our ephemeral with their static.
        let shared = crypto.dh(&ephemeral.secret, &remote_static)?;
        self.symmetric.mix_key(&shared);
        // The responder's identity proof.
        let payload = self.symmetric.decrypt_and_hash(crypto.as_ref(), payload)?;
        self.verify_payload(&payload, &remote_static)
    }

    /// Message 3, tokens "s, se", then the encrypted payload.
    fn write_message3(&mut self) -> Result<(), SecureError> {
        let crypto = Arc::clone(&self.crypto);
        let mut message = Vec::new();
        // s: our static key, encrypted.
        self.symmetric.encrypt_and_hash(
            crypto.as_ref(),
            &self.static_keypair.public,
            &mut message,
        )?;
        // se: our static with their ephemeral.
        let shared = crypto.dh(&self.static_keypair.secret, &self.remote_ephemeral)?;
        self.symmetric.mix_key(&shared);
        // Our identity proof.
        self.symmetric
            .encrypt_and_hash(crypto.as_ref(), &self.payload.encode(), &mut message)?;
        self.frame(&message);
        Ok(())
    }

    /// Reads message 3 as responder.
    fn read_message3(&mut self, message: &[u8]) -> Result<(), SecureError> {
        let crypto = Arc::clone(&self.crypto);
        let ephemeral = self.ephemeral.clone().ok_or(SecureError::InvalidKey)?;
        // s: the initiator's encrypted static key.
        let sealed_len = self.symmetric.sealed_len(DH_LEN);
        if message.len() < sealed_len {
            return Err(SecureError::MessageTooShort);
        }
        let (sealed_static, payload) = message.split_at(sealed_len);
        let remote_static = to_key(
            &self
                .symmetric
                .decrypt_and_hash(crypto.as_ref(), sealed_static)?,
        )?;
        // se: our ephemeral with their static.
        let shared = crypto.dh(&ephemeral.secret, &remote_static)?;
        self.symmetric.mix_key(&shared);
        // The initiator's identity proof.
        let payload = self.symmetric.decrypt_and_hash(crypto.as_ref(), payload)?;
        self.verify_payload(&payload, &remote_static)
    }

    /// Checks that the remote identity key signed the remote static key.
    fn verify_payload(
        &mut self,
        payload: &[u8],
        remote_static: &[u8; DH_LEN],
    ) -> Result<(), SecureError> {
        let payload = NoiseHandshakePayload::decode(payload)?;
        let key = payload.identity_key.ok_or(SecureError::InvalidIdentity)?;
        let signature = payload.identity_sig.ok_or(SecureError::InvalidSignature)?;
        // The binding: identity key signs "noise-libp2p-static-key:" || static key.
        let mut signed = STATIC_KEY_DOMAIN.to_vec();
        signed.extend_from_slice(remote_static);
        if !self.identity.verify(&key, &signed, &signature) {
            return Err(SecureError::InvalidSignature);
        }
        let peer = PeerId::from_public_key(&key);
        // The dialer insists on the identity it dialed.
        if let Some(expected) = self.expected.take()
            && expected != peer
        {
            return Err(SecureError::UnexpectedPeer {
                expected,
                actual: peer,
            });
        }
        self.remote = Some((peer, key));
        Ok(())
    }

    /// Queues a message behind its 2-byte length.
    fn frame(&mut self, message: &[u8]) {
        // Invariant: handshake messages hold two keys, two tags, and a small payload.
        // They stay far below 65535 bytes.
        let len = message.len().min(MAX_MESSAGE_LEN) as u16;
        self.outbound.extend_from_slice(&len.to_be_bytes());
        self.outbound.extend_from_slice(message);
    }

    /// Splits the next complete message off the inbound buffer.
    fn next_message(&mut self) -> Option<Vec<u8>> {
        let prefix = self.inbound.get(..PREFIX_LEN)?;
        let len = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
        if self.inbound.len() < PREFIX_LEN + len {
            return None;
        }
        let message = self.inbound[PREFIX_LEN..PREFIX_LEN + len].to_vec();
        self.inbound.drain(..PREFIX_LEN + len);
        Some(message)
    }

    /// Splits the transcript into transport ciphers and hands out the session.
    fn finish(&mut self) -> Result<SecureSession, SecureError> {
        self.step = Step::Done;
        let (remote_peer, remote_key) = self.remote.take().ok_or(SecureError::InvalidIdentity)?;
        let (initiator_to_responder, responder_to_initiator) = self.symmetric.split();
        // Each side sends with one key and receives with the other.
        let (send, receive) = match self.role {
            Role::Initiator => (initiator_to_responder, responder_to_initiator),
            Role::Responder => (responder_to_initiator, initiator_to_responder),
        };
        let mut opener = NoiseOpener::new(Arc::clone(&self.crypto), receive);
        // Ciphertext that trailed the last handshake message is already transport data.
        let mut early_plaintext = Vec::new();
        opener.open(&mem::take(&mut self.inbound), &mut early_plaintext)?;
        Ok(SecureSession {
            remote_peer,
            remote_key,
            sealer: Box::new(NoiseSealer::new(Arc::clone(&self.crypto), send)),
            opener: Box::new(opener),
            early_plaintext,
        })
    }
}

impl Handshake for NoiseHandshake {
    fn take_output(&mut self) -> Vec<u8> {
        mem::take(&mut self.outbound)
    }

    fn receive(&mut self, bytes: &[u8]) -> Result<Option<SecureSession>, SecureError> {
        if self.step == Step::Done {
            return Err(SecureError::UnexpectedData);
        }
        self.inbound.extend_from_slice(bytes);
        while let Some(message) = self.next_message() {
            match self.step {
                // Responder: message 1 in, message 2 out.
                Step::AwaitMessage1 => {
                    self.read_message1(&message)?;
                    self.write_message2()?;
                    self.step = Step::AwaitMessage3;
                }
                // Initiator: message 2 in, message 3 out, done.
                Step::AwaitMessage2 => {
                    self.read_message2(&message)?;
                    self.write_message3()?;
                    return self.finish().map(Some);
                }
                // Responder: message 3 in, done.
                Step::AwaitMessage3 => {
                    self.read_message3(&message)?;
                    return self.finish().map(Some);
                }
                Step::Done => return Err(SecureError::UnexpectedData),
            }
        }
        Ok(None)
    }
}

/// Splits a 32-byte public key off the front of a message.
fn split_key(message: &[u8]) -> Result<([u8; DH_LEN], &[u8]), SecureError> {
    let (key, rest) = message
        .split_first_chunk::<DH_LEN>()
        .ok_or(SecureError::MessageTooShort)?;
    Ok((*key, rest))
}

/// A decrypted static key as a fixed array.
fn to_key(bytes: &[u8]) -> Result<[u8; DH_LEN], SecureError> {
    bytes.try_into().map_err(|_| SecureError::InvalidKey)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::secure::{
        SecurityUpgrade,
        noise::{
            NoiseConfig, TAG_LEN,
            mock::{MockCrypto, MockIdentity},
        },
    };

    /// A configuration over the insecure test primitives.
    fn config(seed: u8) -> NoiseConfig {
        NoiseConfig::new(
            Arc::new(MockCrypto::new(u64::from(seed))),
            Arc::new(MockIdentity::new(seed)),
        )
    }

    #[test]
    fn xx_handshake_and_transport() {
        let alice = config(1);
        let bob = config(2);
        let bob_peer = PeerId::from_public_key(&MockIdentity::new(2).public_key());
        let mut initiator = alice.handshake(Role::Initiator, Some(bob_peer.clone()));
        let mut responder = bob.handshake(Role::Responder, None);

        // Message 1: 2-byte prefix + 32-byte ephemeral, no payload.
        let message1 = initiator.take_output();
        assert_eq!(message1.len(), 2 + 32);
        assert_eq!(&message1[..2], &[0, 32]);

        // Message 2: e (32) + encrypted s (32 + 16) + encrypted payload (+16).
        assert!(responder.receive(&message1).unwrap().is_none());
        let message2 = responder.take_output();
        let payload_len = alice.payload.encode().len();
        assert_eq!(
            message2.len(),
            2 + 32 + 32 + TAG_LEN + payload_len + TAG_LEN
        );

        // Message 3 completes the initiator, who proves bob's identity.
        let mut alice_session = initiator.receive(&message2).unwrap().unwrap();
        assert_eq!(alice_session.remote_peer, bob_peer);
        let message3 = initiator.take_output();
        assert_eq!(message3.len(), 2 + 32 + TAG_LEN + payload_len + TAG_LEN);

        // Alice's first transport frame trails message 3 in the same flight.
        let mut flight = message3;
        alice_session.sealer.seal(b"ping", &mut flight).unwrap();
        let mut bob_session = responder.receive(&flight).unwrap().unwrap();
        assert_eq!(
            bob_session.remote_peer,
            PeerId::from_public_key(&MockIdentity::new(1).public_key())
        );
        assert_eq!(bob_session.early_plaintext, b"ping");

        // A 100 000-byte reply spans two frames: 65519 + 34481 plaintext bytes.
        let reply = vec![9u8; 100_000];
        let mut wire = Vec::new();
        bob_session.sealer.seal(&reply, &mut wire).unwrap();
        assert_eq!(wire.len(), 2 + 65535 + 2 + 34481 + TAG_LEN);
        assert_eq!(&wire[..2], &[0xff, 0xff]);

        // Delivered in two arbitrary pieces, it reassembles.
        let mut plaintext = Vec::new();
        alice_session
            .opener
            .open(&wire[..1000], &mut plaintext)
            .unwrap();
        alice_session
            .opener
            .open(&wire[1000..], &mut plaintext)
            .unwrap();
        assert_eq!(plaintext, reply);
    }

    #[test]
    fn tampered_message2_fails_authentication() {
        let mut initiator = config(1).handshake(Role::Initiator, None);
        let mut responder = config(2).handshake(Role::Responder, None);
        responder.receive(&initiator.take_output()).unwrap();
        let mut message2 = responder.take_output();
        // Mutation: flip one bit of the encrypted static key, byte 2 + 32 + 5.
        message2[39] ^= 1;
        assert_eq!(
            initiator.receive(&message2).unwrap_err(),
            SecureError::DecryptionFailed
        );
    }

    #[test]
    fn dialer_rejects_the_wrong_peer() {
        let carol = PeerId::from_public_key(&MockIdentity::new(9).public_key());
        let mut initiator = config(1).handshake(Role::Initiator, Some(carol.clone()));
        let mut responder = config(2).handshake(Role::Responder, None);
        responder.receive(&initiator.take_output()).unwrap();
        let error = initiator.receive(&responder.take_output()).unwrap_err();
        assert_eq!(
            error,
            SecureError::UnexpectedPeer {
                expected: carol,
                actual: PeerId::from_public_key(&MockIdentity::new(2).public_key())
            }
        );
    }

    #[test]
    fn forged_signature_is_rejected() {
        // Mutation: bob's payload carries a signature over the wrong static key.
        let crypto: Arc<dyn NoiseCrypto> = Arc::new(MockCrypto::new(2));
        let identity = Arc::new(MockIdentity::new(2));
        let static_keypair = crypto.generate_keypair();
        let payload = NoiseHandshakePayload {
            identity_key: Some(identity.public_key()),
            identity_sig: Some(identity.sign(b"something else")),
            extensions: None,
        };
        let mut responder = NoiseHandshake::new(
            Role::Responder,
            crypto,
            identity,
            static_keypair,
            payload,
            None,
        );
        let mut initiator = config(1).handshake(Role::Initiator, None);
        responder.receive(&initiator.take_output()).unwrap();
        assert_eq!(
            initiator.receive(&responder.take_output()).unwrap_err(),
            SecureError::InvalidSignature
        );
    }

    proptest! {
        #[test]
        fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = config(3).handshake(Role::Responder, None).receive(&bytes);
            let _ = config(4).handshake(Role::Initiator, None).receive(&bytes);
        }
    }
}
