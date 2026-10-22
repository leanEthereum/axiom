//! The libp2p layer over XX: framing, identity payloads, and the session hand-off.

use std::{fmt, mem};

use axiom_crypto::x25519::{PublicKey as DhPublicKey, SecretKey};

use super::{
    MAX_MESSAGE_LEN, NoiseHandshakePayload, STATIC_KEY_DOMAIN,
    transport::{NoiseOpener, NoiseSealer},
    xx::XxState,
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
    /// The session was handed out, or the handshake failed.
    Done,
}

/// One run of noise-libp2p.
pub struct NoiseHandshake {
    /// The current step.
    step: Step,
    /// The Noise state machine.
    xx: XxState,
    /// The responder's ephemeral secret, spent on message 2.
    ephemeral: Option<SecretKey>,
    /// This side's encoded identity proof.
    payload: Vec<u8>,
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
        // Secrets stay out of logs.
        f.debug_struct("NoiseHandshake")
            .field("role", &self.xx.role())
            .field("step", &self.step)
            .finish_non_exhaustive()
    }
}

impl NoiseHandshake {
    /// Starts a handshake; the initiator's message 1 is queued at once.
    ///
    /// # Arguments
    ///
    /// - `static_secret`: the X25519 key the identity signed.
    /// - `ephemeral`: a fresh X25519 secret, used once.
    /// - `payload`: the identity key and its signature over the static public key.
    /// - `expected`: the peer the dialer meant to reach.
    #[must_use]
    pub fn new(
        role: Role,
        static_secret: SecretKey,
        ephemeral: SecretKey,
        payload: &NoiseHandshakePayload,
        expected: Option<PeerId>,
    ) -> Self {
        let mut handshake = Self {
            step: Step::AwaitMessage1,
            // libp2p fixes an empty prologue.
            xx: XxState::new(role, &[], static_secret),
            ephemeral: Some(ephemeral),
            payload: payload.encode(),
            expected,
            remote: None,
            outbound: Vec::new(),
            inbound: Vec::new(),
        };
        if role == Role::Initiator {
            handshake.start();
        }
        handshake
    }

    /// Queues message 1: the ephemeral key and an empty payload.
    fn start(&mut self) {
        let mut message = Vec::new();
        // Invariant: the ephemeral is set at construction and spent only here or on message 2.
        // Message 1 has no DH, so it cannot fail; a failure would leave an empty message.
        if let Some(ephemeral) = self.ephemeral.take()
            && self.xx.write_message1(ephemeral, &[], &mut message).is_ok()
        {
            self.frame(&message);
        }
        self.step = Step::AwaitMessage2;
    }

    /// Reads message 1 and answers with message 2.
    fn respond(&mut self, message: &[u8]) -> Result<(), SecureError> {
        // libp2p sends an empty payload here; anything else is unauthenticated and ignored.
        self.xx.read_message1(message)?;
        let ephemeral = self.ephemeral.take().ok_or(SecureError::InvalidKey)?;
        let mut reply = Vec::new();
        let payload = mem::take(&mut self.payload);
        self.xx.write_message2(ephemeral, &payload, &mut reply)?;
        self.frame(&reply);
        self.step = Step::AwaitMessage3;
        Ok(())
    }

    /// Reads message 2, proves the responder, and answers with message 3.
    fn conclude(&mut self, message: &[u8]) -> Result<SecureSession, SecureError> {
        let payload = self.xx.read_message2(message)?;
        self.verify_payload(&payload)?;
        let mut reply = Vec::new();
        let local = mem::take(&mut self.payload);
        self.xx.write_message3(&local, &mut reply)?;
        self.frame(&reply);
        self.finish()
    }

    /// Reads message 3 and proves the initiator.
    fn accept(&mut self, message: &[u8]) -> Result<SecureSession, SecureError> {
        let payload = self.xx.read_message3(message)?;
        self.verify_payload(&payload)?;
        self.finish()
    }

    /// Checks that the remote identity key signed the remote static key.
    fn verify_payload(&mut self, payload: &[u8]) -> Result<(), SecureError> {
        let remote_static = self
            .xx
            .remote_static()
            .map(DhPublicKey::to_bytes)
            .ok_or(SecureError::InvalidKey)?;
        let payload = NoiseHandshakePayload::decode(payload)?;
        let key = payload.identity_key.ok_or(SecureError::InvalidIdentity)?;
        let signature = payload.identity_sig.ok_or(SecureError::InvalidSignature)?;
        // The binding: identity key signs "noise-libp2p-static-key:" || static key.
        let mut signed = STATIC_KEY_DOMAIN.to_vec();
        signed.extend_from_slice(&remote_static);
        if !key.verify(&signed, &signature) {
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
        // Invariant: handshake messages hold two keys, two tags, and a payload under 200 bytes.
        // They stay far below 65535 bytes.
        let len = message.len().min(MAX_MESSAGE_LEN) as u16;
        self.outbound.extend_from_slice(&len.to_be_bytes());
        self.outbound.extend_from_slice(message);
    }

    /// Splits the next complete message off the inbound buffer.
    fn next_message(&mut self) -> Option<Vec<u8>> {
        let prefix = self.inbound.first_chunk::<PREFIX_LEN>()?;
        let len = usize::from(u16::from_be_bytes(*prefix));
        let message = self.inbound.get(PREFIX_LEN..PREFIX_LEN + len)?.to_vec();
        self.inbound.drain(..PREFIX_LEN + len);
        Some(message)
    }

    /// Splits the transcript into transport ciphers and hands out the session.
    fn finish(&mut self) -> Result<SecureSession, SecureError> {
        self.step = Step::Done;
        let (remote_peer, remote_key) = self.remote.take().ok_or(SecureError::InvalidIdentity)?;
        let (send, receive) = self.xx.split();
        let mut opener = NoiseOpener::new(receive);
        // Ciphertext that trailed the last handshake message is already transport data.
        let mut early_plaintext = Vec::new();
        opener.open(&mem::take(&mut self.inbound), &mut early_plaintext)?;
        Ok(SecureSession {
            remote_peer,
            remote_key,
            sealer: Box::new(NoiseSealer::new(send)),
            opener: Box::new(opener),
            early_plaintext,
        })
    }

    /// Advances on every complete message buffered so far.
    fn advance(&mut self) -> Result<Option<SecureSession>, SecureError> {
        while let Some(message) = self.next_message() {
            match self.step {
                // Responder: message 1 in, message 2 out.
                Step::AwaitMessage1 => self.respond(&message)?,
                // Initiator: message 2 in, message 3 out, done.
                Step::AwaitMessage2 => return self.conclude(&message).map(Some),
                // Responder: message 3 in, done.
                Step::AwaitMessage3 => return self.accept(&message).map(Some),
                Step::Done => return Err(SecureError::UnexpectedData),
            }
        }
        Ok(None)
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
        // A failed handshake is over: it never resumes on later bytes.
        let outcome = self.advance();
        if outcome.is_err() {
            self.step = Step::Done;
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::{
        identity::Keypair,
        secure::{
            SecurityUpgrade,
            noise::{NoiseConfig, TAG_LEN},
        },
    };

    /// An identity whose secret is 32 copies of a byte.
    fn identity(seed: u8) -> Keypair {
        Keypair::from_secret_bytes(&[seed; 32]).unwrap()
    }

    /// A deterministic configuration for an identity.
    fn config(seed: u8) -> NoiseConfig {
        NoiseConfig::from_seed(&identity(seed), [seed; 32])
    }

    #[test]
    fn xx_handshake_and_transport() {
        let alice = config(1);
        let bob = config(2);
        let bob_peer = identity(2).peer_id();
        let mut initiator = alice.handshake(Role::Initiator, Some(bob_peer.clone()));
        let mut responder = bob.handshake(Role::Responder, None);

        // Message 1: 2-byte prefix + 32-byte ephemeral, no payload.
        let message1 = initiator.take_output();
        assert_eq!(message1.len(), 2 + 32);
        assert_eq!(&message1[..2], &[0, 32]);

        // Message 2: e (32) + encrypted s (32 + 16) + encrypted payload (+16).
        assert!(responder.receive(&message1).unwrap().is_none());
        let message2 = responder.take_output();
        // DER signatures run 70 to 72 bytes, so each side's payload length is its own.
        let bob_payload_len = bob.payload().encode().len();
        assert_eq!(
            message2.len(),
            2 + 32 + 32 + TAG_LEN + bob_payload_len + TAG_LEN
        );

        // Message 3 completes the initiator, who proves bob's identity.
        let mut alice_session = initiator.receive(&message2).unwrap().unwrap();
        assert_eq!(alice_session.remote_peer, bob_peer);
        assert_eq!(&alice_session.remote_key, identity(2).public_key());
        let message3 = initiator.take_output();
        let alice_payload_len = alice.payload().encode().len();
        assert_eq!(
            message3.len(),
            2 + 32 + TAG_LEN + alice_payload_len + TAG_LEN
        );

        // Alice's first transport frame trails message 3 in the same flight.
        let mut flight = message3;
        alice_session.sealer.seal(b"ping", &mut flight).unwrap();
        let mut bob_session = responder.receive(&flight).unwrap().unwrap();
        assert_eq!(bob_session.remote_peer, identity(1).peer_id());
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
        // The failure is final: the same bytes again are refused outright.
        assert_eq!(
            initiator.receive(&[]).unwrap_err(),
            SecureError::UnexpectedData
        );
    }

    #[test]
    fn dialer_rejects_the_wrong_peer() {
        let carol = identity(9).peer_id();
        let mut initiator = config(1).handshake(Role::Initiator, Some(carol.clone()));
        let mut responder = config(2).handshake(Role::Responder, None);
        responder.receive(&initiator.take_output()).unwrap();
        let error = initiator.receive(&responder.take_output()).unwrap_err();
        assert_eq!(
            error,
            SecureError::UnexpectedPeer {
                expected: carol,
                actual: identity(2).peer_id(),
            }
        );
    }

    #[test]
    fn signature_over_another_static_key_is_rejected() {
        // Mutation: bob signs the binding of a static key he does not use.
        let bob = identity(2);
        let mut signed = STATIC_KEY_DOMAIN.to_vec();
        signed.extend_from_slice(&[7; 32]);
        let payload = NoiseHandshakePayload {
            identity_key: Some(bob.public_key().clone()),
            identity_sig: Some(bob.sign(&signed).into_bytes()),
            extensions: None,
        };
        let mut responder = NoiseHandshake::new(
            Role::Responder,
            SecretKey::from_bytes([3; 32]),
            SecretKey::from_bytes([4; 32]),
            &payload,
            None,
        );
        let mut initiator = config(1).handshake(Role::Initiator, None);
        responder.receive(&initiator.take_output()).unwrap();
        assert_eq!(
            initiator.receive(&responder.take_output()).unwrap_err(),
            SecureError::InvalidSignature
        );
    }

    #[test]
    fn borrowed_identity_is_rejected() {
        // Mutation: mallory presents bob's key with mallory's own valid signature.
        let static_secret = SecretKey::from_bytes([3; 32]);
        let mut signed = STATIC_KEY_DOMAIN.to_vec();
        signed.extend_from_slice(static_secret.public_key().as_bytes());
        let payload = NoiseHandshakePayload {
            identity_key: Some(identity(2).public_key().clone()),
            identity_sig: Some(identity(66).sign(&signed).into_bytes()),
            extensions: None,
        };
        let mut initiator = NoiseHandshake::new(
            Role::Initiator,
            static_secret,
            SecretKey::from_bytes([4; 32]),
            &payload,
            None,
        );
        let mut responder = config(1).handshake(Role::Responder, None);
        responder.receive(&initiator.take_output()).unwrap();
        initiator.receive(&responder.take_output()).unwrap();
        assert_eq!(
            responder.receive(&initiator.take_output()).unwrap_err(),
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
