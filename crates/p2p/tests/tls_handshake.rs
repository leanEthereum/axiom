//! Full TLS 1.3 handshakes between two in-memory sessions, and the ways they must fail.
//!
//! The pump below plays the QUIC transport: it moves handshake bytes between the sides,
//! level by level, and records the keys each side installs.

use std::sync::Arc;

use axiom_p2p::{
    Keypair, PeerId,
    tls::{
        Alert, CertificateError, CipherSuite, Level, ProtocolError, Secrets, TlsError, TlsIdentity,
        TlsOutput, TlsSession,
    },
};
use proptest::prelude::*;

/// An instant in 2026, in Unix seconds.
const NOW: u64 = 1_792_000_000;

/// The client's transport parameters, opaque to TLS.
const CLIENT_PARAMETERS: &[u8] = &[0x01, 0x02, 0x03];

/// The server's transport parameters.
const SERVER_PARAMETERS: &[u8] = &[0x0a, 0x0b];

/// A host key pair from a fixed secret.
fn host(byte: u8) -> Keypair {
    Keypair::from_secret_bytes(&[byte; 32]).expect("valid secret")
}

/// A TLS identity for a host, with a fixed certificate key.
fn identity(host: &Keypair, seed: u8) -> Arc<TlsIdentity> {
    Arc::new(TlsIdentity::generate(host, [seed; 32]).expect("valid seed"))
}

/// One side of the pump: its session and the keys it installed.
struct Side {
    /// The session.
    session: TlsSession,
    /// Every key output, in order.
    keys: Vec<(Level, Secrets)>,
    /// The kinds of every output, in order, as (is keys, level).
    trace: Vec<(bool, Level)>,
}

impl Side {
    /// Wraps a session.
    const fn new(session: TlsSession) -> Self {
        Self {
            session,
            keys: Vec::new(),
            trace: Vec::new(),
        }
    }

    /// Takes every pending output: keys are recorded, handshake bytes returned.
    fn drain(&mut self) -> Vec<(Level, Vec<u8>)> {
        let mut flights = Vec::new();
        while let Some(output) = self.session.poll_output() {
            match output {
                TlsOutput::Handshake { level, bytes } => {
                    self.trace.push((false, level));
                    flights.push((level, bytes));
                }
                TlsOutput::Keys { level, secrets } => {
                    self.trace.push((true, level));
                    self.keys.push((level, secrets));
                }
                // QUIC never asks for record-layer actions.
                other => panic!("unexpected output {other:?}"),
            }
        }
        flights
    }

    /// The secrets installed for a level.
    fn secrets(&self, level: Level) -> &Secrets {
        &self
            .keys
            .iter()
            .find(|(found, _)| *found == level)
            .expect("keys installed for the level")
            .1
    }
}

/// The two sides of one handshake.
struct Pump {
    /// The dialer.
    client: Side,
    /// The listener.
    server: Side,
}

impl Pump {
    /// A client and a server with fixed identities and entropy.
    fn new(suites: &[CipherSuite]) -> Self {
        Self::with(Some(host(2).peer_id()), NOW, suites)
    }

    /// A pump whose client expects a peer and checks certificates at an instant.
    fn with(expected: Option<PeerId>, now: u64, suites: &[CipherSuite]) -> Self {
        let client = TlsSession::client(
            identity(&host(1), 11),
            CLIENT_PARAMETERS.to_vec(),
            expected,
            [21; 64],
            now,
        );
        let server = TlsSession::server(
            identity(&host(2), 12),
            SERVER_PARAMETERS.to_vec(),
            [22; 64],
            NOW,
        )
        .with_cipher_suites(suites);
        Self {
            client: Side::new(client),
            server: Side::new(server),
        }
    }

    /// Runs flights back and forth, each one mutated and cut into chunks first.
    ///
    /// # Returns
    ///
    /// The first error of the client, then of the server.
    fn run(
        &mut self,
        mut mutate: impl FnMut(bool, Level, &mut Vec<u8>),
        cut: &[usize],
    ) -> (Result<(), TlsError>, Result<(), TlsError>) {
        let mut results = (Ok(()), Ok(()));
        for _ in 0..4 {
            for from_client in [true, false] {
                let (from, to) = if from_client {
                    (&mut self.client, &mut self.server)
                } else {
                    (&mut self.server, &mut self.client)
                };
                for (level, mut bytes) in from.drain() {
                    mutate(from_client, level, &mut bytes);
                    let result = Self::deliver(&mut to.session, level, &bytes, cut);
                    let slot = if from_client {
                        &mut results.1
                    } else {
                        &mut results.0
                    };
                    if slot.is_ok() {
                        *slot = result;
                    }
                }
            }
        }
        results
    }

    /// Feeds bytes in chunks whose lengths cycle through the cut list.
    fn deliver(
        to: &mut TlsSession,
        level: Level,
        bytes: &[u8],
        cut: &[usize],
    ) -> Result<(), TlsError> {
        let mut rest = bytes;
        let mut sizes = cut.iter().cycle();
        while !rest.is_empty() {
            let size = sizes
                .next()
                .map_or(rest.len(), |&size| size.clamp(1, rest.len()));
            let (chunk, tail) = rest.split_at(size);
            to.read_handshake(level, chunk)?;
            rest = tail;
        }
        Ok(())
    }
}

/// Leaves every flight unchanged.
const fn untouched(_: bool, _: Level, _: &mut Vec<u8>) {}

/// The offset of the first message of a type in a flight.
fn find_message(flight: &[u8], kind: u8) -> (usize, usize) {
    let mut at = 0;
    loop {
        let length = usize::from(flight[at + 1]) << 16
            | usize::from(flight[at + 2]) << 8
            | usize::from(flight[at + 3]);
        if flight[at] == kind {
            return (at, 4 + length);
        }
        at += 4 + length;
    }
}

#[test]
fn full_handshake_for_both_suites() {
    for suite in CipherSuite::ALL {
        let mut pump = Pump::new(&[suite]);
        assert_eq!(pump.run(untouched, &[]), (Ok(()), Ok(())));
        let (client, server) = (&pump.client, &pump.server);

        // Both sides finished, on the same suite.
        assert!(!client.session.is_handshaking());
        assert!(!server.session.is_handshaking());
        assert_eq!(client.session.cipher_suite(), Some(suite));
        assert_eq!(server.session.cipher_suite(), Some(suite));

        // The outputs come in the order the transport applies them.
        assert_eq!(
            client.trace,
            [
                (false, Level::Initial),
                (true, Level::Handshake),
                (false, Level::Handshake),
                (true, Level::Application)
            ]
        );
        assert_eq!(
            server.trace,
            [
                (false, Level::Initial),
                (true, Level::Handshake),
                (false, Level::Handshake),
                (true, Level::Application)
            ]
        );

        // Each side's sending secret is the other's receiving secret, at both levels.
        for level in [Level::Handshake, Level::Application] {
            let (ours, theirs) = (client.secrets(level), server.secrets(level));
            assert_eq!(ours.local, theirs.remote);
            assert_eq!(ours.remote, theirs.local);
            assert_ne!(ours.local, ours.remote);
            assert_eq!(ours.local.suite(), suite);
        }

        // Each side authenticated the other's host key, and read its transport parameters.
        let client_peer = client.session.peer().unwrap();
        let server_peer = server.session.peer().unwrap();
        assert_eq!(client_peer.peer_id, host(2).peer_id());
        assert_eq!(&client_peer.public_key, host(2).public_key());
        assert_eq!(server_peer.peer_id, host(1).peer_id());
        assert_eq!(
            client.session.peer_transport_parameters(),
            Some(SERVER_PARAMETERS)
        );
        assert_eq!(
            server.session.peer_transport_parameters(),
            Some(CLIENT_PARAMETERS)
        );
    }
}

#[test]
fn server_prefers_aes_when_both_are_offered() {
    let mut pump = Pump::new(&CipherSuite::ALL);
    assert_eq!(pump.run(untouched, &[]), (Ok(()), Ok(())));
    assert_eq!(
        pump.client.session.cipher_suite(),
        Some(CipherSuite::Aes128GcmSha256)
    );
}

#[test]
fn wrong_expected_peer_is_refused() {
    // The client dials host 3, but host 2 answers.
    let mut pump = Pump::with(Some(host(3).peer_id()), NOW, &CipherSuite::ALL);
    let (client, _) = pump.run(untouched, &[]);
    let error = client.unwrap_err();
    assert_eq!(
        error,
        TlsError::Certificate(CertificateError::PeerIdMismatch {
            expected: host(3).peer_id(),
            actual: host(2).peer_id()
        })
    );
    // bad_certificate.
    assert_eq!(error.alert(), Alert(42));
    assert!(pump.client.session.is_handshaking());
}

#[test]
fn missing_alpn_is_refused() {
    // Mutation: the ALPN extension type 0x0010 becomes the unknown 0xfafa, as if absent.
    let alpn = [
        0x00, 0x10, 0x00, 0x09, 0x00, 0x07, 0x06, b'l', b'i', b'b', b'p', b'2', b'p',
    ];
    let mut pump = Pump::new(&CipherSuite::ALL);
    let (_, server) = pump.run(
        |from_client, level, bytes| {
            if from_client && level == Level::Initial {
                let at = bytes
                    .windows(alpn.len())
                    .position(|window| window == alpn)
                    .unwrap();
                bytes[at..at + 2].copy_from_slice(&[0xfa, 0xfa]);
            }
        },
        &[],
    );
    let error = server.unwrap_err();
    assert_eq!(
        error,
        TlsError::Protocol(ProtocolError::NoApplicationProtocol)
    );
    // no_application_protocol: QUIC closes with 0x100 + 120 = 0x178.
    assert_eq!(error.alert(), Alert(120));
}

#[test]
fn other_application_protocol_is_refused() {
    // Mutation: the server's EncryptedExtensions select "libp2q", which the client never offered.
    let mut pump = Pump::new(&CipherSuite::ALL);
    let (client, _) = pump.run(
        |from_client, level, bytes| {
            if !from_client && level == Level::Handshake {
                let at = bytes
                    .windows(6)
                    .position(|window| window == b"libp2p")
                    .unwrap();
                bytes[at + 5] = b'q';
            }
        },
        &[],
    );
    let error = client.unwrap_err();
    assert_eq!(
        error,
        TlsError::Protocol(ProtocolError::UnofferedApplicationProtocol)
    );
    // illegal_parameter.
    assert_eq!(error.alert(), Alert(47));
}

#[test]
fn tampered_finished_is_refused() {
    // Mutation: the last byte of the server flight, the end of its Finished.
    let mut pump = Pump::new(&CipherSuite::ALL);
    let (client, _) = pump.run(
        |from_client, level, bytes| {
            if !from_client && level == Level::Handshake {
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
            }
        },
        &[],
    );
    let error = client.unwrap_err();
    assert_eq!(error, TlsError::Protocol(ProtocolError::InvalidFinished));
    // decrypt_error.
    assert_eq!(error.alert(), Alert(51));
}

#[test]
fn tampered_certificate_verify_is_refused() {
    // Mutation: the last byte of the server CertificateVerify, the end of s in its DER signature.
    let mut pump = Pump::new(&CipherSuite::ALL);
    let (client, _) = pump.run(
        |from_client, level, bytes| {
            if !from_client && level == Level::Handshake {
                let (at, length) = find_message(bytes, 15);
                bytes[at + length - 1] ^= 1;
            }
        },
        &[],
    );
    assert_eq!(
        client,
        Err(TlsError::Protocol(ProtocolError::InvalidCertificateVerify))
    );
}

#[test]
fn expired_certificate_is_refused() {
    // The client clock reads 10000-01-01, after the last second of 9999 the certificate allows.
    let mut pump = Pump::with(None, 253_402_300_800, &CipherSuite::ALL);
    let (client, _) = pump.run(untouched, &[]);
    let error = client.unwrap_err();
    assert_eq!(
        error,
        TlsError::Certificate(CertificateError::Expired {
            not_after: 253_402_300_799,
            now: 253_402_300_800
        })
    );
    // certificate_expired.
    assert_eq!(error.alert(), Alert(45));
}

#[test]
fn bytes_at_the_wrong_level_are_refused() {
    // The ClientHello arrives at the Handshake level instead of Initial.
    let mut pump = Pump::new(&CipherSuite::ALL);
    let (_, hello) = pump.client.drain().remove(0);
    let error = pump
        .server
        .session
        .read_handshake(Level::Handshake, &hello)
        .unwrap_err();
    assert_eq!(
        error,
        TlsError::Protocol(ProtocolError::WrongLevel {
            expected: Level::Initial,
            found: Level::Handshake
        })
    );
    // unexpected_message; the failure then sticks, even for correct input.
    assert_eq!(error.alert(), Alert(10));
    assert_eq!(
        pump.server.session.read_handshake(Level::Initial, &hello),
        Err(error)
    );
}

#[test]
fn post_handshake_messages() {
    let mut pump = Pump::new(&CipherSuite::ALL);
    assert_eq!(pump.run(untouched, &[]), (Ok(()), Ok(())));
    let client = &mut pump.client.session;

    // A NewSessionTicket at the application level is checked, then ignored.
    // Lifetime 7200, age add, an empty nonce, a 2-byte ticket, no extensions.
    let ticket = [
        0x04, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x1c, 0x20, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x02,
        0xaa, 0xbb, 0x00, 0x00,
    ];
    assert_eq!(client.read_handshake(Level::Application, &ticket), Ok(()));
    assert!(!client.is_handshaking());
    assert_eq!(client.poll_output(), None);

    // A KeyUpdate is refused: QUIC forbids it, per RFC 9001, section 6, though TCP accepts it.
    let key_update = [0x18, 0x00, 0x00, 0x01, 0x00];
    let error = client
        .read_handshake(Level::Application, &key_update)
        .unwrap_err();
    assert_eq!(
        error,
        TlsError::Protocol(ProtocolError::UnexpectedMessage {
            found: 24,
            state: "connected, where only tickets and key updates may arrive"
        })
    );
    assert_eq!(error.alert(), Alert(10));

    // A post-handshake CertificateRequest is refused by a fresh connection too.
    let mut pump = Pump::new(&CipherSuite::ALL);
    assert_eq!(pump.run(untouched, &[]), (Ok(()), Ok(())));
    let request = [0x0d, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00];
    assert_eq!(
        pump.client
            .session
            .read_handshake(Level::Application, &request),
        Err(TlsError::Protocol(ProtocolError::UnexpectedMessage {
            found: 13,
            state: "connected, where only tickets and key updates may arrive"
        }))
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn any_chunking_gives_the_same_outcome(cut in proptest::collection::vec(1_usize..300, 1..8)) {
        // Law: cutting each flight anywhere changes nothing the transport sees.
        let mut reference = Pump::new(&CipherSuite::ALL);
        prop_assert_eq!(reference.run(untouched, &[]), (Ok(()), Ok(())));
        let mut chunked = Pump::new(&CipherSuite::ALL);
        prop_assert_eq!(chunked.run(untouched, &cut), (Ok(()), Ok(())));
        prop_assert_eq!(&chunked.client.keys, &reference.client.keys);
        prop_assert_eq!(&chunked.server.keys, &reference.server.keys);
        prop_assert_eq!(chunked.client.session.peer(), reference.client.session.peer());
        prop_assert_eq!(chunked.server.session.peer(), reference.server.session.peer());
    }
}
