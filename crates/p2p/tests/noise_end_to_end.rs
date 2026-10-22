//! Real Noise over TCP under attack: a tampered ciphertext, and a forged identity signature.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use axiom_crypto::x25519::SecretKey;
use axiom_p2p::{
    Keypair, Multiaddr, PeerId,
    eth::reqresp::Protocol,
    multiaddr::Protocol as Layer,
    secure::{
        Handshake, Role, SecurityUpgrade,
        noise::{self, NoiseHandshake, NoiseHandshakePayload},
    },
    swarm::{self, NetworkConfig, NetworkEvent, NetworkEvents, NetworkHandle},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpListener, TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    runtime::Builder,
    spawn,
    time::timeout,
};

/// The identity whose secret is 32 copies of a seed byte.
fn identity(seed: u8) -> Keypair {
    Keypair::from_secret_bytes(&[seed; 32]).expect("seed is a valid scalar")
}

/// Starts a node with a configuration.
async fn start(config: NetworkConfig) -> (NetworkHandle, NetworkEvents) {
    swarm::start(config).await.expect("listener binds")
}

/// Waits for the first event a filter accepts, discarding the others.
async fn wait_for<T>(events: &mut NetworkEvents, filter: impl Fn(&NetworkEvent) -> Option<T>) -> T {
    loop {
        let event = events.next().await.expect("network still running");
        if let Some(found) = filter(&event) {
            return found;
        }
    }
}

/// Runs a scenario on a single-threaded runtime with a deadline.
fn run(scenario: impl Future<Output = ()>) {
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime builds");
    runtime.block_on(async {
        timeout(Duration::from_secs(20), scenario)
            .await
            .expect("scenario completes in time");
    });
}

/// Copies one direction of a proxied connection, flipping a bit when asked.
async fn pump(mut from: OwnedReadHalf, mut to: OwnedWriteHalf, tamper: Arc<AtomicBool>) {
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let n = match from.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        // Mutation: the last byte of the chunk, inside the final frame's authentication tag.
        if tamper.swap(false, Ordering::SeqCst) {
            buffer[n - 1] ^= 0x01;
        }
        if to.write_all(&buffer[..n]).await.is_err() {
            break;
        }
    }
    // Pass the end of stream on, so the far side notices too.
    let _ = to.shutdown().await;
}

/// A man in the middle between one dialer and a target, returning its address.
async fn proxy(target: Multiaddr, tamper: Arc<AtomicBool>) -> Multiaddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("proxy binds");
    let address = Multiaddr::from_tcp(listener.local_addr().expect("bound address"));
    let target = target.tcp_socket_addr().expect("a TCP target");
    spawn(async move {
        let (client, _) = listener.accept().await.expect("dialer connects");
        let server = TcpStream::connect(target).await.expect("target accepts");
        let (client_read, client_write) = client.into_split();
        let (server_read, server_write) = server.into_split();
        // Only the dialer-to-target direction is ever tampered with.
        spawn(pump(client_read, server_write, tamper));
        spawn(pump(
            server_read,
            client_write,
            Arc::new(AtomicBool::new(false)),
        ));
    });
    address
}

#[test]
fn tampered_ciphertext_kills_the_session() {
    run(async {
        let (alice, mut alice_events) =
            start(NetworkConfig::new(identity(1)).expect("entropy")).await;
        let (bob, mut bob_events) = start(NetworkConfig::new(identity(2)).expect("entropy")).await;
        let alice_id = alice.local_peer().clone();
        let bob_id = bob.local_peer().clone();

        // Fixture state: alice reaches bob through a proxy that forwards faithfully for now.
        let tamper = Arc::new(AtomicBool::new(false));
        let relay = proxy(bob.listen_addr().clone(), Arc::clone(&tamper)).await;
        alice
            .dial(relay.with(Layer::P2p(bob_id.clone())))
            .await
            .expect("dial queued");
        let connected = |event: &NetworkEvent| match event {
            NetworkEvent::PeerConnected { peer, .. } => Some(peer.clone()),
            _ => None,
        };
        assert_eq!(wait_for(&mut alice_events, connected).await, bob_id);
        assert_eq!(wait_for(&mut bob_events, connected).await, alice_id);

        // Mutation: arm the proxy, then make alice send a Ping request through it.
        tamper.store(true, Ordering::SeqCst);
        alice
            .send_request(bob_id.clone(), Protocol::PingV1, vec![0; 8])
            .await
            .expect("request queued");

        // Bob's opener refuses the frame, and the connection dies on both sides.
        let disconnected = |event: &NetworkEvent| match event {
            NetworkEvent::PeerDisconnected { peer } => Some(peer.clone()),
            _ => None,
        };
        assert_eq!(wait_for(&mut bob_events, disconnected).await, alice_id);
        assert_eq!(wait_for(&mut alice_events, disconnected).await, bob_id);
    });
}

/// A Noise responder whose payload signs a static key it does not use.
#[derive(Debug)]
struct ForgedNoise {
    /// The payload with the mismatched signature.
    payload: NoiseHandshakePayload,
}

impl ForgedNoise {
    /// A responder claiming an identity, with a signature over 32 bytes of 0x07.
    fn new(identity: &Keypair) -> Self {
        let mut signed = noise::STATIC_KEY_DOMAIN.to_vec();
        signed.extend_from_slice(&[7; 32]);
        Self {
            payload: NoiseHandshakePayload {
                identity_key: Some(identity.public_key().clone()),
                identity_sig: Some(identity.sign(&signed).into_bytes()),
                extensions: None,
            },
        }
    }
}

impl SecurityUpgrade for ForgedNoise {
    fn protocol(&self) -> &'static str {
        noise::PROTOCOL
    }

    fn handshake(&self, role: Role, expected: Option<PeerId>) -> Box<dyn Handshake> {
        // The static key actually used is 0x03 repeated, not the one signed.
        Box::new(NoiseHandshake::new(
            role,
            SecretKey::from_bytes([3; 32]),
            SecretKey::from_bytes([4; 32]),
            &self.payload,
            expected,
        ))
    }
}

#[test]
fn wrong_identity_signature_is_rejected() {
    run(async {
        let (alice, mut alice_events) =
            start(NetworkConfig::new(identity(1)).expect("entropy")).await;
        // Fixture state: mallory claims bob's identity with a signature over another static key.
        let bob = identity(2);
        let forged = Arc::new(ForgedNoise::new(&bob));
        let (mallory, _mallory_events) =
            start(NetworkConfig::with_security(bob.clone(), forged)).await;

        // Alice dials and the handshake fails on the signature check.
        alice
            .dial(
                mallory
                    .listen_addr()
                    .clone()
                    .with(Layer::P2p(bob.peer_id())),
            )
            .await
            .expect("dial queued");
        let error = wait_for(&mut alice_events, |event| match event {
            NetworkEvent::ConnectionFailed { error, .. } => Some(error.clone()),
            NetworkEvent::PeerConnected { .. } => Some("connected".to_owned()),
            _ => None,
        })
        .await;
        assert_eq!(
            error,
            format!(
                "security handshake failed: identity signature of {} over its static key is absent or invalid",
                bob.peer_id()
            )
        );
    });
}
