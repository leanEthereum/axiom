//! The client and server over TLS on loopback, under a test certificate authority.
//!
//! The fixtures form one small PKI, written once with OpenSSL:
//!
//! - root.pem: a P-384 root, valid for a century;
//! - an RSA 2048 intermediate, in both chain files after the leaf;
//! - chain-ec.pem: a P-256 leaf signed with RSA-PSS, for localhost, 127.0.0.1 and ::1;
//! - chain-rsa.pem: an RSA 2048 leaf signed with PKCS#1 v1.5, for the same names;
//! - leaf-ec.key in PKCS#8, leaf-ec.sec1 in SEC 1, and leaf-rsa.key in PKCS#1.

use std::{future::Future, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use axiom_http::{
    Client, ClientConfig, Endpoint, HttpError, Method, Request, Response, Router, Server,
    ServerConfig, ServerIdentity, StatusCode, TrustRoots,
};
use axiom_tls::{CertificateError, TlsError, pki::RootStore};
use tokio::{sync::oneshot, task::JoinHandle};

/// Runs a test body on a single-threaded runtime with timers and sockets.
fn run<F: Future<Output = ()>>(test: F) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime builds")
        .block_on(test);
}

/// The path of a fixture file.
fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// The test root alone, so the platform's roots play no part.
fn test_roots() -> TrustRoots {
    let mut store = RootStore::new();
    let pem = std::fs::read(fixture("root.pem")).expect("root fixture");
    let summary = store.add_pem_bundle(&pem).expect("root is PEM");
    assert_eq!(summary.added, 1);
    TrustRoots::from_store(Arc::new(store))
}

/// An https echo server on a free port of an address, under a chain and key.
async fn echo_server(
    bind: &str,
    chain: &str,
    key: &str,
) -> (SocketAddr, oneshot::Sender<()>, JoinHandle<()>) {
    let identity =
        ServerIdentity::from_pem_files(&fixture(chain), &fixture(key)).expect("identity loads");
    let router = Router::new().route(Method::Post, "/echo", |request: Request| async move {
        Response::new(StatusCode::OK).with_body("application/octet-stream", request.body)
    });
    let server = Server::bind(bind, router, ServerConfig::default())
        .await
        .expect("loopback binds")
        .with_tls(identity);
    let address = server.local_addr().expect("bound address");
    let (trigger, signal) = oneshot::channel::<()>();
    let handle = tokio::spawn(server.serve(async {
        let _ = signal.await;
    }));
    (address, trigger, handle)
}

/// A client for a URL that trusts the given roots.
fn client(url: &str, roots: Option<TrustRoots>) -> Client {
    let config = ClientConfig {
        request_timeout: Duration::from_secs(5),
        roots,
        ..ClientConfig::default()
    };
    Client::new(Endpoint::parse(url).expect("URL parses"), config)
}

/// A POST to the echo route with a body.
fn echo(body: Vec<u8>) -> Request {
    let mut request = Request::new(Method::Post, "/echo");
    request.body = body;
    request
}

#[test]
fn ecdsa_server_answers_by_name_and_address() {
    run(async {
        let (address, stop, handle) =
            echo_server("127.0.0.1:0", "chain-ec.pem", "leaf-ec.key").await;
        let port = address.port();

        // The same server reached by DNS name and by IP address, both in its certificate.
        for url in [
            format!("https://localhost:{port}"),
            format!("https://127.0.0.1:{port}"),
        ] {
            let client = client(&url, Some(test_roots()));
            // 100 000 bytes span seven records each way; a second request reuses the connection.
            let body: Vec<u8> = (0..100_000_u32).map(|i| i as u8).collect();
            let first = client.send(&echo(body.clone())).await.expect("first echo");
            let second = client
                .send(&echo(b"again".to_vec()))
                .await
                .expect("second echo");
            assert_eq!(first.status, StatusCode::OK);
            assert_eq!(first.body, body, "{url}");
            assert_eq!(second.body, b"again", "{url}");
        }
        stop.send(()).unwrap();
        handle.await.unwrap();
    });
}

#[test]
fn rsa_server_with_a_pkcs1_key() {
    run(async {
        // The RSA leaf signs its handshake with RSA-PSS; its chain uses PKCS#1 v1.5.
        let (address, stop, handle) =
            echo_server("127.0.0.1:0", "chain-rsa.pem", "leaf-rsa.key").await;
        let client = client(
            &format!("https://localhost:{}", address.port()),
            Some(test_roots()),
        );
        let reply = client.send(&echo(b"rsa".to_vec())).await.expect("echo");
        assert_eq!(reply.body, b"rsa");
        stop.send(()).unwrap();
        handle.await.unwrap();
    });
}

#[test]
fn sec1_keys_load() {
    // The same P-256 key in SEC 1 form serves the same chain.
    let identity =
        ServerIdentity::from_pem_files(&fixture("chain-ec.pem"), &fixture("leaf-ec.sec1"));
    assert!(identity.is_ok());

    // Mutation: the RSA key against the P-256 certificate.
    let mismatch =
        ServerIdentity::from_pem_files(&fixture("chain-ec.pem"), &fixture("leaf-rsa.key"));
    assert_eq!(
        mismatch.unwrap_err(),
        axiom_http::TlsSetupError::Identity(axiom_tls::KeyError::KeyMismatch)
    );
}

#[test]
fn untrusted_root_and_wrong_name_are_refused() {
    run(async {
        // Every loopback address reaches the server, so names outside its certificate can be dialed.
        let (address, stop, handle) = echo_server("0.0.0.0:0", "chain-ec.pem", "leaf-ec.key").await;
        let port = address.port();

        // A store without the test root finds no path.
        let empty = TrustRoots::from_store(Arc::new(RootStore::new()));
        let error = client(&format!("https://localhost:{port}"), Some(empty))
            .send(&echo(Vec::new()))
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                HttpError::Tls(TlsError::Certificate(CertificateError::UnknownIssuer))
            ),
            "{error}"
        );

        // 127.0.0.2 is loopback, but the certificate does not name it.
        let error = client(&format!("https://127.0.0.2:{port}"), Some(test_roots()))
            .send(&echo(Vec::new()))
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                HttpError::Tls(TlsError::Certificate(CertificateError::NotValidForName))
            ),
            "{error}"
        );

        // A plain client gets no HTTP answer from a TLS server.
        let plain = client(&format!("http://localhost:{port}"), None)
            .send(&echo(Vec::new()))
            .await;
        assert!(plain.is_err());

        // The server still answers a good client after those failures.
        let reply = client(&format!("https://localhost:{port}"), Some(test_roots()))
            .send(&echo(b"ok".to_vec()))
            .await
            .expect("echo");
        assert_eq!(reply.body, b"ok");
        stop.send(()).unwrap();
        handle.await.unwrap();
    });
}
