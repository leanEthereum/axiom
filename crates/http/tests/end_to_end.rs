//! The client and server over real loopback sockets.
//!
//! Hand-written peers on raw sockets pin down exact bytes and connection reuse.

use std::{
    future::Future,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axiom_http::{
    Client, ClientConfig, Endpoint, HttpError, Limits, Method, ProtocolError, Request, Response,
    Router, Server, ServerConfig, StatusCode,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time,
};

/// Runs a test body on a single-threaded runtime with timers and sockets.
fn run<F: Future<Output = ()>>(test: F) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime builds")
        .block_on(test);
}

/// A client for a loopback address with a short timeout.
fn client(address: SocketAddr, limits: Limits) -> Client {
    let endpoint = Endpoint::parse(&format!("http://{address}")).expect("loopback URL parses");
    let config = ClientConfig {
        request_timeout: Duration::from_secs(2),
        limits,
        ..ClientConfig::default()
    };
    Client::new(endpoint, config)
}

/// Reads from a raw socket until a full request head and its fixed body have arrived.
async fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        // Stop once the head is in and the declared body length is satisfied.
        if let Some(end) = bytes.windows(4).position(|four| four == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .map_or(0, |value| {
                    value.trim().parse::<usize>().expect("decimal length")
                });
            if bytes.len() >= end + 4 + length {
                return bytes;
            }
        }
        let mut chunk = [0; 1024];
        let read = stream.read(&mut chunk).await.expect("socket reads");
        assert_ne!(read, 0, "peer closed mid-request");
        bytes.extend_from_slice(&chunk[..read]);
    }
}

/// An echo server on a free port, with a shutdown trigger.
async fn echo_server(config: ServerConfig) -> (SocketAddr, oneshot::Sender<()>, JoinHandle<()>) {
    let router = Router::new()
        .route(Method::Post, "/echo", |request: Request| async move {
            Response::new(StatusCode::OK).with_body("application/octet-stream", request.body)
        })
        .route(Method::Get, "/slow", |_| async {
            // Long enough for a shutdown to arrive while the handler runs.
            time::sleep(Duration::from_millis(200)).await;
            Response::new(StatusCode::OK).with_body("text/plain", b"done".to_vec())
        });
    let server = Server::bind("127.0.0.1:0", router, config)
        .await
        .expect("loopback binds");
    let address = server.local_addr().expect("bound address");
    let (trigger, signal) = oneshot::channel::<()>();
    let handle = tokio::spawn(server.serve(async {
        let _ = signal.await;
    }));
    (address, trigger, handle)
}

#[test]
fn client_reuses_one_connection_and_decodes_chunked() {
    run(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        // The peer accepts once and answers two requests on that one socket.
        // The second answer is chunked: "hel" + "lo".
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_request(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\none")
                .await
                .unwrap();
            read_request(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n3\r\nhel\r\n2\r\nlo\r\n0\r\n\r\n")
                .await
                .unwrap();
            // A third connection attempt would show the pool failed; none arrives.
            let again = time::timeout(Duration::from_millis(100), listener.accept()).await;
            assert!(again.is_err(), "client opened a second connection");
        });

        let client = client(address, Limits::DEFAULT);
        let first = client.send(&Request::new(Method::Get, "/a")).await.unwrap();
        let second = client.send(&Request::new(Method::Get, "/b")).await.unwrap();
        assert_eq!(first.body, b"one");
        assert_eq!(second.body, b"hello");
        peer.await.unwrap();
    });
}

#[test]
fn client_retries_a_connection_the_server_closed() {
    run(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        // Connection 1 answers once with keep-alive, then the peer drops it.
        // Connection 2 answers the retried request.
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_request(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 1\r\n\r\n1")
                .await
                .unwrap();
            drop(stream);

            let (mut stream, _) = listener.accept().await.unwrap();
            read_request(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 1\r\n\r\n2")
                .await
                .unwrap();
        });

        let client = client(address, Limits::DEFAULT);
        let first = client.send(&Request::new(Method::Get, "/")).await.unwrap();
        // Give the close time to reach the client's socket.
        time::sleep(Duration::from_millis(50)).await;
        let second = client.send(&Request::new(Method::Get, "/")).await.unwrap();
        assert_eq!((first.body, second.body), (b"1".to_vec(), b"2".to_vec()));
        peer.await.unwrap();
    });
}

#[test]
fn client_enforces_timeout_and_body_limit() {
    run(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        // Connection 1 never answers; connection 2 announces a body over the limit.
        let peer = tokio::spawn(async move {
            let (mut silent, _) = listener.accept().await.unwrap();
            read_request(&mut silent).await;
            let (mut large, _) = listener.accept().await.unwrap();
            read_request(&mut large).await;
            large
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 1000\r\n\r\n")
                .await
                .unwrap();
            // Hold the silent socket open until the client gives up on it.
            time::sleep(Duration::from_millis(100)).await;
            drop(silent);
        });

        let limits = Limits {
            max_body_bytes: 999,
            ..Limits::DEFAULT
        };
        let client = client(address, limits);
        let request = Request::new(Method::Get, "/");

        // 50 ms pass without a byte of response.
        let timed_out = client
            .send_with_timeout(&request, Duration::from_millis(50))
            .await;
        assert!(matches!(
            timed_out,
            Err(HttpError::Timeout { after }) if after == Duration::from_millis(50)
        ));

        // 1000 declared bytes against a 999-byte limit.
        let too_large = client.send(&request).await;
        assert!(matches!(
            too_large,
            Err(HttpError::Protocol(ProtocolError::BodyTooLarge {
                size: 1000,
                limit: 999
            }))
        ));
        peer.await.unwrap();
    });
}

#[test]
fn client_and_server_round_trip() {
    run(async {
        let (address, trigger, handle) = echo_server(ServerConfig::default()).await;
        let client = client(address, Limits::DEFAULT);

        // Three requests share one pooled connection; each body comes back unchanged.
        for body in [b"a".to_vec(), Vec::new(), vec![7; 100_000]] {
            let request = Request::new(Method::Post, "/echo")
                .with_body("application/octet-stream", body.clone());
            let response = client.send(&request).await.unwrap();
            assert_eq!(response.status, StatusCode::OK);
            assert_eq!(response.body, body);
            assert!(response.headers.get("date").is_some());
        }

        // The router's 404 and 405 travel back as statuses.
        let missing = client
            .send(&Request::new(Method::Get, "/nope"))
            .await
            .unwrap();
        assert_eq!(missing.status, StatusCode::NOT_FOUND);
        let wrong = client
            .send(&Request::new(Method::Get, "/echo"))
            .await
            .unwrap();
        assert_eq!(wrong.status, StatusCode::METHOD_NOT_ALLOWED);

        trigger.send(()).unwrap();
        handle.await.unwrap();
    });
}

#[test]
fn server_serves_pipelined_requests_and_rejects_bad_ones() {
    run(async {
        let config = ServerConfig {
            limits: Limits {
                max_body_bytes: 10,
                ..Limits::DEFAULT
            },
            ..ServerConfig::default()
        };
        let (address, trigger, handle) = echo_server(config).await;

        // Two requests in one write; both responses come back in order on the same socket.
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"POST /echo HTTP/1.1\r\ncontent-length: 1\r\n\r\nAPOST /echo HTTP/1.1\r\ncontent-length: 1\r\nconnection: close\r\n\r\nB")
            .await
            .unwrap();
        let mut replies = String::new();
        stream.read_to_string(&mut replies).await.unwrap();
        let bodies: Vec<&str> = replies
            .split("HTTP/1.1 200 OK\r\n")
            .skip(1)
            .map(|reply| reply.rsplit("\r\n\r\n").next().unwrap())
            .collect();
        assert_eq!(bodies, ["A", "B"]);

        // Each malformed request gets its status, then the server closes the socket.
        let cases: [(&[u8], &str); 4] = [
            (
                b"GET / HTTP/1.1\r\nbad header\r\n\r\n",
                "HTTP/1.1 400 Bad Request\r\n",
            ),
            (
                b"BREW / HTTP/1.1\r\n\r\n",
                "HTTP/1.1 501 Not Implemented\r\n",
            ),
            (
                b"POST /echo HTTP/1.1\r\ncontent-length: 11\r\n\r\n",
                "HTTP/1.1 413 Content Too Large\r\n",
            ),
            (
                b"POST /echo HTTP/1.1\r\ncontent-length: 1\r\ntransfer-encoding: chunked\r\n\r\n",
                "HTTP/1.1 400 Bad Request\r\n",
            ),
        ];
        for (request, status_line) in cases {
            let mut stream = TcpStream::connect(address).await.unwrap();
            stream.write_all(request).await.unwrap();
            let mut reply = String::new();
            stream.read_to_string(&mut reply).await.unwrap();
            assert!(reply.starts_with(status_line), "{reply}");
            assert!(reply.contains("connection: close\r\n"), "{reply}");
        }

        trigger.send(()).unwrap();
        handle.await.unwrap();
    });
}

#[test]
fn server_answers_expect_continue() {
    run(async {
        let (address, trigger, handle) = echo_server(ServerConfig::default()).await;

        // The client sends only the head and waits for the go-ahead before the body.
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"POST /echo HTTP/1.1\r\nexpect: 100-continue\r\ncontent-length: 2\r\nconnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut interim = [0; 25];
        stream.read_exact(&mut interim).await.unwrap();
        assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");

        // Then the body goes out and the echo comes back.
        stream.write_all(b"hi").await.unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).await.unwrap();
        assert!(reply.starts_with("HTTP/1.1 200 OK\r\n") && reply.ends_with("\r\n\r\nhi"));

        trigger.send(()).unwrap();
        handle.await.unwrap();
    });
}

#[test]
fn shutdown_finishes_in_flight_requests() {
    run(async {
        let (address, trigger, handle) = echo_server(ServerConfig::default()).await;
        let client = Arc::new(client(address, Limits::DEFAULT));

        // Start a 200 ms request, then signal shutdown 50 ms into it.
        let started = Arc::new(AtomicUsize::new(0));
        let in_flight = {
            let client = Arc::clone(&client);
            let started = Arc::clone(&started);
            tokio::spawn(async move {
                started.fetch_add(1, Ordering::SeqCst);
                client.send(&Request::new(Method::Get, "/slow")).await
            })
        };
        time::sleep(Duration::from_millis(50)).await;
        assert_eq!(started.load(Ordering::SeqCst), 1);
        trigger.send(()).unwrap();

        // The slow request still completes, told that the connection will close.
        let response = in_flight.await.unwrap().unwrap();
        assert_eq!(response.body, b"done");
        assert_eq!(response.headers.get("connection"), Some("close"));

        // The server returns once drained, and the port no longer accepts.
        handle.await.unwrap();
        assert!(TcpStream::connect(address).await.is_err());
    });
}
