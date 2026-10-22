//! The server: an accept loop, one task per connection, and graceful shutdown.

use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::pin,
    sync::Arc,
    time::{Duration, SystemTime},
};

use tokio::{
    net::{TcpListener, TcpStream, ToSocketAddrs},
    sync::{OwnedSemaphorePermit, Semaphore, watch},
    task::JoinSet,
    time::{self, Instant},
};

use crate::{
    BodyLength, HttpError, Limits, Method, Request, Response, Router, StatusCode,
    connection::Connection,
    date::http_date,
    race::{Either, race},
};

/// How a server treats its connections.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerConfig {
    /// Bounds on each request.
    pub limits: Limits,

    /// Longest wait for the next request head on an open connection.
    ///
    /// It also closes the gap a slow client could hold open by trickling a head.
    pub idle_timeout: Duration,

    /// Longest wait for a request body once its head has arrived, and for a response to be written.
    pub io_timeout: Duration,

    /// Most connections served at once; further clients wait in the listen backlog.
    pub max_connections: usize,

    /// Longest wait for in-flight requests to finish once shutdown begins.
    pub shutdown_grace: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            limits: Limits::DEFAULT,
            idle_timeout: Duration::from_secs(60),
            io_timeout: Duration::from_secs(30),
            max_connections: 256,
            shutdown_grace: Duration::from_secs(10),
        }
    }
}

/// A listening HTTP/1.1 server.
///
/// # Overview
///
/// Each connection runs in its own task and serves requests one after another.
/// Shutdown stops accepting, lets each in-flight request finish, then closes.
///
/// ```text
///     accept loop ── conn task ── read head ─ read body ─ handler ─ write ─┐
///                                    ^                                     │
///                                    └──────────── keep-alive ─────────────┘
///     shutdown:  accept stops -> idle conns close -> busy conns finish, then close
/// ```
#[derive(Debug)]
pub struct Server {
    /// The bound socket.
    listener: TcpListener,
    /// The routes, shared by every connection task.
    router: Arc<Router>,
    /// Timeouts and bounds.
    config: ServerConfig,
}

impl Server {
    /// Binds a listening socket; port zero picks a free port.
    ///
    /// # Errors
    ///
    /// Fails when the address cannot be bound.
    pub async fn bind(
        address: impl ToSocketAddrs,
        router: Router,
        config: ServerConfig,
    ) -> io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(address).await?,
            router: Arc::new(router),
            config,
        })
    }

    /// The address the socket is bound to.
    ///
    /// # Errors
    ///
    /// Fails when the operating system cannot report it.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Serves connections until a shutdown future completes, then drains.
    ///
    /// # Returns
    ///
    /// Once every connection has closed, or the grace period has passed.
    pub async fn serve(self, shutdown: impl Future<Output = ()>) {
        let Self {
            listener,
            router,
            config,
        } = self;
        let mut shutdown = pin!(shutdown);

        // One flag tells every connection task that shutdown has begun.
        let (stop, stopped) = watch::channel(false);
        // Each connection holds a permit; at the limit, accepting pauses until one closes.
        let permits = Arc::new(Semaphore::new(config.max_connections));
        let mut tasks = JoinSet::new();

        loop {
            // Reap finished connections so the task set stays as small as the live set.
            while tasks.try_join_next().is_some() {}

            // Phase 1: wait for a free slot, unless shutdown comes first.
            let permit = match race(Arc::clone(&permits).acquire_owned(), shutdown.as_mut()).await {
                Either::Left(Ok(permit)) => permit,
                Either::Left(Err(_)) | Either::Right(()) => break,
            };

            // Phase 2: wait for a client, unless shutdown comes first.
            let stream = match race(listener.accept(), shutdown.as_mut()).await {
                Either::Left(Ok((stream, _))) => stream,
                // Accept errors such as a full file table are transient.
                // A short pause keeps the loop from spinning while they last.
                Either::Left(Err(_)) => {
                    time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
                Either::Right(()) => break,
            };

            tasks.spawn(serve_connection(
                stream,
                Arc::clone(&router),
                config,
                stopped.clone(),
                permit,
            ));
        }

        // Shutdown: refuse new clients, then tell every connection to finish up.
        drop(listener);
        stop.send_replace(true);

        // Drain within the grace period, then cut whatever remains.
        let drain = async { while tasks.join_next().await.is_some() {} };
        if time::timeout(config.shutdown_grace, drain).await.is_err() {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
    }
}

/// Serves requests on one connection until it closes.
async fn serve_connection(
    stream: TcpStream,
    router: Arc<Router>,
    config: ServerConfig,
    mut stopped: watch::Receiver<bool>,
    _permit: OwnedSemaphorePermit,
) {
    // Small responses go out at once rather than waiting to coalesce.
    let _ = stream.set_nodelay(true);
    let mut connection = Connection::new(stream, config.limits);

    loop {
        // Wait for the next head; an idle connection also yields to shutdown.
        let waited = race(
            time::timeout(config.idle_timeout, connection.read_request_head()),
            // The guard the wait returns is dropped at once; only the event matters.
            async {
                let _ = stopped.wait_for(|stop| *stop).await;
            },
        )
        .await;
        let head = match waited {
            // A complete head.
            Either::Left(Ok(Ok(Some(head)))) => head,
            // A malformed head gets the matching status, then the connection closes.
            Either::Left(Ok(Err(HttpError::Protocol(error)))) => {
                reject(&mut connection, error.status(), config.io_timeout).await;
                return;
            }
            // Clean close, socket error, idle timeout, or shutdown: close quietly.
            _ => return,
        };

        // Framing errors are answered before any body byte is read.
        let length = match head.body_length() {
            Ok(length) => length,
            Err(error) => {
                reject(&mut connection, error.status(), config.io_timeout).await;
                return;
            }
        };

        // A client that sent "expect: 100-continue" waits for this go-ahead before its body.
        if length != BodyLength::Empty && head.headers.has_token("expect", "100-continue") {
            let interim = b"HTTP/1.1 100 Continue\r\n\r\n";
            if connection.write(interim).await.is_err() {
                return;
            }
        }

        // Read the body under the I/O timeout.
        let body = match time::timeout(config.io_timeout, connection.read_body(length)).await {
            Ok(Ok(body)) => body,
            Ok(Err(HttpError::Protocol(error))) => {
                reject(&mut connection, error.status(), config.io_timeout).await;
                return;
            }
            Ok(Err(_)) => return,
            Err(_) => {
                reject(
                    &mut connection,
                    StatusCode::REQUEST_TIMEOUT,
                    config.io_timeout,
                )
                .await;
                return;
            }
        };

        // Hand the complete request to its handler.
        let head_only = head.method == Method::Head;
        let client_keeps_alive = head.keep_alive();
        let mut request = Request::new(head.method, &head.target);
        request.headers = head.headers;
        request.body = body;
        let mut response = router.handle(request).await;

        // Persist only when the client, the handler, and the shutdown flag all allow it.
        let keep_alive = client_keeps_alive
            && !response.headers.has_token("connection", "close")
            && !*stopped.borrow();
        if !keep_alive {
            response.headers.insert("connection", "close");
        }
        if !send(&mut connection, response, head_only, config.io_timeout).await || !keep_alive {
            return;
        }
    }
}

/// Answers a request the server will not process, then lets the connection close.
async fn reject(connection: &mut Connection<TcpStream>, status: StatusCode, timeout: Duration) {
    let response = Response::new(status).with_header("connection", "close");
    send(connection, response, false, timeout).await;
}

/// Writes a response with a date field under a timeout.
///
/// # Returns
///
/// Whether the whole response was written.
async fn send(
    connection: &mut Connection<TcpStream>,
    mut response: Response,
    head_only: bool,
    timeout: Duration,
) -> bool {
    // RFC 9110 section 6.6.1: a server with a clock dates its responses.
    response
        .headers
        .insert("date", http_date(SystemTime::now()));

    // A handler that set an unwritable field yields a bare 500 instead.
    let bytes = match response.encode(head_only) {
        Ok(bytes) => bytes,
        Err(_) => {
            let fallback =
                Response::new(StatusCode::INTERNAL_SERVER_ERROR).with_header("connection", "close");
            match fallback.encode(false) {
                Ok(bytes) => bytes,
                Err(_) => return false,
            }
        }
    };
    let deadline = Instant::now() + timeout;
    matches!(
        time::timeout_at(deadline, connection.write(&bytes)).await,
        Ok(Ok(()))
    )
}
