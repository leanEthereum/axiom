//! One server connection, serving requests one after another until it closes.

use std::{sync::Arc, time::SystemTime};

use tokio::{
    net::TcpStream,
    sync::{OwnedSemaphorePermit, watch},
    time::{self, Instant},
};

use crate::{
    BodyLength, HttpError, Method, Request, Response, Router, ServerConfig, StatusCode,
    connection::Connection,
    date::HttpDate,
    race::{Either, race},
};

/// The server side of one accepted connection.
///
/// It owns its socket and its slot in the connection limit, so dropping it frees both.
#[derive(Debug)]
pub(crate) struct Session {
    /// The socket and its read buffer.
    connection: Connection<TcpStream>,
    /// The routes, shared by every session.
    router: Arc<Router>,
    /// Timeouts and bounds.
    config: ServerConfig,
    /// Turns true once shutdown begins.
    stopped: watch::Receiver<bool>,
    /// The slot this session holds in the connection limit, released on drop.
    _permit: OwnedSemaphorePermit,
}

impl Session {
    /// Wraps an accepted stream.
    pub(crate) fn new(
        stream: TcpStream,
        router: Arc<Router>,
        config: ServerConfig,
        stopped: watch::Receiver<bool>,
        permit: OwnedSemaphorePermit,
    ) -> Self {
        // Small responses go out at once rather than waiting to coalesce.
        let _ = stream.set_nodelay(true);
        Self {
            connection: Connection::new(stream, config.limits),
            router,
            config,
            stopped,
            _permit: permit,
        }
    }

    /// Serves requests until the connection closes.
    pub(crate) async fn run(mut self) {
        loop {
            // Wait for the next head; an idle connection also yields to shutdown.
            let stopped = &mut self.stopped;
            let waited = race(
                time::timeout(
                    self.config.idle_timeout,
                    self.connection.read_request_head(),
                ),
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
                    self.reject(error.status()).await;
                    return;
                }
                // Clean close, socket error, idle timeout, or shutdown: close quietly.
                _ => return,
            };

            // Framing errors are answered before any body byte is read.
            let length = match head.body_length() {
                Ok(length) => length,
                Err(error) => {
                    self.reject(error.status()).await;
                    return;
                }
            };

            // A client that sent "expect: 100-continue" waits for this go-ahead before its body.
            if length != BodyLength::Empty && head.headers.has_token("expect", "100-continue") {
                let interim = b"HTTP/1.1 100 Continue\r\n\r\n";
                if self.connection.write(interim).await.is_err() {
                    return;
                }
            }

            // Read the body under the I/O timeout.
            let read = time::timeout(self.config.io_timeout, self.connection.read_body(length));
            let body = match read.await {
                Ok(Ok(body)) => body,
                Ok(Err(HttpError::Protocol(error))) => {
                    self.reject(error.status()).await;
                    return;
                }
                Ok(Err(_)) => return,
                Err(_) => {
                    self.reject(StatusCode::REQUEST_TIMEOUT).await;
                    return;
                }
            };

            // Hand the complete request to its handler.
            let head_only = head.method == Method::Head;
            let client_keeps_alive = head.keep_alive();
            let mut request = Request::new(head.method, &head.target);
            request.headers = head.headers;
            request.body = body;
            let mut response = self.router.handle(request).await;

            // Persist only when the client, the handler, and the shutdown flag all allow it.
            let keep_alive = client_keeps_alive
                && !response.headers.has_token("connection", "close")
                && !*self.stopped.borrow();
            if !keep_alive {
                response.headers.insert("connection", "close");
            }
            if !self.send(response, head_only).await || !keep_alive {
                return;
            }
        }
    }

    /// Answers a request the server will not process, then lets the connection close.
    async fn reject(&mut self, status: StatusCode) {
        let response = Response::new(status).with_header("connection", "close");
        self.send(response, false).await;
    }

    /// Writes a response with a date field under the I/O timeout.
    ///
    /// # Returns
    ///
    /// Whether the whole response was written.
    async fn send(&mut self, mut response: Response, head_only: bool) -> bool {
        // RFC 9110 section 6.6.1: a server with a clock dates its responses.
        response
            .headers
            .insert("date", HttpDate::from(SystemTime::now()).to_string());

        // A handler that set an unwritable field yields a bare 500 instead.
        let bytes = match response.encode(head_only) {
            Ok(bytes) => bytes,
            Err(_) => {
                let fallback = Response::new(StatusCode::INTERNAL_SERVER_ERROR)
                    .with_header("connection", "close");
                match fallback.encode(false) {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                }
            }
        };
        let deadline = Instant::now() + self.config.io_timeout;
        matches!(
            time::timeout_at(deadline, self.connection.write(&bytes)).await,
            Ok(Ok(()))
        )
    }
}
