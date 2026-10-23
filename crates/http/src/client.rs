//! The client: requests over a small pool of persistent connections.

use std::{
    sync::{Mutex, PoisonError},
    time::Duration,
};

use tokio::{net::TcpStream, time};

use crate::{
    BodyLength, Endpoint, HttpError, Limits, Method, Request, Response, TrustRoots,
    connection::Connection, transport::Transport,
};

/// How a client connects and what it accepts.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// Longest wait for a TCP connection to open.
    pub connect_timeout: Duration,

    /// Longest wait for a whole exchange, from sending to the last body byte.
    pub request_timeout: Duration,

    /// Bounds on each response.
    pub limits: Limits,

    /// Most idle connections kept open for reuse.
    pub max_idle: usize,

    /// The roots an https server's chain must reach; none means the platform's roots.
    pub roots: Option<TrustRoots>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
            limits: Limits::DEFAULT,
            max_idle: 4,
            roots: None,
        }
    }
}

/// An HTTP/1.1 client bound to one server.
///
/// Connections stay open after each exchange and serve the next request.
/// A pooled connection the server has since closed is detected on use.
/// The request then goes out once more on a fresh connection.
///
/// Requests may run concurrently; each takes its own connection.
#[derive(Debug)]
pub struct Client {
    /// The server.
    endpoint: Endpoint,
    /// Timeouts and bounds.
    config: ClientConfig,
    /// Open connections waiting for a request, most recently used last.
    idle: Mutex<Vec<Connection<Transport>>>,
}

impl Client {
    /// A client for a server, opening no connection until the first request.
    #[must_use]
    pub const fn new(endpoint: Endpoint, config: ClientConfig) -> Self {
        Self {
            endpoint,
            config,
            idle: Mutex::new(Vec::new()),
        }
    }

    /// The server this client talks to.
    #[must_use]
    pub const fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Sends a request under the configured timeout.
    ///
    /// # Errors
    ///
    /// Fails on a timeout, a socket error, or a malformed or oversized response.
    pub async fn send(&self, request: &Request) -> Result<Response, HttpError> {
        self.send_with_timeout(request, self.config.request_timeout)
            .await
    }

    /// Sends a request under an explicit timeout, such as one an API method prescribes.
    ///
    /// # Errors
    ///
    /// Fails on a timeout, a socket error, or a malformed or oversized response.
    pub async fn send_with_timeout(
        &self,
        request: &Request,
        timeout: Duration,
    ) -> Result<Response, HttpError> {
        // Serialize once; a retry resends the same bytes.
        let bytes = request.encode(self.endpoint.authority())?;
        time::timeout(timeout, self.exchange(request.method, &bytes))
            .await
            .map_err(|_| HttpError::Timeout { after: timeout })?
    }

    /// Sends bytes on a pooled connection, falling back to a fresh one if the pooled one is dead.
    async fn exchange(&self, method: Method, bytes: &[u8]) -> Result<Response, HttpError> {
        // A server may close an idle connection at any time; that failure is safe to retry.
        //
        //     pooled conn  -> write ok, read EOF  -> stale, retry
        //     fresh conn   -> any failure         -> reported
        if let Some(connection) = self.take_idle() {
            match self.round_trip(connection, method, bytes).await {
                Err(error) if error.is_stale_connection() => {}
                outcome => return outcome,
            }
        }
        let connection = self.connect().await?;
        self.round_trip(connection, method, bytes).await
    }

    /// Writes one request and reads its response, pooling the connection when it can persist.
    async fn round_trip(
        &self,
        mut connection: Connection<Transport>,
        method: Method,
        bytes: &[u8],
    ) -> Result<Response, HttpError> {
        connection.write(bytes).await?;

        // Skip interim 1xx responses, such as 100 Continue, until the final one.
        // 101 Switching Protocols is final, but this client never asks for an upgrade.
        let head = loop {
            let head = connection.read_response_head().await?;
            if !head.status.is_informational() || head.status.as_u16() == 101 {
                break head;
            }
        };
        let length = head.body_length(method)?;
        let body = connection.read_body(length).await?;

        // Reuse needs a persistent connection, a body with a known end, and no stray bytes.
        // After a 101 the connection speaks another protocol, so it never returns to the pool.
        let reusable = head.keep_alive()
            && length != BodyLength::UntilClose
            && head.status.as_u16() != 101
            && !connection.has_buffered();
        if reusable {
            self.put_idle(connection);
        }
        Ok(Response {
            status: head.status,
            headers: head.headers,
            body,
            stream: None,
        })
    }

    /// Opens a new connection under the connect timeout, which covers the TLS handshake too.
    async fn connect(&self) -> Result<Connection<Transport>, HttpError> {
        let timeout = self.config.connect_timeout;
        let transport = time::timeout(timeout, self.open())
            .await
            .map_err(|_| HttpError::Timeout { after: timeout })??;
        Ok(Connection::new(transport, self.config.limits))
    }

    /// Opens the socket, then runs the TLS handshake for an https endpoint.
    async fn open(&self) -> Result<Transport, HttpError> {
        // Name resolution runs as part of the connect, under the same timeout.
        let address = (self.endpoint.host(), self.endpoint.port());
        let stream = TcpStream::connect(address).await?;
        // Requests are small and latency-bound; Nagle's delay would only add to it.
        stream.set_nodelay(true)?;
        if !self.endpoint.is_tls() {
            return Ok(Transport::Plain(stream));
        }
        let roots = match &self.config.roots {
            Some(roots) => roots.clone(),
            None => TrustRoots::system()?,
        };
        Transport::connect_tls(stream, self.endpoint.host(), roots).await
    }

    /// Takes the most recently used idle connection.
    fn take_idle(&self) -> Option<Connection<Transport>> {
        // No code panics while holding the lock, so poisoning carries no meaning here.
        self.idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop()
    }

    /// Returns a connection to the pool, or drops it when the pool is full.
    fn put_idle(&self, connection: Connection<Transport>) {
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        if idle.len() < self.config.max_idle {
            idle.push(connection);
        }
    }
}
