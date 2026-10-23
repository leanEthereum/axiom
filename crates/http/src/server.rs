//! The server: an accept loop, one task per connection, and graceful shutdown.

use std::{future::Future, io, net::SocketAddr, pin::pin, sync::Arc, time::Duration};

use tokio::{
    net::{TcpListener, ToSocketAddrs},
    sync::{Semaphore, watch},
    task::JoinSet,
    time,
};

use crate::{Limits, Router, ServerIdentity, race::Either, session::Session, transport::Transport};

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
/// A connection runs in four steps:
///
/// 1. The accept loop hands the new connection to its own task.
/// 2. The task reads the head, then the body.
/// 3. The handler runs, and the task writes its response.
/// 4. On keep-alive, the task goes back to step 2.
///
/// Shutdown runs in three steps:
///
/// 1. The accept loop stops.
/// 2. Idle connections close.
/// 3. Busy connections finish their request, then close.
#[derive(Debug)]
pub struct Server {
    /// The bound socket.
    listener: TcpListener,
    /// The routes, shared by every connection task.
    router: Arc<Router>,
    /// Timeouts and bounds.
    config: ServerConfig,
    /// The certificate and key when serving https.
    tls: Option<ServerIdentity>,
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
            tls: None,
        })
    }

    /// Serves https under an identity: every connection opens with a TLS 1.3 handshake.
    #[must_use]
    pub fn with_tls(mut self, identity: ServerIdentity) -> Self {
        self.tls = Some(identity);
        self
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
            tls,
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
            let permit =
                match Either::race(Arc::clone(&permits).acquire_owned(), shutdown.as_mut()).await {
                    Either::Left(Ok(permit)) => permit,
                    Either::Left(Err(_)) | Either::Right(()) => break,
                };

            // Phase 2: wait for a client, unless shutdown comes first.
            let stream = match Either::race(listener.accept(), shutdown.as_mut()).await {
                Either::Left(Ok((stream, _))) => stream,
                // Accept errors such as a full file table are transient.
                // A short pause keeps the loop from spinning while they last.
                Either::Left(Err(_)) => {
                    time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
                Either::Right(()) => break,
            };

            // Small responses go out at once rather than waiting to coalesce.
            let _ = stream.set_nodelay(true);
            // The session holds the permit, so its slot frees when the connection ends.
            // The TLS handshake runs in the connection's own task, under the I/O timeout.
            let (router, stopped, tls) = (Arc::clone(&router), stopped.clone(), tls.clone());
            tasks.spawn(async move {
                let transport = match tls {
                    None => Transport::Plain(stream),
                    Some(identity) => {
                        let handshake = Transport::accept_tls(stream, &identity);
                        match time::timeout(config.io_timeout, handshake).await {
                            Ok(Ok(transport)) => transport,
                            // A failed or slow handshake closes the connection quietly.
                            _ => return,
                        }
                    }
                };
                Session::new(transport, router, config, stopped, permit)
                    .run()
                    .await;
            });
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
