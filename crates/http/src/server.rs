//! The server: an accept loop, one task per connection, and graceful shutdown.

use std::{future::Future, io, net::SocketAddr, pin::pin, sync::Arc, time::Duration};

use tokio::{
    net::{TcpListener, ToSocketAddrs},
    sync::{Semaphore, watch},
    task::JoinSet,
    time,
};

use crate::{Limits, Router, race::Either, session::Session};

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

            // The session holds the permit, so its slot frees when the connection ends.
            tasks.spawn(
                Session::new(stream, Arc::clone(&router), config, stopped.clone(), permit).run(),
            );
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
