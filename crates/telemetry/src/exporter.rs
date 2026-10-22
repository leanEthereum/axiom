//! The HTTP endpoint a Prometheus server scrapes.

use std::{future::Future, io, net::SocketAddr};

use axiom_http::{Cors, Method, Response, Router, Server, ServerConfig, StatusCode};

use crate::metrics::{CONTENT_TYPE, Registry};

/// The path scrapers request by convention.
const METRICS_PATH: &str = "/metrics";

/// A bound server that answers scrapes with the current registry contents.
///
/// ```text
///     GET /metrics   -> 200, text format 0.0.4
///     anything else  -> 404 or 405
/// ```
#[derive(Debug)]
pub struct MetricsServer {
    /// The bound HTTP server.
    server: Server,
}

impl MetricsServer {
    /// Binds a listening socket; port zero picks a free port.
    ///
    /// # Errors
    ///
    /// Fails when the address cannot be bound.
    pub async fn bind(address: SocketAddr, registry: Registry) -> io::Result<Self> {
        Self::bind_router(address, Self::router(registry)).await
    }

    /// Binds a listening socket whose replies browser pages at the policy's origin may read.
    ///
    /// # Errors
    ///
    /// Fails when the address cannot be bound.
    pub async fn bind_with_cors(
        address: SocketAddr,
        registry: Registry,
        cors: Cors,
    ) -> io::Result<Self> {
        Self::bind_router(address, Self::router(registry).with_cors(cors)).await
    }

    /// The single route that renders the registry.
    fn router(registry: Registry) -> Router {
        // Each scrape renders afresh, so the reply reflects the values at that instant.
        Router::new().route(Method::Get, METRICS_PATH, move |_| {
            let body = registry.render().into_bytes();
            async move { Response::new(StatusCode::OK).with_body(CONTENT_TYPE, body) }
        })
    }

    /// Binds a socket serving a router.
    async fn bind_router(address: SocketAddr, router: Router) -> io::Result<Self> {
        let server = Server::bind(address, router, ServerConfig::default()).await?;
        Ok(Self { server })
    }

    /// The address the socket is bound to.
    ///
    /// # Errors
    ///
    /// Fails when the operating system cannot report it.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        // The listener knows the port the system picked for a zero request.
        self.server.local_addr()
    }

    /// Serves scrapes until a shutdown future completes, then drains.
    pub async fn serve(self, shutdown: impl Future<Output = ()>) {
        // The HTTP server owns the accept loop and the graceful drain.
        self.server.serve(shutdown).await;
    }
}
