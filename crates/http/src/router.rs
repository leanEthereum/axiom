//! Routing requests to handlers by method and path.

use std::{fmt, future::Future, pin::Pin, sync::Arc};

use crate::{
    Method, Request, Response, StatusCode,
    cors::{Admission, Cors},
};

/// The future a handler returns, boxed so handlers of different types share one table.
type HandlerFuture = Pin<Box<dyn Future<Output = Response> + Send>>;

/// A handler with its concrete type erased.
type BoxedHandler = Arc<dyn Fn(Request) -> HandlerFuture + Send + Sync>;

/// One piece of a path pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Segment {
    /// Matches exactly this text.
    Literal(String),
    /// Matches any one segment and captures it under this name.
    Param(String),
}

/// A pattern, a method, and the handler serving them.
struct Route {
    /// The method served.
    method: Method,
    /// The pattern as written, for debugging.
    pattern: String,
    /// The pattern split on slashes.
    segments: Vec<Segment>,
    /// The handler.
    handler: BoxedHandler,
}

/// A table from method and path pattern to handler.
///
/// A pattern is a path whose segments are literal or a name in braces.
///
/// ```text
///     pattern  /eth/v1/beacon/states/{state_id}/root
///     path     /eth/v1/beacon/states/head/root      -> match, state_id = "head"
///     path     /eth/v1/beacon/states/head           -> no match, one segment short
/// ```
///
/// Captured segments stay percent-encoded, exactly as the path carried them.
/// Routes are tried in insertion order, so a literal route added first shadows a parameter.
#[derive(Default)]
pub struct Router {
    /// Routes in insertion order.
    routes: Vec<Route>,
    /// The cross-origin policy, when browser pages may call the server.
    cors: Option<Cors>,
}

impl Router {
    /// An empty table, which answers every request with 404.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a route.
    ///
    /// A GET route also serves HEAD, and the server drops the body of the reply.
    #[must_use]
    pub fn route<F, Fut>(mut self, method: Method, pattern: &str, handler: F) -> Self
    where
        F: Fn(Request) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Response> + Send + 'static,
    {
        // Split the pattern the same way paths are split, so the counts line up.
        let segments = Route::segments(pattern)
            .map(
                |segment| match segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                    Some(name) => Segment::Param(name.to_owned()),
                    None => Segment::Literal(segment.to_owned()),
                },
            )
            .collect();
        self.routes.push(Route {
            method,
            pattern: pattern.to_owned(),
            segments,
            handler: Arc::new(move |request| Box::pin(handler(request))),
        });
        self
    }

    /// Applies a cross-origin policy to every request.
    #[must_use]
    pub fn with_cors(mut self, cors: Cors) -> Self {
        self.cors = Some(cors);
        self
    }

    /// Runs the handler for a request, or answers 403, 404, or 405.
    ///
    /// The server calls this for every request; tests may call it without a socket.
    pub async fn handle(&self, request: Request) -> Response {
        let Some(cors) = &self.cors else {
            return self.dispatch(request).await;
        };
        match cors.admit(&request) {
            Admission::Pass => self.dispatch(request).await,
            Admission::Refuse(refusal) => refusal,
            Admission::Preflight(origin) => {
                let methods = self.methods(&request.path);
                cors.preflight(&request, &origin, &methods)
            }
            Admission::Serve(origin) => {
                let response = self.dispatch(request).await;
                cors.decorate(response, &origin)
            }
        }
    }

    /// The methods some route serves at a path, in insertion order.
    fn methods(&self, path: &str) -> Vec<Method> {
        let mut methods = Vec::new();
        for route in &self.routes {
            if route.capture(path).is_some() && !methods.contains(&route.method) {
                methods.push(route.method);
            }
        }
        methods
    }

    /// Runs the handler for a request, or answers 404 or 405.
    async fn dispatch(&self, mut request: Request) -> Response {
        let mut allowed = Vec::new();
        let mut fallback = None;
        for route in &self.routes {
            let Some(params) = route.capture(&request.path) else {
                continue;
            };
            // The path matches; the method decides between this route, a fallback, or 405.
            if route.method == request.method {
                request.params = params;
                return (route.handler)(request).await;
            }
            if request.method == Method::Head && route.method == Method::Get && fallback.is_none() {
                fallback = Some((route, params));
            }
            if !allowed.contains(&route.method.as_str()) {
                allowed.push(route.method.as_str());
            }
        }

        // HEAD without its own route borrows the GET handler.
        if let Some((route, params)) = fallback {
            request.params = params;
            return (route.handler)(request).await;
        }

        // A known path with the wrong method lists what it accepts, per RFC 9110 section 15.5.6.
        if allowed.is_empty() {
            Response::new(StatusCode::NOT_FOUND)
        } else {
            Response::new(StatusCode::METHOD_NOT_ALLOWED).with_header("allow", allowed.join(", "))
        }
    }
}

impl Route {
    /// Splits a path on slashes, dropping the leading one.
    ///
    /// ```text
    ///     "/"      -> [""]
    ///     "/a/b"   -> ["a", "b"]
    ///     "/a/"    -> ["a", ""]
    /// ```
    fn segments(path: &str) -> impl Iterator<Item = &str> {
        path.strip_prefix('/').unwrap_or(path).split('/')
    }

    /// The captured parameters, when a path matches the pattern.
    fn capture(&self, path: &str) -> Option<Vec<(String, String)>> {
        let mut params = Vec::new();
        let mut parts = Self::segments(path);
        // Walk pattern and path in step; every segment must pair up.
        for segment in &self.segments {
            let part = parts.next()?;
            match segment {
                Segment::Literal(text) if text == part => {}
                Segment::Literal(_) => return None,
                Segment::Param(name) => params.push((name.clone(), part.to_owned())),
            }
        }
        // A path with segments left over is longer than the pattern.
        parts.next().is_none().then_some(params)
    }
}

impl fmt::Debug for Router {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Handlers are opaque closures; list each route as method and pattern.
        f.debug_list()
            .entries(
                self.routes
                    .iter()
                    .map(|route| format!("{} {}", route.method, route.pattern)),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs a future to completion on a fresh single-threaded runtime.
    fn block_on<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime builds")
            .block_on(future)
    }

    /// A router with one literal and one parameter route.
    fn router() -> Router {
        Router::new()
            .route(Method::Get, "/health", |_| async {
                Response::new(StatusCode::OK).with_body("text/plain", b"up".to_vec())
            })
            .route(
                Method::Get,
                "/states/{id}/root",
                |request: Request| async move {
                    let id = request.param("id").unwrap_or_default().to_owned();
                    Response::new(StatusCode::OK).with_body("text/plain", id.into_bytes())
                },
            )
    }

    #[test]
    fn parameters_are_captured() {
        // "head" fills the id segment and comes back as the body.
        let response = block_on(router().handle(Request::new(Method::Get, "/states/head/root")));
        assert_eq!(
            (response.status, response.body),
            (StatusCode::OK, b"head".to_vec())
        );
    }

    #[test]
    fn misses_and_wrong_methods() {
        // One segment short of the pattern: no route, 404.
        let response = block_on(router().handle(Request::new(Method::Get, "/states/head")));
        assert_eq!(response.status, StatusCode::NOT_FOUND);

        // Right path, wrong method: 405 naming the one allowed method.
        let response = block_on(router().handle(Request::new(Method::Post, "/health")));
        assert_eq!(response.status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers.get("allow"), Some("GET"));

        // HEAD borrows the GET handler.
        let response = block_on(router().handle(Request::new(Method::Head, "/health")));
        assert_eq!(response.status, StatusCode::OK);
    }

    #[test]
    fn a_cors_policy_wraps_every_route() {
        let router = router().with_cors(Cors::parse("http://localhost:3000").unwrap());
        let page =
            |method| Request::new(method, "/health").with_header("origin", "http://localhost:3000");

        // The allowed page reads the reply.
        let response = block_on(router.handle(page(Method::Get)));
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response.headers.get("access-control-allow-origin"),
            Some("http://localhost:3000")
        );

        // Its preflight lists the one method the path serves, without running the handler.
        let preflight = page(Method::Options).with_header("access-control-request-method", "GET");
        let response = block_on(router.handle(preflight));
        assert_eq!(
            (
                response.status,
                response.headers.get("access-control-allow-methods")
            ),
            (StatusCode::OK, Some("GET"))
        );
        assert!(response.body.is_empty());

        // Another page is refused before routing.
        let other =
            Request::new(Method::Get, "/health").with_header("origin", "http://evil.example");
        assert_eq!(block_on(router.handle(other)).status, StatusCode::FORBIDDEN);
    }
}
