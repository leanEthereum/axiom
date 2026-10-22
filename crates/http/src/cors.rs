//! Cross-origin resource sharing: which web pages may read a server's replies.
//!
//! See the CORS protocol in the WHATWG Fetch standard, section 3.2.

use std::{fmt, net::SocketAddr};

use crate::{HttpError, Method, Request, Response, StatusCode};

/// The origins a browser may let a page read replies from.
#[derive(Clone, Debug, PartialEq, Eq)]
enum AllowedOrigin {
    /// Any origin, as the wildcard allows.
    Any,
    /// One serialized origin, such as `http://localhost:5062`, in lowercase.
    Exact(String),
}

/// A server's cross-origin policy: one allowed origin and the request headers it accepts.
///
/// # Overview
///
/// A browser sends a page's origin with every cross-origin request.
/// The policy answers it in three ways:
///
/// 1. A request without an origin comes from no browser page, so it passes untouched.
/// 2. A request from another origin is refused with 403.
/// 3. A preflight from the allowed origin is answered at once, listing what the route accepts.
///
/// Every other reply to the allowed origin carries the header that lets the page read it.
/// The browser enforces the policy; a server only states it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cors {
    /// The origin allowed.
    origin: AllowedOrigin,
    /// Request headers a page may send, in lowercase.
    headers: Vec<String>,
}

impl Cors {
    /// Header naming the page's origin.
    const ORIGIN: &'static str = "origin";

    /// Header a preflight uses to name the method it plans.
    const REQUEST_METHOD: &'static str = "access-control-request-method";

    /// Header a preflight uses to name the headers it plans.
    const REQUEST_HEADERS: &'static str = "access-control-request-headers";

    /// Reads a policy from the text an operator gives.
    ///
    /// The text is either the wildcard or an origin: a scheme, a host, and an optional port.
    ///
    /// # Errors
    ///
    /// Fails when the text is neither, such as a URL with a path.
    pub fn parse(text: &str) -> Result<Self, HttpError> {
        if text == "*" {
            return Ok(Self::new(AllowedOrigin::Any));
        }
        let invalid = || HttpError::InvalidOrigin {
            origin: text.to_owned(),
        };
        // Schemes and hosts compare without case, per RFC 3986 sections 3.1 and 3.2.2.
        let origin = text.to_ascii_lowercase();
        let (scheme, authority) = origin.split_once("://").ok_or_else(invalid)?;
        // A serialized origin has no path, query, fragment, or credentials, per RFC 6454 section 6.2.
        let well_formed = matches!(scheme, "http" | "https")
            && !authority.is_empty()
            && !authority.contains(['/', '?', '#', '@']);
        if !well_formed {
            return Err(invalid());
        }
        Ok(Self::new(AllowedOrigin::Exact(origin)))
    }

    /// The policy that allows only pages served from a server's own address.
    ///
    /// It is the default when an operator allows no origin.
    #[must_use]
    pub fn local(address: SocketAddr) -> Self {
        Self::new(AllowedOrigin::Exact(format!("http://{address}")))
    }

    /// Lets pages send one more request header, such as the authorization header.
    #[must_use]
    pub fn with_header(mut self, name: &str) -> Self {
        self.headers.push(name.to_ascii_lowercase());
        self
    }

    /// A policy over an origin, accepting the content type header.
    fn new(origin: AllowedOrigin) -> Self {
        Self {
            origin,
            headers: vec!["content-type".to_owned()],
        }
    }

    /// The decision on a request, before any route runs.
    pub(crate) fn admit(&self, request: &Request) -> Admission {
        let Some(origin) = request.headers.get(Self::ORIGIN) else {
            return Admission::Pass;
        };
        let allowed = match &self.origin {
            AllowedOrigin::Any => true,
            AllowedOrigin::Exact(exact) => origin.eq_ignore_ascii_case(exact),
        };
        if !allowed {
            return Admission::Refuse(Self::refusal("origin not allowed"));
        }
        let preflight = request.method == Method::Options
            && request.headers.get(Self::REQUEST_METHOD).is_some();
        if preflight {
            Admission::Preflight(origin.to_owned())
        } else {
            Admission::Serve(origin.to_owned())
        }
    }

    /// The answer to a preflight, given the methods the requested path serves.
    pub(crate) fn preflight(
        &self,
        request: &Request,
        origin: &str,
        methods: &[Method],
    ) -> Response {
        let method = request
            .headers
            .get(Self::REQUEST_METHOD)
            .and_then(|name| Method::from_bytes(name.trim().as_bytes()));
        if !method.is_some_and(|method| methods.contains(&method)) {
            return Self::refusal("method not allowed");
        }
        let unknown_header = request
            .headers
            .get_all(Self::REQUEST_HEADERS)
            .flat_map(|value| value.split(','))
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .any(|name| {
                !self
                    .headers
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(name))
            });
        if unknown_header {
            return Self::refusal("header not allowed");
        }
        let methods: Vec<&str> = methods.iter().map(|method| method.as_str()).collect();
        self.decorate(Response::new(StatusCode::OK), origin)
            .with_header("access-control-allow-methods", methods.join(", "))
            .with_header("access-control-allow-headers", self.headers.join(", "))
    }

    /// Lets the page at an allowed origin read a reply.
    pub(crate) fn decorate(&self, response: Response, origin: &str) -> Response {
        match self.origin {
            AllowedOrigin::Any => response.with_header("access-control-allow-origin", "*"),
            // Why: the reply depends on the origin, so a shared cache must key on it.
            AllowedOrigin::Exact(_) => response
                .with_header("access-control-allow-origin", origin)
                .with_header("vary", "origin"),
        }
    }

    /// The reply to a cross-origin request the policy refuses.
    fn refusal(reason: &str) -> Response {
        Response::new(StatusCode::FORBIDDEN).with_body(
            "text/plain",
            format!("CORS request forbidden: {reason}").into_bytes(),
        )
    }
}

impl fmt::Display for Cors {
    /// Writes the allowed origin as an operator gives it: the wildcard or the origin.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.origin {
            AllowedOrigin::Any => f.write_str("*"),
            AllowedOrigin::Exact(origin) => f.write_str(origin),
        }
    }
}

/// What a policy decides about a request before routing.
#[derive(Debug)]
pub(crate) enum Admission {
    /// No browser page sent it: serve it untouched.
    Pass,
    /// A page at an allowed origin sent it: serve it, then mark the reply readable.
    Serve(String),
    /// A page at an allowed origin asks what it may send.
    Preflight(String),
    /// A page at another origin sent it.
    Refuse(Response),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cross-origin request from a page.
    fn from(origin: &str, method: Method) -> Request {
        Request::new(method, "/eth/v1/keystores").with_header("origin", origin)
    }

    #[test]
    fn only_origins_and_the_wildcard_parse() {
        assert_eq!(Cors::parse("*").unwrap().origin, AllowedOrigin::Any);
        assert_eq!(
            Cors::parse("HTTP://Localhost:5062").unwrap().origin,
            AllowedOrigin::Exact("http://localhost:5062".to_owned())
        );
        // A path, a missing host, credentials, or another scheme is no origin.
        for text in [
            "http://localhost:5062/",
            "http://",
            "localhost:5062",
            "http://user@localhost",
            "ftp://localhost",
        ] {
            assert!(
                matches!(Cors::parse(text), Err(HttpError::InvalidOrigin { origin }) if origin == text),
                "{text}"
            );
        }
    }

    #[test]
    fn a_policy_prints_the_origin_it_allows() {
        // The text round-trips, lowercased, so configuration dumps read back.
        assert_eq!(Cors::parse("*").unwrap().to_string(), "*");
        assert_eq!(
            Cors::parse("HTTP://Localhost:3000").unwrap().to_string(),
            "http://localhost:3000"
        );
        assert_eq!(
            Cors::local("127.0.0.1:5052".parse().unwrap()).to_string(),
            "http://127.0.0.1:5052"
        );
    }

    #[test]
    fn requests_without_an_origin_pass_and_others_are_refused() {
        let cors = Cors::local("127.0.0.1:5062".parse().unwrap());

        // A command line tool sends no origin.
        let plain = Request::new(Method::Get, "/eth/v1/keystores");
        assert!(matches!(cors.admit(&plain), Admission::Pass));

        // The server's own address is allowed; any other page is refused with 403.
        let own = from("http://127.0.0.1:5062", Method::Get);
        assert!(
            matches!(cors.admit(&own), Admission::Serve(origin) if origin == "http://127.0.0.1:5062")
        );
        let Admission::Refuse(refusal) = cors.admit(&from("http://evil.example", Method::Get))
        else {
            panic!("another origin is refused");
        };
        assert_eq!(refusal.status, StatusCode::FORBIDDEN);
        assert_eq!(refusal.body, b"CORS request forbidden: origin not allowed");
    }

    #[test]
    fn a_preflight_lists_the_route_methods_and_the_allowed_headers() {
        let cors = Cors::parse("*").unwrap().with_header("Authorization");
        let request = from("http://dashboard.example", Method::Options)
            .with_header("access-control-request-method", "DELETE")
            .with_header(
                "access-control-request-headers",
                "authorization, content-type",
            );
        let Admission::Preflight(origin) = cors.admit(&request) else {
            panic!("an options request naming a method is a preflight");
        };
        let methods = [Method::Get, Method::Post, Method::Delete];
        let reply = cors.preflight(&request, &origin, &methods);
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.headers.get("access-control-allow-origin"), Some("*"));
        assert_eq!(
            reply.headers.get("access-control-allow-methods"),
            Some("GET, POST, DELETE")
        );
        assert_eq!(
            reply.headers.get("access-control-allow-headers"),
            Some("content-type, authorization")
        );

        // A method the route does not serve, or a header outside the list, is refused.
        let patch = from("http://dashboard.example", Method::Options)
            .with_header("access-control-request-method", "PATCH");
        assert_eq!(
            cors.preflight(&patch, &origin, &methods).body,
            b"CORS request forbidden: method not allowed"
        );
        let header = from("http://dashboard.example", Method::Options)
            .with_header("access-control-request-method", "GET")
            .with_header("access-control-request-headers", "x-secret");
        assert_eq!(
            cors.preflight(&header, &origin, &methods).body,
            b"CORS request forbidden: header not allowed"
        );
    }

    #[test]
    fn an_exact_origin_is_echoed_and_varies_the_cache() {
        let cors = Cors::parse("http://localhost:3000").unwrap();
        let reply = cors.decorate(Response::new(StatusCode::OK), "http://localhost:3000");
        assert_eq!(
            reply.headers.get("access-control-allow-origin"),
            Some("http://localhost:3000")
        );
        assert_eq!(reply.headers.get("vary"), Some("origin"));
    }
}
