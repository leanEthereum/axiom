//! The address of a server, read from an http or https URL.

use crate::HttpError;

/// Where a client sends its requests, and whether over TLS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// Whether the URL is https.
    tls: bool,
    /// Host name or address, without the brackets of an IPv6 literal.
    host: String,
    /// TCP port.
    port: u16,
    /// Value of the host field: the authority as the URL wrote it.
    authority: String,
    /// Path and query, starting with a slash.
    path: String,
}

impl Endpoint {
    /// Reads an http or https URL.
    ///
    /// ```text
    ///     http://localhost:8551          host localhost,  port 8551, path /
    ///     http://[::1]/engine            host ::1,        port 80,   path /engine
    ///     https://relay.example/a?b=c    host relay.example, port 443, path /a?b=c, TLS
    /// ```
    ///
    /// # Errors
    ///
    /// Fails on any other scheme, on user information, on an empty host, and on a bad port.
    pub fn parse(url: &str) -> Result<Self, HttpError> {
        // The scheme is case-insensitive per RFC 3986 section 3.1.
        let (tls, rest) = if url
            .get(..7)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http://"))
        {
            (false, &url[7..])
        } else if url
            .get(..8)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))
        {
            (true, &url[8..])
        } else {
            return Err(HttpError::InvalidUrl);
        };

        // The authority runs to the first slash or question mark.
        let split = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, path) = rest.split_at(split);
        let path = match path {
            "" => "/".to_owned(),
            path if path.starts_with('?') => format!("/{path}"),
            path => path.to_owned(),
        };

        // Credentials in a URL would leak into logs; JWT carries authentication instead.
        if authority.contains('@') {
            return Err(HttpError::InvalidUrl);
        }

        // An IPv6 literal sits in brackets, so its colons are not the port separator.
        let (host, port) = if let Some(literal) = authority.strip_prefix('[') {
            let (host, after) = literal.split_once(']').ok_or(HttpError::InvalidUrl)?;
            (host, after.strip_prefix(':'))
        } else {
            match authority.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            }
        };
        if host.is_empty() {
            return Err(HttpError::InvalidUrl);
        }

        // The default ports are 80 for http and 443 for https, per RFC 9110, sections 4.2.1 and 4.2.2.
        let port = match port {
            None if tls => 443,
            None => 80,
            Some(digits) if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) => {
                digits.parse().map_err(|_| HttpError::InvalidUrl)?
            }
            Some(_) => return Err(HttpError::InvalidUrl),
        };

        Ok(Self {
            tls,
            host: host.to_owned(),
            port,
            authority: authority.to_owned(),
            path,
        })
    }

    /// Whether requests go over TLS.
    #[must_use]
    pub const fn is_tls(&self) -> bool {
        self.tls
    }

    /// Host name or address.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// TCP port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The authority, as sent in the host field.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// Path and query, starting with a slash.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_forms() {
        // Each URL maps to host, port, authority, and path.
        let cases = [
            (
                "http://localhost:8551",
                "localhost",
                8551,
                "localhost:8551",
                "/",
            ),
            ("HTTP://[::1]/engine", "::1", 80, "[::1]", "/engine"),
            ("http://[::1]:9/", "::1", 9, "[::1]:9", "/"),
            (
                "http://10.0.0.1:5052/a?b=c",
                "10.0.0.1",
                5052,
                "10.0.0.1:5052",
                "/a?b=c",
            ),
            ("http://h?x", "h", 80, "h", "/?x"),
            (
                "https://relay.example",
                "relay.example",
                443,
                "relay.example",
                "/",
            ),
            ("HTTPS://[::1]:9443/x", "::1", 9443, "[::1]:9443", "/x"),
        ];
        for (url, host, port, authority, path) in cases {
            let endpoint = Endpoint::parse(url).unwrap();
            assert_eq!(
                (
                    endpoint.host(),
                    endpoint.port(),
                    endpoint.authority(),
                    endpoint.path()
                ),
                (host, port, authority, path),
                "{url}"
            );
        }
    }

    #[test]
    fn rejected_forms() {
        // Other schemes, credentials, empty hosts, and bad ports are all refused.
        for url in [
            "ftp://localhost",
            "https:/localhost",
            "http://user:pw@host",
            "http://:80",
            "http://host:",
            "http://host:65536",
            "http://host:8a",
            "http://[::1",
        ] {
            assert!(
                matches!(Endpoint::parse(url), Err(HttpError::InvalidUrl)),
                "{url}"
            );
        }
    }
}
