//! Request methods.

use std::fmt;

/// A request method from RFC 9110 section 9.
///
/// The set is closed: a request with any other method gets a 501 reply.
/// CONNECT and TRACE are left out, since neither API serves a proxy or loops a request back.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Method {
    /// Reads a resource.
    Get,

    /// Reads a resource's head only.
    Head,

    /// Submits data, as every JSON-RPC call does.
    Post,

    /// Replaces a resource.
    Put,

    /// Removes a resource.
    Delete,

    /// Asks which methods a resource allows.
    Options,

    /// Partially updates a resource.
    Patch,
}

impl Method {
    /// The method as written on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Options => "OPTIONS",
            Self::Patch => "PATCH",
        }
    }

    /// Reads a method token, which is case-sensitive per RFC 9110 section 9.1.
    #[must_use]
    pub const fn from_bytes(token: &[u8]) -> Option<Self> {
        match token {
            b"GET" => Some(Self::Get),
            b"HEAD" => Some(Self::Head),
            b"POST" => Some(Self::Post),
            b"PUT" => Some(Self::Put),
            b"DELETE" => Some(Self::Delete),
            b"OPTIONS" => Some(Self::Options),
            b"PATCH" => Some(Self::Patch),
            _ => None,
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
