//! Response status codes.

use std::fmt;

/// A three-digit response status code, from 100 to 999.
///
/// RFC 9110 section 15 defines the classes by the first digit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StatusCode(u16);

impl StatusCode {
    /// 100: the client may send the body it announced.
    pub const CONTINUE: Self = Self(100);
    /// 200: the request succeeded.
    pub const OK: Self = Self(200);
    /// 202: the request was accepted for later processing.
    pub const ACCEPTED: Self = Self(202);
    /// 204: the request succeeded with nothing to return.
    pub const NO_CONTENT: Self = Self(204);
    /// 206: part of the resource, or in the beacon API, a node still syncing.
    pub const PARTIAL_CONTENT: Self = Self(206);
    /// 400: the request is malformed.
    pub const BAD_REQUEST: Self = Self(400);
    /// 401: the request lacks valid credentials.
    pub const UNAUTHORIZED: Self = Self(401);
    /// 403: the credentials do not grant access.
    pub const FORBIDDEN: Self = Self(403);
    /// 404: no resource at this path.
    pub const NOT_FOUND: Self = Self(404);
    /// 405: the resource exists but not for this method.
    pub const METHOD_NOT_ALLOWED: Self = Self(405);
    /// 406: no representation matches what the client accepts.
    pub const NOT_ACCEPTABLE: Self = Self(406);
    /// 408: the request took too long to arrive.
    pub const REQUEST_TIMEOUT: Self = Self(408);
    /// 413: the body is larger than the server accepts.
    pub const CONTENT_TOO_LARGE: Self = Self(413);
    /// 415: the body's media type is not accepted.
    pub const UNSUPPORTED_MEDIA_TYPE: Self = Self(415);
    /// 431: the head is larger than the server accepts.
    pub const REQUEST_HEADER_FIELDS_TOO_LARGE: Self = Self(431);
    /// 500: the server failed while handling the request.
    pub const INTERNAL_SERVER_ERROR: Self = Self(500);
    /// 501: the server does not support the method or framing.
    pub const NOT_IMPLEMENTED: Self = Self(501);
    /// 503: the server cannot handle the request right now.
    pub const SERVICE_UNAVAILABLE: Self = Self(503);
    /// 505: the server does not support the protocol version.
    pub const HTTP_VERSION_NOT_SUPPORTED: Self = Self(505);

    /// A code, when it has three digits.
    #[must_use]
    pub const fn new(code: u16) -> Option<Self> {
        if code >= 100 && code <= 999 {
            Some(Self(code))
        } else {
            None
        }
    }

    /// The numeric code.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Whether the code is in the 2xx success class.
    #[must_use]
    pub const fn is_success(self) -> bool {
        self.0 >= 200 && self.0 < 300
    }

    /// Whether the code is in the 1xx informational class.
    #[must_use]
    pub const fn is_informational(self) -> bool {
        self.0 < 200
    }

    /// The reason phrase RFC 9110 suggests, or an empty phrase for unlisted codes.
    ///
    /// Recipients ignore the phrase, so an empty one is valid.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self.0 {
            100 => "Continue",
            200 => "OK",
            202 => "Accepted",
            204 => "No Content",
            206 => "Partial Content",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            406 => "Not Acceptable",
            408 => "Request Timeout",
            413 => "Content Too Large",
            415 => "Unsupported Media Type",
            431 => "Request Header Fields Too Large",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            503 => "Service Unavailable",
            505 => "HTTP Version Not Supported",
            _ => "",
        }
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.0, self.reason())
    }
}
