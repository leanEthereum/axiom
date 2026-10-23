//! Errors of the builder API client.

use std::fmt;

use axiom_beacon_json::ApiJsonError;
use axiom_http::{HttpError, Response, StatusCode};
use axiom_json::{Json, ParseError};
use axiom_ssz::DecodeError;
use axiom_types::ForkName;
use thiserror::Error;

use crate::{BidError, RevealError};

/// A builder API call that did not produce a usable result.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BuilderError {
    /// The relay URL is not an http or https URL, with an optional builder key as user name.
    #[error("relay URL {url:?} is not of the form http://[0x<builder key>@]host[:port][/path]")]
    InvalidUrl {
        /// The URL as configured.
        url: String,
    },

    /// The HTTP exchange failed: connection, timeout, or framing.
    #[error("relay transport: {0}")]
    Http(#[from] HttpError),

    /// The relay answered with an unexpected status.
    #[error("relay replied with HTTP status {status}: {message}")]
    Status {
        /// The status.
        status: StatusCode,
        /// The relay's error message, or the start of its body.
        message: String,
    },

    /// The response body is not JSON.
    #[error("relay response is not JSON: {0}")]
    Json(#[source] ParseError),

    /// The response body does not decode as the fork's SSZ container.
    #[error("relay response is not the fork's SSZ container: {0}")]
    Ssz(#[source] DecodeError),

    /// An SSZ response does not name its fork in the consensus version header.
    #[error("relay SSZ response lacks the eth-consensus-version header")]
    MissingVersionHeader,

    /// A required member of the response envelope is absent or not a string.
    #[error("relay response lacks the {member} member")]
    MissingMember {
        /// The member's name.
        member: &'static str,
    },

    /// The response names a fork this client does not know.
    #[error("relay response names unknown version {version:?}")]
    UnknownVersion {
        /// The version string.
        version: String,
    },

    /// The response belongs to another fork than the request.
    #[error("relay answered with a {actual} response to a {expected} request")]
    Version {
        /// The fork of the request.
        expected: ForkName,
        /// The fork the response names.
        actual: ForkName,
    },

    /// The data does not map onto the fork's container.
    #[error("relay response data is malformed: {0}")]
    Decode(#[from] ApiJsonError),

    /// The fork has no builder API: before the merge, or once Gloas enshrines the bid.
    #[error("the {fork} fork has no builder API")]
    NoBuilderApi {
        /// The fork asked for.
        fork: ForkName,
    },

    /// The relay's bid failed verification.
    #[error("relay bid refused: {0}")]
    Bid(#[from] BidError),

    /// The relay's revealed payload does not complete the block.
    #[error("relay reveal refused: {0}")]
    Reveal(#[from] RevealError),

    /// Every relay asked failed.
    #[error("every relay failed: {0}")]
    AllRelaysFailed(RelayFailures),
}

/// One relay's failure within a call to several relays.
#[derive(Debug, Error)]
#[error("{relay}: {error}")]
pub struct RelayFailure {
    /// The relay's URL.
    pub relay: String,

    /// What went wrong.
    #[source]
    pub error: BuilderError,
}

/// The failures of every relay asked, in relay order.
#[derive(Debug, Default)]
pub struct RelayFailures(pub Vec<RelayFailure>);

impl fmt::Display for RelayFailures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("no relay configured");
        }
        for (index, failure) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{failure}")?;
        }
        Ok(())
    }
}

impl BuilderError {
    /// Most bytes of an error body quoted in a status error.
    const MAX_MESSAGE_BYTES: usize = 256;

    /// The error for a response with an unexpected status.
    ///
    /// The builder API answers errors with a JSON code and message, as the beacon API does.
    /// Any other body is quoted, cut to a bound so a hostile relay cannot flood the logs.
    pub(crate) fn status(response: &Response) -> Self {
        let message = Json::parse(&response.body)
            .ok()
            .and_then(|json| {
                json.get("message")
                    .and_then(Json::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| String::from_utf8_lossy(&response.body).into_owned());
        Self::Status {
            status: response.status,
            message: Self::truncate(message),
        }
    }

    /// Cuts a message to the bound, on a character boundary.
    fn truncate(mut message: String) -> String {
        if message.len() > Self::MAX_MESSAGE_BYTES {
            let mut end = Self::MAX_MESSAGE_BYTES;
            while !message.is_char_boundary(end) {
                end -= 1;
            }
            message.truncate(end);
        }
        message
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_json_error_body_yields_its_message() {
        let response = Response::new(StatusCode::BAD_REQUEST).with_body(
            "application/json",
            br#"{"code":400,"message":"unknown validator"}"#.to_vec(),
        );
        let BuilderError::Status { status, message } = BuilderError::status(&response) else {
            panic!("a status error");
        };
        assert_eq!(
            (status, message.as_str()),
            (StatusCode::BAD_REQUEST, "unknown validator")
        );
    }

    #[test]
    fn a_long_plain_body_is_cut_to_256_bytes() {
        // 300 ASCII bytes keep their first 256.
        let response = Response::new(StatusCode::INTERNAL_SERVER_ERROR)
            .with_body("text/plain", vec![b'x'; 300]);
        let BuilderError::Status { message, .. } = BuilderError::status(&response) else {
            panic!("a status error");
        };
        assert_eq!(message, "x".repeat(256));

        // A two-byte character straddling byte 256 is dropped whole.
        let mut body = vec![b'x'; 255];
        body.extend_from_slice("é".as_bytes());
        let response =
            Response::new(StatusCode::INTERNAL_SERVER_ERROR).with_body("text/plain", body);
        let BuilderError::Status { message, .. } = BuilderError::status(&response) else {
            panic!("a status error");
        };
        assert_eq!(message, "x".repeat(255));
    }
}
