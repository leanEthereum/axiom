//! Why a beacon node request failed.

use axiom_beacon_json::ApiJsonError;
use axiom_http::{HttpError, StatusCode};
use axiom_json::{Json, ParseError};
use axiom_ssz::DecodeError;
use axiom_types::combined::BlindedBlockError;
use thiserror::Error;

/// A beacon node request that did not produce its answer.
#[derive(Debug, Error)]
pub enum BeaconError {
    /// The node could not be reached, or the exchange broke.
    #[error("beacon node unreachable: {0}")]
    Http(#[from] HttpError),
    /// The node answered with an error status.
    #[error("beacon node answered {status}: {message}")]
    Status {
        /// The HTTP status.
        status: StatusCode,
        /// The node's message with each refused item's reason, or the raw body.
        message: String,
    },
    /// The answer is not JSON.
    #[error("beacon node answer is not JSON: {0}")]
    Parse(#[from] ParseError),
    /// The answer is JSON of the wrong shape.
    #[error("beacon node answer is malformed: {0}")]
    Json(#[from] ApiJsonError),
    /// The answer is not the SSZ value expected.
    #[error("beacon node answer is not valid SSZ: {0}")]
    Ssz(#[from] DecodeError),
    /// A response header the answer needs is missing or malformed.
    #[error("beacon node answer lacks a valid {0} header")]
    Header(&'static str),
    /// The answer is of another fork than the slot it is for.
    #[error("beacon node answered for fork {found}, expected {expected}")]
    WrongFork {
        /// The fork the slot is in.
        expected: String,
        /// The fork the answer claims.
        found: String,
    },
    /// A broadcast topic name is not one of the known topics.
    #[error("unknown broadcast topic {0:?}")]
    UnknownTopic(String),
    /// The node has nothing to answer, such as no block yet for a payload vote.
    #[error("beacon node has no content for this request")]
    NoContent,
    /// The answer is not the block of its fork, blinded or full.
    #[error("beacon node answered an invalid block: {0}")]
    Block(#[from] BlindedBlockError),
    /// A duty names a committee seat outside its committee.
    #[error("committee seat {seat} is outside a committee of {length}")]
    Seat {
        /// The seat.
        seat: u64,
        /// Members of the committee.
        length: u64,
    },
    /// A duty names a committee larger than an attestation's bits.
    #[error("committee of {length} exceeds the {max} members an attestation holds")]
    CommitteeTooLarge {
        /// Members of the committee.
        length: u64,
        /// Most members allowed.
        max: u64,
    },
    /// No beacon node is configured.
    #[error("no beacon node configured")]
    NoNodes,
}

impl BeaconError {
    /// The error an error status carries, read from the API's error object.
    ///
    /// A list submission's object names each refused item and why.
    /// Anything that is not an error object is shown raw.
    /// See `ErrorMessage` and `IndexedErrorMessage` in the beacon API.
    pub(crate) fn from_reply(status: StatusCode, body: &[u8]) -> Self {
        let json = Json::parse(body).ok();
        let Some(mut message) = json
            .as_ref()
            .and_then(|json| json.get("message"))
            .and_then(Json::as_str)
            .map(str::to_owned)
        else {
            return Self::Status {
                status,
                message: String::from_utf8_lossy(body).into_owned(),
            };
        };
        let failures = json
            .as_ref()
            .and_then(|json| json.get("failures"))
            .and_then(Json::as_array)
            .unwrap_or_default();
        message.extend(failures.iter().map(|failure| {
            let index = failure
                .get("index")
                .map(ToString::to_string)
                .unwrap_or_default();
            let reason = failure
                .get("message")
                .and_then(Json::as_str)
                .unwrap_or_default();
            format!("; item {index}: {reason}")
        }));
        Self::Status { status, message }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_indexed_error_names_each_refused_item() {
        // Fixture state: the node refused items 0 and 2 of a list of three.
        let body = br#"{"code":400,"message":"2 of the submitted items were refused","failures":[{"index":0,"message":"unknown block"},{"index":2,"message":"too late"}]}"#;
        let error = BeaconError::from_reply(StatusCode::BAD_REQUEST, body);
        assert_eq!(
            error.to_string(),
            "beacon node answered 400 Bad Request: 2 of the submitted items were refused; item 0: unknown block; item 2: too late"
        );
    }

    #[test]
    fn a_body_without_an_error_object_is_shown_raw() {
        let error = BeaconError::from_reply(StatusCode::NOT_FOUND, b"no route");
        assert_eq!(
            error.to_string(),
            "beacon node answered 404 Not Found: no route"
        );
    }
}
