//! Why a request to a keymanager API failed.

use axiom_beacon_json::ApiJsonError;
use axiom_http::{HttpError, StatusCode};
use axiom_json::{Json, ParseError};
use thiserror::Error;

/// Why a request to a keymanager API failed.
#[derive(Debug, Error)]
pub enum KeymanagerClientError {
    /// The client could not be reached, or the URL is not an http or https URL.
    #[error("keymanager API unreachable: {0}")]
    Http(#[from] HttpError),
    /// The client answered with an error status.
    #[error("keymanager API answered {status}: {message}")]
    Status {
        /// The HTTP status.
        status: StatusCode,
        /// The client's message, or the raw body.
        message: String,
    },
    /// The answer is not JSON.
    #[error("keymanager API answer is not JSON: {0}")]
    Parse(#[from] ParseError),
    /// The answer is JSON of the wrong shape.
    #[error("keymanager API answer is malformed: {0}")]
    Json(#[from] ApiJsonError),
    /// The answer lacks a part every answer of its route has.
    #[error("keymanager API answer is malformed: {0}")]
    Shape(&'static str),
    /// A key's outcome is not one the keymanager API defines.
    #[error("keymanager API answered the unknown status {0:?}")]
    UnknownStatus(String),
}

impl KeymanagerClientError {
    /// The error an error status carries, read from the API's error object.
    pub(crate) fn from_reply(status: StatusCode, body: &[u8]) -> Self {
        let message = Json::parse(body)
            .ok()
            .and_then(|json| {
                json.get("message")
                    .and_then(Json::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| String::from_utf8_lossy(body).into_owned());
        Self::Status { status, message }
    }
}
