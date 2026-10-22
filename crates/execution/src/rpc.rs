//! The JSON-RPC 2.0 envelope.
//!
//! ```text
//!     request   {"jsonrpc":"2.0","id":7,"method":"engine_newPayloadV4","params":[...]}
//!     success   {"jsonrpc":"2.0","id":7,"result":{...}}
//!     failure   {"jsonrpc":"2.0","id":7,"error":{"code":-38005,"message":"Unsupported fork"}}
//! ```
//!
//! The specification is at jsonrpc.org; the engine's error codes are in `src/engine/common.md`.

use axiom_json::{Json, Object};
use thiserror::Error;

use crate::EnvelopeError;

/// Builds the request envelope for a call.
pub(crate) fn request(id: u64, method: &str, params: Vec<Json>) -> Json {
    // Member order follows the spec's examples, which keeps logs easy to compare.
    let mut envelope = Object::new();
    envelope.insert("jsonrpc", Json::from("2.0"));
    envelope.insert("id", Json::from(id));
    envelope.insert("method", Json::from(method));
    envelope.insert("params", Json::Array(params));
    Json::Object(envelope)
}

/// Extracts the result of a response to the request with a given id.
///
/// # Errors
///
/// Fails on a broken envelope, or with the engine's error object.
pub(crate) fn result(response: Json, id: u64) -> Result<Json, ResponseError> {
    let Json::Object(mut envelope) = response else {
        return Err(EnvelopeError::NotAnObject.into());
    };
    if envelope.get("jsonrpc").and_then(Json::as_str) != Some("2.0") {
        return Err(EnvelopeError::WrongVersion.into());
    }
    if envelope.get("id").and_then(Json::as_u64) != Some(id) {
        return Err(EnvelopeError::IdMismatch.into());
    }

    // Exactly one of result and error, per JSON-RPC 2.0 section 5.
    // A null result is a real result, such as engine_getBlobsV2 reporting missing blobs.
    match (envelope.remove("result"), envelope.remove("error")) {
        (Some(result), None) => Ok(result),
        (None, Some(error)) => Err(ResponseError::Rpc(RpcError::from_json(&error)?)),
        _ => Err(EnvelopeError::ResultOrError.into()),
    }
}

/// Why a response yields no result.
#[derive(Debug)]
pub(crate) enum ResponseError {
    /// The envelope is broken.
    Envelope(EnvelopeError),
    /// The engine reported an error.
    Rpc(RpcError),
}

impl From<EnvelopeError> for ResponseError {
    fn from(error: EnvelopeError) -> Self {
        Self::Envelope(error)
    }
}

/// An error object returned by the engine.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("{message} ({code}){}", self.detail())]
pub struct RpcError {
    /// The error code, standard or engine-specific.
    pub code: i64,

    /// A short description.
    pub message: String,

    /// Extra detail, present for server errors.
    pub data: Option<Json>,
}

impl RpcError {
    /// Invalid JSON was received.
    pub const PARSE_ERROR: i64 = -32700;
    /// The JSON is not a valid request object.
    pub const INVALID_REQUEST: i64 = -32600;
    /// The method does not exist or is not available.
    pub const METHOD_NOT_FOUND: i64 = -32601;
    /// The parameters do not match the method.
    pub const INVALID_PARAMS: i64 = -32602;
    /// An internal JSON-RPC error.
    pub const INTERNAL_ERROR: i64 = -32603;
    /// A generic client error, with detail in the data member.
    pub const SERVER_ERROR: i64 = -32000;
    /// The payload does not exist or is not available.
    pub const UNKNOWN_PAYLOAD: i64 = -38001;
    /// The fork choice state is invalid or inconsistent.
    pub const INVALID_FORKCHOICE_STATE: i64 = -38002;
    /// The payload attributes are invalid or inconsistent.
    pub const INVALID_PAYLOAD_ATTRIBUTES: i64 = -38003;
    /// The number of requested entities is too large.
    pub const TOO_LARGE_REQUEST: i64 = -38004;
    /// The payload belongs to a fork the engine does not support.
    pub const UNSUPPORTED_FORK: i64 = -38005;
    /// The reorg is deeper than the engine allows.
    pub const TOO_DEEP_REORG: i64 = -38006;

    /// An error object with no data.
    #[must_use]
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// The error as a JSON object.
    #[must_use]
    pub fn to_json(&self) -> Json {
        let mut object = Object::new();
        object.insert("code", Json::from(self.code));
        object.insert("message", Json::from(self.message.as_str()));
        if let Some(data) = &self.data {
            object.insert("data", data.clone());
        }
        Json::Object(object)
    }

    /// The extra detail with its separator, or nothing when absent.
    fn detail(&self) -> String {
        self.data
            .as_ref()
            .map_or_else(String::new, |data| format!(": {data}"))
    }

    /// Reads an error object.
    fn from_json(value: &Json) -> Result<Self, EnvelopeError> {
        let code = value.get("code").and_then(Json::as_i64);
        let message = value.get("message").and_then(Json::as_str);
        let (Some(code), Some(message)) = (code, message) else {
            return Err(EnvelopeError::MalformedError);
        };
        Ok(Self {
            code,
            message: message.to_owned(),
            // A null data member is the same as none.
            data: value.get("data").filter(|data| !data.is_null()).cloned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses JSON text that must be valid.
    fn json(text: &str) -> Json {
        Json::parse(text).expect("test JSON parses")
    }

    #[test]
    fn request_layout() {
        // The exact bytes a call with id 7 and one parameter puts on the wire.
        let envelope = request(7, "eth_chainId", vec![Json::from("x")]);
        assert_eq!(
            envelope.to_string(),
            r#"{"jsonrpc":"2.0","id":7,"method":"eth_chainId","params":["x"]}"#
        );
    }

    #[test]
    fn result_extraction() {
        // A null result is still a result.
        let response = json(r#"{"jsonrpc":"2.0","id":3,"result":null}"#);
        assert_eq!(result(response, 3).ok(), Some(Json::Null));

        // An error object comes back typed, data included.
        let response = json(
            r#"{"jsonrpc":"2.0","id":3,"error":{"code":-32000,"message":"Server error","data":{"err":"db"}}}"#,
        );
        let Err(ResponseError::Rpc(error)) = result(response, 3) else {
            panic!("expected an error object");
        };
        assert_eq!(error.code, RpcError::SERVER_ERROR);
        assert_eq!(error.to_string(), r#"Server error (-32000): {"err":"db"}"#);
    }

    #[test]
    fn envelope_rejections() {
        // Each broken envelope maps to one error.
        let cases = [
            ("[]", EnvelopeError::NotAnObject),
            (r#"{"id":3,"result":1}"#, EnvelopeError::WrongVersion),
            (
                r#"{"jsonrpc":"2.0","id":4,"result":1}"#,
                EnvelopeError::IdMismatch,
            ),
            (r#"{"jsonrpc":"2.0","id":3}"#, EnvelopeError::ResultOrError),
            (
                r#"{"jsonrpc":"2.0","id":3,"result":1,"error":{"code":1,"message":"x"}}"#,
                EnvelopeError::ResultOrError,
            ),
            (
                r#"{"jsonrpc":"2.0","id":3,"error":{"message":"x"}}"#,
                EnvelopeError::MalformedError,
            ),
        ];
        for (text, expected) in cases {
            match result(json(text), 3) {
                Err(ResponseError::Envelope(error)) => assert_eq!(error, expected, "{text}"),
                other => panic!("{text}: {other:?}"),
            }
        }
    }
}
