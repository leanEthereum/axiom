//! The per-key outcomes that import and delete requests report.

use axiom_beacon_json::Fields;
use axiom_json::Json;

use crate::keymanager::KeymanagerClientError;

/// What became of one key in an import request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportStatus {
    /// The key is stored and runs.
    Imported,
    /// The client already runs the key.
    Duplicate,
    /// The key was not imported, for the given reason.
    Error(String),
}

impl ImportStatus {
    /// Reads a status object of a response.
    ///
    /// # Errors
    ///
    /// Fails on a status the keymanager API does not define.
    pub fn from_json(json: &Json) -> Result<Self, KeymanagerClientError> {
        let fields = Fields::of(json)?;
        let status: String = fields.required("status")?;
        match status.as_str() {
            "imported" => Ok(Self::Imported),
            "duplicate" => Ok(Self::Duplicate),
            "error" => Ok(Self::Error(fields.optional("message")?.unwrap_or_default())),
            _ => Err(KeymanagerClientError::UnknownStatus(status)),
        }
    }

    /// The status object of the response.
    pub(crate) fn to_json(&self) -> Json {
        match self {
            Self::Imported => Json::from([("status", Json::from("imported"))]),
            Self::Duplicate => Json::from([("status", Json::from("duplicate"))]),
            Self::Error(message) => Json::from([
                ("status", Json::from("error")),
                ("message", Json::from(message.as_str())),
            ]),
        }
    }
}

/// What became of one key in a delete request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeleteStatus {
    /// The key ran, and no longer does.
    Deleted,
    /// The key did not run, but its slashing protection history is returned.
    NotActive,
    /// The client knows nothing of the key.
    NotFound,
    /// The key could not be removed, for the given reason.
    Error(String),
}

impl DeleteStatus {
    /// Reads a status object of a response.
    ///
    /// # Errors
    ///
    /// Fails on a status the keymanager API does not define.
    pub fn from_json(json: &Json) -> Result<Self, KeymanagerClientError> {
        let fields = Fields::of(json)?;
        let status: String = fields.required("status")?;
        match status.as_str() {
            "deleted" => Ok(Self::Deleted),
            "not_active" => Ok(Self::NotActive),
            "not_found" => Ok(Self::NotFound),
            "error" => Ok(Self::Error(fields.optional("message")?.unwrap_or_default())),
            _ => Err(KeymanagerClientError::UnknownStatus(status)),
        }
    }

    /// The status object of the response.
    pub(crate) fn to_json(&self) -> Json {
        match self {
            Self::Deleted => Json::from([("status", Json::from("deleted"))]),
            Self::NotActive => Json::from([("status", Json::from("not_active"))]),
            Self::NotFound => Json::from([("status", Json::from("not_found"))]),
            Self::Error(message) => Json::from([
                ("status", Json::from("error")),
                ("message", Json::from(message.as_str())),
            ]),
        }
    }
}
