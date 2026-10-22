//! The per-key outcomes that import and delete requests report.

use axiom_json::Json;

/// What became of one key in an import request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ImportStatus {
    /// The key is stored and runs.
    Imported,
    /// The client already runs the key.
    Duplicate,
    /// The key was not imported, for the given reason.
    Error(String),
}

impl ImportStatus {
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
pub(crate) enum DeleteStatus {
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
