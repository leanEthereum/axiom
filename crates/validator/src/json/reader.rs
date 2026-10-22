//! Reading the members of a JSON object by name, with the name in every error.

use axiom_json::{Json, Object};

use crate::json::{ApiJson, JsonError};

/// The members of one JSON object.
#[derive(Clone, Copy, Debug)]
pub struct Fields<'a> {
    /// The object.
    object: &'a Object,
}

impl<'a> Fields<'a> {
    /// The members of a value that must be an object.
    ///
    /// # Errors
    ///
    /// Fails when the value is not an object.
    pub fn of(json: &'a Json) -> Result<Self, JsonError> {
        let object = json
            .as_object()
            .ok_or_else(|| JsonError::mismatch("object", json))?;
        Ok(Self { object })
    }

    /// A member that must be present, as JSON.
    ///
    /// # Errors
    ///
    /// Fails when the member is absent.
    pub fn raw(self, name: &'static str) -> Result<&'a Json, JsonError> {
        self.object.get(name).ok_or(JsonError::Missing(name))
    }

    /// A member that must be present, decoded.
    ///
    /// # Errors
    ///
    /// Fails when the member is absent or does not decode.
    pub fn get<T: ApiJson>(self, name: &'static str) -> Result<T, JsonError> {
        T::from_json(self.raw(name)?).map_err(|source| JsonError::Member {
            name,
            source: Box::new(source),
        })
    }

    /// A member that may be absent or null, decoded when present.
    ///
    /// # Errors
    ///
    /// Fails when the member is present and does not decode.
    pub fn optional<T: ApiJson>(self, name: &'static str) -> Result<Option<T>, JsonError> {
        match self.object.get(name) {
            None | Some(Json::Null) => Ok(None),
            Some(_) => self.get(name).map(Some),
        }
    }
}
