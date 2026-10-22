//! The validators file: a list of keystores, their passwords, and their settings, to import.
//!
//! The file is a JSON array, one object per validator.
//! The keystore and the slashing protection interchange are JSON documents written as strings.
//! It is the format validator managers exchange, so files made elsewhere import here too.

use axiom_json::{Data, Json, Object};
use axiom_types::{BlsPubkey, ExecutionAddress};
use axiom_validator::keys::Keystore;

use crate::manager::ManagerError;

/// One validator of a validators file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ValidatorSpec {
    /// The EIP-2335 keystore, as JSON text.
    pub(crate) keystore: String,
    /// The keystore's password.
    pub(crate) password: String,
    /// The validator's EIP-3076 slashing protection interchange, as JSON text.
    pub(crate) slashing_protection: Option<String>,
    /// A fee recipient overriding the client's.
    pub(crate) fee_recipient: Option<ExecutionAddress>,
    /// A gas limit overriding the client's.
    pub(crate) gas_limit: Option<u64>,
    /// Whether the validator uses builders.
    pub(crate) builder_proposals: Option<bool>,
    /// The boost factor of its block requests.
    pub(crate) builder_boost_factor: Option<u64>,
    /// Whether a builder's bid always wins.
    pub(crate) prefer_builder_proposals: Option<bool>,
    /// Whether the validator runs.
    pub(crate) enabled: Option<bool>,
}

impl ValidatorSpec {
    /// The validator's public key, read from its keystore.
    ///
    /// # Errors
    ///
    /// Fails when the keystore is malformed.
    pub(crate) fn pubkey(&self) -> Result<BlsPubkey, ManagerError> {
        Ok(Keystore::parse(&self.keystore)?.pubkey())
    }

    /// Reads a validators file.
    ///
    /// # Errors
    ///
    /// Fails when the text is not a JSON array of validator objects.
    pub(crate) fn parse_list(text: &str) -> Result<Vec<Self>, ManagerError> {
        let json = Json::parse(text)?;
        let items = json.as_array().ok_or(ManagerError::NotAList)?;
        items
            .iter()
            .enumerate()
            .map(|(index, item)| Self::from_json(index, item))
            .collect()
    }

    /// The text of a validators file.
    pub(crate) fn list_to_text(specs: &[Self]) -> String {
        Json::Array(specs.iter().map(Self::to_json).collect()).to_string()
    }

    /// The validator as an object of the file.
    fn to_json(&self) -> Json {
        let optional = |value: Option<Json>| value.unwrap_or(Json::Null);
        let mut object = Object::new();
        object.insert("voting_keystore", Json::from(self.keystore.as_str()));
        object.insert(
            "voting_keystore_password",
            Json::from(self.password.as_str()),
        );
        object.insert(
            "slashing_protection",
            optional(self.slashing_protection.as_deref().map(Json::from)),
        );
        object.insert(
            "fee_recipient",
            optional(
                self.fee_recipient
                    .map(|address| Json::from(address.0.to_data())),
            ),
        );
        object.insert("gas_limit", optional(self.gas_limit.map(Json::from)));
        object.insert(
            "builder_proposals",
            optional(self.builder_proposals.map(Json::from)),
        );
        object.insert(
            "builder_boost_factor",
            optional(self.builder_boost_factor.map(Json::from)),
        );
        object.insert(
            "prefer_builder_proposals",
            optional(self.prefer_builder_proposals.map(Json::from)),
        );
        object.insert("enabled", optional(self.enabled.map(Json::from)));
        Json::from(object)
    }

    /// Reads one validator object of the file.
    fn from_json(index: usize, json: &Json) -> Result<Self, ManagerError> {
        let field = |name: &str| json.get(name).filter(|value| !value.is_null());
        let text = |name: &'static str| -> Result<Option<String>, ManagerError> {
            field(name)
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| ManagerError::spec(index, name))
                })
                .transpose()
        };
        let integer = |name: &'static str| -> Result<Option<u64>, ManagerError> {
            field(name)
                .map(|value| {
                    value
                        .as_u64()
                        .ok_or_else(|| ManagerError::spec(index, name))
                })
                .transpose()
        };
        let boolean = |name: &'static str| -> Result<Option<bool>, ManagerError> {
            field(name)
                .map(|value| match value {
                    Json::Bool(flag) => Ok(*flag),
                    _ => Err(ManagerError::spec(index, name)),
                })
                .transpose()
        };
        let fee_recipient = text("fee_recipient")?
            .map(|address| {
                <[u8; 20]>::from_data(&address)
                    .map(ExecutionAddress)
                    .map_err(|_| ManagerError::spec(index, "fee_recipient"))
            })
            .transpose()?;
        Ok(Self {
            keystore: text("voting_keystore")?
                .ok_or_else(|| ManagerError::spec(index, "voting_keystore"))?,
            password: text("voting_keystore_password")?
                .ok_or_else(|| ManagerError::spec(index, "voting_keystore_password"))?,
            slashing_protection: text("slashing_protection")?,
            fee_recipient,
            gas_limit: integer("gas_limit")?,
            builder_proposals: boolean("builder_proposals")?,
            builder_boost_factor: integer("builder_boost_factor")?,
            prefer_builder_proposals: boolean("prefer_builder_proposals")?,
            enabled: boolean("enabled")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_validators_file_round_trips() {
        // Fixture state: one validator with every field, one with only its keystore and password.
        let full = ValidatorSpec {
            keystore: r#"{"version":4}"#.to_owned(),
            password: "pw".to_owned(),
            slashing_protection: Some(r#"{"data":[]}"#.to_owned()),
            fee_recipient: Some(ExecutionAddress([0x5f; 20])),
            gas_limit: Some(36_000_000),
            builder_proposals: Some(true),
            builder_boost_factor: Some(90),
            prefer_builder_proposals: Some(false),
            enabled: Some(true),
        };
        let bare = ValidatorSpec {
            slashing_protection: None,
            fee_recipient: None,
            gas_limit: None,
            builder_proposals: None,
            builder_boost_factor: None,
            prefer_builder_proposals: None,
            enabled: None,
            ..full.clone()
        };
        let specs = vec![full, bare];
        let text = ValidatorSpec::list_to_text(&specs);
        assert_eq!(ValidatorSpec::parse_list(&text).unwrap(), specs);

        // Integers are JSON numbers, and an absent setting is null.
        let json = Json::parse(&text).unwrap();
        assert_eq!(
            json.as_array().unwrap()[0].get("gas_limit"),
            Some(&Json::from(36_000_000_u64))
        );
        assert_eq!(
            json.as_array().unwrap()[1].get("enabled"),
            Some(&Json::Null)
        );
    }

    #[test]
    fn a_malformed_entry_names_its_index_and_field() {
        let text = r#"[{"voting_keystore":"{}","voting_keystore_password":"pw"},
                       {"voting_keystore":"{}","voting_keystore_password":"pw","gas_limit":"many"}]"#;
        assert_eq!(
            ValidatorSpec::parse_list(text).unwrap_err().to_string(),
            "validators file entry 1: invalid gas_limit"
        );
    }
}
