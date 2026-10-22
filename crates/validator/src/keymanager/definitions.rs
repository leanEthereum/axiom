//! The validator definitions file: each key's signer, whether it runs, and its overrides.
//!
//! # Overview
//!
//! The file is a YAML sequence, one mapping per validator, which an operator may edit by hand:
//!
//! ```text
//! - enabled: true
//!   voting_public_key: "0x8000...06aa"
//!   type: local_keystore
//!   suggested_fee_recipient: "0x0000...05fa"
//!   gas_limit: "36000000"
//! - enabled: false
//!   voting_public_key: "0x9035...0c02"
//!   type: remote_signer
//!   url: "http://127.0.0.1:9000"
//! ```
//!
//! A local key's keystore and password live in the key directory under its public key.
//! Every override field is optional; an absent one follows the client's default.

use std::collections::BTreeMap;

use axiom_json::Data;
use axiom_types::{BlsPubkey, ExecutionAddress};
use axiom_yaml::Yaml;

use crate::{
    keymanager::DefinitionsError,
    validators::{BuilderConfig, FieldError, Graffiti, ValidatorSettings, YamlFields, YamlWriter},
};

/// Where a defined validator's key lives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignerKind {
    /// An EIP-2335 keystore in the key directory, decrypted into this process.
    LocalKeystore,
    /// A remote signer, by its URL.
    Remote {
        /// The signer's URL.
        url: String,
    },
}

impl SignerKind {
    /// The type field naming a local keystore.
    const LOCAL: &'static str = "local_keystore";

    /// The type field naming a remote signer.
    const REMOTE: &'static str = "remote_signer";
}

/// One validator's entry in the definitions file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorDefinition {
    /// The validator's key.
    pub pubkey: BlsPubkey,
    /// Whether the client loads the key and performs its duties.
    pub enabled: bool,
    /// Where the key lives.
    pub signer: SignerKind,
    /// The validator's overrides of the client's defaults.
    pub settings: ValidatorSettings,
}

impl ValidatorDefinition {
    /// An enabled local key without overrides.
    #[must_use]
    pub fn local(pubkey: BlsPubkey) -> Self {
        Self {
            pubkey,
            enabled: true,
            signer: SignerKind::LocalKeystore,
            settings: ValidatorSettings::default(),
        }
    }

    /// An enabled remote key without overrides.
    #[must_use]
    pub fn remote(pubkey: BlsPubkey, url: &str) -> Self {
        Self {
            pubkey,
            enabled: true,
            signer: SignerKind::Remote {
                url: url.to_owned(),
            },
            settings: ValidatorSettings::default(),
        }
    }

    /// The entry as a mapping of the file.
    fn to_yaml(&self) -> Yaml {
        let settings = &self.settings;
        let mut writer = YamlWriter::default();
        writer
            .bool("enabled", Some(self.enabled))
            .text("voting_public_key", self.pubkey.0.to_data());
        match &self.signer {
            SignerKind::LocalKeystore => writer.text("type", SignerKind::LOCAL),
            SignerKind::Remote { url } => writer
                .text("type", SignerKind::REMOTE)
                .text("url", url.clone()),
        };
        writer
            .bytes(
                "suggested_fee_recipient",
                settings
                    .fee_recipient
                    .as_ref()
                    .map(|address| &address.0[..]),
            )
            .u64("gas_limit", settings.gas_limit);
        if let Some(graffiti) = settings.graffiti {
            writer.text("graffiti", graffiti.text());
        }
        writer
            .bool("builder_proposals", settings.builder_proposals)
            .u64("builder_boost_factor", settings.builder_boost_factor)
            .bool(
                "prefer_builder_proposals",
                settings.prefer_builder_proposals,
            );
        if let Some(config) = &settings.builder_config {
            writer.node("builder_config", config.to_yaml());
        }
        writer.finish()
    }

    /// Reads an entry from a mapping of the file.
    fn from_yaml(node: &Yaml) -> Result<Self, FieldError> {
        let fields = YamlFields::of(node)?;
        let pubkey = fields
            .array::<48>("voting_public_key")?
            .map(BlsPubkey)
            .ok_or_else(|| FieldError::new("voting_public_key", "a 48-byte hex key"))?;
        let signer = match fields.required_text("type")? {
            SignerKind::LOCAL => SignerKind::LocalKeystore,
            SignerKind::REMOTE => SignerKind::Remote {
                url: fields.required_text("url")?.to_owned(),
            },
            _ => return Err(FieldError::new("type", "local_keystore or remote_signer")),
        };
        let graffiti = fields
            .text("graffiti")?
            .map(|text| {
                Graffiti::parse(text)
                    .map_err(|_| FieldError::new("graffiti", "text of at most 32 bytes"))
            })
            .transpose()?;
        let builder_config = fields
            .node("builder_config")
            .map(BuilderConfig::from_yaml)
            .transpose()?;
        Ok(Self {
            pubkey,
            enabled: fields
                .bool("enabled")?
                .ok_or_else(|| FieldError::new("enabled", "true or false"))?,
            signer,
            settings: ValidatorSettings {
                fee_recipient: fields
                    .array::<20>("suggested_fee_recipient")?
                    .map(ExecutionAddress),
                gas_limit: fields.u64("gas_limit")?,
                graffiti,
                builder_proposals: fields.bool("builder_proposals")?,
                builder_boost_factor: fields.u64("builder_boost_factor")?,
                prefer_builder_proposals: fields.bool("prefer_builder_proposals")?,
                builder_config,
            },
        })
    }
}

/// Every definition in the file, by key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Definitions {
    /// The definitions, ordered by key.
    entries: BTreeMap<BlsPubkey, ValidatorDefinition>,
}

impl Definitions {
    /// Reads the file's text.
    ///
    /// # Errors
    ///
    /// Fails when the text is not YAML, not a sequence, has a malformed entry, or repeats a key.
    pub fn parse(text: &str) -> Result<Self, DefinitionsError> {
        let document = Yaml::parse(text).map_err(DefinitionsError::Text)?;
        // A file holding only comments, or nothing, defines no validator.
        let items = match &document {
            Yaml::Null => &[][..],
            node => node.as_sequence().ok_or(DefinitionsError::NotASequence)?,
        };
        let mut entries = BTreeMap::new();
        for (index, item) in items.iter().enumerate() {
            let definition = ValidatorDefinition::from_yaml(item)
                .map_err(|source| DefinitionsError::Entry { index, source })?;
            let pubkey = definition.pubkey;
            if entries.insert(pubkey, definition).is_some() {
                return Err(DefinitionsError::Duplicate { index, pubkey });
            }
        }
        Ok(Self { entries })
    }

    /// The file's text.
    #[must_use]
    pub fn to_text(&self) -> String {
        let items = self
            .entries
            .values()
            .map(ValidatorDefinition::to_yaml)
            .collect();
        Yaml::Sequence(items).to_string()
    }

    /// A key's definition.
    #[must_use]
    pub fn get(&self, pubkey: &BlsPubkey) -> Option<&ValidatorDefinition> {
        self.entries.get(pubkey)
    }

    /// A key's definition, for changing it.
    pub fn get_mut(&mut self, pubkey: &BlsPubkey) -> Option<&mut ValidatorDefinition> {
        self.entries.get_mut(pubkey)
    }

    /// Adds a definition, replacing any of the same key.
    pub fn insert(&mut self, definition: ValidatorDefinition) {
        self.entries.insert(definition.pubkey, definition);
    }

    /// Removes a key's definition.
    pub fn remove(&mut self, pubkey: &BlsPubkey) -> Option<ValidatorDefinition> {
        self.entries.remove(pubkey)
    }

    /// The definitions, ordered by key.
    pub fn iter(&self) -> impl Iterator<Item = &ValidatorDefinition> {
        self.entries.values()
    }

    /// The definitions, ordered by key, for changing them.
    ///
    /// A key is the map's own order, so only the other fields should change.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut ValidatorDefinition> {
        self.entries.values_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validators::BuilderEntry;

    #[test]
    fn every_field_round_trips_through_the_file() {
        // Fixture state: one local key with every override, one disabled remote key with none.
        let mut local = ValidatorDefinition::local(BlsPubkey([0x80; 48]));
        local.settings = ValidatorSettings {
            fee_recipient: Some(ExecutionAddress([0x5f; 20])),
            gas_limit: Some(36_000_000),
            graffiti: Some(Graffiti::parse("true").unwrap()),
            builder_proposals: Some(true),
            builder_boost_factor: Some(90),
            prefer_builder_proposals: Some(false),
            builder_config: Some(BuilderConfig {
                min_bid: Some(1),
                builder_boost_factor: None,
                builders: Some(vec![BuilderEntry {
                    url: "https://builder.example".to_owned(),
                    auth_data: None,
                    builder_pubkeys: Some(Vec::new()),
                    max_execution_payment: Some(0),
                    min_bid: None,
                    builder_boost_factor: None,
                }]),
            }),
        };
        let mut remote =
            ValidatorDefinition::remote(BlsPubkey([0x90; 48]), "http://127.0.0.1:9000");
        remote.enabled = false;
        let mut definitions = Definitions::default();
        definitions.insert(remote.clone());
        definitions.insert(local.clone());

        // Graffiti spelled like a boolean comes back as text, not as a boolean.
        let parsed = Definitions::parse(&definitions.to_text()).unwrap();
        assert_eq!(parsed, definitions);
        assert_eq!(parsed.iter().cloned().collect::<Vec<_>>(), [local, remote]);
    }

    #[test]
    fn an_empty_file_defines_nothing() {
        assert_eq!(Definitions::parse("").unwrap(), Definitions::default());
        assert_eq!(Definitions::parse("[]").unwrap(), Definitions::default());
    }

    #[test]
    fn malformed_files_name_the_entry() {
        let key = BlsPubkey([0x80; 48]).0.to_data();

        // Entry 0 has an unknown type.
        let text = format!("- enabled: true\n  voting_public_key: \"{key}\"\n  type: hardware\n");
        assert_eq!(
            Definitions::parse(&text).unwrap_err().to_string(),
            "entry 0: field type: expected local_keystore or remote_signer"
        );

        // Entry 1 repeats the key of entry 0.
        let entry =
            format!("- enabled: true\n  voting_public_key: \"{key}\"\n  type: local_keystore\n");
        assert_eq!(
            Definitions::parse(&format!("{entry}{entry}"))
                .unwrap_err()
                .to_string(),
            format!("entry 1 defines validator {key} again")
        );

        // A mapping at the top is not a list of definitions.
        assert_eq!(
            Definitions::parse("enabled: true\n")
                .unwrap_err()
                .to_string(),
            "the document is not a sequence of definitions"
        );
    }
}
