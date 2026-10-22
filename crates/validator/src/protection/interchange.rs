//! The EIP-3076 interchange format, which moves slashing protection between clients.

use axiom_json::{Data, Json, Object};
use axiom_types::{BlsPubkey, Epoch, Root, Slot};

use crate::protection::InterchangeError;

/// A signing history in the interchange format, version 5.
///
/// See EIP-3076.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Interchange {
    /// The chain the history belongs to.
    pub genesis_validators_root: Root,
    /// One entry per validator.
    pub data: Vec<ValidatorHistory>,
}

/// The messages one validator signed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ValidatorHistory {
    /// The validator's key.
    pub pubkey: BlsPubkey,
    /// Blocks it signed.
    pub signed_blocks: Vec<SignedBlock>,
    /// Votes it signed.
    pub signed_attestations: Vec<SignedAttestation>,
}

/// A block a validator signed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SignedBlock {
    /// Its slot.
    pub slot: Slot,
    /// Its signing root, when the exporter kept it.
    pub signing_root: Option<Root>,
}

/// A vote a validator signed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SignedAttestation {
    /// Epoch of the source checkpoint.
    pub source_epoch: Epoch,
    /// Epoch of the target checkpoint.
    pub target_epoch: Epoch,
    /// Its signing root, when the exporter kept it.
    pub signing_root: Option<Root>,
}

impl Interchange {
    /// The format version this client reads and writes.
    pub const VERSION: &'static str = "5";

    /// Reads an interchange document.
    ///
    /// # Errors
    ///
    /// Fails on text that is not JSON, a missing field, another version, or a malformed value.
    pub fn parse(text: &str) -> Result<Self, InterchangeError> {
        Self::from_json(&Json::parse(text)?)
    }

    /// Reads an interchange from parsed JSON.
    ///
    /// # Errors
    ///
    /// Fails on a missing field, another version, or a malformed value.
    pub fn from_json(json: &Json) -> Result<Self, InterchangeError> {
        let document = Fields::of(json, "interchange")?;
        let metadata = Fields::of(document.get("metadata")?, "metadata")?;
        let version = metadata.text("interchange_format_version")?;
        if version != Self::VERSION {
            return Err(InterchangeError::Version {
                found: version.to_owned(),
                expected: Self::VERSION,
            });
        }
        let genesis_validators_root = Root(metadata.hex("genesis_validators_root")?);
        let data = document
            .array("data")?
            .iter()
            .map(ValidatorHistory::from_json)
            .collect::<Result<_, _>>()?;
        Ok(Self {
            genesis_validators_root,
            data,
        })
    }

    /// The document as JSON, with members in the order of the EIP's example.
    #[must_use]
    pub fn to_json(&self) -> Json {
        let metadata = Json::from([
            ("interchange_format_version", Json::from(Self::VERSION)),
            (
                "genesis_validators_root",
                Json::from(self.genesis_validators_root.0.to_data()),
            ),
        ]);
        let data = self.data.iter().map(ValidatorHistory::to_json).collect();
        Json::from([("metadata", metadata), ("data", Json::Array(data))])
    }
}

impl ValidatorHistory {
    /// Reads one validator's entry.
    fn from_json(json: &Json) -> Result<Self, InterchangeError> {
        let entry = Fields::of(json, "data")?;
        Ok(Self {
            pubkey: BlsPubkey(entry.hex("pubkey")?),
            signed_blocks: entry
                .array("signed_blocks")?
                .iter()
                .map(SignedBlock::from_json)
                .collect::<Result<_, _>>()?,
            signed_attestations: entry
                .array("signed_attestations")?
                .iter()
                .map(SignedAttestation::from_json)
                .collect::<Result<_, _>>()?,
        })
    }

    /// The entry as JSON.
    fn to_json(&self) -> Json {
        Json::from([
            ("pubkey", Json::from(self.pubkey.0.to_data())),
            (
                "signed_blocks",
                Json::Array(
                    self.signed_blocks
                        .iter()
                        .copied()
                        .map(SignedBlock::to_json)
                        .collect(),
                ),
            ),
            (
                "signed_attestations",
                Json::Array(
                    self.signed_attestations
                        .iter()
                        .copied()
                        .map(SignedAttestation::to_json)
                        .collect(),
                ),
            ),
        ])
    }
}

impl SignedBlock {
    /// Reads one signed block.
    fn from_json(json: &Json) -> Result<Self, InterchangeError> {
        let block = Fields::of(json, "signed_blocks")?;
        Ok(Self {
            slot: Slot(block.decimal("slot")?),
            signing_root: block.optional_hex("signing_root")?.map(Root),
        })
    }

    /// The block as JSON, leaving out an unknown root.
    fn to_json(self) -> Json {
        let mut object = Object::new();
        object.insert("slot", Json::from(self.slot.0.to_string()));
        if let Some(root) = self.signing_root {
            object.insert("signing_root", Json::from(root.0.to_data()));
        }
        Json::Object(object)
    }
}

impl SignedAttestation {
    /// Reads one signed vote.
    fn from_json(json: &Json) -> Result<Self, InterchangeError> {
        let vote = Fields::of(json, "signed_attestations")?;
        Ok(Self {
            source_epoch: Epoch(vote.decimal("source_epoch")?),
            target_epoch: Epoch(vote.decimal("target_epoch")?),
            signing_root: vote.optional_hex("signing_root")?.map(Root),
        })
    }

    /// The vote as JSON, leaving out an unknown root.
    fn to_json(self) -> Json {
        let mut object = Object::new();
        object.insert("source_epoch", Json::from(self.source_epoch.0.to_string()));
        object.insert("target_epoch", Json::from(self.target_epoch.0.to_string()));
        if let Some(root) = self.signing_root {
            object.insert("signing_root", Json::from(root.0.to_data()));
        }
        Json::Object(object)
    }
}

/// The members of one JSON object of the document, read by name.
#[derive(Clone, Copy, Debug)]
struct Fields<'a> {
    /// The object.
    object: &'a Object,
}

impl<'a> Fields<'a> {
    /// The object a value must be.
    fn of(json: &'a Json, field: &'static str) -> Result<Self, InterchangeError> {
        let object = json.as_object().ok_or(InterchangeError::Field {
            field,
            expected: "an object",
        })?;
        Ok(Self { object })
    }

    /// A member that must be present.
    fn get(self, field: &'static str) -> Result<&'a Json, InterchangeError> {
        self.object.get(field).ok_or(InterchangeError::Field {
            field,
            expected: "present",
        })
    }

    /// A string member.
    fn text(self, field: &'static str) -> Result<&'a str, InterchangeError> {
        self.get(field)?.as_str().ok_or(InterchangeError::Field {
            field,
            expected: "a string",
        })
    }

    /// An array member.
    fn array(self, field: &'static str) -> Result<&'a [Json], InterchangeError> {
        self.get(field)?.as_array().ok_or(InterchangeError::Field {
            field,
            expected: "an array",
        })
    }

    /// A fixed-length hex member.
    fn hex<const N: usize>(self, field: &'static str) -> Result<[u8; N], InterchangeError> {
        <[u8; N]>::from_data(self.text(field)?)
            .map_err(|source| InterchangeError::Hex { field, source })
    }

    /// A fixed-length hex member that may be absent.
    fn optional_hex<const N: usize>(
        self,
        field: &'static str,
    ) -> Result<Option<[u8; N]>, InterchangeError> {
        match self.object.get(field) {
            None => Ok(None),
            Some(_) => self.hex(field).map(Some),
        }
    }

    /// An integer written as a decimal string, as the format writes every number.
    fn decimal(self, field: &'static str) -> Result<u64, InterchangeError> {
        let text = self.text(field)?;
        // Plain ASCII digits only: no sign, no spaces, no empty string.
        let digits = !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
        digits
            .then(|| text.parse().ok())
            .flatten()
            .ok_or_else(|| InterchangeError::Number {
                field,
                value: text.to_owned(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example instance of EIP-3076.
    const EXAMPLE: &str = r#"{
      "metadata": {
        "interchange_format_version": "5",
        "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
      },
      "data": [
        {
          "pubkey": "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed",
          "signed_blocks": [
            {
              "slot": "81952",
              "signing_root": "0x4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b"
            },
            {
              "slot": "81951"
            }
          ],
          "signed_attestations": [
            {
              "source_epoch": "2290",
              "target_epoch": "3007",
              "signing_root": "0x587d6a4f59a58fe24f406e0502413e77fe1babddee641fda30034ed37ecc884d"
            },
            {
              "source_epoch": "2290",
              "target_epoch": "3008"
            }
          ]
        }
      ]
    }"#;

    #[test]
    fn the_eip_example_reads_and_writes_back_unchanged() {
        let interchange = Interchange::parse(EXAMPLE).unwrap();

        // One validator: two blocks, the second without root, and two votes.
        let entry = &interchange.data[0];
        assert_eq!(
            entry.signed_blocks,
            [
                SignedBlock {
                    slot: Slot(81952),
                    signing_root: Some(Root(
                        <[u8; 32]>::from_data(
                            "0x4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b"
                        )
                        .unwrap()
                    )),
                },
                SignedBlock {
                    slot: Slot(81951),
                    signing_root: None,
                },
            ]
        );
        assert_eq!(entry.signed_attestations.len(), 2);
        assert_eq!(entry.signed_attestations[1].signing_root, None);

        // Writing it out gives the same JSON value as the example, member for member.
        assert_eq!(interchange.to_json(), Json::parse(EXAMPLE).unwrap());
    }

    #[test]
    fn another_version_is_refused() {
        let text = EXAMPLE.replace(
            r#""interchange_format_version": "5""#,
            r#""interchange_format_version": "4""#,
        );
        assert!(matches!(
            Interchange::parse(&text),
            Err(InterchangeError::Version { found, expected: "5" }) if found == "4"
        ));
    }

    #[test]
    fn numbers_must_be_decimal_strings() {
        // A signed slot of "-1" is no u64.
        let text = EXAMPLE.replace(r#""slot": "81951""#, r#""slot": "-1""#);
        assert!(matches!(
            Interchange::parse(&text),
            Err(InterchangeError::Number { field: "slot", value }) if value == "-1"
        ));
    }
}
