//! Builder configurations: which builders a Gloas proposal asks for bids, and on what terms.
//!
//! See `types/builder_entry.yaml` and `apis/builder_config.yaml` in the keymanager API repository.
//! See also `produceBlockV4` in the beacon API, whose request body is the resolved configuration.

use std::{collections::BTreeMap, net::Ipv6Addr};

use axiom_beacon_json::{ApiJson, Fields};
use axiom_json::{Data, Json, Object};
use axiom_types::BlsPubkey;
use axiom_yaml::Yaml;

use crate::validators::{
    BuilderConfigError, FieldError,
    yaml::{YamlFields, YamlWriter},
};

/// Most builders one configuration names: `MAX_BUILDER_ENTRIES` in the keymanager API.
pub const MAX_BUILDER_ENTRIES: usize = 64;

/// Most builder keys one entry accepts: `MAX_BUILDER_PUBKEYS` in the keymanager API.
pub const MAX_BUILDER_PUBKEYS: usize = 64;

/// Most bytes of authentication data: `MAX_BUILDER_AUTH_DATA_SIZE` in the keymanager API.
pub const MAX_BUILDER_AUTH_DATA_SIZE: usize = 4096;

/// Most bytes of a builder URL: `MAX_BUILDER_URL_SIZE` in the keymanager API.
pub const MAX_BUILDER_URL_SIZE: usize = 2048;

/// One builder a validator asks for bids, with the terms it accepts them on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuilderEntry {
    /// Where the bid requests go.
    pub url: String,
    /// The data the validator signs to authenticate itself, agreed with the builder.
    pub auth_data: Option<Vec<u8>>,
    /// The builder keys a bid may be signed by; none or empty accepts any.
    pub builder_pubkeys: Option<Vec<BlsPubkey>>,
    /// The cap on the execution payment counted from this builder, in Gwei.
    pub max_execution_payment: Option<u64>,
    /// The floor on the total payment accepted from this builder, in Gwei.
    pub min_bid: Option<u64>,
    /// The percentage weighing this builder's bid against the local payload.
    pub builder_boost_factor: Option<u64>,
}

impl BuilderEntry {
    /// The authentication data a builder URL implies when none was agreed: its hostname.
    ///
    /// The hostname is lowercase ASCII, and an IPv6 literal is compressed inside brackets.
    /// See "Default auth data" in the Gloas validator spec of the builder API.
    ///
    /// # Returns
    ///
    /// None when the URL is not an http or https URL with a host.
    #[must_use]
    pub fn default_auth_data(url: &str) -> Option<Vec<u8>> {
        let (scheme, rest) = url.split_once("://")?;
        if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")) {
            return None;
        }
        // The authority ends at the path, query, or fragment, and drops any user information.
        let authority = rest.split(['/', '?', '#']).next()?;
        let host_port = authority.rsplit('@').next()?;
        let host = if let Some(literal) = host_port.strip_prefix('[') {
            let (address, _) = literal.split_once(']')?;
            let address: Ipv6Addr = address.parse().ok()?;
            format!("[{}]", Self::compress(address))
        } else {
            host_port.split(':').next()?.to_ascii_lowercase()
        };
        if host.is_empty() || !host.is_ascii() {
            return None;
        }
        Some(host.into_bytes())
    }

    /// The RFC 5952 text of an IPv6 address, in hexadecimal groups only.
    ///
    /// The longest run of two or more zero groups becomes a double colon, the first on a tie.
    fn compress(address: Ipv6Addr) -> String {
        let groups = address.segments();
        let mut best = (0, 0);
        let mut run = (0, 0);
        for (index, group) in groups.iter().enumerate() {
            if *group == 0 {
                run = if run.1 == 0 {
                    (index, 1)
                } else {
                    (run.0, run.1 + 1)
                };
                if run.1 > best.1 {
                    best = run;
                }
            } else {
                run = (0, 0);
            }
        }
        let hex = |range: &[u16]| {
            range
                .iter()
                .map(|group| format!("{group:x}"))
                .collect::<Vec<_>>()
                .join(":")
        };
        if best.1 < 2 {
            return hex(&groups);
        }
        let (start, len) = best;
        format!("{}::{}", hex(&groups[..start]), hex(&groups[start + len..]))
    }

    /// The authentication data the entry signs: its own, else the URL's hostname.
    fn effective_auth_data(&self) -> Option<Vec<u8>> {
        self.auth_data
            .clone()
            .or_else(|| Self::default_auth_data(&self.url))
    }

    /// Reads one entry of a JSON configuration.
    fn from_json(index: usize, json: &Json) -> Result<Self, BuilderConfigError> {
        let fields = Fields::of(json)?;
        let auth_data = fields
            .optional::<String>("auth_data")?
            .map(|text| {
                Vec::<u8>::from_data(&text)
                    .map_err(|_| BuilderConfigError::AuthDataHex { index, text })
            })
            .transpose()?;
        Ok(Self {
            url: fields.required("url")?,
            auth_data,
            builder_pubkeys: fields.optional("builder_pubkeys")?,
            max_execution_payment: fields.optional("max_execution_payment")?,
            min_bid: fields.optional("min_bid")?,
            builder_boost_factor: fields.optional("builder_boost_factor")?,
        })
    }

    /// The entry as a mapping of a hand-editable file.
    fn to_yaml(&self) -> Yaml {
        let mut writer = YamlWriter::default();
        writer
            .text("url", self.url.clone())
            .bytes("auth_data", self.auth_data.as_deref());
        if let Some(keys) = &self.builder_pubkeys {
            let keys = keys
                .iter()
                .map(|key| Yaml::String(key.0.to_data()))
                .collect();
            writer.node("builder_pubkeys", Yaml::Sequence(keys));
        }
        writer
            .u64("max_execution_payment", self.max_execution_payment)
            .u64("min_bid", self.min_bid)
            .u64("builder_boost_factor", self.builder_boost_factor)
            .finish()
    }

    /// Reads an entry from a mapping of a hand-editable file.
    fn from_yaml(node: &Yaml) -> Result<Self, FieldError> {
        let fields = YamlFields::of(node)?;
        let builder_pubkeys = fields
            .sequence("builder_pubkeys")?
            .map(|keys| {
                keys.iter()
                    .map(|key| {
                        key.as_hex_array()
                            .map(BlsPubkey)
                            .ok_or_else(|| FieldError::new("builder_pubkeys", "48-byte hex keys"))
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        Ok(Self {
            url: fields.required_text("url")?.to_owned(),
            auth_data: fields.bytes("auth_data")?,
            builder_pubkeys,
            max_execution_payment: fields.u64("max_execution_payment")?,
            min_bid: fields.u64("min_bid")?,
            builder_boost_factor: fields.u64("builder_boost_factor")?,
        })
    }
}

/// A validator's builder configuration as an operator set it, each value absent until set.
///
/// No builder list follows the client, which names none.
/// An empty list asks no builder, leaving bids from the gossip network only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuilderConfig {
    /// The validator's default floor on a bid's total payment, in Gwei.
    pub min_bid: Option<u64>,
    /// The validator's default weight of a bid against the local payload.
    pub builder_boost_factor: Option<u64>,
    /// The builders asked for bids.
    pub builders: Option<Vec<BuilderEntry>>,
}

impl BuilderConfig {
    /// Reads and checks a configuration from a keymanager API request body.
    ///
    /// # Errors
    ///
    /// Fails on a malformed body, too many entries, an invalid entry, or two equal entries.
    pub fn from_json(json: &Json) -> Result<Self, BuilderConfigError> {
        let fields = Fields::of(json)?;
        let builders = match json.get("builders") {
            None | Some(Json::Null) => None,
            Some(list) => {
                let entries = list.as_array().ok_or(BuilderConfigError::BuildersShape)?;
                let entries = entries
                    .iter()
                    .enumerate()
                    .map(|(index, entry)| BuilderEntry::from_json(index, entry))
                    .collect::<Result<Vec<_>, _>>()?;
                Some(entries)
            }
        };
        let config = Self {
            min_bid: fields.optional("min_bid")?,
            builder_boost_factor: fields.optional("builder_boost_factor")?,
            builders,
        };
        config.validate()?;
        Ok(config)
    }

    /// Checks the rules the keymanager API sets on a configuration.
    ///
    /// # Errors
    ///
    /// Fails on too many entries, an invalid entry, or two entries with one URL and one auth data.
    pub fn validate(&self) -> Result<(), BuilderConfigError> {
        let Some(builders) = &self.builders else {
            return Ok(());
        };
        if builders.len() > MAX_BUILDER_ENTRIES {
            return Err(BuilderConfigError::TooManyBuilders {
                count: builders.len(),
                max: MAX_BUILDER_ENTRIES,
            });
        }
        // Entries are equal when both their URL and the data they sign are equal.
        let mut seen: BTreeMap<(&str, Vec<u8>), usize> = BTreeMap::new();
        for (index, entry) in builders.iter().enumerate() {
            if entry.url.len() > MAX_BUILDER_URL_SIZE {
                return Err(BuilderConfigError::UrlTooLong {
                    index,
                    len: entry.url.len(),
                    max: MAX_BUILDER_URL_SIZE,
                });
            }
            if BuilderEntry::default_auth_data(&entry.url).is_none() {
                return Err(BuilderConfigError::Url {
                    index,
                    url: entry.url.clone(),
                });
            }
            if let Some(data) = &entry.auth_data
                && !(1..=MAX_BUILDER_AUTH_DATA_SIZE).contains(&data.len())
            {
                return Err(BuilderConfigError::AuthDataLength {
                    index,
                    len: data.len(),
                    max: MAX_BUILDER_AUTH_DATA_SIZE,
                });
            }
            let keys = entry.builder_pubkeys.as_ref().map_or(0, Vec::len);
            if keys > MAX_BUILDER_PUBKEYS {
                return Err(BuilderConfigError::TooManyBuilderPubkeys {
                    index,
                    count: keys,
                    max: MAX_BUILDER_PUBKEYS,
                });
            }
            let auth = entry.effective_auth_data().unwrap_or_default();
            if let Some(first) = seen.insert((entry.url.as_str(), auth), index) {
                return Err(BuilderConfigError::Duplicate {
                    first,
                    second: index,
                    url: entry.url.clone(),
                });
            }
        }
        Ok(())
    }

    /// Resolves every omitted value, as a request to the beacon node needs.
    ///
    /// # Arguments
    ///
    /// - `config`: the validator's configuration, if it has one.
    /// - `boost_factor`: the factor the client resolves for the validator without one.
    #[must_use]
    pub fn resolve(config: Option<&Self>, boost_factor: u64) -> ResolvedBuilderConfig {
        // The client sets no floor of its own, so the floor defaults to zero.
        let min_bid = config.and_then(|config| config.min_bid).unwrap_or(0);
        let builder_boost_factor = config
            .and_then(|config| config.builder_boost_factor)
            .unwrap_or(boost_factor);
        let entries = config
            .and_then(|config| config.builders.as_deref())
            .unwrap_or_default();
        let builders = entries
            .iter()
            .filter_map(|entry| {
                // Invariant: a stored entry passed validation, so its URL has a host.
                let auth_data = entry.effective_auth_data()?;
                Some(ResolvedBuilderEntry {
                    url: entry.url.clone(),
                    auth_data,
                    builder_pubkeys: entry.builder_pubkeys.clone().unwrap_or_default(),
                    // The client configures no cap, so an omitted one counts no payment.
                    max_execution_payment: entry.max_execution_payment.unwrap_or(0),
                    min_bid: entry.min_bid.unwrap_or(min_bid),
                    builder_boost_factor: entry
                        .builder_boost_factor
                        .unwrap_or(builder_boost_factor),
                })
            })
            .collect();
        ResolvedBuilderConfig {
            min_bid,
            builder_boost_factor,
            builders,
        }
    }

    /// The configuration as a mapping of a hand-editable file.
    #[must_use]
    pub fn to_yaml(&self) -> Yaml {
        let mut writer = YamlWriter::default();
        writer
            .u64("min_bid", self.min_bid)
            .u64("builder_boost_factor", self.builder_boost_factor);
        if let Some(builders) = &self.builders {
            let builders = builders.iter().map(BuilderEntry::to_yaml).collect();
            writer.node("builders", Yaml::Sequence(builders));
        }
        writer.finish()
    }

    /// Reads a configuration from a mapping of a hand-editable file.
    ///
    /// # Errors
    ///
    /// Fails when a field does not hold what it must.
    pub fn from_yaml(node: &Yaml) -> Result<Self, FieldError> {
        let fields = YamlFields::of(node)?;
        let builders = fields
            .sequence("builders")?
            .map(|entries| entries.iter().map(BuilderEntry::from_yaml).collect())
            .transpose()?;
        Ok(Self {
            min_bid: fields.u64("min_bid")?,
            builder_boost_factor: fields.u64("builder_boost_factor")?,
            builders,
        })
    }
}

/// A builder configuration with every value resolved, as a beacon node receives it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedBuilderConfig {
    /// The floor on a bid's total payment from the gossip network, in Gwei.
    pub min_bid: u64,
    /// The weight of a bid from the gossip network against the local payload.
    pub builder_boost_factor: u64,
    /// The builders asked for bids.
    pub builders: Vec<ResolvedBuilderEntry>,
}

impl ResolvedBuilderConfig {
    /// The keymanager API's JSON form, with every value written out.
    #[must_use]
    pub fn to_json(&self) -> Json {
        let builders: Vec<Json> = self
            .builders
            .iter()
            .map(ResolvedBuilderEntry::to_json)
            .collect();
        Json::from([
            ("min_bid", self.min_bid.to_json()),
            ("builder_boost_factor", self.builder_boost_factor.to_json()),
            ("builders", Json::from(builders)),
        ])
    }
}

/// One builder entry with every value resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedBuilderEntry {
    /// Where the bid requests go.
    pub url: String,
    /// The data the validator signs.
    pub auth_data: Vec<u8>,
    /// The builder keys a bid may be signed by; empty accepts any.
    pub builder_pubkeys: Vec<BlsPubkey>,
    /// The cap on the execution payment counted, in Gwei.
    pub max_execution_payment: u64,
    /// The floor on the total payment, in Gwei.
    pub min_bid: u64,
    /// The weight of the bid against the local payload.
    pub builder_boost_factor: u64,
}

impl ResolvedBuilderEntry {
    /// The keymanager API's JSON form.
    fn to_json(&self) -> Json {
        let mut entry = Object::new();
        entry.insert("url", Json::from(self.url.clone()));
        entry.insert("auth_data", Json::from(self.auth_data.to_data()));
        entry.insert("builder_pubkeys", self.builder_pubkeys.to_json());
        entry.insert(
            "max_execution_payment",
            self.max_execution_payment.to_json(),
        );
        entry.insert("min_bid", self.min_bid.to_json());
        entry.insert("builder_boost_factor", self.builder_boost_factor.to_json());
        Json::from(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An entry with only a URL.
    fn entry(url: &str) -> BuilderEntry {
        BuilderEntry {
            url: url.to_owned(),
            auth_data: None,
            builder_pubkeys: None,
            max_execution_payment: None,
            min_bid: None,
            builder_boost_factor: None,
        }
    }

    #[test]
    fn default_auth_data_matches_the_builder_spec_table() {
        // Every row of the table under "Default auth data" in the builder API's Gloas validator spec.
        let table = [
            ("https://builder.example.com/", "builder.example.com"),
            (
                "HTTPS://Builder.Example.com:443/bids?x=1",
                "builder.example.com",
            ),
            ("https://builder.example.com:8080", "builder.example.com"),
            (
                "https://user:pw@builder.example.com/",
                "builder.example.com",
            ),
            ("https://10.0.0.5:18550/eth/v1/builder", "10.0.0.5"),
            ("https://[0:0:0:0:0:0:0:1]:8443/", "[::1]"),
            ("https://[::ffff:192.0.2.1]/", "[::ffff:c000:201]"),
        ];
        for (url, expected) in table {
            assert_eq!(
                BuilderEntry::default_auth_data(url),
                Some(expected.as_bytes().to_vec()),
                "{url}"
            );
        }
        // A run of zeros shorter than two groups stays written out; the first longest run wins.
        assert_eq!(
            BuilderEntry::compress("2001:db8:0:1:1:1:1:1".parse().unwrap()),
            "2001:db8:0:1:1:1:1:1"
        );
        assert_eq!(
            BuilderEntry::compress("2001:0:0:1:0:0:1:1".parse().unwrap()),
            "2001::1:0:0:1:1"
        );
        // No host, or another scheme, has no default.
        for url in [
            "https://",
            "ftp://builder.example.com",
            "builder.example.com",
        ] {
            assert_eq!(BuilderEntry::default_auth_data(url), None, "{url}");
        }
    }

    #[test]
    fn the_api_rules_are_checked() {
        let config = |builders: Vec<BuilderEntry>| BuilderConfig {
            builders: Some(builders),
            ..BuilderConfig::default()
        };

        // One URL may appear twice with different data, but not twice with the hostname's data.
        let mut own = entry("https://builder.example.com");
        own.auth_data = Some(b"secret".to_vec());
        assert!(
            config(vec![entry("https://builder.example.com"), own])
                .validate()
                .is_ok()
        );
        let mut implied = entry("https://builder.example.com");
        implied.auth_data = Some(b"builder.example.com".to_vec());
        assert_eq!(
            config(vec![entry("https://builder.example.com"), implied])
                .validate()
                .unwrap_err()
                .to_string(),
            "builders 0 and 1 share URL \"https://builder.example.com\" and auth_data"
        );

        // Empty data, a URL without a host, and 65 entries are refused.
        let mut empty = entry("https://builder.example.com");
        empty.auth_data = Some(Vec::new());
        assert_eq!(
            config(vec![empty]).validate().unwrap_err().to_string(),
            "builder 0: auth_data of 0 bytes is outside 1 to 4096"
        );
        assert_eq!(
            config(vec![entry("https:///bids")])
                .validate()
                .unwrap_err()
                .to_string(),
            "builder 0: \"https:///bids\" is not an http or https URL with a host"
        );
        let many = (0..65)
            .map(|index| entry(&format!("https://builder{index}.example.com")))
            .collect();
        assert_eq!(
            config(many).validate().unwrap_err().to_string(),
            "65 builders exceed the limit of 64"
        );
    }

    #[test]
    fn resolution_fills_entries_from_the_validator_then_the_client() {
        // Fixture state: a validator floor of 10, one entry with its own factor of 120.
        let mut favoured = entry("https://b.example");
        favoured.builder_boost_factor = Some(120);
        let config = BuilderConfig {
            min_bid: Some(10),
            builder_boost_factor: None,
            builders: Some(vec![entry("https://a.example"), favoured]),
        };
        // The client's factor for this validator is 90.
        let resolved = BuilderConfig::resolve(Some(&config), 90);
        assert_eq!(
            resolved,
            ResolvedBuilderConfig {
                min_bid: 10,
                builder_boost_factor: 90,
                builders: vec![
                    ResolvedBuilderEntry {
                        url: "https://a.example".to_owned(),
                        auth_data: b"a.example".to_vec(),
                        builder_pubkeys: Vec::new(),
                        max_execution_payment: 0,
                        min_bid: 10,
                        builder_boost_factor: 90,
                    },
                    ResolvedBuilderEntry {
                        url: "https://b.example".to_owned(),
                        auth_data: b"b.example".to_vec(),
                        builder_pubkeys: Vec::new(),
                        max_execution_payment: 0,
                        min_bid: 10,
                        builder_boost_factor: 120,
                    },
                ],
            }
        );
        // No configuration follows the client entirely, which names no builder.
        assert_eq!(
            BuilderConfig::resolve(None, 100),
            ResolvedBuilderConfig {
                min_bid: 0,
                builder_boost_factor: 100,
                builders: Vec::new(),
            }
        );
    }

    #[test]
    fn json_and_yaml_forms_round_trip() {
        let mut full = entry("https://b.example/bids");
        full.auth_data = Some(vec![0xab, 0xcd]);
        full.builder_pubkeys = Some(vec![BlsPubkey([0x93; 48])]);
        full.max_execution_payment = Some(250_000_000);
        full.min_bid = Some(1);
        full.builder_boost_factor = Some(u64::MAX);
        let config = BuilderConfig {
            min_bid: Some(10_000_000),
            builder_boost_factor: Some(100),
            builders: Some(vec![full, entry("https://a.example")]),
        };
        let yaml = Yaml::parse(&config.to_yaml().to_string()).unwrap();
        assert_eq!(BuilderConfig::from_yaml(&yaml).unwrap(), config);

        // The API form of the same entry, with quoted integers and hex data.
        let json = Json::parse(
            r#"{"min_bid":"10000000","builder_boost_factor":"100","builders":[
                {"url":"https://b.example/bids","auth_data":"0xabcd",
                 "builder_pubkeys":["0x939393939393939393939393939393939393939393939393939393939393939393939393939393939393939393939393"],
                 "max_execution_payment":"250000000","min_bid":"1",
                 "builder_boost_factor":"18446744073709551615"},
                {"url":"https://a.example"}]}"#,
        )
        .unwrap();
        assert_eq!(BuilderConfig::from_json(&json).unwrap(), config);

        // An empty list is kept apart from no list.
        let none = BuilderConfig::from_json(&Json::parse("{}").unwrap()).unwrap();
        let empty = BuilderConfig::from_json(&Json::parse(r#"{"builders":[]}"#).unwrap()).unwrap();
        assert_eq!((none.builders, empty.builders), (None, Some(Vec::new())));
    }
}
