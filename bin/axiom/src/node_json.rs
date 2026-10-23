//! The resolved node configuration as JSON, for the configuration dump.

use std::{path::Path, time::Duration};

use axiom_json::{Json, Object};
use axiom_node::{
    AnchorSource, ChainSettings, GenesisState, HistorySettings, NetworkSettings, NodeConfig,
    ProposerSettings, StorageMode,
};

/// A node configuration rendered member by member, every field under its own name.
///
/// Paths, addresses, and roots are strings; counts are numbers; durations are milliseconds.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NodeJson<'a>(pub(crate) &'a NodeConfig);

impl NodeJson<'_> {
    /// The configuration as one JSON object.
    pub(crate) fn to_json(self) -> Json {
        let node = self.0;
        let mut object = Object::new();
        object.insert("data_dir", Self::path(node.data_dir.as_deref()));
        object.insert(
            "anchor",
            node.anchor.as_ref().map_or(Json::Null, Self::anchor),
        );
        object.insert("http_address", Self::text(node.http_address));
        object.insert(
            "http_allow_origin",
            Self::text(node.http_allow_origin.as_ref()),
        );
        object.insert(
            "http_tls",
            node.http_tls.as_ref().map_or(Json::Null, |tls| {
                Json::from([
                    ("certificate", Self::path(Some(&tls.certificate))),
                    ("key", Self::path(Some(&tls.key))),
                ])
            }),
        );
        object.insert("metrics_address", Self::text(node.metrics_address));
        object.insert(
            "metrics_allow_origin",
            Self::text(node.metrics_allow_origin.as_ref()),
        );
        object.insert(
            "engine",
            node.engine.as_ref().map_or(Json::Null, |engine| {
                Json::from([
                    ("url", Json::from(engine.url.as_str())),
                    ("jwt_secret", Self::path(Some(&engine.jwt_secret))),
                    (
                        "timeout_multiplier",
                        Json::from(u64::from(engine.timeout_multiplier)),
                    ),
                ])
            }),
        );
        object.insert(
            "network",
            node.network.as_ref().map_or(Json::Null, Self::network),
        );
        object.insert("history", Self::history(&node.history));
        object.insert("proposer", Self::proposer(&node.proposer));
        object.insert("slasher", Self::slasher(node));
        object.insert("chain", Self::chain(&node.chain));
        object.insert(
            "database",
            Json::from([
                ("auto_compact", Json::from(node.database.auto_compact)),
                (
                    "compact_on_start",
                    Json::from(node.database.compact_on_start),
                ),
            ]),
        );
        object.insert("shutdown_after_sync", Json::from(node.shutdown_after_sync));
        object.insert("trusted_setup", Self::path(node.trusted_setup.as_deref()));
        Json::Object(object)
    }

    /// The slasher's layout and where it runs, or null when it is off.
    fn slasher(node: &NodeConfig) -> Json {
        node.slasher.as_ref().map_or(Json::Null, |slasher| {
            Json::from([
                ("history_length", Json::from(slasher.history_length)),
                ("chunk_size", Json::from(slasher.chunk_size)),
                (
                    "validator_chunk_size",
                    Json::from(slasher.validator_chunk_size),
                ),
                ("record_chunk_size", Json::from(slasher.record_chunk_size)),
                ("prune_period", Json::from(slasher.prune_period)),
                (
                    "directory",
                    Self::path(node.slasher_setup.directory.as_deref()),
                ),
                (
                    "update_period_ms",
                    Self::millis(node.slasher_setup.update_period),
                ),
                ("broadcast", Json::from(node.slasher_setup.broadcast)),
            ])
        })
    }

    /// The chain thread's settings.
    fn chain(chain: &ChainSettings) -> Json {
        Json::from([
            ("max_skip_slots", Json::from(chain.max_skip_slots)),
            ("fast_confirmation", Json::from(chain.fast_confirmation)),
            ("light_client_server", Json::from(chain.light_client_server)),
            (
                "import_all_attestations",
                Json::from(chain.import_all_attestations),
            ),
            ("prune_blobs", Json::from(chain.sidecar_pruning.enabled)),
            (
                "epochs_per_blob_prune",
                Json::from(chain.sidecar_pruning.interval_epochs),
            ),
            (
                "blob_prune_margin_epochs",
                Json::from(chain.sidecar_pruning.margin_epochs),
            ),
        ])
    }

    /// Where an empty database starts.
    fn anchor(anchor: &AnchorSource) -> Json {
        match anchor {
            AnchorSource::Genesis(genesis) => Json::from([("genesis", Self::genesis(genesis))]),
            AnchorSource::Checkpoint {
                state,
                block,
                blobs,
            } => Json::from([(
                "checkpoint",
                Json::from([
                    ("state", Self::path(Some(state))),
                    ("block", Self::path(Some(block))),
                    ("blobs", Self::path(blobs.as_deref())),
                ]),
            )]),
            AnchorSource::Url { url, timeout } => Json::from([(
                "checkpoint_sync_url",
                Json::from([
                    ("url", Json::from(url.as_str())),
                    ("timeout_ms", Self::millis(Some(*timeout))),
                ]),
            )]),
        }
    }

    /// Where a genesis state comes from.
    fn genesis(genesis: &GenesisState) -> Json {
        match genesis {
            GenesisState::File(path) => Json::from([("file", Self::path(Some(path)))]),
            GenesisState::Embedded(embedded) => {
                Json::from([("embedded", Json::from(embedded.network()))])
            }
            GenesisState::Download(download) => Json::from([(
                "download",
                Json::from([
                    ("url", Json::from(download.url.as_str())),
                    ("checksum", Json::from(download.checksum.to_string())),
                    ("timeout_ms", Self::millis(Some(download.timeout))),
                ]),
            )]),
        }
    }

    /// The peer-to-peer settings.
    fn network(network: &NetworkSettings) -> Json {
        let texts = |items: Vec<String>| Json::Array(items.into_iter().map(Json::from).collect());
        Json::from([
            (
                "listen_address",
                Json::from(network.listen_address.to_string()),
            ),
            (
                "boot_nodes",
                texts(network.boot_nodes.iter().map(ToString::to_string).collect()),
            ),
            (
                "custody_group_count",
                Json::from(network.custody_group_count),
            ),
            (
                "discovery",
                network.discovery.as_ref().map_or(Json::Null, |discovery| {
                    Json::from([
                        ("udp_port", Json::from(u64::from(discovery.udp_port))),
                        ("enr_address", Self::text(discovery.enr_address)),
                        (
                            "boot_enrs",
                            texts(
                                discovery
                                    .boot_enrs
                                    .iter()
                                    .map(ToString::to_string)
                                    .collect(),
                            ),
                        ),
                    ])
                }),
            ),
            ("quic_port", Json::from(network.quic_port.map(u64::from))),
            ("target_peers", Json::from(network.target_peers as u64)),
            ("nat", Json::from(network.port_mapping.enabled)),
            (
                "subscribe_all_subnets",
                Json::from(network.subscribe_all_subnets),
            ),
            (
                "backfill_rate_limiting",
                Json::from(network.backfill_rate_limiting),
            ),
        ])
    }

    /// History and trust settings.
    fn history(history: &HistorySettings) -> Json {
        let mode = match history.mode {
            StorageMode::Pruned => Json::from("pruned"),
            StorageMode::Archive(interval) => {
                Json::from([("archive", Json::from(interval.to_string()))])
            }
        };
        Json::from([
            ("mode", mode),
            ("weak_subjectivity", Self::text(history.weak_subjectivity)),
            (
                "genesis",
                history.genesis.as_ref().map_or(Json::Null, Self::genesis),
            ),
            (
                "allow_insecure_genesis_sync",
                Json::from(history.allow_insecure_genesis_sync),
            ),
            ("ignore_ws_check", Json::from(history.ignore_ws_check)),
        ])
    }

    /// Block production settings.
    fn proposer(proposer: &ProposerSettings) -> Json {
        let fallback = proposer.builder_fallback;
        Json::from([
            (
                "suggested_fee_recipient",
                Json::from(proposer.default_fee_recipient.to_string()),
            ),
            ("graffiti", Json::from(proposer.graffiti.to_string())),
            (
                "builders",
                Json::Array(
                    proposer
                        .builders
                        .iter()
                        .map(|url| Json::from(url.as_str()))
                        .collect(),
                ),
            ),
            (
                "builder_header_timeout_ms",
                Self::millis(proposer.builder_client.header_timeout),
            ),
            (
                "builder_user_agent",
                Json::from(proposer.builder_client.user_agent.clone()),
            ),
            ("builder_fallback_skips", Json::from(fallback.skips)),
            (
                "builder_fallback_skips_per_epoch",
                Json::from(fallback.skips_per_epoch),
            ),
            (
                "builder_fallback_epochs_since_finalization",
                Json::from(fallback.epochs_since_finalization),
            ),
            (
                "builder_fallback_disable_checks",
                Json::from(fallback.disable_checks),
            ),
            (
                "prepare_payload_lookahead_ms",
                Self::millis(proposer.prepare_lookahead),
            ),
            (
                "always_prepare_payload",
                Json::from(proposer.always_prepare_payload),
            ),
        ])
    }

    /// A path as text, or null.
    fn path(path: Option<&Path>) -> Json {
        path.map_or(Json::Null, |path| Json::from(path.display().to_string()))
    }

    /// Any value through its display form, or null.
    fn text(value: Option<impl ToString>) -> Json {
        value.map_or(Json::Null, |value| Json::from(value.to_string()))
    }

    /// A duration in whole milliseconds, or null.
    fn millis(duration: Option<Duration>) -> Json {
        duration.map_or(Json::Null, |duration| {
            Json::from(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        })
    }
}

#[cfg(test)]
mod tests {
    use axiom_json::Json;
    use axiom_node::{EngineConfig, NodeConfig};

    use super::*;

    #[test]
    fn a_default_node_renders_its_defaults() {
        // Every optional part is null; the defaults of the rest show as values.
        let json = NodeJson(&NodeConfig::default()).to_json();
        let Json::Object(object) = &json else {
            panic!("expected an object, got {json}");
        };
        assert_eq!(object.get("anchor"), Some(&Json::Null));
        assert_eq!(object.get("engine"), Some(&Json::Null));
        assert_eq!(object.get("shutdown_after_sync"), Some(&Json::from(false)));
        assert_eq!(
            object.get("database").map(ToString::to_string).as_deref(),
            Some(r#"{"auto_compact":true,"compact_on_start":false}"#)
        );
    }

    #[test]
    fn engines_and_anchors_render_their_settings() {
        let node = NodeConfig {
            engine: Some(EngineConfig {
                url: "http://127.0.0.1:8551".to_owned(),
                jwt_secret: "jwt.hex".into(),
                timeout_multiplier: 3,
            }),
            anchor: Some(AnchorSource::Url {
                url: "http://10.0.0.2:5052".to_owned(),
                timeout: Duration::from_secs(180),
            }),
            ..NodeConfig::default()
        };
        let Json::Object(object) = NodeJson(&node).to_json() else {
            panic!("expected an object");
        };
        assert_eq!(
            object.get("engine").map(ToString::to_string).as_deref(),
            Some(
                r#"{"url":"http://127.0.0.1:8551","jwt_secret":"jwt.hex","timeout_multiplier":3}"#
            )
        );
        assert_eq!(
            object.get("anchor").map(ToString::to_string).as_deref(),
            Some(r#"{"checkpoint_sync_url":{"url":"http://10.0.0.2:5052","timeout_ms":180000}}"#)
        );
    }
}
