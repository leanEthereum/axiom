//! Conformance of the beacon API against its published definition and the spec's configuration.
//!
//! The route check walks the pinned OpenAPI definition of the beacon node API.
//! Every path and method there is served.
//!
//! The configuration check reads the pinned release's configuration and preset files.
//! Every key there must come back from the config route with the same value.

use std::{collections::BTreeSet, fs, path::Path};

use axiom_beacon_json::ApiJson;
use axiom_ef_tests::Vectors;
use axiom_json::{Json, Object};
use axiom_node::BeaconApi;
use axiom_types::{
    ChainConfig, ConfigValue, Mainnet, Minimal, Preset, altair, capella, electra, gloas, phase0,
};
use axiom_yaml::Yaml;

/// A file of the pinned vectors.
fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// A YAML file of the pinned vectors, which must be a mapping.
fn mapping(path: &Path) -> Yaml {
    let yaml =
        Yaml::parse(&read(path)).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    assert!(
        yaml.as_mapping().is_some(),
        "{} is not a mapping",
        path.display()
    );
    yaml
}

/// Every path and method of the definition, from its index and the route files it names.
///
/// The files use YAML features beyond the vectors' subset, such as block scalars.
/// Only two line shapes matter here, so the walk reads lines rather than YAML.
///
/// ```text
///     index:       "  /eth/v1/beacon/genesis:"  then  "    $ref: \"./apis/beacon/genesis.yaml\""
///     route file:  "get:" or "post:" at the file's top indentation
/// ```
fn defined_routes(root: &Path) -> BTreeSet<(String, String)> {
    let index = read(&root.join("beacon-node-oapi.yaml"));
    let mut routes = BTreeSet::new();
    let lines = index.lines().skip_while(|line| *line != "paths:").skip(1);
    let mut path = None;
    for line in lines {
        if let Some(name) = line
            .strip_prefix("  /")
            .and_then(|rest| rest.strip_suffix(':'))
        {
            path = Some(format!("/{name}"));
        } else if let Some(file) = line.trim().strip_prefix("$ref: ") {
            let file = file.trim_matches(['"', '\'']).trim_start_matches("./");
            let route_file = read(&root.join(file));
            let path = path.take().expect("a reference follows its path");
            // Some files indent every line; their top level is the first line's indentation.
            let top = route_file
                .lines()
                .find(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
                .map_or(0, |line| line.len() - line.trim_start().len());
            for method in ["get", "post", "put", "delete"] {
                let key = format!("{}{method}:", " ".repeat(top));
                if route_file.lines().any(|line| line == key) {
                    routes.insert((method.to_uppercase(), path.clone()));
                }
            }
        } else if !line.starts_with(' ') && !line.is_empty() {
            // The next top-level key ends the paths section.
            break;
        }
    }
    routes
}

#[test]
fn every_defined_route_is_served() {
    let Some(vectors) = Vectors::locate() else {
        return;
    };
    let defined = defined_routes(&vectors.beacon_apis());

    // The pinned definition has 94 path and method pairs.
    assert_eq!(defined.len(), 94);

    let served: BTreeSet<(String, String)> = BeaconApi::served::<Mainnet>()
        .into_iter()
        .map(|(method, path)| (method.as_str().to_owned(), path))
        .collect();

    // Every defined route is served.
    let missing: Vec<&(String, String)> = defined.difference(&served).collect();
    assert_eq!(missing, Vec::<&(String, String)>::new());

    // Routes served beyond the definition, each kept on purpose.
    let extra: Vec<_> = served.difference(&defined).collect();
    assert_eq!(
        extra,
        [&(
            "GET".to_owned(),
            "/eth/v1/beacon/blob_sidecars/{block_id}".to_owned()
        )],
        "blob sidecars stay served for the Deneb and Electra blocks still in retention"
    );
}

/// A configuration value as text, the way the spec's YAML writes the scalar.
fn rendered(value: &ConfigValue) -> String {
    match value {
        ConfigValue::Number(number) => number.to_string(),
        ConfigValue::Text(text) => text.to_lowercase(),
        ConfigValue::Schedule(schedule) => schedule
            .iter()
            .map(|(epoch, limit)| format!("{}:{limit}", epoch.0))
            .collect::<Vec<_>>()
            .join(","),
    }
}

/// A YAML value as text, in the same form.
fn expected(value: &Yaml) -> String {
    match value {
        Yaml::Sequence(entries) => entries
            .iter()
            .map(|entry| {
                let field = |name| entry.get(name).and_then(Yaml::as_str).unwrap_or_default();
                format!("{}:{}", field("EPOCH"), field("MAX_BLOBS_PER_BLOCK"))
            })
            .collect::<Vec<_>>()
            .join(","),
        other => other.as_str().unwrap_or_default().to_lowercase(),
    }
}

/// Configuration keys of features past Gloas, which Axiom does not target.
///
/// Heze and its inclusion lists, and the EIP-8321 and EIP-8198 test forks, ship in the release.
const BEYOND_TARGET: [&str; 13] = [
    "HEZE_FORK_VERSION",
    "HEZE_FORK_EPOCH",
    "EIP8321_FORK_VERSION",
    "EIP8321_FORK_EPOCH",
    "EIP8198_FORK_VERSION",
    "EIP8198_FORK_EPOCH",
    "INCLUSION_LIST_DUE_BPS",
    "SLOT_DURATION_MS_EIP8198",
    "MAX_REQUEST_INCLUSION_LIST",
    "MIN_SLOTS_FOR_INCLUSION_LISTS_REQUESTS",
    "MAX_TRANSACTIONS_BYTES_PER_INCLUSION_LIST",
    "MIN_BLOB_DATA_RETENTION_MS",
    "GAS_LIMIT_SCHEDULE",
];

/// Checks a preset and its configuration against the release's files.
///
/// # Returns
///
/// How many keys matched, and the keys that did not.
fn check_spec<P: Preset>(root: &Path, config: &ChainConfig) -> (usize, Vec<String>) {
    let mut matched = 0;
    let mut differing = Vec::new();

    // Preset files: one per targeted fork, every key a number.
    let ours = P::entries();
    for fork in [
        "phase0",
        "altair",
        "bellatrix",
        "capella",
        "deneb",
        "electra",
        "fulu",
        "gloas",
    ] {
        let path = root.join(format!("presets/{}/{fork}.yaml", P::NAME));
        let yaml = mapping(&path);
        for (key, value) in yaml.as_mapping().into_iter().flatten() {
            let ours = ours.iter().find(|(name, _)| *name == key);
            if ours.map(|(_, value)| value.to_string()) == Some(expected(value)) {
                matched += 1;
            } else {
                differing.push(key.to_owned());
            }
        }
    }

    // The configuration file: numbers, hex, names, and the blob schedule.
    let entries = config.entries(P::NAME);
    let path = root.join(format!("configs/{}.yaml", P::NAME));
    let yaml = mapping(&path);
    for (key, value) in yaml.as_mapping().into_iter().flatten() {
        let ours = entries.iter().find(|(name, _)| *name == key);
        if ours.map(|(_, value)| rendered(value)) == Some(expected(value)) {
            matched += 1;
        } else {
            differing.push(key.to_owned());
        }
    }
    (matched, differing)
}

#[test]
fn the_spec_route_echoes_every_preset_and_config_value() {
    let Some(vectors) = Vectors::locate() else {
        return;
    };
    let root = vectors.spec_configs();
    let beyond: Vec<String> = BEYOND_TARGET.iter().map(|key| (*key).to_owned()).collect();

    // Every key of both presets and both configurations matches, features past Gloas aside.
    let (matched, differing) = check_spec::<Mainnet>(&root, &ChainConfig::mainnet());
    assert_eq!((matched, differing), (163, beyond.clone()));
    let (matched, differing) = check_spec::<Minimal>(&root, &ChainConfig::minimal());
    assert_eq!((matched, differing), (163, beyond));
}

/// The data line of an event's example in the event stream definition.
fn event_example(root: &Path, topic: &str) -> Json {
    let text = read(&root.join("apis/eventstream/index.yaml"));
    let key = format!("            {topic}:");
    let data = text
        .lines()
        .skip_while(|line| *line != key)
        .find_map(|line| line.trim().strip_prefix("data: "))
        .unwrap_or_else(|| panic!("no example for {topic}"));
    Json::parse(data).unwrap_or_else(|error| panic!("{topic}: {error}"))
}

/// A JSON value with every string lowercased, since hex may come in either case.
fn lowercased(json: &Json) -> Json {
    match json {
        Json::String(text) => Json::from(text.to_lowercase()),
        Json::Array(items) => Json::Array(items.iter().map(lowercased).collect()),
        Json::Object(object) => Json::Object(
            object
                .iter()
                .map(|(name, value)| (name.clone(), lowercased(value)))
                .collect::<Object>(),
        ),
        other => other.clone(),
    }
}

/// Reads an example as a container and writes it back, requiring the example's own text.
fn round_trip<T: ApiJson>(topic: &str, json: &Json) -> usize {
    let value = T::from_json(json).unwrap_or_else(|error| panic!("{topic}: {error}"));
    assert_eq!(lowercased(&value.to_json()), lowercased(json), "{topic}");
    1
}

#[test]
fn event_examples_round_trip_through_their_containers() {
    let Some(vectors) = Vectors::locate() else {
        return;
    };
    let root = vectors.beacon_apis();
    let plain = |topic| event_example(&root, topic);
    // Versioned events wrap the container with its fork's name.
    let versioned = |topic| {
        let example = event_example(&root, topic);
        assert_eq!(
            example.get("version").and_then(Json::as_str),
            Some("gloas"),
            "{topic}"
        );
        example.get("data").cloned().unwrap_or_default()
    };

    // Eleven events carry a consensus container, each read and written back exactly.
    let checked = [
        round_trip::<electra::Attestation<Mainnet>>("attestation", &plain("attestation")),
        round_trip::<electra::SingleAttestation>(
            "single_attestation",
            &plain("single_attestation"),
        ),
        round_trip::<phase0::SignedVoluntaryExit>("voluntary_exit", &plain("voluntary_exit")),
        round_trip::<phase0::ProposerSlashing>("proposer_slashing", &plain("proposer_slashing")),
        round_trip::<phase0::AttesterSlashing<Mainnet>>(
            "attester_slashing",
            &plain("attester_slashing"),
        ),
        round_trip::<capella::SignedBlsToExecutionChange>(
            "bls_to_execution_change",
            &plain("bls_to_execution_change"),
        ),
        round_trip::<altair::SignedContributionAndProof<Mainnet>>(
            "contribution_and_proof",
            &plain("contribution_and_proof"),
        ),
        round_trip::<gloas::SignedExecutionPayloadBid>(
            "execution_payload_bid",
            &versioned("execution_payload_bid"),
        ),
        round_trip::<gloas::PayloadAttestationMessage>(
            "payload_attestation_message",
            &versioned("payload_attestation_message"),
        ),
        round_trip::<gloas::SignedProposerPreferences>(
            "proposer_preferences",
            &versioned("proposer_preferences"),
        ),
        round_trip::<gloas::LightClientOptimisticUpdate<Mainnet>>(
            "light_client_optimistic_update",
            &versioned("light_client_optimistic_update"),
        ),
    ];
    assert_eq!(checked.iter().sum::<usize>(), 11);
}
