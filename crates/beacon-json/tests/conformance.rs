//! Conformance against the SSZ static vectors of the consensus specs.
//!
//! Each case holds a container twice: as snappy-compressed SSZ, and as YAML.
//! The YAML has the shape of the beacon API JSON, with one difference.
//! YAML leaves integers unquoted, while the API quotes them as decimal strings.
//! The YAML reader keeps every scalar as text, so the two forms then agree member for member.
//!
//! For every case of every container this crate encodes, in every fork and both presets:
//!
//! 1. Decode the SSZ.
//! 2. Encode it as JSON, and require exactly the YAML's value, member order included.
//! 3. Decode that JSON's text, and require the SSZ value back.
//!
//! The vectors live outside the repository, downloaded by the vector Makefile.
//! AXIOM_VECTORS names their root, else the nearest ancestor's testing/vectors is used.
//!
//! ```text
//!     $AXIOM_VECTORS/consensus-spec-tests/tests/<preset>/<fork>/ssz_static/<container>/<suite>/<case>
//! ```

use std::{
    env,
    fmt::Debug,
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
    thread,
};

use axiom_beacon_json::ApiJson;
use axiom_json::{Json, Object};
use axiom_snappy::raw;
use axiom_ssz::Ssz;
use axiom_types::{
    ForkName, Mainnet, Minimal, Preset, altair, bellatrix, capella, deneb, electra, fulu, gloas,
    phase0,
};
use axiom_yaml::Yaml;

/// Cases per container in the minimal preset.
///
/// Seven suites: zero, one, nil, max, lengthy, random, and random chaos.
const MINIMAL_CASES: usize = 123;

/// Cases per container in the mainnet preset, which ships only the random suite.
const MAINNET_CASES: usize = 5;

/// Most bytes a decompressed vector may hold; the largest is a few megabytes.
const MAX_CASE_BYTES: usize = 1 << 30;

/// Containers with vectors that the beacon and builder APIs do not carry in this crate.
///
/// A container in neither this list nor a fork's table fails the run, so none is skipped silently.
const OUT_OF_SCOPE: &[(&str, &str)] = &[
    ("BeaconState", "state endpoints are outside this crate"),
    ("Validator", "state endpoints are outside this crate"),
    ("HistoricalBatch", "a state component"),
    ("HistoricalSummary", "a state component"),
    ("PendingAttestation", "a state component"),
    ("PendingConsolidation", "a state component"),
    ("PendingDeposit", "a state component"),
    ("PendingPartialWithdrawal", "a state component"),
    ("SyncCommittee", "a state component"),
    ("Builder", "a state component"),
    ("BuilderPendingPayment", "a state component"),
    ("BuilderPendingWithdrawal", "a state component"),
    ("DepositMessage", "signed, never sent"),
    ("ForkData", "signed, never sent"),
    ("SigningData", "signed, never sent"),
    ("SyncAggregatorSelectionData", "signed, never sent"),
    ("Eth1Block", "an execution layer view"),
    ("PowBlock", "an execution layer view"),
    ("NewPayloadRequest", "an engine API request"),
    ("IndexedPayloadAttestation", "internal to block processing"),
    (
        "LightClientBootstrap",
        "light client endpoints are outside this crate",
    ),
    (
        "LightClientFinalityUpdate",
        "light client endpoints are outside this crate",
    ),
    (
        "LightClientHeader",
        "light client endpoints are outside this crate",
    ),
    (
        "LightClientOptimisticUpdate",
        "light client endpoints are outside this crate",
    ),
    (
        "LightClientUpdate",
        "light client endpoints are outside this crate",
    ),
    ("BlobIdentifier", "a peer-to-peer request"),
    ("DataColumnsByRootIdentifier", "a peer-to-peer request"),
    ("MatrixEntry", "internal to data availability sampling"),
    ("PartialDataColumnGroupID", "a peer-to-peer message"),
    ("PartialDataColumnHeader", "a peer-to-peer message"),
    ("PartialDataColumnPartsMetadata", "a peer-to-peer message"),
    ("PartialDataColumnSidecar", "a peer-to-peer message"),
];

/// Checks one case directory of one container.
type Check = fn(&Path) -> Result<(), String>;

/// A container's vector directory name, and its check.
type Entry = (&'static str, Check);

/// The downloaded vectors.
struct Vectors {
    /// Root of the consensus spec tests.
    root: PathBuf,
}

impl Vectors {
    /// The vectors, or nothing when they are absent and not required.
    ///
    /// # Panics
    ///
    /// Panics when they are missing and AXIOM_REQUIRE_VECTORS is set, as in CI.
    #[expect(
        clippy::print_stderr,
        reason = "the suite reports why it skipped to the test output"
    )]
    fn locate() -> Option<Self> {
        let root = env::var_os("AXIOM_VECTORS").map(PathBuf::from).or_else(|| {
            // Vectors are gitignored, so a git worktree finds them in the main checkout above it.
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .ancestors()
                .map(|dir| dir.join("testing/vectors"))
                .find(|dir| dir.join("consensus-spec-tests").is_dir())
        });
        let root = root.map(|root| root.join("consensus-spec-tests/tests"));
        let found = root.as_ref().is_some_and(|root| root.is_dir());
        assert!(
            found || env::var_os("AXIOM_REQUIRE_VECTORS").is_none(),
            "consensus spec vectors required but missing; run `make -C testing/ef-tests`"
        );
        if !found {
            eprintln!("skipping SSZ static conformance: vectors not found");
        }
        root.filter(|_| found).map(|root| Self { root })
    }

    /// Runs one fork in both presets, and returns the cases run per preset.
    fn run(&self, fork: ForkName, minimal: &[Entry], mainnet: &[Entry]) -> (usize, usize) {
        (
            self.run_preset("minimal", fork, minimal, MINIMAL_CASES),
            self.run_preset("mainnet", fork, mainnet, MAINNET_CASES),
        )
    }

    /// Runs every container of one preset and fork, and returns the number of cases run.
    ///
    /// # Panics
    ///
    /// Panics on any failed case, on a container neither checked nor out of scope,
    /// and on a container whose case count differs from the preset's.
    fn run_preset(
        &self,
        preset: &str,
        fork: ForkName,
        table: &[Entry],
        per_container: usize,
    ) -> usize {
        let dir = self
            .root
            .join(preset)
            .join(fork.as_str())
            .join("ssz_static");
        let mut containers: Vec<String> = fs::read_dir(&dir)
            .unwrap_or_else(|error| panic!("{}: {error}", dir.display()))
            .map(|entry| {
                let entry = entry.expect("directory entry is readable");
                entry.file_name().to_string_lossy().into_owned()
            })
            .collect();
        containers.sort();

        // Every container on disk is either checked or named out of scope.
        let unknown: Vec<&String> = containers
            .iter()
            .filter(|name| {
                !table.iter().any(|(checked, _)| checked == name)
                    && !OUT_OF_SCOPE.iter().any(|(skipped, _)| skipped == name)
            })
            .collect();
        assert!(
            unknown.is_empty(),
            "{preset}/{fork}: unknown containers {unknown:?}"
        );

        // Every checked container has vectors, so a renamed directory cannot pass.
        for (name, _) in table {
            assert!(
                containers.iter().any(|found| found == name),
                "{preset}/{fork}: no vectors for {name}"
            );
        }

        let failures = Mutex::new(Vec::new());
        let counts = Mutex::new(Vec::new());
        thread::scope(|scope| {
            for (name, check) in table {
                let container = dir.join(name);
                let failures = &failures;
                let counts = &counts;
                scope.spawn(move || {
                    let cases = Self::cases(&container);
                    for case in &cases {
                        if let Err(message) = check(case) {
                            failures
                                .lock()
                                .expect("no checker panics while holding the lock")
                                .push(format!("{}: {message}", case.display()));
                        }
                    }
                    counts
                        .lock()
                        .expect("no checker panics while holding the lock")
                        .push((*name, cases.len()));
                });
            }
        });

        let failures = failures
            .into_inner()
            .expect("no checker panicked while holding the lock");
        assert!(
            failures.is_empty(),
            "{} failures:\n{}",
            failures.len(),
            failures.join("\n")
        );

        // Each container ran exactly the preset's number of cases.
        let mut counts = counts
            .into_inner()
            .expect("no checker panicked while holding the lock");
        counts.sort_unstable();
        for (name, count) in &counts {
            assert_eq!(*count, per_container, "{preset}/{fork}/{name}");
        }
        counts.iter().map(|(_, count)| count).sum()
    }

    /// The case directories of one container, across its suites, in name order.
    fn cases(container: &Path) -> Vec<PathBuf> {
        let suites = fs::read_dir(container).expect("container directory is readable");
        let mut cases: Vec<PathBuf> = suites
            .flat_map(|suite| {
                let suite = suite.expect("directory entry is readable");
                fs::read_dir(suite.path()).expect("suite directory is readable")
            })
            .map(|case| case.expect("directory entry is readable").path())
            .collect();
        cases.sort();
        cases
    }
}

/// Checks one case of a container against its JSON form.
fn check<T: Ssz + ApiJson + PartialEq + Debug>(case: &Path) -> Result<(), String> {
    // Phase 1: the SSZ value.
    let compressed =
        fs::read(case.join("serialized.ssz_snappy")).map_err(|error| error.to_string())?;
    let bytes = raw::decompress(&compressed, MAX_CASE_BYTES).map_err(|error| error.to_string())?;
    let value = T::decode(&bytes).map_err(|error| format!("SSZ decode failed: {error}"))?;

    // Phase 2: its JSON form is exactly the YAML's value.
    let text = fs::read_to_string(case.join("value.yaml")).map_err(|error| error.to_string())?;
    let yaml = Yaml::parse(&text).map_err(|error| error.to_string())?;
    let expected = YamlJson::convert(&yaml);
    let json = value.to_json();
    if let Some(difference) = YamlJson::difference(&json, &expected, "") {
        return Err(difference);
    }

    // Phase 3: the JSON text decodes back to the SSZ value.
    let reparsed = Json::parse(json.to_string()).map_err(|error| error.to_string())?;
    match T::from_json(&reparsed) {
        Ok(decoded) if decoded == value => Ok(()),
        Ok(_) => Err("JSON decoded to a different value".to_owned()),
        Err(error) => Err(format!("JSON decode failed: {error}")),
    }
}

/// The YAML of a vector, read as the beacon API's JSON.
struct YamlJson;

impl YamlJson {
    /// The JSON value of a YAML node.
    ///
    /// Every YAML scalar is text, which is what the API writes for integers and bytes alike.
    fn convert(yaml: &Yaml) -> Json {
        match yaml {
            Yaml::Null => Json::Null,
            Yaml::Bool(value) => Json::Bool(*value),
            Yaml::String(text) => Json::from(text.as_str()),
            Yaml::Sequence(items) => Json::Array(items.iter().map(Self::convert).collect()),
            Yaml::Mapping(mapping) => Json::Object(
                mapping
                    .iter()
                    .map(|(key, value)| (key, Self::convert(value)))
                    .collect::<Object>(),
            ),
        }
    }

    /// The first place two values differ, as a path and both sides.
    fn difference(actual: &Json, expected: &Json, path: &str) -> Option<String> {
        match (actual, expected) {
            (Json::Object(actual), Json::Object(expected)) => {
                let names = |object: &Object| {
                    object
                        .iter()
                        .map(|(name, _)| name.clone())
                        .collect::<Vec<_>>()
                };
                if names(actual) != names(expected) {
                    return Some(format!(
                        "{path}: members {:?}, expected {:?}",
                        names(actual),
                        names(expected)
                    ));
                }
                actual
                    .iter()
                    .zip(expected)
                    .find_map(|((name, left), (_, right))| {
                        Self::difference(left, right, &format!("{path}.{name}"))
                    })
            }
            (Json::Array(actual), Json::Array(expected)) => {
                if actual.len() != expected.len() {
                    return Some(format!(
                        "{path}: {} items, expected {}",
                        actual.len(),
                        expected.len()
                    ));
                }
                actual
                    .iter()
                    .zip(expected)
                    .enumerate()
                    .find_map(|(index, (left, right))| {
                        Self::difference(left, right, &format!("{path}[{index}]"))
                    })
            }
            _ if actual == expected => None,
            _ => Some(format!("{path}: {actual}, expected {expected}")),
        }
    }
}

/// The phase0 containers.
fn phase0_table<P: Preset>() -> Vec<Entry> {
    vec![
        ("AggregateAndProof", check::<phase0::AggregateAndProof<P>>),
        ("Attestation", check::<phase0::Attestation<P>>),
        ("AttestationData", check::<phase0::AttestationData>),
        ("AttesterSlashing", check::<phase0::AttesterSlashing<P>>),
        ("BeaconBlock", check::<phase0::BeaconBlock<P>>),
        ("BeaconBlockBody", check::<phase0::BeaconBlockBody<P>>),
        ("BeaconBlockHeader", check::<phase0::BeaconBlockHeader>),
        ("Checkpoint", check::<phase0::Checkpoint>),
        ("Deposit", check::<phase0::Deposit>),
        ("DepositData", check::<phase0::DepositData>),
        ("Eth1Data", check::<phase0::Eth1Data>),
        ("Fork", check::<phase0::Fork>),
        ("IndexedAttestation", check::<phase0::IndexedAttestation<P>>),
        ("ProposerSlashing", check::<phase0::ProposerSlashing>),
        (
            "SignedAggregateAndProof",
            check::<phase0::SignedAggregateAndProof<P>>,
        ),
        ("SignedBeaconBlock", check::<phase0::SignedBeaconBlock<P>>),
        (
            "SignedBeaconBlockHeader",
            check::<phase0::SignedBeaconBlockHeader>,
        ),
        ("SignedVoluntaryExit", check::<phase0::SignedVoluntaryExit>),
        ("VoluntaryExit", check::<phase0::VoluntaryExit>),
    ]
}

/// The containers every fork from phase0 to Deneb shares.
fn shared<P: Preset>() -> Vec<Entry> {
    vec![
        ("AttestationData", check::<phase0::AttestationData>),
        ("BeaconBlockHeader", check::<phase0::BeaconBlockHeader>),
        ("Checkpoint", check::<phase0::Checkpoint>),
        ("Deposit", check::<phase0::Deposit>),
        ("DepositData", check::<phase0::DepositData>),
        ("Eth1Data", check::<phase0::Eth1Data>),
        ("Fork", check::<phase0::Fork>),
        ("ProposerSlashing", check::<phase0::ProposerSlashing>),
        (
            "SignedBeaconBlockHeader",
            check::<phase0::SignedBeaconBlockHeader>,
        ),
        ("SignedVoluntaryExit", check::<phase0::SignedVoluntaryExit>),
        ("VoluntaryExit", check::<phase0::VoluntaryExit>),
        (
            "ContributionAndProof",
            check::<altair::ContributionAndProof<P>>,
        ),
        (
            "SignedContributionAndProof",
            check::<altair::SignedContributionAndProof<P>>,
        ),
        ("SyncAggregate", check::<altair::SyncAggregate<P>>),
        (
            "SyncCommitteeContribution",
            check::<altair::SyncCommitteeContribution<P>>,
        ),
        (
            "SyncCommitteeMessage",
            check::<altair::SyncCommitteeMessage>,
        ),
    ]
}

/// The attestation containers of phase0, which Altair to Deneb keep.
fn phase0_attestations<P: Preset>() -> Vec<Entry> {
    vec![
        ("AggregateAndProof", check::<phase0::AggregateAndProof<P>>),
        ("Attestation", check::<phase0::Attestation<P>>),
        ("AttesterSlashing", check::<phase0::AttesterSlashing<P>>),
        ("IndexedAttestation", check::<phase0::IndexedAttestation<P>>),
        (
            "SignedAggregateAndProof",
            check::<phase0::SignedAggregateAndProof<P>>,
        ),
    ]
}

/// The Altair containers.
fn altair_table<P: Preset>() -> Vec<Entry> {
    let mut table = [shared::<P>(), phase0_attestations::<P>()].concat();
    table.extend::<[Entry; 3]>([
        ("BeaconBlock", check::<altair::BeaconBlock<P>>),
        ("BeaconBlockBody", check::<altair::BeaconBlockBody<P>>),
        ("SignedBeaconBlock", check::<altair::SignedBeaconBlock<P>>),
    ]);
    table
}

/// The Bellatrix containers.
fn bellatrix_table<P: Preset>() -> Vec<Entry> {
    let mut table = [shared::<P>(), phase0_attestations::<P>()].concat();
    table.extend::<[Entry; 5]>([
        ("BeaconBlock", check::<bellatrix::BeaconBlock<P>>),
        ("BeaconBlockBody", check::<bellatrix::BeaconBlockBody<P>>),
        (
            "SignedBeaconBlock",
            check::<bellatrix::SignedBeaconBlock<P>>,
        ),
        ("ExecutionPayload", check::<bellatrix::ExecutionPayload<P>>),
        (
            "ExecutionPayloadHeader",
            check::<bellatrix::ExecutionPayloadHeader<P>>,
        ),
    ]);
    table
}

/// The containers Capella adds, which every later fork keeps.
fn capella_additions() -> Vec<Entry> {
    vec![
        (
            "BLSToExecutionChange",
            check::<capella::BlsToExecutionChange>,
        ),
        (
            "SignedBLSToExecutionChange",
            check::<capella::SignedBlsToExecutionChange>,
        ),
        ("Withdrawal", check::<capella::Withdrawal>),
    ]
}

/// The Capella containers.
fn capella_table<P: Preset>() -> Vec<Entry> {
    let mut table = [
        shared::<P>(),
        phase0_attestations::<P>(),
        capella_additions(),
    ]
    .concat();
    table.extend::<[Entry; 5]>([
        ("BeaconBlock", check::<capella::BeaconBlock<P>>),
        ("BeaconBlockBody", check::<capella::BeaconBlockBody<P>>),
        ("SignedBeaconBlock", check::<capella::SignedBeaconBlock<P>>),
        ("ExecutionPayload", check::<capella::ExecutionPayload<P>>),
        (
            "ExecutionPayloadHeader",
            check::<capella::ExecutionPayloadHeader<P>>,
        ),
    ]);
    table
}

/// The Deneb containers.
fn deneb_table<P: Preset>() -> Vec<Entry> {
    let mut table = [
        shared::<P>(),
        phase0_attestations::<P>(),
        capella_additions(),
    ]
    .concat();
    table.extend::<[Entry; 6]>([
        ("BeaconBlock", check::<deneb::BeaconBlock<P>>),
        ("BeaconBlockBody", check::<deneb::BeaconBlockBody<P>>),
        ("SignedBeaconBlock", check::<deneb::SignedBeaconBlock<P>>),
        ("ExecutionPayload", check::<deneb::ExecutionPayload<P>>),
        (
            "ExecutionPayloadHeader",
            check::<deneb::ExecutionPayloadHeader<P>>,
        ),
        ("BlobSidecar", check::<deneb::BlobSidecar<P>>),
    ]);
    table
}

/// The containers Electra adds that Gloas keeps.
fn electra_requests() -> Vec<Entry> {
    vec![
        (
            "ConsolidationRequest",
            check::<electra::ConsolidationRequest>,
        ),
        ("DepositRequest", check::<electra::DepositRequest>),
        ("SingleAttestation", check::<electra::SingleAttestation>),
        ("WithdrawalRequest", check::<electra::WithdrawalRequest>),
    ]
}

/// The Electra containers that Fulu keeps.
fn electra_kept<P: Preset>() -> Vec<Entry> {
    let mut table = [shared::<P>(), capella_additions(), electra_requests()].concat();
    table.extend::<[Entry; 10]>([
        ("AggregateAndProof", check::<electra::AggregateAndProof<P>>),
        ("Attestation", check::<electra::Attestation<P>>),
        ("AttesterSlashing", check::<electra::AttesterSlashing<P>>),
        (
            "IndexedAttestation",
            check::<electra::IndexedAttestation<P>>,
        ),
        (
            "SignedAggregateAndProof",
            check::<electra::SignedAggregateAndProof<P>>,
        ),
        ("BeaconBlock", check::<electra::BeaconBlock<P>>),
        ("BeaconBlockBody", check::<electra::BeaconBlockBody<P>>),
        ("SignedBeaconBlock", check::<electra::SignedBeaconBlock<P>>),
        ("ExecutionPayload", check::<electra::ExecutionPayload<P>>),
        (
            "ExecutionPayloadHeader",
            check::<electra::ExecutionPayloadHeader<P>>,
        ),
    ]);
    table.push(("ExecutionRequests", check::<electra::ExecutionRequests<P>>));
    table
}

/// The Electra containers.
fn electra_table<P: Preset>() -> Vec<Entry> {
    let mut table = electra_kept::<P>();
    table.push(("BlobSidecar", check::<deneb::BlobSidecar<P>>));
    table
}

/// The Fulu containers, which trade the blob sidecar for the data column sidecar.
fn fulu_table<P: Preset>() -> Vec<Entry> {
    let mut table = electra_kept::<P>();
    table.push(("DataColumnSidecar", check::<fulu::DataColumnSidecar<P>>));
    table
}

/// The Gloas containers.
fn gloas_table<P: Preset>() -> Vec<Entry> {
    let mut table = [shared::<P>(), capella_additions(), electra_requests()].concat();
    table.extend::<[Entry; 21]>([
        ("AggregateAndProof", check::<gloas::AggregateAndProof<P>>),
        ("Attestation", check::<gloas::Attestation<P>>),
        ("AttesterSlashing", check::<gloas::AttesterSlashing>),
        ("IndexedAttestation", check::<gloas::IndexedAttestation>),
        (
            "SignedAggregateAndProof",
            check::<gloas::SignedAggregateAndProof<P>>,
        ),
        ("BeaconBlock", check::<gloas::BeaconBlock<P>>),
        ("BeaconBlockBody", check::<gloas::BeaconBlockBody<P>>),
        ("SignedBeaconBlock", check::<gloas::SignedBeaconBlock<P>>),
        ("ExecutionPayload", check::<gloas::ExecutionPayload<P>>),
        ("ExecutionRequests", check::<gloas::ExecutionRequests>),
        (
            "BuilderDepositRequest",
            check::<gloas::BuilderDepositRequest>,
        ),
        ("BuilderExitRequest", check::<gloas::BuilderExitRequest>),
        ("ExecutionPayloadBid", check::<gloas::ExecutionPayloadBid>),
        (
            "SignedExecutionPayloadBid",
            check::<gloas::SignedExecutionPayloadBid>,
        ),
        (
            "ExecutionPayloadEnvelope",
            check::<gloas::ExecutionPayloadEnvelope<P>>,
        ),
        (
            "SignedExecutionPayloadEnvelope",
            check::<gloas::SignedExecutionPayloadEnvelope<P>>,
        ),
        ("PayloadAttestation", check::<gloas::PayloadAttestation<P>>),
        (
            "PayloadAttestationData",
            check::<gloas::PayloadAttestationData>,
        ),
        (
            "PayloadAttestationMessage",
            check::<gloas::PayloadAttestationMessage>,
        ),
        ("ProposerPreferences", check::<gloas::ProposerPreferences>),
        (
            "SignedProposerPreferences",
            check::<gloas::SignedProposerPreferences>,
        ),
    ]);
    table.push(("DataColumnSidecar", check::<gloas::DataColumnSidecar<P>>));
    table
}

/// Runs a fork and pins its container count and its cases per preset.
fn conform(fork: ForkName, minimal: &[Entry], mainnet: &[Entry], containers: usize) {
    assert_eq!(minimal.len(), containers);
    assert_eq!(mainnet.len(), containers);
    let Some(vectors) = Vectors::locate() else {
        return;
    };
    let cases = vectors.run(fork, minimal, mainnet);
    assert_eq!(
        cases,
        (containers * MINIMAL_CASES, containers * MAINNET_CASES)
    );
}

#[test]
fn phase0_containers() {
    // 19 containers: 2337 minimal cases and 95 mainnet cases.
    conform(
        ForkName::Phase0,
        &phase0_table::<Minimal>(),
        &phase0_table::<Mainnet>(),
        19,
    );
}

#[test]
fn altair_containers() {
    // 24 containers: phase0's 19 and five of the sync committee.
    conform(
        ForkName::Altair,
        &altair_table::<Minimal>(),
        &altair_table::<Mainnet>(),
        24,
    );
}

#[test]
fn bellatrix_containers() {
    // 26 containers: Altair's 24, the payload, and its header.
    conform(
        ForkName::Bellatrix,
        &bellatrix_table::<Minimal>(),
        &bellatrix_table::<Mainnet>(),
        26,
    );
}

#[test]
fn capella_containers() {
    // 29 containers: Bellatrix's 26, the withdrawal, and the credential change and its signature.
    conform(
        ForkName::Capella,
        &capella_table::<Minimal>(),
        &capella_table::<Mainnet>(),
        29,
    );
}

#[test]
fn deneb_containers() {
    // 30 containers: Capella's 29 and the blob sidecar.
    conform(
        ForkName::Deneb,
        &deneb_table::<Minimal>(),
        &deneb_table::<Mainnet>(),
        30,
    );
}

#[test]
fn electra_containers() {
    // 35 containers: Deneb's 30, four requests and their container, and the single attestation.
    conform(
        ForkName::Electra,
        &electra_table::<Minimal>(),
        &electra_table::<Mainnet>(),
        35,
    );
}

#[test]
fn fulu_containers() {
    // 35 containers: Electra's, with the data column sidecar in place of the blob sidecar.
    conform(
        ForkName::Fulu,
        &fulu_table::<Minimal>(),
        &fulu_table::<Mainnet>(),
        35,
    );
}

#[test]
fn gloas_containers() {
    // 45 containers: 23 kept from earlier forks and 22 of Gloas.
    conform(
        ForkName::Gloas,
        &gloas_table::<Minimal>(),
        &gloas_table::<Mainnet>(),
        45,
    );
}
