//! Fork choice vectors: a store driven through ticks, blocks, and votes, with checks between.

use std::{collections::HashMap, fmt::Debug, marker::PhantomData};

use axiom_das::ColumnSidecar;
use axiom_fork_choice::{
    DataAvailability, FastConfirmation, ForkChoiceNode, NodePayload, PayloadStatus, PayloadVotes,
    Store,
};
use axiom_kzg::{Blob, Bytes48, Kzg};
use axiom_ssz::List;
use axiom_state_transition::{State, Verification};
use axiom_types::{
    ChainConfig, Epoch, ForkName, Gwei, Hash32, Preset, Root, Slot,
    accessors::ForkState,
    bellatrix::PowBlock,
    combined,
    deneb::Blob as BlobBytes,
    fulu::DataColumnSidecar,
    gloas::{PayloadAttestationMessage, SignedExecutionPayloadEnvelope},
    phase0::Checkpoint,
};
use axiom_yaml::Yaml;

use crate::{Case, Failure, Runner, forks::SpecFork};

/// Check keys that belong to the fast confirmation rule rather than the store.
const FAST_CONFIRMATION_KEYS: [&str; 7] = [
    "previous_epoch_observed_justified_checkpoint",
    "current_epoch_observed_justified_checkpoint",
    "previous_epoch_greatest_unrealized_checkpoint",
    "previous_slot_head",
    "current_slot_head",
    "confirmed_root",
    "safe_execution_block_hash",
];

/// The blobs a Deneb block step offers, as the vectors encode them.
type Blobs<P> = List<BlobBytes<P>, <P as Preset>::MaxBlobCommitmentsPerBlock>;

/// Replays the case's steps on a store, and checks it wherever the case asks.
///
/// The fork choice, fast confirmation, and optimistic sync runners share this format.
/// The fork marker names the containers of the case's votes; blocks enter as any fork's.
#[derive(Debug)]
pub struct StoreReplay<P, F> {
    /// The runner directory these vectors live under.
    runner: &'static str,
    /// The preset and the fork.
    marker: PhantomData<(P, F)>,
}

/// What a replay carries between steps besides the store.
#[derive(Debug, Default)]
struct Mocks {
    /// The engine's verdict on each payload, by block hash.
    payload_statuses: HashMap<Hash32, PayloadStatus>,
}

impl<P: Preset, F: SpecFork> StoreReplay<P, F> {
    /// The fork choice runner.
    #[must_use]
    pub const fn fork_choice() -> Self {
        Self {
            runner: "fork_choice",
            marker: PhantomData,
        }
    }

    /// The optimistic sync runner.
    #[must_use]
    pub const fn sync() -> Self {
        Self {
            runner: "sync",
            marker: PhantomData,
        }
    }

    /// The fast confirmation runner.
    #[must_use]
    pub const fn fast_confirmation() -> Self {
        Self {
            runner: "fast_confirmation",
            marker: PhantomData,
        }
    }

    /// Runs the fast confirmation rule when a check asks for its outputs, then compares them.
    ///
    /// The vector generator runs the rule once per slot and records its outputs right after.
    fn fast_confirmation_checks(
        store: &mut Store<P>,
        confirmation: &mut FastConfirmation,
        checks: &Yaml,
    ) -> Result<(), Failure> {
        if !FAST_CONFIRMATION_KEYS
            .iter()
            .any(|key| checks.get(key).is_some())
        {
            return Ok(());
        }
        confirmation
            .on_fast_confirmation(store)
            .map_err(|error| Failure(format!("fast confirmation failed: {error}")))?;
        let checkpoints = [
            (
                "previous_epoch_observed_justified_checkpoint",
                confirmation.previous_epoch_observed_justified_checkpoint,
            ),
            (
                "current_epoch_observed_justified_checkpoint",
                confirmation.current_epoch_observed_justified_checkpoint,
            ),
            (
                "previous_epoch_greatest_unrealized_checkpoint",
                confirmation.previous_epoch_greatest_unrealized_checkpoint,
            ),
        ];
        for (key, actual) in checkpoints {
            if let Some(expected) = checks.get(key) {
                expect_eq(key, &checkpoint(expected)?, &actual)?;
            }
        }
        let roots = [
            ("previous_slot_head", confirmation.previous_slot_head),
            ("current_slot_head", confirmation.current_slot_head),
            ("confirmed_root", confirmation.confirmed_root),
            (
                "safe_execution_block_hash",
                Root(confirmation.safe_execution_block_hash(store).0),
            ),
        ];
        for (key, actual) in roots {
            if let Some(expected) = checks.get(key) {
                let expected = expected
                    .as_hex_array::<32>()
                    .map(Root)
                    .ok_or_else(|| Failure(format!("{key} is not hex")))?;
                expect_eq(key, &expected, &actual)?;
            }
        }
        Ok(())
    }

    /// Data availability of a block step, from the blobs or columns the step lists.
    ///
    /// Deneb and Electra list blobs with their proofs; Fulu lists sampled columns.
    /// Nothing listed means nothing to sample, so the data counts as available.
    pub(super) fn availability(
        case: &Case,
        step: &Yaml,
        block: &combined::BeaconBlock<P>,
    ) -> Result<DataAvailability, Failure> {
        let verdict = |available| {
            if available {
                DataAvailability::Available
            } else {
                DataAvailability::Unavailable
            }
        };
        if let Some(columns) = step.get("columns").and_then(Yaml::as_sequence) {
            // An empty list means sampling failed.
            if columns.is_empty() {
                return Ok(DataAvailability::Unavailable);
            }
            let config = ChainConfig::for_preset::<P>().with_forks_at_genesis(ForkName::Fulu);
            let mut available = true;
            for name in columns {
                let name = name
                    .as_str()
                    .ok_or_else(|| Failure::new("column name is not a string"))?;
                let sidecar = case.ssz::<DataColumnSidecar<P>>(name)?;
                let column = ColumnSidecar(&sidecar);
                available &= column.verify_structure(&config).is_ok()
                    && column.verify_kzg_proofs(Kzg::mainnet()).is_ok();
            }
            return Ok(verdict(available));
        }
        let commitments = block.blob_kzg_commitments();
        let blobs = match step.get("blobs").and_then(Yaml::as_str) {
            Some(name) => case.ssz::<Blobs<P>>(name)?.iter().cloned().collect(),
            None => Vec::new(),
        };
        let proofs = step
            .get("proofs")
            .and_then(Yaml::as_sequence)
            .unwrap_or_default()
            .iter()
            .map(|proof| proof.as_hex_array::<48>().map(Bytes48::from))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| Failure::new("proof is not 48 hex bytes"))?;
        if commitments.is_empty() && blobs.is_empty() && proofs.is_empty() {
            return Ok(DataAvailability::Available);
        }
        let blobs = blobs
            .iter()
            .map(|blob| Blob::from_bytes(blob))
            .collect::<Result<Vec<_>, _>>();
        let Ok(blobs) = blobs else {
            return Ok(DataAvailability::Unavailable);
        };
        let commitments: Vec<Bytes48> = commitments
            .iter()
            .map(|commitment| Bytes48::from(commitment.0))
            .collect();
        // Mismatched lengths and malformed points fail the check, as the spec's assertion does.
        let available = Kzg::mainnet()
            .verify_blob_kzg_proof_batch(&blobs, &commitments, &proofs)
            .unwrap_or(false);
        Ok(verdict(available))
    }

    /// Applies one block step, deciding data availability from the step's blobs or columns.
    fn block_step(
        store: &mut Store<P>,
        case: &Case,
        step: &Yaml,
        verification: Verification,
        mocks: &Mocks,
    ) -> Result<bool, Failure> {
        let name = step
            .get("block")
            .and_then(Yaml::as_str)
            .ok_or_else(|| Failure::new("block step without a name"))?;
        let block = combined::SignedBeaconBlock::<P>::decode(&case.ssz_bytes(name)?, F::FORK)
            .map_err(|error| Failure(format!("{name}: {error}")))?;
        let message = block.message();
        let availability = Self::availability(case, step, &message)?;
        let payload = mocks
            .payload_statuses
            .get(&message.execution_hashes().block_hash)
            .copied()
            .unwrap_or(PayloadStatus::Valid);
        Ok(store
            .import_block(&block, availability, verification, payload)
            .is_ok())
    }

    /// Compares the store with every check of a checks step.
    fn checks(store: &mut Store<P>, checks: &Yaml) -> Result<(), Failure> {
        let Some(mapping) = checks.as_mapping() else {
            return Err(Failure::new("checks step is not a mapping"));
        };
        for (key, expected) in mapping {
            match key {
                "head" => {
                    let head = store
                        .head()
                        .map_err(|error| Failure(format!("head failed: {error}")))?;
                    let slot = store
                        .blocks()
                        .get(&head.root)
                        .map_or(Slot::GENESIS, |node| node.slot);
                    expect_eq("head root", &root(expected, "root")?, &head.root)?;
                    expect_eq("head slot", &number(expected, "slot")?, &slot.0)?;
                    if let Some(status) = expected.get("payload_status") {
                        expect_eq(
                            "head payload status",
                            &scalar(status)?,
                            &u64::from(head.payload.code()),
                        )?;
                    }
                }
                "time" => {
                    expect_eq("time", &scalar(expected)?, &(store.time_ms() / 1000))?;
                }
                "genesis_time" => {
                    expect_eq(
                        "genesis time",
                        &scalar(expected)?,
                        &(store.slot_clock().genesis_ms() / 1000),
                    )?;
                }
                "justified_checkpoint" => {
                    expect_eq(
                        "justified checkpoint",
                        &checkpoint(expected)?,
                        &store.justified_checkpoint(),
                    )?;
                }
                "finalized_checkpoint" => {
                    expect_eq(
                        "finalized checkpoint",
                        &checkpoint(expected)?,
                        &store.finalized_checkpoint(),
                    )?;
                }
                "proposer_boost_root" => {
                    let root = expected
                        .as_hex_array::<32>()
                        .ok_or_else(|| Failure::new("proposer boost root is not hex"))?;
                    expect_eq(
                        "proposer boost root",
                        &Root(root),
                        &store.proposer_boost_root(),
                    )?;
                }
                "get_proposer_head" => {
                    let expected = expected
                        .as_hex_array::<32>()
                        .ok_or_else(|| Failure::new("proposer head is not hex"))?;
                    let head = store
                        .head()
                        .map_err(|error| Failure(format!("head failed: {error}")))?;
                    let slot = store.current_slot();
                    let proposer_head = store
                        .proposer_head(head, slot)
                        .map_err(|error| Failure(format!("proposer head failed: {error}")))?;
                    expect_eq("proposer head", &Root(expected), &proposer_head.root)?;
                }
                "viable_for_head_roots_and_weights" => {
                    let actual = store
                        .viable_leaves_and_weights()
                        .map_err(|error| Failure(format!("viable leaves failed: {error}")))?;
                    expect_eq("viable leaves", &viable_leaves(expected)?, &actual)?;
                }
                "payload_timeliness_vote" => {
                    let (root, votes) = ptc_votes(expected)?;
                    let actual = store.payload_votes(&root).map(|votes| &votes.timely);
                    expect_eq("payload timeliness votes", &Some(&votes), &actual)?;
                }
                "payload_data_availability_vote" => {
                    let (root, votes) = ptc_votes(expected)?;
                    let actual = store
                        .payload_votes(&root)
                        .map(|votes: &PayloadVotes| &votes.available);
                    expect_eq("payload availability votes", &Some(&votes), &actual)?;
                }
                key if FAST_CONFIRMATION_KEYS.contains(&key) => {}
                other => return Err(Failure(format!("unsupported check {other}"))),
            }
        }
        Ok(())
    }

    /// Runs one step, returning whether the store accepted it.
    fn step(
        store: &mut Store<P>,
        confirmation: &mut FastConfirmation,
        mocks: &mut Mocks,
        case: &Case,
        step: &Yaml,
        verification: Verification,
    ) -> Result<bool, Failure> {
        let name = |key| step.get(key).and_then(Yaml::as_str);
        if let Some(tick) = step.get("tick") {
            store.on_tick(scalar(tick)?.saturating_mul(1000));
            Ok(true)
        } else if step.get("block").is_some() {
            Self::block_step(store, case, step, verification, mocks)
        } else if let Some(file) = name("attestation") {
            let vote = F::committee_vote(&case.ssz::<F::Attestation<P>>(file)?);
            Ok(store.on_attestation(&vote, false, verification).is_ok())
        } else if let Some(file) = name("attester_slashing") {
            let votes = F::conflicting_votes(&case.ssz::<F::AttesterSlashing<P>>(file)?);
            Ok(store.on_attester_slashing(&votes, verification).is_ok())
        } else if let Some(file) = name("pow_block") {
            store.on_pow_block(case.ssz::<PowBlock>(file)?);
            Ok(true)
        } else if let Some(file) = name("execution_payload") {
            let envelope = case.ssz::<SignedExecutionPayloadEnvelope<P>>(file)?;
            let payload = mocks
                .payload_statuses
                .get(&envelope.message.payload.block_hash)
                .copied()
                .unwrap_or(PayloadStatus::Valid);
            Ok(store
                .on_execution_payload_envelope(
                    &envelope,
                    DataAvailability::Available,
                    verification,
                    payload,
                )
                .is_ok())
        } else if let Some(file) = name("payload_attestation_message") {
            let message = case.ssz::<PayloadAttestationMessage>(file)?;
            Ok(store
                .on_payload_attestation_message(&message, false, verification)
                .is_ok())
        } else if let Some(hash) = step.get("block_hash") {
            let hash = hash
                .as_hex_array::<32>()
                .map(Hash32)
                .ok_or_else(|| Failure::new("block_hash is not hex"))?;
            let status = step
                .get("payload_status")
                .ok_or_else(|| Failure::new("payload step without status"))?;
            mocks.payload_statuses.insert(hash, payload_status(status)?);
            Ok(true)
        } else if let Some(checks) = step.get("checks") {
            Self::fast_confirmation_checks(store, confirmation, checks)?;
            Self::checks(store, checks)?;
            Ok(true)
        } else {
            Err(Failure::new("unsupported step"))
        }
    }
}

impl<P: Preset, F: SpecFork> Runner for StoreReplay<P, F> {
    fn name(&self) -> &'static str {
        self.runner
    }

    fn run_case(&self, _handler: &str, case: &Case) -> Result<(), Failure> {
        let meta = case.meta()?;
        let verification = if meta.bls_ignored() {
            Verification::Skip
        } else {
            Verification::Verify
        };
        let anchor_state = case.ssz::<F::State<P>>("anchor_state")?.into_any();
        let anchor_block =
            combined::BeaconBlock::<P>::decode(&case.ssz_bytes("anchor_block")?, F::FORK)
                .map_err(|error| Failure(format!("anchor block: {error}")))?;
        let mut store = Store::new(
            case.config::<P>(F::FORK)?,
            State::new(anchor_state),
            &anchor_block,
        )
        .map_err(|error| Failure(format!("anchor rejected: {error}")))?;
        let mut confirmation = FastConfirmation::new(&store);
        let mut mocks = Mocks::default();

        let steps = case.yaml("steps.yaml")?;
        let steps = steps
            .as_sequence()
            .ok_or_else(|| Failure::new("steps.yaml is not a sequence"))?;
        for (number, step) in steps.iter().enumerate() {
            let expected_valid = step.get("valid").and_then(Yaml::as_bool).unwrap_or(true);
            let accepted = Self::step(
                &mut store,
                &mut confirmation,
                &mut mocks,
                case,
                step,
                verification,
            )
            .map_err(|failure| Failure(format!("step {number}: {failure}")))?;
            if accepted != expected_valid {
                return Err(Failure(format!(
                    "step {number}: expected {}, got {}",
                    verdict(expected_valid),
                    verdict(accepted)
                )));
            }
        }
        Ok(())
    }
}

/// How a step's outcome reads in a failure.
const fn verdict(accepted: bool) -> &'static str {
    if accepted { "acceptance" } else { "rejection" }
}

/// The mocked engine verdict of a payload step.
pub(super) fn payload_status(status: &Yaml) -> Result<PayloadStatus, Failure> {
    let latest_valid_hash = status
        .get("latest_valid_hash")
        .and_then(Yaml::as_hex_array::<32>)
        .map(Hash32);
    match status.get("status").and_then(Yaml::as_str) {
        Some("VALID") => Ok(PayloadStatus::Valid),
        Some("SYNCING" | "ACCEPTED") => Ok(PayloadStatus::NotValidated),
        Some("INVALID") => Ok(PayloadStatus::Invalid { latest_valid_hash }),
        Some("INVALID_BLOCK_HASH") => Ok(PayloadStatus::Invalid {
            latest_valid_hash: None,
        }),
        other => Err(Failure(format!("unknown payload status {other:?}"))),
    }
}

/// Fails unless two values are equal.
pub(super) fn expect_eq<T: PartialEq + Debug>(
    what: &str,
    expected: &T,
    actual: &T,
) -> Result<(), Failure> {
    if expected == actual {
        Ok(())
    } else {
        Err(Failure(format!(
            "{what}: expected {expected:?}, got {actual:?}"
        )))
    }
}

/// A number scalar.
pub(super) fn scalar(value: &Yaml) -> Result<u64, Failure> {
    value
        .as_u64()
        .ok_or_else(|| Failure::new("expected a number"))
}

/// A number field of a mapping.
pub(super) fn number(value: &Yaml, key: &str) -> Result<u64, Failure> {
    value
        .get(key)
        .and_then(Yaml::as_u64)
        .ok_or_else(|| Failure(format!("missing number {key}")))
}

/// A root field of a mapping.
pub(super) fn root(value: &Yaml, key: &str) -> Result<Root, Failure> {
    value
        .get(key)
        .and_then(Yaml::as_hex_array::<32>)
        .map(Root)
        .ok_or_else(|| Failure(format!("missing root {key}")))
}

/// A checkpoint mapping.
pub(super) fn checkpoint(value: &Yaml) -> Result<Checkpoint, Failure> {
    Ok(Checkpoint {
        epoch: Epoch(number(value, "epoch")?),
        root: root(value, "root")?,
    })
}

/// The expected viable leaves, sorted as the store sorts them.
///
/// Before Gloas a leaf names no payload status, and the store reports its block full.
fn viable_leaves(value: &Yaml) -> Result<Vec<(ForkChoiceNode, Gwei)>, Failure> {
    let entries = value
        .as_sequence()
        .ok_or_else(|| Failure::new("viable leaves are not a sequence"))?;
    let mut leaves = entries
        .iter()
        .map(|entry| {
            let payload = match entry.get("payload_status").map(scalar).transpose()? {
                Some(0) => NodePayload::Empty,
                None | Some(1) => NodePayload::Full,
                Some(_) => NodePayload::Pending,
            };
            let node = ForkChoiceNode {
                root: root(entry, "root")?,
                payload,
            };
            Ok((node, Gwei(number(entry, "weight")?)))
        })
        .collect::<Result<Vec<_>, Failure>>()?;
    leaves.sort_by_key(|(node, weight)| (node.root, node.payload.code(), *weight));
    Ok(leaves)
}

/// A block's committee votes, one per seat, as a check lists them.
fn ptc_votes(value: &Yaml) -> Result<(Root, Vec<Option<bool>>), Failure> {
    let block = root(value, "block_root")?;
    let votes = value
        .get("votes")
        .and_then(Yaml::as_sequence)
        .ok_or_else(|| Failure::new("committee votes are not a sequence"))?
        .iter()
        .map(|vote| {
            if vote.is_null() {
                Ok(None)
            } else {
                vote.as_bool()
                    .map(Some)
                    .ok_or_else(|| Failure::new("committee vote is not a boolean"))
            }
        })
        .collect::<Result<Vec<_>, Failure>>()?;
    Ok((block, votes))
}
