//! Fork choice vectors replayed through the node's chain service, with a real database.

use std::{
    collections::HashMap,
    env, fs,
    marker::PhantomData,
    path::PathBuf,
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use axiom_fork_choice::{DataAvailability, PayloadStatus};
use axiom_node::{Chain, ChainDatabase};
use axiom_types::{
    BlsSignature, Hash32, Preset,
    accessors::ForkState,
    bellatrix::PowBlock,
    combined,
    gloas::{PayloadAttestationMessage, SignedExecutionPayloadEnvelope},
    vote::CommitteeVote,
};
use axiom_yaml::Yaml;

use super::{
    StoreReplay,
    fork_choice::{checkpoint, expect_eq, number, payload_status, root, scalar},
};
use crate::{Case, Failure, Meta, Runner, forks::SpecFork};

/// Distinguishes the database directories of cases running in parallel.
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

/// Replays fork choice cases through the chain the node runs, rather than the bare store.
///
/// # Overview
///
/// The chain adds persistence, pruning, and head tracking on top of the store.
/// Each case runs against a fresh on-disk database, then the database is reopened.
///
/// 1. The steps run through the chain, in the case's fork.
/// 2. Every check compares the head and the checkpoints.
/// 3. The database is reopened, and its anchor must be the final finalized block.
///
/// The chain takes blocks, states, and payload envelopes of any fork through the combined enums.
/// Only the vote containers name the case's fork, through its marker.
/// Only head and checkpoint checks apply: the chain does not expose the store's internals.
#[derive(Debug)]
pub struct ChainReplay<P, F> {
    /// The preset and the fork.
    marker: PhantomData<(P, F)>,
}

impl<P: Preset, F: SpecFork> ChainReplay<P, F> {
    /// The runner.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            marker: PhantomData,
        }
    }

    /// Compares the chain's head and checkpoints with a checks step.
    fn checks(chain: &mut Chain<P>, checks: &Yaml) -> Result<(), Failure> {
        // Votes do not move the head on their own, so bring it up to date first.
        chain
            .update_head()
            .map_err(|error| Failure(format!("head update failed: {error}")))?;
        let head = chain.head();
        if let Some(expected) = checks.get("head") {
            expect_eq("head root", &root(expected, "root")?, &head.root)?;
            expect_eq("head slot", &number(expected, "slot")?, &head.slot.0)?;
        }
        if let Some(expected) = checks.get("justified_checkpoint") {
            expect_eq(
                "justified checkpoint",
                &checkpoint(expected)?,
                &head.justified,
            )?;
        }
        if let Some(expected) = checks.get("finalized_checkpoint") {
            expect_eq(
                "finalized checkpoint",
                &checkpoint(expected)?,
                &head.finalized,
            )?;
        }
        Ok(())
    }

    /// Whether a vote comes from one validator, as an attestation subnet carries it.
    fn is_single(vote: &CommitteeVote) -> bool {
        vote.committees.len() == 1 && vote.bits.iter().filter(|bit| **bit).count() == 1
    }

    /// Runs one step, returning whether the chain accepted it.
    fn step(
        case: &Case,
        chain: &mut Chain<P>,
        payload_statuses: &mut HashMap<Hash32, PayloadStatus>,
        step: &Yaml,
        expected_valid: bool,
    ) -> Result<bool, Failure> {
        let name = |key| step.get(key).and_then(Yaml::as_str);
        let verdict = |hash: &Hash32| {
            payload_statuses
                .get(hash)
                .copied()
                .unwrap_or(PayloadStatus::Valid)
        };
        if let Some(tick) = step.get("tick") {
            Ok(chain.on_tick(scalar(tick)?.saturating_mul(1000)).is_ok())
        } else if let Some(file) = name("block") {
            let block = combined::SignedBeaconBlock::<P>::decode(&case.ssz_bytes(file)?, F::FORK)
                .map_err(|error| Failure(format!("{file}: {error}")))?;
            let message = block.message();
            let availability = StoreReplay::<P, F>::availability(case, step, &message)?;
            let payload = verdict(&message.execution_hashes().block_hash);
            Ok(chain.import_block(&block, availability, payload).is_ok())
        } else if let Some(file) = name("attestation") {
            let vote = F::committee_vote(&case.ssz::<F::Attestation<P>>(file)?);
            // A valid vote with one participant takes the path of votes gossiped alone.
            if expected_valid && Self::is_single(&vote) {
                Ok(chain.on_subnet_vote(&vote, vote.payload).is_ok())
            } else {
                Ok(chain.on_vote(&vote).is_ok())
            }
        } else if let Some(file) = name("attester_slashing") {
            let votes = F::conflicting_votes(&case.ssz::<F::AttesterSlashing<P>>(file)?);
            Ok(chain.on_attester_slashing(&votes).is_ok())
        } else if let Some(file) = name("pow_block") {
            chain.on_pow_block(case.ssz::<PowBlock>(file)?);
            Ok(true)
        } else if let Some(file) = name("execution_payload") {
            let envelope = case.ssz::<SignedExecutionPayloadEnvelope<P>>(file)?;
            let payload = verdict(&envelope.message.payload.block_hash);
            Ok(chain
                .import_envelope(&envelope, DataAvailability::Available, payload)
                .is_ok())
        } else if let Some(file) = name("payload_attestation_message") {
            let message = case.ssz::<PayloadAttestationMessage>(file)?;
            Ok(chain.on_payload_attestation(&message).is_ok())
        } else if let Some(hash) = step.get("block_hash") {
            let hash = hash
                .as_hex_array::<32>()
                .map(Hash32)
                .ok_or_else(|| Failure::new("block_hash is not hex"))?;
            let status = step
                .get("payload_status")
                .ok_or_else(|| Failure::new("payload step without status"))?;
            payload_statuses.insert(hash, payload_status(status)?);
            Ok(true)
        } else if let Some(checks) = step.get("checks") {
            Self::checks(chain, checks)?;
            Ok(true)
        } else {
            Err(Failure::new("unsupported step"))
        }
    }

    /// Runs every step, returning the chain for the restart check.
    fn replay(case: &Case, mut chain: Chain<P>) -> Result<Chain<P>, Failure> {
        let mut payload_statuses = HashMap::new();
        let steps = case.yaml("steps.yaml")?;
        let steps = steps
            .as_sequence()
            .ok_or_else(|| Failure::new("steps.yaml is not a sequence"))?;
        for (number, step) in steps.iter().enumerate() {
            let expected_valid = step.get("valid").and_then(Yaml::as_bool).unwrap_or(true);
            let accepted = Self::step(
                case,
                &mut chain,
                &mut payload_statuses,
                step,
                expected_valid,
            )
            .map_err(|failure| Failure(format!("step {number}: {failure}")))?;
            if accepted != expected_valid {
                return Err(Failure(format!(
                    "step {number}: expected valid = {expected_valid}, got {accepted}"
                )));
            }
        }
        Ok(chain)
    }
}

impl<P: Preset, F: SpecFork> Default for ChainReplay<P, F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: Preset, F: SpecFork> Runner for ChainReplay<P, F> {
    fn name(&self) -> &'static str {
        "fork_choice"
    }

    fn skip_case(&self, _handler: &str, case: &Case) -> Option<&'static str> {
        // The node always checks signatures, so cases built without them cannot run here.
        case.meta()
            .ok()
            .filter(Meta::bls_ignored)
            .map(|_| "the node always verifies signatures")
    }

    fn run_case(&self, _handler: &str, case: &Case) -> Result<(), Failure> {
        let directory = TempDirectory::new();
        let config = case.config::<P>(F::FORK)?;
        let anchor_state = case.ssz::<F::State<P>>("anchor_state")?.into_any();
        let anchor_block =
            combined::BeaconBlock::<P>::decode(&case.ssz_bytes("anchor_block")?, F::FORK)
                .map_err(|error| Failure(format!("anchor block: {error}")))?;
        let database = ChainDatabase::open(&directory.0, config.clone())
            .map_err(|error| Failure(format!("database: {error}")))?;
        let chain = Chain::from_anchor(
            config.clone(),
            anchor_state,
            &combined::SignedBeaconBlock::from_parts(anchor_block, BlsSignature::default()),
            database,
        )
        .map_err(|error| Failure(format!("anchor rejected: {error}")))?;

        let chain = Self::replay(case, chain)?;
        let finalized = chain.head().finalized;
        drop(chain);

        // A restart resumes from the last finalized block, whatever came after it.
        let database = ChainDatabase::<P>::open(&directory.0, config.clone())
            .map_err(|error| Failure(format!("reopening the database: {error}")))?;
        let resumed = Chain::resume(config, database)
            .map_err(|error| Failure(format!("resume failed: {error}")))?;
        expect_eq("resumed anchor", &finalized.root, &resumed.head().root)
    }
}

/// A directory removed when dropped.
struct TempDirectory(PathBuf);

impl TempDirectory {
    /// A fresh, empty directory under the system's temporary directory.
    fn new() -> Self {
        let index = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        Self(env::temp_dir().join(format!("axiom-chain-{}-{index}", process::id())))
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        // A leftover directory in the temporary area is harmless, so a failure is ignored.
        let _ignored = fs::remove_dir_all(&self.0);
    }
}
