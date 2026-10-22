//! Fork choice vectors replayed through the node's chain service, with a real database.

use std::{
    collections::HashMap,
    env, fs,
    marker::PhantomData,
    path::PathBuf,
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use axiom_fork_choice::PayloadStatus;
use axiom_node::{Chain, ChainDatabase};
use axiom_state_transition::EpochCommittees;
use axiom_types::{
    BlsSignature, ChainConfig, CommitteeIndex, ForkName, Hash32, Preset,
    fulu::{
        Attestation, AttesterSlashing, BeaconBlock, BeaconState, SignedBeaconBlock,
        SingleAttestation,
    },
};
use axiom_yaml::Yaml;

use super::StoreReplay;
use crate::{Case, Failure, Meta, Runner};

/// Distinguishes the database directories of cases running in parallel.
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

/// Replays fork choice cases through the chain the node runs, rather than the bare store.
///
/// # Overview
///
/// The chain adds persistence, pruning, and head tracking on top of the store.
/// Each case runs against a fresh on-disk database, then the database is reopened.
///
/// 1. The steps run through the chain.
/// 2. Every check compares the head and the checkpoints.
/// 3. The database is reopened, and its anchor must be the final finalized block.
///
/// Only head and checkpoint checks apply: the chain does not expose the store's internals.
#[derive(Debug)]
pub struct ChainReplay<P> {
    /// The preset.
    preset: PhantomData<P>,
}

impl<P: Preset> ChainReplay<P> {
    /// The runner.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            preset: PhantomData,
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
            StoreReplay::<P>::expect_eq(
                "head root",
                &StoreReplay::<P>::root(expected, "root")?,
                &head.root,
            )?;
            StoreReplay::<P>::expect_eq(
                "head slot",
                &StoreReplay::<P>::number(expected, "slot")?,
                &head.slot.0,
            )?;
        }
        if let Some(expected) = checks.get("justified_checkpoint") {
            StoreReplay::<P>::expect_eq(
                "justified checkpoint",
                &StoreReplay::<P>::checkpoint(expected)?,
                &head.justified,
            )?;
        }
        if let Some(expected) = checks.get("finalized_checkpoint") {
            StoreReplay::<P>::expect_eq(
                "finalized checkpoint",
                &StoreReplay::<P>::checkpoint(expected)?,
                &head.finalized,
            )?;
        }
        Ok(())
    }

    /// The one validator's vote an attestation carries, if it has exactly one participant.
    ///
    /// This is the inverse of the conversion the chain applies to gossiped single votes.
    fn single(chain: &Chain<P>, attestation: &Attestation<P>) -> Option<SingleAttestation> {
        let mut committees = attestation
            .committee_bits
            .iter()
            .enumerate()
            .filter(|(_, bit)| *bit);
        let (committee_index, _) = committees.next().filter(|_| committees.next().is_none())?;
        let mut bits = attestation
            .aggregation_bits
            .iter()
            .enumerate()
            .filter(|(_, bit)| *bit);
        let (position, _) = bits.next().filter(|_| bits.next().is_none())?;

        // The attester sits at that position in the committee, as the head state shuffles it.
        let state = chain.state(&chain.head().root)?;
        let shuffling = EpochCommittees::compute(state.beacon(), attestation.data.target.epoch);
        let committee_index = CommitteeIndex(committee_index as u64);
        let attester_index = *shuffling
            .committee(attestation.data.slot, committee_index)?
            .get(position)?;
        Some(SingleAttestation {
            committee_index,
            attester_index,
            data: attestation.data.clone(),
            signature: attestation.signature,
        })
    }

    /// Runs every step, returning the chain for the restart check.
    fn replay(case: &Case, mut chain: Chain<P>) -> Result<Chain<P>, Failure> {
        let mut payload_statuses: HashMap<Hash32, PayloadStatus> = HashMap::new();
        let steps = case.yaml("steps.yaml")?;
        let steps = steps
            .as_sequence()
            .ok_or_else(|| Failure::new("steps.yaml is not a sequence"))?;
        for (number, step) in steps.iter().enumerate() {
            let expected_valid = step.get("valid").and_then(Yaml::as_bool).unwrap_or(true);
            let accepted = if let Some(tick) = step.get("tick") {
                let time_ms = StoreReplay::<P>::scalar(tick)?.saturating_mul(1000);
                chain.on_tick(time_ms).is_ok()
            } else if let Some(name) = step.get("block").and_then(Yaml::as_str) {
                let block = case.ssz::<SignedBeaconBlock<P>>(name)?;
                let availability = StoreReplay::<P>::availability(case, step)?;
                let payload = payload_statuses
                    .get(&block.message.body.execution_payload.block_hash)
                    .copied()
                    .unwrap_or(PayloadStatus::Valid);
                chain.import_block(&block, availability, payload).is_ok()
            } else if let Some(name) = step.get("attestation").and_then(Yaml::as_str) {
                let attestation = case.ssz::<Attestation<P>>(name)?;
                // A valid vote with one participant takes the gossip path for single votes.
                match Self::single(&chain, &attestation).filter(|_| expected_valid) {
                    Some(single) => chain.on_single_attestation(&single).is_ok(),
                    None => chain.on_attestation(&attestation).is_ok(),
                }
            } else if let Some(name) = step.get("attester_slashing").and_then(Yaml::as_str) {
                chain
                    .on_attester_slashing(&case.ssz::<AttesterSlashing<P>>(name)?)
                    .is_ok()
            } else if let Some(hash) = step.get("block_hash") {
                let hash = hash
                    .as_hex_array::<32>()
                    .map(Hash32)
                    .ok_or_else(|| Failure::new("block_hash is not hex"))?;
                let status = step
                    .get("payload_status")
                    .ok_or_else(|| Failure::new("payload step without status"))?;
                payload_statuses.insert(hash, StoreReplay::<P>::payload_status(status)?);
                true
            } else if let Some(checks) = step.get("checks") {
                Self::checks(&mut chain, checks)
                    .map_err(|failure| Failure(format!("step {number}: {failure}")))?;
                true
            } else {
                return Err(Failure(format!("step {number}: unsupported step")));
            };
            if accepted != expected_valid {
                return Err(Failure(format!(
                    "step {number}: expected valid = {expected_valid}, got {accepted}"
                )));
            }
        }
        Ok(chain)
    }
}

impl<P: Preset> Default for ChainReplay<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: Preset> Runner for ChainReplay<P> {
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
        let anchor_state = case.ssz::<BeaconState<P>>("anchor_state")?;
        let anchor_block = case.ssz::<BeaconBlock<P>>("anchor_block")?;
        let database = ChainDatabase::open(&directory.0)
            .map_err(|error| Failure(format!("database: {error}")))?;
        let chain = Chain::from_anchor(
            ChainConfig::for_preset::<P>().with_forks_at_genesis(ForkName::Fulu),
            anchor_state,
            &SignedBeaconBlock {
                message: anchor_block,
                signature: BlsSignature::default(),
            },
            database,
        )
        .map_err(|error| Failure(format!("anchor rejected: {error}")))?;

        let chain = Self::replay(case, chain)?;
        let finalized = chain.head().finalized;
        drop(chain);

        // A restart resumes from the last finalized block, whatever came after it.
        let database = ChainDatabase::<P>::open(&directory.0)
            .map_err(|error| Failure(format!("reopening the database: {error}")))?;
        let resumed = Chain::resume(
            ChainConfig::for_preset::<P>().with_forks_at_genesis(ForkName::Fulu),
            database,
        )
        .map_err(|error| Failure(format!("resume failed: {error}")))?;
        StoreReplay::<P>::expect_eq("resumed anchor", &finalized.root, &resumed.head().root)
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
