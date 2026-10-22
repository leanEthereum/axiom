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
use axiom_ssz::Ssz;
use axiom_state_transition::{EpochCommittees, Fork};
use axiom_types::{
    BlsSignature, CommitteeIndex, Hash32, Preset, combined,
    fulu::{
        Attestation, AttesterSlashing, BeaconBlock, BeaconState, SignedBeaconBlock,
        SingleAttestation,
    },
};
use axiom_yaml::Yaml;

use super::{
    StoreReplay,
    fork_choice::{checkpoint, expect_eq, number, payload_status, root, scalar},
};
use crate::{
    Case, Failure, Meta, Runner,
    forks::{Fulu, SpecFork},
};

/// A fork whose blocks the node imports, with its containers as the node names them.
///
/// The node runs Fulu, and the later forks once node integration reaches them.
/// Each conversion is the identity for the fork the node was built on.
pub trait NodeFork: SpecFork {
    /// A state of the fork, as the node anchors on it.
    fn node_state<P: Preset>(state: Self::State<P>) -> BeaconState<P>;

    /// An unsigned block of the fork, as the node anchors on it.
    fn node_anchor<P: Preset>(block: <Self::State<P> as Fork>::Block) -> BeaconBlock<P>;

    /// A signed block of the fork, as the node imports it.
    fn node_block<P: Preset>(block: Self::SignedBeaconBlock<P>) -> SignedBeaconBlock<P>;

    /// An attestation of the fork, as the node counts it.
    fn node_attestation<P: Preset>(attestation: Self::Attestation<P>) -> Attestation<P>;

    /// An attester slashing of the fork, as the node applies it.
    fn node_slashing<P: Preset>(slashing: Self::AttesterSlashing<P>) -> AttesterSlashing<P>;
}

impl NodeFork for Fulu {
    fn node_state<P: Preset>(state: Self::State<P>) -> BeaconState<P> {
        state
    }

    fn node_anchor<P: Preset>(block: <Self::State<P> as Fork>::Block) -> BeaconBlock<P> {
        block
    }

    fn node_block<P: Preset>(block: Self::SignedBeaconBlock<P>) -> SignedBeaconBlock<P> {
        block
    }

    fn node_attestation<P: Preset>(attestation: Self::Attestation<P>) -> Attestation<P> {
        attestation
    }

    fn node_slashing<P: Preset>(slashing: Self::AttesterSlashing<P>) -> AttesterSlashing<P> {
        slashing
    }
}

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
pub struct ChainReplay<P, F> {
    /// The preset and the fork.
    marker: PhantomData<(P, F)>,
}

impl<P: Preset, F: NodeFork> ChainReplay<P, F> {
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
                let time_ms = scalar(tick)?.saturating_mul(1000);
                chain.on_tick(time_ms).is_ok()
            } else if let Some(name) = step.get("block").and_then(Yaml::as_str) {
                let block = F::node_block(case.ssz::<F::SignedBeaconBlock<P>>(name)?);
                let any_block = combined::BeaconBlock::decode(&block.message.encode(), F::FORK)
                    .map_err(|error| Failure(format!("{name}: {error}")))?;
                let availability = StoreReplay::<P, F>::availability(case, step, &any_block)?;
                let payload = payload_statuses
                    .get(&block.message.body.execution_payload.block_hash)
                    .copied()
                    .unwrap_or(PayloadStatus::Valid);
                chain.import_block(&block, availability, payload).is_ok()
            } else if let Some(name) = step.get("attestation").and_then(Yaml::as_str) {
                let attestation = F::node_attestation(case.ssz::<F::Attestation<P>>(name)?);
                // A valid vote with one participant takes the gossip path for single votes.
                match Self::single(&chain, &attestation).filter(|_| expected_valid) {
                    Some(single) => chain.on_single_attestation(&single).is_ok(),
                    None => chain.on_attestation(&attestation).is_ok(),
                }
            } else if let Some(name) = step.get("attester_slashing").and_then(Yaml::as_str) {
                chain
                    .on_attester_slashing(&F::node_slashing(
                        case.ssz::<F::AttesterSlashing<P>>(name)?,
                    ))
                    .is_ok()
            } else if let Some(hash) = step.get("block_hash") {
                let hash = hash
                    .as_hex_array::<32>()
                    .map(Hash32)
                    .ok_or_else(|| Failure::new("block_hash is not hex"))?;
                let status = step
                    .get("payload_status")
                    .ok_or_else(|| Failure::new("payload step without status"))?;
                payload_statuses.insert(hash, payload_status(status)?);
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

impl<P: Preset, F: NodeFork> Default for ChainReplay<P, F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: Preset, F: NodeFork> Runner for ChainReplay<P, F> {
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
        let anchor_state = F::node_state(case.ssz::<F::State<P>>("anchor_state")?);
        let anchor_block =
            F::node_anchor(case.ssz::<<F::State<P> as Fork>::Block>("anchor_block")?);
        let database = ChainDatabase::open(&directory.0)
            .map_err(|error| Failure(format!("database: {error}")))?;
        let chain = Chain::from_anchor(
            case.config::<P>(F::FORK)?,
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
        let resumed = Chain::resume(case.config::<P>(F::FORK)?, database)
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
