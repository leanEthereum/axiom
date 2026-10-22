//! The slasher beside the chain: fed verified votes and headers, it hands back evidence.

use std::{
    io,
    marker::PhantomData,
    path::Path,
    sync::{Arc, mpsc as std_mpsc},
    thread,
};

use axiom_fork_choice::Store;
use axiom_slasher::{Slasher, SlasherConfig, SlasherDatabase, SlasherError, Slashing};
use axiom_state_transition::EpochCommittees;
use axiom_types::{
    BlsSignature, Epoch, Preset, ValidatorIndex,
    accessors::CoreState,
    combined,
    phase0::{AttestationData, Checkpoint, SignedBeaconBlockHeader},
    vote::{CommitteeVote, IndexedVote},
};
use tokio::sync::mpsc::{self, error::TrySendError};
use tracing::{debug, info, warn};

use crate::NodeError;

/// Observations that may queue for the slasher thread before new ones are dropped.
///
/// A mainnet epoch brings about 32 thousand aggregates, under a thousand a slot.
/// The bound absorbs a pass that runs long without letting the queue grow unbounded.
const FEED_DEPTH: usize = 1 << 16;

/// Target checkpoints whose committees the feed keeps: two epochs, two branches each.
const COMMITTEE_CACHE: usize = 4;

/// What the chain thread hands the slasher thread.
#[derive(Debug)]
enum Observation {
    /// A vote whose signature was verified, with its signers.
    Vote(IndexedVote),
    /// A block header whose proposer signature was verified.
    Header(SignedBeaconBlockHeader),
    /// The clock entered a new slot of this epoch: time for a pass.
    Pass(Epoch),
}

/// The chain's end of the slasher: it names each vote's signers and queues what it saw.
///
/// # Overview
///
/// Only verified messages enter, so evidence never rests on a forged signature.
///
/// - Aggregates and single votes enter once the fork choice verified them.
/// - Blocks enter once imported: their header, and every vote in their body.
///
/// Signers come from the committees of the vote's target checkpoint, as the spec computes them.
/// The slasher thread does the rest, so the chain thread never waits on its disk.
/// Evidence comes back the same way, and the chain collects it once a slot.
///
/// The thread ends once the feed is dropped with the chain.
/// Each pass commits atomically, so stopping mid-pass loses only the queue.
#[derive(Debug)]
pub(crate) struct SlasherFeed<P: Preset> {
    /// The slasher thread's queue.
    queue: mpsc::Sender<Observation>,
    /// Evidence the slasher thread found.
    evidence: std_mpsc::Receiver<Slashing>,
    /// Committees by target checkpoint, the most recent last.
    committees: Vec<(Checkpoint, Arc<EpochCommittees>)>,
    /// The preset of the states committees come from.
    preset: PhantomData<P>,
}

impl<P: Preset> SlasherFeed<P> {
    /// Opens the slasher's database and starts its thread.
    ///
    /// # Errors
    ///
    /// Fails when the database cannot be opened under the layout, or the thread cannot start.
    pub(crate) fn start(
        config: SlasherConfig,
        directory: Option<&Path>,
    ) -> Result<Self, NodeError> {
        let database = match directory {
            Some(directory) => SlasherDatabase::open(directory),
            None => SlasherDatabase::in_memory(),
        }
        .map_err(NodeError::Slasher)?;
        let slasher = Slasher::<P>::open(config, database).map_err(NodeError::Slasher)?;
        let (queue, observations) = mpsc::channel(FEED_DEPTH);
        // Unbounded: evidence is rare, and the chain never waits on this thread.
        let (found, evidence) = std_mpsc::channel();
        let worker = SlasherWorker { slasher, found };
        thread::Builder::new()
            .name("slasher".to_owned())
            .spawn(move || worker.run(observations))
            .map_err(|error: io::Error| NodeError::Io {
                context: "spawning the slasher thread",
                error,
            })?;
        info!(history = config.history_length, "slasher enabled");
        Ok(Self {
            queue,
            evidence,
            committees: Vec::new(),
            preset: PhantomData,
        })
    }

    /// Queues an aggregate vote, once its signers are known.
    pub(crate) fn vote(&mut self, store: &Store<P>, vote: &CommitteeVote) {
        let data = &vote.data;
        let Some(committees) = self.committees(store, data.target) else {
            debug!(slot = %data.slot, "no committees for the vote's target; slasher skips it");
            return;
        };
        match committees.attesters(
            data.slot,
            vote.committees.iter().copied(),
            vote.bits.iter().copied(),
        ) {
            Ok(signers) => self.send(Observation::Vote(IndexedVote {
                indices: signers.into_iter().collect(),
                data: data.clone(),
                signature: vote.signature,
            })),
            Err(error) => debug!(slot = %data.slot, %error, "vote signers unresolved"),
        }
    }

    /// Queues one validator's vote.
    pub(crate) fn single(
        &self,
        attester: ValidatorIndex,
        data: &AttestationData,
        signature: BlsSignature,
    ) {
        self.send(Observation::Vote(IndexedVote {
            indices: vec![attester],
            data: data.clone(),
            signature,
        }));
    }

    /// Queues an imported block's header and the votes its body carries.
    pub(crate) fn block(&mut self, store: &Store<P>, block: &combined::SignedBeaconBlock<P>) {
        let message = block.message();
        self.send(Observation::Header(SignedBeaconBlockHeader {
            message: message.header(),
            signature: *block.signature(),
        }));
        for vote in message.committee_votes() {
            self.vote(store, &vote);
        }
    }

    /// Asks for a pass at an epoch.
    pub(crate) fn pass(&self, epoch: Epoch) {
        self.send(Observation::Pass(epoch));
    }

    /// Evidence found since the last call.
    pub(crate) fn found(&self) -> Vec<Slashing> {
        self.evidence.try_iter().collect()
    }

    /// Queues an observation, dropping it when the slasher thread is far behind.
    fn send(&self, observation: Observation) {
        match self.queue.try_send(observation) {
            Err(TrySendError::Full(_)) => warn!("slasher queue full; observation dropped"),
            // A stopped thread already logged why.
            Ok(()) | Err(TrySendError::Closed(_)) => {}
        }
    }

    /// The committees of a target checkpoint, from the cache or the target block's state.
    ///
    /// Shuffling walks every validator, so each target's committees are computed once.
    /// A target block more than an epoch old is advanced to the target's epoch first.
    /// Its active set and seed then match the checkpoint state's, see the phase0 fork choice spec.
    fn committees(&mut self, store: &Store<P>, target: Checkpoint) -> Option<Arc<EpochCommittees>> {
        if let Some((_, committees)) = self.committees.iter().find(|(seen, _)| *seen == target) {
            return Some(Arc::clone(committees));
        }
        let state = store.block_state(&target.root)?;
        let computed = if state.beacon().current_epoch() + 1 < target.epoch {
            let mut advanced = state.clone();
            advanced
                .process_slots(store.config(), target.epoch.start_slot::<P>())
                .ok()?;
            EpochCommittees::compute(advanced.beacon(), target.epoch)
        } else {
            EpochCommittees::compute(state.beacon(), target.epoch)
        };
        let computed = Arc::new(computed);
        if self.committees.len() == COMMITTEE_CACHE {
            self.committees.remove(0);
        }
        self.committees.push((target, Arc::clone(&computed)));
        Some(computed)
    }
}

/// The slasher thread's state: the slasher, and where its evidence goes.
#[derive(Debug)]
struct SlasherWorker<P: Preset> {
    /// The slasher.
    slasher: Slasher<P>,
    /// The chain's end of the evidence channel.
    found: std_mpsc::Sender<Slashing>,
}

impl<P: Preset> SlasherWorker<P> {
    /// Takes observations until the feed is dropped.
    fn run(mut self, mut observations: mpsc::Receiver<Observation>) {
        // Blocking receive is right here: this thread does nothing else.
        while let Some(observation) = observations.blocking_recv() {
            match observation {
                Observation::Vote(vote) => self.slasher.accept_vote(vote),
                Observation::Header(header) => self.slasher.accept_header(header),
                Observation::Pass(epoch) => {
                    if let Err(error) = self.pass(epoch) {
                        warn!(%error, "slasher pass failed; its observations stay queued");
                    }
                }
            }
        }
    }

    /// Runs a pass and sends its evidence to the chain.
    fn pass(&mut self, epoch: Epoch) -> Result<(), SlasherError> {
        let pass = self.slasher.process(epoch)?;
        debug!(
            %epoch,
            votes = pass.votes,
            headers = pass.headers,
            deferred = pass.deferred,
            dropped = pass.dropped,
            pruned = pass.pruned,
            "slasher pass"
        );
        for slashing in pass.slashings {
            // A closed receiver means the chain is gone; the evidence has nowhere to go.
            if self.found.send(slashing).is_err() {
                break;
            }
        }
        Ok(())
    }
}
