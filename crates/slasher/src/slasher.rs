//! The slasher: queues what the node saw, and finds offences in batches.

use std::{marker::PhantomData, mem};

use axiom_store::Batch;
use axiom_types::{
    Epoch, Preset,
    phase0::{ProposerSlashing, SignedBeaconBlockHeader},
    vote::{ConflictingVotes, IndexedVote},
};

use crate::{
    Geometry, SlasherConfig, SlasherDatabase, SlasherError, attestations::AttestationPass,
    proposals::ProposalPass,
};

/// Evidence that a validator broke a slashing condition.
///
/// The evidence is fork-neutral: the block that carries it picks its fork's container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Slashing {
    /// Two votes breaking a Casper FFG commandment, the surrounding or earlier one first.
    Attester(ConflictingVotes),
    /// Two different headers signed by one proposer for one slot.
    Proposer(ProposerSlashing),
}

/// What one processing pass did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pass {
    /// Evidence found, in no particular order.
    pub slashings: Vec<Slashing>,
    /// Votes checked and recorded.
    pub votes: usize,
    /// Votes kept for a later pass, since their target lies after the pass's epoch.
    pub deferred: usize,
    /// Votes dropped: a source before the window, or after the target.
    pub dropped: usize,
    /// Headers checked and recorded.
    pub headers: usize,
    /// Database entries deleted for leaving the window.
    pub pruned: usize,
}

/// A slasher over a durable history of votes and headers.
///
/// # Overview
///
/// The node hands over every vote and header whose signature it verified.
/// They queue until a pass, which the node runs about once a slot.
///
/// 1. Votes with a target after the pass's epoch wait for a later pass.
/// 2. Votes whose source left the window are dropped, as their cells no longer exist.
/// 3. Headers are checked for a second header of the same slot and proposer.
/// 4. Votes are checked for double and surround votes, then recorded.
/// 5. One batch commits the whole pass, so a crash loses the queue but never corrupts history.
///
/// # Invariants
///
/// The pass epoch never decreases, even across restarts: the database keeps the last one.
///
/// Every validator that cast two slashable votes within the window is found.
/// Its first offending vote yields evidence, and later votes may yield more.
/// No evidence is ever produced for votes that do not conflict.
///
/// The adversary is a validator who equivocates and hopes the evidence never surfaces.
/// A double vote hides only by never reaching this node.
/// A surround vote hides only by reaching back beyond the window.
#[derive(Debug)]
pub struct Slasher<P: Preset> {
    /// The durable history.
    database: SlasherDatabase,
    /// The layout of the history.
    geometry: Geometry,
    /// Epochs between pruning passes.
    prune_period: u64,
    /// Votes waiting for a pass.
    votes: Vec<IndexedVote>,
    /// Headers waiting for a pass.
    headers: Vec<SignedBeaconBlockHeader>,
    /// The epoch of the latest pass.
    epoch: Option<Epoch>,
    /// The epoch of the latest pruning.
    pruned: Option<Epoch>,
    /// The preset that maps slots to epochs.
    preset: PhantomData<P>,
}

impl<P: Preset> Slasher<P> {
    /// A slasher over a database, which must have been written under the same layout.
    ///
    /// # Errors
    ///
    /// Fails when the configuration is invalid, or differs from the database's layout.
    pub fn open(config: SlasherConfig, database: SlasherDatabase) -> Result<Self, SlasherError> {
        let geometry = config.geometry()?;
        database.adopt(geometry)?;
        let epoch = database.epoch()?;
        Ok(Self {
            database,
            geometry,
            prune_period: config.prune_period,
            votes: Vec::new(),
            headers: Vec::new(),
            epoch,
            pruned: None,
            preset: PhantomData,
        })
    }

    /// Queues a vote whose signature was verified against its signers.
    ///
    /// The signers are sorted and deduplicated, as an indexed attestation lists them.
    /// A vote without signers carries no evidence and is ignored.
    pub fn accept_vote(&mut self, mut vote: IndexedVote) {
        vote.indices.sort_unstable();
        vote.indices.dedup();
        if !vote.indices.is_empty() {
            self.votes.push(vote);
        }
    }

    /// Queues a block header whose proposer signature was verified.
    pub fn accept_header(&mut self, header: SignedBeaconBlockHeader) {
        self.headers.push(header);
    }

    /// Votes and headers waiting for a pass.
    #[must_use]
    pub const fn queued(&self) -> usize {
        self.votes.len() + self.headers.len()
    }

    /// The epoch of the latest pass.
    #[must_use]
    pub const fn epoch(&self) -> Option<Epoch> {
        self.epoch
    }

    /// The durable history, for its metrics.
    #[must_use]
    pub const fn database(&self) -> &SlasherDatabase {
        &self.database
    }

    /// Checks and records everything queued, as of an epoch.
    ///
    /// An epoch earlier than the latest pass's is raised to it.
    /// On failure the queue is kept, and nothing of the pass is committed.
    ///
    /// # Errors
    ///
    /// Fails when the database cannot be read or written, or holds corrupt history.
    pub fn process(&mut self, epoch: Epoch) -> Result<Pass, SlasherError> {
        let current = self.epoch.map_or(epoch, |latest| latest.max(epoch));
        let window_start = self.geometry.window_start(current);

        // Votes are taken out of the queue, and come back on failure.
        let queued = mem::take(&mut self.votes);
        let (ready, deferred): (Vec<_>, Vec<_>) = queued
            .into_iter()
            .partition(|vote| vote.data.target.epoch <= current);
        let total = ready.len();
        let ready: Vec<IndexedVote> = ready
            .into_iter()
            .filter(|vote| {
                let (source, target) = (vote.data.source.epoch, vote.data.target.epoch);
                source <= target && source >= window_start
            })
            .collect();
        let headers = mem::take(&mut self.headers);

        match self.run(current, &ready, &headers) {
            Ok(slashings) => {
                self.votes = deferred;
                self.epoch = Some(current);
                let pruned = self.prune(current)?;
                Ok(Pass {
                    slashings,
                    votes: ready.len(),
                    deferred: self.votes.len(),
                    dropped: total - ready.len(),
                    headers: headers.len(),
                    pruned,
                })
            }
            Err(error) => {
                self.votes = ready.into_iter().chain(deferred).collect();
                self.headers = headers;
                Err(error)
            }
        }
    }

    /// Runs both checks and commits their changes in one batch.
    fn run(
        &self,
        current: Epoch,
        votes: &[IndexedVote],
        headers: &[SignedBeaconBlockHeader],
    ) -> Result<Vec<Slashing>, SlasherError> {
        let mut batch = Batch::new();
        let window_start = self.geometry.window_start(current);
        let mut slashings = Vec::new();

        let mut proposals = ProposalPass::new(&self.database);
        for header in headers {
            // A header from before the window would be pruned at once, so it is not kept.
            if header.message.slot.epoch::<P>() < window_start {
                continue;
            }
            if let Some(slashing) = proposals.check(header)? {
                slashings.push(Slashing::Proposer(slashing));
            }
        }
        proposals.stage(&mut batch)?;

        let pass = AttestationPass::new(&self.database, self.geometry, current, votes);
        slashings.extend(pass.run(&mut batch)?.into_iter().map(Slashing::Attester));

        self.database.put_epoch(&mut batch, current)?;
        self.database.write(&batch)?;
        Ok(slashings)
    }

    /// Deletes history that left the window, once per prune period.
    fn prune(&mut self, current: Epoch) -> Result<usize, SlasherError> {
        if self
            .pruned
            .is_some_and(|pruned| current.0 < pruned.0.saturating_add(self.prune_period))
        {
            return Ok(0);
        }
        let start = self.geometry.window_start(current);
        let deleted = self.database.prune(start, start.start_slot::<P>())?;
        self.pruned = Some(current);
        Ok(deleted)
    }
}
