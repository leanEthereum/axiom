//! Double and surround votes: one pass over the votes received since the last one.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use axiom_store::Batch;
use axiom_types::{
    Epoch, ValidatorIndex,
    phase0::AttestationData,
    vote::{ConflictingVotes, IndexedVote},
};

use crate::{
    Geometry, SlasherDatabase, SlasherError,
    records::{Records, VoteId},
    signers::Signers,
    span::{SpanRow, Surround},
};

/// A vote of this pass, or one stored by an earlier pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum VoteRef {
    /// The vote at this position of the pass's arrivals.
    Arrival(usize),
    /// A stored vote.
    Stored(VoteId),
}

/// One pass over votes whose targets lie in the window.
///
/// # Overview
///
/// Validators are independent, so the pass walks one row of validators at a time.
/// Within a row each validator sees its votes in arrival order.
///
/// 1. A validator's record for the target names the vote it already cast there.
///    A different vote for the same target is a double vote.
/// 2. A first vote for the target is recorded, then checked against the span arrays.
///
/// # Invariants
///
/// A span cell naming target t for validator v was set by the vote recorded for (v, t).
/// A vote found to conflict sets no span, and a repeated vote sets none either.
/// So the record the spans point at is always the vote that conflicts.
///
/// A vote is stored only if some validator's record names it.
/// An aggregate whose signers all voted the same way before adds nothing, and is dropped.
#[derive(Debug)]
pub(crate) struct AttestationPass<'a> {
    /// The stored history.
    database: &'a SlasherDatabase,
    /// The layout.
    geometry: Geometry,
    /// The epoch the pass runs at.
    current: Epoch,
    /// The votes of the pass, each with sorted unique signers in the window.
    arrivals: &'a [IndexedVote],
    /// The number each recorded arrival received.
    numbers: Vec<Option<VoteId>>,
    /// Which arrival each number of this pass belongs to.
    arrival_of: HashMap<VoteId, usize>,
    /// Record chunks the pass touched.
    records: Records,
    /// Data of stored votes the pass compared against.
    stored_data: HashMap<VoteId, AttestationData>,
    /// Last number given per target epoch.
    counters: BTreeMap<Epoch, u32>,
    /// Conflicting pairs found, first vote first.
    conflicts: BTreeSet<(VoteRef, VoteRef)>,
}

impl<'a> AttestationPass<'a> {
    /// A pass over votes at an epoch.
    pub(crate) fn new(
        database: &'a SlasherDatabase,
        geometry: Geometry,
        current: Epoch,
        arrivals: &'a [IndexedVote],
    ) -> Self {
        Self {
            database,
            geometry,
            current,
            arrivals,
            numbers: vec![None; arrivals.len()],
            arrival_of: HashMap::new(),
            records: Records::new(geometry),
            stored_data: HashMap::new(),
            counters: BTreeMap::new(),
            conflicts: BTreeSet::new(),
        }
    }

    /// Checks and records every vote, staging every change.
    ///
    /// # Returns
    ///
    /// The conflicting pairs, the first vote of each surrounding or equal in target to the second.
    pub(crate) fn run(mut self, batch: &mut Batch) -> Result<Vec<ConflictingVotes>, SlasherError> {
        // Each signer's votes, grouped by row, in arrival order within a row.
        let mut rows: BTreeMap<u64, Vec<(usize, ValidatorIndex)>> = BTreeMap::new();
        for (position, vote) in self.arrivals.iter().enumerate() {
            for &validator in &vote.indices {
                rows.entry(self.geometry.row(validator))
                    .or_default()
                    .push((position, validator));
            }
        }
        for (row, entries) in rows {
            self.run_row(row, &entries, batch)?;
        }
        self.stage(batch)?;
        self.conflicts
            .iter()
            .map(|&(first, second)| {
                Ok(ConflictingVotes {
                    first: self.indexed(first)?,
                    second: self.indexed(second)?,
                })
            })
            .collect()
    }

    /// Brings one row to the current epoch, then applies its validators' votes.
    fn run_row(
        &mut self,
        row: u64,
        entries: &[(usize, ValidatorIndex)],
        batch: &mut Batch,
    ) -> Result<(), SlasherError> {
        let database = self.database;
        let cells = self.geometry.span_cells();
        let mut load = |span, row, column| database.span(span, row, column, cells);
        let window_start = self.geometry.window_start(self.current);
        let mut spans = SpanRow::new(self.geometry, row);

        // The columns of epochs the row has not seen yet still hold epochs that left the window.
        let last = database.row_epoch(row)?;
        if let Some(last) = last
            && last < self.current
        {
            let from = (last + 1).0.max(window_start.0);
            spans.clear((from..=self.current.0).map(Epoch), &mut load)?;
        }
        if last.is_none_or(|last| last < self.current) {
            database.put_row(batch, row, self.current)?;
        }

        for &(position, validator) in entries {
            self.apply(&mut spans, position, validator, window_start)?;
        }
        for (span, column, chunk) in spans.changed() {
            database.put_span(batch, span, spans.row(), column, chunk)?;
        }
        Ok(())
    }

    /// Applies one validator's share of one vote.
    fn apply(
        &mut self,
        spans: &mut SpanRow,
        position: usize,
        validator: ValidatorIndex,
        window_start: Epoch,
    ) -> Result<(), SlasherError> {
        let database = self.database;
        let record_cells = self.geometry.record_cells();
        let mut load_record = |target, index| database.record(target, index, record_cells);
        let span_cells = self.geometry.span_cells();
        let mut load_span = |span, row, column| database.span(span, row, column, span_cells);

        let arrival = VoteRef::Arrival(position);
        let data = &self.arrivals[position].data;
        let (source, target) = (data.source.epoch, data.target.epoch);

        // Phase 1: the validator's earlier vote for this target, if any.
        if let Some(earlier) = self.records.get(validator, target, &mut load_record)? {
            let earlier = self.resolve(earlier);
            if self.data(earlier)? != *data {
                // Double vote: two different votes for one target epoch.
                self.conflicts.insert((earlier, arrival));
            }
            return Ok(());
        }
        let number = self.number(position)?;
        self.records.set(validator, number, &mut load_record)?;

        // Phase 2: the span arrays, against every other target in the window.
        let (existing, surrounds) =
            match spans.apply(validator, source, target, window_start, &mut load_span)? {
                Surround::None => return Ok(()),
                Surround::Surrounds(existing) => (existing, true),
                Surround::SurroundedBy(existing) => (existing, false),
            };
        let stored = self
            .records
            .get(validator, existing, &mut load_record)?
            .ok_or(SlasherError::MissingRecord {
                validator,
                target: existing,
            })?;
        let stored = self.resolve(stored);
        // The surrounding vote goes first, as the spec's slashability check orders them.
        let pair = if surrounds {
            (arrival, stored)
        } else {
            (stored, arrival)
        };
        if self.data(pair.0)?.is_slashable_with(&self.data(pair.1)?) {
            self.conflicts.insert(pair);
        }
        Ok(())
    }

    /// The vote a stored number names, as this pass refers to it.
    fn resolve(&self, number: VoteId) -> VoteRef {
        self.arrival_of
            .get(&number)
            .map_or(VoteRef::Stored(number), |&position| {
                VoteRef::Arrival(position)
            })
    }

    /// The data of a vote.
    fn data(&mut self, vote: VoteRef) -> Result<AttestationData, SlasherError> {
        match vote {
            VoteRef::Arrival(position) => Ok(self.arrivals[position].data.clone()),
            VoteRef::Stored(number) => {
                if let Some(data) = self.stored_data.get(&number) {
                    return Ok(data.clone());
                }
                let data = self.database.vote_data(number)?;
                self.stored_data.insert(number, data.clone());
                Ok(data)
            }
        }
    }

    /// The whole vote, signers included.
    fn indexed(&self, vote: VoteRef) -> Result<IndexedVote, SlasherError> {
        match vote {
            VoteRef::Arrival(position) => Ok(self.arrivals[position].clone()),
            VoteRef::Stored(number) => {
                let signers = self.database.vote_signers(number)?;
                Ok(IndexedVote {
                    indices: signers.indices,
                    data: self.database.vote_data(number)?,
                    signature: signers.signature,
                })
            }
        }
    }

    /// The number of an arrival, given on its first record.
    fn number(&mut self, position: usize) -> Result<VoteId, SlasherError> {
        if let Some(number) = self.numbers[position] {
            return Ok(number);
        }
        let target = self.arrivals[position].data.target.epoch;
        let last = match self.counters.get(&target) {
            Some(&last) => last,
            None => self.database.counter(target)?,
        };
        let next = last
            .checked_add(1)
            .ok_or(SlasherError::VoteNumbersExhausted(target))?;
        self.counters.insert(target, next);
        let number = VoteId {
            target,
            number: next,
        };
        self.numbers[position] = Some(number);
        self.arrival_of.insert(number, position);
        Ok(number)
    }

    /// Stages the records, counters, and every vote a record names.
    fn stage(&self, batch: &mut Batch) -> Result<(), SlasherError> {
        for (target, index, chunk) in self.records.changed() {
            self.database.put_record(batch, target, index, chunk)?;
        }
        for (&target, &last) in &self.counters {
            self.database.put_counter(batch, target, last)?;
        }
        for (vote, number) in self.arrivals.iter().zip(&self.numbers) {
            if let Some(number) = number {
                let signers = Signers {
                    signature: vote.signature,
                    indices: vote.indices.clone(),
                };
                self.database
                    .put_vote(batch, *number, &vote.data, &signers)?;
            }
        }
        Ok(())
    }
}
