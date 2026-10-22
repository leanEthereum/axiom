//! The min-max span arrays, which find surround votes in constant time per vote.
//!
//! # Algorithm
//!
//! For validator v and epoch e of the window, two arrays summarise every vote of v:
//!
//! ```text
//! min_target[v][e] = min { t : v voted (s, t) with s > e }
//! max_target[v][e] = max { t : v voted (s, t) with s < e }
//! ```
//!
//! A new vote (s, t) then conflicts with a recorded one exactly when:
//!
//! ```text
//! min_target[v][s] < t    it surrounds a vote (s', t') with s < s' and t' < t
//! max_target[v][s] > t    a vote (s', t') with s' < s and t < t' surrounds it
//! ```
//!
//! Recording (s, t) lowers min_target below s and raises max_target above s.
//! Both arrays are monotone in e, so each walk stops at the first cell already as tight.
//! An honest validator votes (e - 1, e) each epoch, and its walks stop after one or two cells.
//!
//! A cell stores the target as a distance from its own epoch, in 16 bits.
//! For the max array a target at or below the cell's epoch is never useful.
//! So distance zero means no vote, and the all-ones distance means no vote in the min array.
//!
//! See Sproul, "Min-max slasher", hackmd.io/@sproul/min-max-slasher, 2020.

use std::collections::{BTreeMap, btree_map::Entry};

use axiom_types::{Epoch, ValidatorIndex};

use crate::{Geometry, SlasherError, chunk::Chunk};

/// One of the two span arrays.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Span {
    /// Lowest target among votes with a later source.
    Min,
    /// Highest target among votes with an earlier source.
    Max,
}

impl Span {
    /// The cell value meaning no vote constrains the epoch.
    const fn empty(self) -> u16 {
        match self {
            Self::Min => u16::MAX,
            Self::Max => 0,
        }
    }

    /// The target a cell names, if any.
    const fn target(self, epoch: Epoch, cell: u16) -> Option<Epoch> {
        if cell == self.empty() {
            None
        } else {
            Some(Epoch(epoch.0 + cell as u64))
        }
    }

    /// The cell naming a target from an epoch.
    ///
    /// Invariant: the target lies after the epoch and within the window.
    /// So the distance is between 1 and the history length minus one, below the reserved value.
    const fn cell(epoch: Epoch, target: Epoch) -> u16 {
        (target.0 - epoch.0) as u16
    }
}

/// How a new vote relates to the votes the arrays summarise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Surround {
    /// No surround either way.
    None,
    /// The new vote surrounds a recorded vote with this target.
    Surrounds(Epoch),
    /// A recorded vote with this target surrounds the new vote.
    SurroundedBy(Epoch),
}

/// The span chunks of one row of validators, loaded as a batch touches them.
///
/// The loader reads a stored chunk by array and column, or finds none.
#[derive(Debug)]
pub(crate) struct SpanRow {
    /// The layout.
    geometry: Geometry,
    /// The row.
    row: u64,
    /// Chunks by array and column, empty where nothing is stored.
    chunks: BTreeMap<(Span, u64), Option<Chunk<u16>>>,
}

impl SpanRow {
    /// A row with nothing loaded.
    pub(crate) const fn new(geometry: Geometry, row: u64) -> Self {
        Self {
            geometry,
            row,
            chunks: BTreeMap::new(),
        }
    }

    /// The row this working set covers.
    pub(crate) const fn row(&self) -> u64 {
        self.row
    }

    /// Empties the cells of a run of epochs for every validator of the row.
    ///
    /// The window reuses a column once its epoch leaves, so a new epoch first clears it.
    /// Every recorded vote has a target at or before the last epoch the row saw.
    /// So the cleared values are exact: no later source exists, and no target lies beyond.
    pub(crate) fn clear<L>(
        &mut self,
        epochs: impl Iterator<Item = Epoch>,
        load: &mut L,
    ) -> Result<(), SlasherError>
    where
        L: FnMut(Span, u64, u64) -> Result<Option<Chunk<u16>>, SlasherError>,
    {
        for epoch in epochs {
            for span in [Span::Min, Span::Max] {
                // A chunk never stored is already empty.
                let geometry = self.geometry;
                let Some(chunk) = self.loaded(span, epoch, load)? else {
                    continue;
                };
                for cell in geometry.span_epoch_cells(epoch) {
                    chunk.set(cell, span.empty());
                }
            }
        }
        Ok(())
    }

    /// Checks a new vote of a validator, then records it if it conflicts with nothing.
    ///
    /// A conflicting vote is not recorded: the evidence already condemns its validator.
    ///
    /// # Arguments
    ///
    /// - `window_start`: the earliest epoch whose cells are live, at or before the source.
    pub(crate) fn apply<L>(
        &mut self,
        validator: ValidatorIndex,
        source: Epoch,
        target: Epoch,
        window_start: Epoch,
        load: &mut L,
    ) -> Result<Surround, SlasherError>
    where
        L: FnMut(Span, u64, u64) -> Result<Option<Chunk<u16>>, SlasherError>,
    {
        if let Some(min) = self.target(Span::Min, validator, source, load)?
            && min < target
        {
            return Ok(Surround::Surrounds(min));
        }
        if let Some(max) = self.target(Span::Max, validator, source, load)?
            && max > target
        {
            return Ok(Surround::SurroundedBy(max));
        }

        // Every epoch before the source now sees this vote's target as a candidate minimum.
        let mut epoch = source;
        while epoch > window_start {
            epoch = epoch - 1;
            match self.target(Span::Min, validator, epoch, load)? {
                Some(min) if min <= target => break,
                _ => self.set(Span::Min, validator, epoch, target, load)?,
            }
        }
        // Every epoch strictly between source and target sees it as a candidate maximum.
        // From the target on, a maximum would not exceed the cell's own epoch.
        for epoch in (source.0 + 1..target.0).map(Epoch) {
            match self.target(Span::Max, validator, epoch, load)? {
                Some(max) if max >= target => break,
                _ => self.set(Span::Max, validator, epoch, target, load)?,
            }
        }
        Ok(Surround::None)
    }

    /// The chunks a batch changed, by array and column.
    pub(crate) fn changed(&self) -> impl Iterator<Item = (Span, u64, &Chunk<u16>)> {
        self.chunks.iter().filter_map(|(&(span, column), chunk)| {
            chunk
                .as_ref()
                .filter(|chunk| chunk.is_dirty())
                .map(|chunk| (span, column, chunk))
        })
    }

    /// The target a validator's cell names for an epoch.
    fn target<L>(
        &mut self,
        span: Span,
        validator: ValidatorIndex,
        epoch: Epoch,
        load: &mut L,
    ) -> Result<Option<Epoch>, SlasherError>
    where
        L: FnMut(Span, u64, u64) -> Result<Option<Chunk<u16>>, SlasherError>,
    {
        let cell = self.geometry.span_cell(validator, epoch);
        Ok(match self.loaded(span, epoch, load)? {
            Some(chunk) => span.target(epoch, chunk.get(cell)),
            None => None,
        })
    }

    /// Points a validator's cell for an epoch at a target, creating the chunk if needed.
    fn set<L>(
        &mut self,
        span: Span,
        validator: ValidatorIndex,
        epoch: Epoch,
        target: Epoch,
        load: &mut L,
    ) -> Result<(), SlasherError>
    where
        L: FnMut(Span, u64, u64) -> Result<Option<Chunk<u16>>, SlasherError>,
    {
        let cell = self.geometry.span_cell(validator, epoch);
        let cells = self.geometry.span_cells();
        self.loaded(span, epoch, load)?;
        let column = self.geometry.column(epoch);
        let slot = self.chunks.entry((span, column)).or_insert(None);
        slot.get_or_insert_with(|| Chunk::filled(cells, span.empty()))
            .set(cell, Span::cell(epoch, target));
        Ok(())
    }

    /// The chunk holding an epoch, read once per batch.
    fn loaded<L>(
        &mut self,
        span: Span,
        epoch: Epoch,
        load: &mut L,
    ) -> Result<Option<&mut Chunk<u16>>, SlasherError>
    where
        L: FnMut(Span, u64, u64) -> Result<Option<Chunk<u16>>, SlasherError>,
    {
        let column = self.geometry.column(epoch);
        let chunk = match self.chunks.entry((span, column)) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(load(span, self.row, column)?),
        };
        Ok(chunk.as_mut())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SlasherConfig;

    /// A row over a 64-epoch window in chunks of 16 epochs by 4 validators, with nothing stored.
    fn row() -> SpanRow {
        let geometry = SlasherConfig {
            history_length: 64,
            chunk_size: 16,
            validator_chunk_size: 4,
            ..SlasherConfig::default()
        }
        .geometry()
        .expect("valid");
        SpanRow::new(geometry, 0)
    }

    /// A loader over an empty database.
    fn nothing() -> impl FnMut(Span, u64, u64) -> Result<Option<Chunk<u16>>, SlasherError> {
        |_, _, _| Ok(None)
    }

    fn vote(row: &mut SpanRow, source: u64, target: u64) -> Surround {
        row.apply(
            ValidatorIndex(1),
            Epoch(source),
            Epoch(target),
            Epoch(0),
            &mut nothing(),
        )
        .expect("nothing fails in memory")
    }

    #[test]
    fn a_wider_vote_surrounds_a_recorded_one() {
        // Recorded (3, 4); the new vote (2, 5) wraps it: min_target[2] is 4, below 5.
        let mut row = row();
        assert_eq!(vote(&mut row, 3, 4), Surround::None);
        assert_eq!(vote(&mut row, 2, 5), Surround::Surrounds(Epoch(4)));
    }

    #[test]
    fn a_narrower_vote_is_surrounded_by_a_recorded_one() {
        // Recorded (2, 9); the new vote (4, 6) sits inside: max_target[4] is 9, above 6.
        let mut row = row();
        assert_eq!(vote(&mut row, 2, 9), Surround::None);
        assert_eq!(vote(&mut row, 4, 6), Surround::SurroundedBy(Epoch(9)));
    }

    #[test]
    fn consecutive_honest_votes_never_conflict() {
        // An honest validator votes (e - 1, e) for 40 epochs.
        let mut row = row();
        for epoch in 1..40 {
            assert_eq!(vote(&mut row, epoch - 1, epoch), Surround::None);
        }
    }

    #[test]
    fn votes_sharing_a_source_or_a_target_do_not_surround() {
        // Recorded (2, 6); (2, 8) shares its source and (4, 6) its target: no strict nesting.
        let mut row = row();
        assert_eq!(vote(&mut row, 2, 6), Surround::None);
        assert_eq!(vote(&mut row, 2, 8), Surround::None);
        assert_eq!(vote(&mut row, 4, 8), Surround::None);
    }

    #[test]
    fn a_cleared_epoch_forgets_its_constraints() {
        // Recorded (2, 9) sets max_target[4] to 9; clearing epoch 4 forgets it.
        let mut row = row();
        assert_eq!(vote(&mut row, 2, 9), Surround::None);
        row.clear((4..5).map(Epoch), &mut nothing())
            .expect("clears");
        assert_eq!(vote(&mut row, 4, 6), Surround::None);
    }
}
