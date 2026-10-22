//! Which stored vote each validator cast for each target epoch.

use std::collections::{BTreeMap, btree_map::Entry};

use axiom_types::{Epoch, ValidatorIndex};

use crate::{Geometry, SlasherError, chunk::Chunk};

/// A stored vote: its target epoch, and its number among the votes stored for that epoch.
///
/// Numbers start at one, so a record cell of zero means no vote.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct VoteId {
    /// Target epoch of the vote.
    pub(crate) target: Epoch,
    /// Its number within the epoch.
    pub(crate) number: u32,
}

impl VoteId {
    /// The database key: the epoch then the number, both big-endian, so keys sort by epoch.
    pub(crate) fn key(self) -> [u8; 12] {
        let mut key = [0; 12];
        key[..8].copy_from_slice(&self.target.0.to_be_bytes());
        key[8..].copy_from_slice(&self.number.to_be_bytes());
        key
    }
}

/// The record chunks a batch touches, loaded on first use.
///
/// The loader reads a stored chunk by target epoch and chunk index, or finds none.
#[derive(Debug)]
pub(crate) struct Records {
    /// The layout.
    geometry: Geometry,
    /// Chunks by target epoch and chunk index, empty where nothing is stored.
    chunks: BTreeMap<(Epoch, u64), Option<Chunk<u32>>>,
}

impl Records {
    /// A working set with nothing loaded.
    pub(crate) const fn new(geometry: Geometry) -> Self {
        Self {
            geometry,
            chunks: BTreeMap::new(),
        }
    }

    /// The vote a validator cast for a target epoch, if one is recorded.
    pub(crate) fn get<L>(
        &mut self,
        validator: ValidatorIndex,
        target: Epoch,
        load: &mut L,
    ) -> Result<Option<VoteId>, SlasherError>
    where
        L: FnMut(Epoch, u64) -> Result<Option<Chunk<u32>>, SlasherError>,
    {
        let cell = self.geometry.record_cell(validator);
        let number = self
            .loaded(validator, target, load)?
            .as_ref()
            .map_or(0, |chunk| chunk.get(cell));
        Ok((number != 0).then_some(VoteId { target, number }))
    }

    /// Records a validator's vote for its target epoch.
    pub(crate) fn set<L>(
        &mut self,
        validator: ValidatorIndex,
        vote: VoteId,
        load: &mut L,
    ) -> Result<(), SlasherError>
    where
        L: FnMut(Epoch, u64) -> Result<Option<Chunk<u32>>, SlasherError>,
    {
        let cell = self.geometry.record_cell(validator);
        let cells = self.geometry.record_cells();
        self.loaded(validator, vote.target, load)?
            .get_or_insert_with(|| Chunk::filled(cells, 0))
            .set(cell, vote.number);
        Ok(())
    }

    /// The chunks a batch changed, by target epoch and chunk index.
    pub(crate) fn changed(&self) -> impl Iterator<Item = (Epoch, u64, &Chunk<u32>)> {
        self.chunks.iter().filter_map(|(&(target, index), chunk)| {
            chunk
                .as_ref()
                .filter(|chunk| chunk.is_dirty())
                .map(|chunk| (target, index, chunk))
        })
    }

    /// The slot of the chunk holding a validator's record for a target epoch.
    fn loaded<L>(
        &mut self,
        validator: ValidatorIndex,
        target: Epoch,
        load: &mut L,
    ) -> Result<&mut Option<Chunk<u32>>, SlasherError>
    where
        L: FnMut(Epoch, u64) -> Result<Option<Chunk<u32>>, SlasherError>,
    {
        let index = self.geometry.record_chunk(validator);
        Ok(match self.chunks.entry((target, index)) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(load(target, index)?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SlasherConfig;

    #[test]
    fn a_record_reads_back_and_others_stay_empty() {
        // Records in chunks of 8 validators; validator 9 votes number 3 for epoch 5.
        let geometry = SlasherConfig {
            record_chunk_size: 8,
            ..SlasherConfig::default()
        }
        .geometry()
        .expect("valid");
        let mut records = Records::new(geometry);
        let mut nothing = |_: Epoch, _: u64| Ok(None);
        let vote = VoteId {
            target: Epoch(5),
            number: 3,
        };
        records
            .set(ValidatorIndex(9), vote, &mut nothing)
            .expect("sets");
        assert_eq!(
            records
                .get(ValidatorIndex(9), Epoch(5), &mut nothing)
                .expect("reads"),
            Some(vote)
        );
        // Validator 10 shares the chunk but cast nothing; epoch 6 has no chunk at all.
        assert_eq!(
            records
                .get(ValidatorIndex(10), Epoch(5), &mut nothing)
                .expect("reads"),
            None
        );
        assert_eq!(
            records
                .get(ValidatorIndex(9), Epoch(6), &mut nothing)
                .expect("reads"),
            None
        );
        assert_eq!(records.changed().count(), 1);
    }
}
