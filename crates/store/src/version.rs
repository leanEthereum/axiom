//! One immutable state of the store: every table's index and the segments it points into.

use std::{collections::BTreeMap, ops::Bound, sync::Arc};

use crate::{Error, Table, map::Map, metrics::Counters, segment::Segment, slot::Slot};

/// A consistent state of the whole store.
///
/// The index and the segment set travel together.
/// A reader holding a version can always open the segments its locations name.
/// That holds even after compaction deletes them from the directory.
///
/// Cloning costs one pointer copy per table and one for the segment set.
#[derive(Clone, Debug)]
pub(crate) struct Version {
    /// Index of each table, by identifier; identifier zero is the catalog.
    tables: Vec<Map<Slot>>,
    /// Open segments by identifier; empty for the memory backend.
    segments: Arc<BTreeMap<u32, Arc<Segment>>>,
}

impl Version {
    /// Creates the state of an empty store: a catalog with no table.
    pub(crate) fn new() -> Self {
        Self {
            tables: vec![Map::new()],
            segments: Arc::default(),
        }
    }

    /// Returns the number of table identifiers in use, catalog included.
    pub(crate) const fn table_count(&self) -> usize {
        self.tables.len()
    }

    /// Returns the index of a table.
    pub(crate) fn table(&self, table: Table) -> Result<&Map<Slot>, Error> {
        self.tables
            .get(usize::from(table.id()))
            .ok_or(Error::UnknownTable(table))
    }

    /// Returns where a key's value lives, if the key is present.
    pub(crate) fn slot(&self, table: u8, key: &[u8]) -> Option<&Slot> {
        self.tables.get(usize::from(table))?.get(key)
    }

    /// Looks up a user table by name in the catalog.
    pub(crate) fn find_table(&self, name: &str) -> Option<Table> {
        // Catalog keys are the identifier byte followed by the name.
        //
        //     key = [3, b'b', b'l', b'o', b'b', b's']  ->  table 3 is named "blobs"
        self.tables
            .first()?
            .range(Bound::Unbounded, Bound::Unbounded)
            .find_map(|node| match node.key().split_first() {
                Some((&id, stored)) if stored == name.as_bytes() => Some(Table::from_id(id)),
                _ => None,
            })
    }

    /// Applies one write, returning the slot it displaced.
    ///
    /// A slot binds the key and no slot deletes it.
    pub(crate) fn apply(&mut self, table: u8, key: &[u8], slot: Option<Slot>) -> Option<Slot> {
        // A catalog entry announces a table: make room for its index before any data arrives.
        let announced = if table == Table::CATALOG.id() && slot.is_some() {
            key.first().copied()
        } else {
            None
        };
        let needed = usize::from(announced.unwrap_or(table)).max(usize::from(table)) + 1;
        if self.tables.len() < needed {
            self.tables.resize_with(needed, Map::new);
        }

        let index = &mut self.tables[usize::from(table)];
        match slot {
            Some(slot) => index.insert(key, slot),
            None => index.remove(key),
        }
    }

    /// Returns an open segment.
    pub(crate) fn segment(&self, id: u32) -> Option<&Arc<Segment>> {
        self.segments.get(&id)
    }

    /// Makes a segment readable.
    pub(crate) fn add_segment(&mut self, segment: Arc<Segment>) {
        Arc::make_mut(&mut self.segments).insert(segment.id(), segment);
    }

    /// Stops new readers from reaching a segment; older versions keep it open.
    pub(crate) fn remove_segment(&mut self, id: u32) {
        Arc::make_mut(&mut self.segments).remove(&id);
    }

    /// Fetches the value a slot points to.
    pub(crate) fn read(
        &self,
        table: u8,
        key: &[u8],
        slot: &Slot,
        counters: &Counters,
    ) -> Result<Vec<u8>, Error> {
        match slot {
            Slot::Memory(value) => {
                counters.record_read(value.len() as u64);
                Ok(value.to_vec())
            }
            Slot::Disk(location) => {
                // Invariant: a version holds every segment its index points into.
                let segment = self.segment(location.segment).ok_or(Error::Corruption {
                    segment: location.segment,
                    offset: location.offset,
                    reason: "index points into a missing segment",
                })?;
                let value = segment.read_value(table, key, *location)?;
                counters.record_read(location.entry_len(key.len()));
                Ok(value)
            }
        }
    }
}
