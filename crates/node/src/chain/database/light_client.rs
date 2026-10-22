//! Light client data on disk, so a restarted node serves it at once.

use axiom_light_client::{
    LightClientServer,
    combined::{LightClientBootstrap, LightClientUpdate},
};
use axiom_ssz::{DecodeError, Ssz};
use axiom_store::{Batch, Snapshot, Table};
use axiom_types::{ChainConfig, Preset, Root, Slot};

use crate::ChainError;

/// Key tag of the settled best update of one period.
const BEST: u8 = b'u';

/// Key tag of the latest settled updates, the plain one and the finality one.
const LATEST: u8 = b'l';

/// Key tag of a bootstrap.
const BOOTSTRAP: u8 = b'b';

/// The light client table: settled updates and bootstraps.
///
/// # Layout
///
/// ```text
///     key                                  value
///     'u' + period (8, BE)                 context slot (8, BE) + SSZ update
///     'l' + position (1)                   context slot (8, BE) + SSZ update
///     'b' + context slot (8, BE) + root    SSZ bootstrap
/// ```
///
/// The context slot fixes the fork each record decodes in.
/// Bootstraps sort by slot, so pruning old ones is a range scan over keys alone.
#[derive(Clone, Copy, Debug)]
pub(super) struct LightClientRecords {
    /// The table.
    table: Table,
}

impl LightClientRecords {
    /// The records in a table.
    pub(super) const fn new(table: Table) -> Self {
        Self { table }
    }

    /// Stages what the server settled, from a period on, and drops what it pruned.
    ///
    /// # Arguments
    ///
    /// - `from_period`: the first period whose best update may have changed.
    /// - `earliest`: the oldest slot still served; older records go.
    pub(super) fn stage<P: Preset>(
        self,
        snapshot: &Snapshot,
        batch: &mut Batch,
        server: &LightClientServer<P>,
        from_period: u64,
        earliest: Slot,
    ) -> Result<(), ChainError> {
        let earliest_period = earliest.sync_committee_period::<P>();
        for key in snapshot
            .range(self.table, [BEST].as_slice()..[BOOTSTRAP].as_slice())?
            .keys()
        {
            // Settled updates of pruned periods are no longer served.
            if key.first() == Some(&BEST)
                && key.len() == 9
                && Self::number(&key[1..]) < earliest_period
            {
                batch.delete(self.table, &key)?;
            }
        }
        for (period, update) in server.settled_updates() {
            if period >= from_period {
                let key = Self::tagged(BEST, &period.to_be_bytes());
                batch.put(
                    self.table,
                    &key,
                    &Self::slotted(update.context_slot(), &update.encode()),
                )?;
            }
        }
        for position in 0..2_u8 {
            batch.delete(self.table, &[LATEST, position])?;
        }
        for (position, update) in (0_u8..).zip(server.latest_settled()) {
            let value = Self::slotted(update.context_slot(), &update.encode());
            batch.put(self.table, &[LATEST, position], &value)?;
        }

        // Bootstraps never change, so only new ones are written.
        let end = Self::tagged(BOOTSTRAP, &earliest.0.to_be_bytes());
        for key in snapshot
            .range(self.table, [BOOTSTRAP].as_slice()..end.as_slice())?
            .keys()
        {
            batch.delete(self.table, &key)?;
        }
        for (root, bootstrap) in server.bootstraps() {
            let mut key = Self::tagged(BOOTSTRAP, &bootstrap.context_slot().0.to_be_bytes());
            key.extend_from_slice(&root.0);
            if bootstrap.context_slot() >= earliest && !snapshot.contains_key(self.table, &key)? {
                batch.put(self.table, &key, &bootstrap.encode())?;
            }
        }
        Ok(())
    }

    /// Hands every stored record back to a server.
    pub(super) fn restore<P: Preset>(
        self,
        snapshot: &Snapshot,
        config: &ChainConfig,
        server: &mut LightClientServer<P>,
    ) -> Result<(), ChainError> {
        for entry in snapshot.entries(self.table)? {
            let (key, value) = entry?;
            let corrupt = |error| ChainError::Corrupt {
                what: "light client record",
                error,
            };
            match key.first() {
                Some(&BEST | &LATEST) => {
                    let (slot, bytes) = Self::split_slot(&value).map_err(corrupt)?;
                    let fork = config.fork_at(slot.epoch::<P>());
                    let update = LightClientUpdate::decode(bytes, fork)?;
                    server.restore_settled(update)?;
                }
                Some(&BOOTSTRAP) if key.len() == 1 + 8 + 32 => {
                    let slot = Slot(Self::number(&key[1..9]));
                    let fork = config.fork_at(slot.epoch::<P>());
                    let bootstrap = LightClientBootstrap::decode(&value, fork)?;
                    server.restore_bootstrap(Root::decode(&key[9..]).map_err(corrupt)?, bootstrap);
                }
                _ => {
                    return Err(corrupt(DecodeError::InvalidLength {
                        expected: 1 + 8 + 32,
                        actual: key.len(),
                    }));
                }
            }
        }
        Ok(())
    }

    /// A key: a tag, then its suffix.
    fn tagged(tag: u8, suffix: &[u8]) -> Vec<u8> {
        let mut key = Vec::with_capacity(1 + suffix.len());
        key.push(tag);
        key.extend_from_slice(suffix);
        key
    }

    /// A value: the context slot, then the encoded record.
    fn slotted(slot: Slot, encoded: &[u8]) -> Vec<u8> {
        let mut value = Vec::with_capacity(8 + encoded.len());
        value.extend_from_slice(&slot.0.to_be_bytes());
        value.extend_from_slice(encoded);
        value
    }

    /// Splits a value into its context slot and its encoded record.
    fn split_slot(value: &[u8]) -> Result<(Slot, &[u8]), DecodeError> {
        if value.len() < 8 {
            return Err(DecodeError::InvalidLength {
                expected: 8,
                actual: value.len(),
            });
        }
        let (slot, rest) = value.split_at(8);
        Ok((Slot(Self::number(slot)), rest))
    }

    /// A big-endian number of eight bytes; callers pass exactly eight.
    fn number(bytes: &[u8]) -> u64 {
        u64::from_be_bytes(bytes.try_into().unwrap_or_default())
    }
}
