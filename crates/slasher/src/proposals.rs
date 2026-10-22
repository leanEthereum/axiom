//! Double proposals: two signed headers from one proposer for one slot.

use std::collections::HashMap;

use axiom_store::Batch;
use axiom_types::{
    Slot, ValidatorIndex,
    phase0::{ProposerSlashing, SignedBeaconBlockHeader},
};

use crate::{SlasherDatabase, SlasherError};

/// One pass over the headers received since the last one.
///
/// The first header seen for a slot and proposer is kept.
/// A later header that differs is the evidence, see `process_proposer_slashing` in the phase0 spec.
#[derive(Debug)]
pub(crate) struct ProposalPass<'a> {
    /// The stored history.
    database: &'a SlasherDatabase,
    /// Headers this pass kept, not yet committed.
    kept: HashMap<(Slot, ValidatorIndex), SignedBeaconBlockHeader>,
}

impl<'a> ProposalPass<'a> {
    /// A pass over a database.
    pub(crate) fn new(database: &'a SlasherDatabase) -> Self {
        Self {
            database,
            kept: HashMap::new(),
        }
    }

    /// Checks one header against the first one its proposer signed for the slot.
    ///
    /// # Returns
    ///
    /// The slashing, when the proposer signed a different header before.
    pub(crate) fn check(
        &mut self,
        header: &SignedBeaconBlockHeader,
    ) -> Result<Option<ProposerSlashing>, SlasherError> {
        let key = (header.message.slot, header.message.proposer_index);
        let first = match self.kept.get(&key) {
            Some(first) => Some(first.clone()),
            None => self.database.proposal(key.0, key.1)?,
        };
        Ok(match first {
            None => {
                self.kept.insert(key, header.clone());
                None
            }
            // The same header twice, as gossip and an import both deliver it, is no offence.
            // Signatures are deterministic, so equal messages carry equal signatures.
            Some(first) if first.message == header.message => None,
            Some(first) => Some(ProposerSlashing {
                signed_header_1: first,
                signed_header_2: header.clone(),
            }),
        })
    }

    /// Stages the headers kept.
    pub(crate) fn stage(&self, batch: &mut Batch) -> Result<(), SlasherError> {
        for header in self.kept.values() {
            self.database.put_proposal(batch, header)?;
        }
        Ok(())
    }
}
