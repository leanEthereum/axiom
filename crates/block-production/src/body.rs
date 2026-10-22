//! The parts of a block body every fork shares, gathered before the fork assembles them.

use axiom_operation_pool::{BlockOperations, PoolFork};
use axiom_ssz::{Length, List};
use axiom_types::{
    BlsSignature, Bytes32, Root, Slot, ValidatorIndex,
    altair::SyncAggregate,
    gloas::PayloadAttestation,
    phase0::{Deposit, Eth1Data},
};

use crate::ProductionError;

/// What a block carries besides its payload, ready for its fork's container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BodyParts<S: PoolFork> {
    /// The slot of the block.
    pub slot: Slot,
    /// The proposer the state elects.
    pub proposer_index: ValidatorIndex,
    /// Root of the parent block.
    pub parent_root: Root,
    /// The proposer's signature over the epoch.
    pub randao_reveal: BlsSignature,
    /// The eth1 vote.
    pub eth1_data: Eth1Data,
    /// Free-form bytes of the proposer's choosing.
    pub graffiti: Bytes32,
    /// Deposits from the deposit contract, in tree order.
    pub deposits: Vec<Deposit>,
    /// Slashings, attestations, exits, and credential changes.
    pub operations: BlockOperations<S>,
    /// The sync committee's signature over the parent, from Altair on.
    pub sync_aggregate: SyncAggregate<S::Preset>,
    /// Votes on the parent's payload, from Gloas on.
    pub payload_attestations: Vec<PayloadAttestation<S::Preset>>,
}

/// Turns the parts' vectors into a body's bounded lists.
#[derive(Clone, Copy, Debug)]
pub struct Bounded;

impl Bounded {
    /// A bounded list of a body, naming the list in the error.
    ///
    /// # Errors
    ///
    /// Fails when the items exceed the list's bound.
    pub fn list<T: Clone, N: Length>(
        list: &'static str,
        items: &[T],
    ) -> Result<List<T, N>, ProductionError> {
        List::try_from(items.to_vec()).map_err(|_| ProductionError::TooMany {
            list,
            count: items.len(),
            limit: N::LEN,
        })
    }
}
