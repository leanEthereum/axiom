//! One marker per fork, naming the types its vectors exercise.
//!
//! # Overview
//!
//! A runner generic over a fork asks the fork's marker for the concrete types.
//! Each fork lists only what its spec defines or changes, and defers the rest to the fork before.
//! This mirrors the fork modules of the types crate, which re-export their predecessor.

mod altair;
mod bellatrix;
mod capella;
mod deneb;
mod electra;
mod fulu;
mod gloas;
mod phase0;

use std::fmt::Debug;

pub use altair::Altair;
use axiom_ssz::{Container, Ssz};
use axiom_state_transition::{Fork, SignedBlock};
use axiom_types::{ForkName, Preset};
pub use bellatrix::Bellatrix;
pub use capella::Capella;
pub use deneb::Deneb;
pub use electra::Electra;
pub use fulu::Fulu;
pub use gloas::Gloas;
pub use phase0::Phase0;

use crate::{Applied, Case, Failure, FieldNames, OperationInput};

/// One fork's view of the spec vectors.
///
/// A trait exists here because eight forks differ in their containers and rules.
/// Runners generic over the fork take the fork's types and per-fork hooks from here.
pub trait SpecFork: Copy + Debug + Default + Send + Sync + 'static {
    /// The fork.
    const FORK: ForkName;

    /// Field names of the fork's beacon state, in order, for readable mismatch reports.
    const STATE_FIELDS: FieldNames;

    /// The fork's beacon state.
    type State<P: Preset>: Fork<Preset = P> + Container + PartialEq;

    /// The signed block the fork's state applies.
    type SignedBeaconBlock<P: Preset>: SignedBlock<P> + Ssz;

    /// Applies one operations vector, choosing the operation type and rule by handler.
    ///
    /// A fork whose block processing is not written yet keeps this default.
    ///
    /// # Errors
    ///
    /// Fails when the handler is unknown or the case's files are broken.
    fn operation<P: Preset>(
        handler: &str,
        _input: &mut OperationInput<'_, '_, '_, Self::State<P>>,
    ) -> Applied {
        Err(Failure(format!(
            "unsupported operation {handler} in {}",
            Self::FORK
        )))
    }

    /// Checks an SSZ static case of a container, as this fork defines it.
    ///
    /// # Errors
    ///
    /// Fails when the case does not round-trip, or when no fork up to this one defines the container.
    fn ssz_static<P: Preset>(container: &str, case: &Case) -> Result<(), Failure>;
}
