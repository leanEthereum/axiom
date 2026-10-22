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
use axiom_types::{ForkName, Preset};
pub use bellatrix::Bellatrix;
pub use capella::Capella;
pub use deneb::Deneb;
pub use electra::Electra;
pub use fulu::Fulu;
pub use gloas::Gloas;
pub use phase0::Phase0;

use crate::{Case, Failure};

/// One fork's view of the spec vectors.
///
/// A trait exists here because eight forks differ in their containers and rules.
pub trait SpecFork: Copy + Debug + Default + Send + Sync + 'static {
    /// The fork.
    const FORK: ForkName;

    /// Checks an SSZ static case of a container, as this fork defines it.
    ///
    /// # Errors
    ///
    /// Fails when the case does not round-trip, or when no fork up to this one defines the container.
    fn ssz_static<P: Preset>(container: &str, case: &Case) -> Result<(), Failure>;
}
