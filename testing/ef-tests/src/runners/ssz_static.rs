//! SSZ static vectors: every container round-trips and hashes to the expected root.

use std::marker::PhantomData;

use axiom_types::Preset;

use crate::{Case, Failure, Runner, forks::SpecFork};

/// Decodes each container's vector, then checks its root and its re-encoding.
///
/// The fork names the container types, so one runner serves every fork.
#[derive(Debug, Default)]
pub struct SszStatic<P, F>(PhantomData<(P, F)>);

impl<P: Preset, F: SpecFork> Runner for SszStatic<P, F> {
    fn name(&self) -> &'static str {
        "ssz_static"
    }

    fn run_case(&self, handler: &str, case: &Case) -> Result<(), Failure> {
        F::ssz_static::<P>(handler, case)
    }
}
