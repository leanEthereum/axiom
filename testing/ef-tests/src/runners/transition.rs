//! Transition vectors: a chain of blocks that crosses a fork boundary.

use std::marker::PhantomData;

use axiom_types::Preset;

use crate::{Case, Failure, Runner};

/// Fork transition vectors, which Axiom does not run yet.
///
/// Their blocks before the boundary are Electra blocks, processed by Electra rules.
/// Axiom implements Fulu block processing only, so these vectors are skipped by name.
#[derive(Debug, Default)]
pub struct Transition<P>(PhantomData<P>);

impl<P: Preset> Runner for Transition<P> {
    fn name(&self) -> &'static str {
        "transition"
    }

    fn run_case(&self, handler: &str, _case: &Case) -> Result<(), Failure> {
        Err(Failure(format!("unsupported handler {handler}")))
    }

    fn skip_handler(&self, _handler: &str) -> Option<&'static str> {
        Some("pre-fork blocks need Electra block processing, which Axiom does not implement")
    }
}
