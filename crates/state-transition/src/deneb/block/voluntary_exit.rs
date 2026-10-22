//! Voluntary exits signed once for every later fork.

use axiom_types::{Domain, constants::DOMAIN_VOLUNTARY_EXIT, phase0::SignedVoluntaryExit};

use crate::{BlockError, BlockProcessor, Fork, Operation, phase0::block::SignedExit};

/// A voluntary exit, checked by Deneb's rule.
///
/// Phase0 introduced the operation, and Electra added a rule of its own.
#[derive(Clone, Copy, Debug)]
pub struct Exit<'a>(pub &'a SignedVoluntaryExit);

impl<S: Fork> Operation<S> for Exit<'_> {
    /// Starts an exit signed in the Capella domain, whatever the fork.
    ///
    /// A signed exit therefore stays valid across every later fork, see EIP-7044.
    /// See `process_voluntary_exit` in the Deneb beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let domain = Domain::compute(
            DOMAIN_VOLUNTARY_EXIT,
            processor.config.capella_fork_version,
            processor.state.beacon().genesis_validators_root(),
        );
        processor.apply(&SignedExit {
            exit: self.0,
            domain,
        })
    }
}
