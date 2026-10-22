//! Operations vectors: one block operation applied to a state.

use std::marker::PhantomData;

use axiom_ssz::{DecodeError, Ssz};
use axiom_state_transition::{BlockError, BlockProcessor, Fork, Operation, State, Verification};
use axiom_types::{ChainConfig, Preset, accessors::ForkState};
use axiom_yaml::Yaml;
use thiserror::Error;

use crate::{Case, Failure, Runner, forks::SpecFork};

/// Why an operation vector's input was not applied.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum Rejection {
    /// The input file does not decode, which the vectors count as an invalid operation.
    #[error("input {stem} does not decode: {source}")]
    Undecodable {
        /// Stem of the input file, such as the attestation.
        stem: &'static str,
        /// Why the bytes do not decode.
        #[source]
        source: DecodeError,
    },
    /// The operation breaks a rule of block processing.
    #[error(transparent)]
    Block(#[from] BlockError),
}

/// What applying a case's operation came to: applied, rejected, or a broken case.
pub type Applied = Result<Result<(), Rejection>, Failure>;

/// One operation case, with the processor its operation applies to.
///
/// Each fork maps a handler name to the operation type and rule version it runs.
#[derive(Debug)]
pub struct OperationInput<'c, 'p, 's, S> {
    /// The case directory.
    case: &'c Case,
    /// The processor over the case's pre-state.
    processor: &'p mut BlockProcessor<'s, S>,
}

impl<S: Fork> OperationInput<'_, '_, '_, S> {
    /// Decodes an input file, counting undecodable input as an invalid operation.
    ///
    /// # Errors
    ///
    /// Fails when the file is missing or does not decompress.
    pub fn decode<T: Ssz>(&self, stem: &'static str) -> Result<Result<T, Rejection>, Failure> {
        let bytes = self.case.ssz_bytes(stem)?;
        Ok(T::decode(&bytes).map_err(|source| Rejection::Undecodable { stem, source }))
    }

    /// Decodes an input and applies it as the operation it is.
    ///
    /// # Errors
    ///
    /// Fails when the file is missing or does not decompress.
    pub fn apply<O: Operation<S> + Ssz>(&mut self, stem: &'static str) -> Applied {
        self.apply_with::<O>(stem, |operation, processor| processor.apply(operation))
    }

    /// Decodes an input and hands it to a step of the fork's choosing.
    ///
    /// # Errors
    ///
    /// Fails when the file is missing or does not decompress.
    pub fn apply_with<T: Ssz>(
        &mut self,
        stem: &'static str,
        step: impl FnOnce(&T, &mut BlockProcessor<'_, S>) -> Result<(), BlockError>,
    ) -> Applied {
        Ok(self
            .decode::<T>(stem)?
            .and_then(|input| Ok(step(&input, self.processor)?)))
    }

    /// The execution engine's verdict the case ships.
    ///
    /// # Errors
    ///
    /// Fails when the execution file is missing or carries no verdict.
    pub fn execution_verdict(&self) -> Result<bool, Failure> {
        self.case
            .yaml("execution.yaml")?
            .get("execution_valid")
            .and_then(Yaml::as_bool)
            .ok_or_else(|| Failure::new("execution.yaml has no verdict"))
    }
}

/// Applies the case's operation, and compares with the post-state or expects rejection.
#[derive(Debug, Default)]
pub struct Operations<P, F>(PhantomData<(P, F)>);

impl<P: Preset, F: SpecFork> Runner for Operations<P, F> {
    fn name(&self) -> &'static str {
        "operations"
    }

    fn run_case(&self, handler: &str, case: &Case) -> Result<(), Failure> {
        let config = ChainConfig::for_preset::<P>().with_forks_at_genesis(F::FORK);
        let verification = if case.meta()?.bls_ignored() {
            Verification::Skip
        } else {
            Verification::Verify
        };
        let mut state = State::new(case.ssz::<F::State<P>>("pre")?.into_any());
        let expected = case.ssz_if_present::<F::State<P>>("post")?;

        let outcome = {
            let typed = state
                .of_fork::<F::State<P>>()
                .ok_or_else(|| Failure::new("pre-state is not of the case's fork"))?;
            let mut processor = BlockProcessor::new(typed, &config, verification);
            let mut input = OperationInput {
                case,
                processor: &mut processor,
            };
            let applied = F::operation::<P>(handler, &mut input)?;
            applied.and_then(|()| Ok(processor.finish()?))
        };

        match (outcome, expected) {
            (Ok(()), Some(expected)) => {
                let actual = F::State::<P>::from_any(state.beacon())
                    .ok_or_else(|| Failure::new("post-state left the case's fork"))?;
                F::STATE_FIELDS.check(&expected, actual)
            }
            (Err(_), None) => Ok(()),
            (Ok(()), None) => Err(Failure::new("operation accepted, the vector rejects it")),
            (Err(error), Some(_)) => Err(Failure(format!("operation rejected: {error}"))),
        }
    }
}
