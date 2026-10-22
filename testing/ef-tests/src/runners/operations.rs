//! Operations vectors: one block operation applied to a state.

use std::marker::PhantomData;

use axiom_ssz::{DecodeError, Ssz};
use axiom_state_transition::{
    BlockError, BlockProcessor, KnownVerdict, Operation, PayloadExecution, State, Verification,
};
use axiom_types::{
    Attestation, AttesterSlashing, BeaconBlock, BeaconBlockBody, BeaconState, ChainConfig,
    ConsolidationRequest, DepositRequest, ExecutionPayload, Preset, ProposerSlashing,
    SignedBlsToExecutionChange, SignedVoluntaryExit, SyncAggregate, WithdrawalRequest,
};
use axiom_yaml::Yaml;
use thiserror::Error;

use super::BEACON_STATE_FIELDS;
use crate::{Case, Failure, Runner};

/// Why an operation vector's input was not applied.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
enum Rejection {
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

/// Applies the case's operation, and compares with the post-state or expects rejection.
#[derive(Debug, Default)]
pub struct Operations<P>(PhantomData<P>);

impl<P: Preset> Operations<P> {
    /// Decodes an operation input, treating undecodable input as an invalid operation.
    fn input<T: Ssz>(case: &Case, stem: &'static str) -> Result<Result<T, Rejection>, Failure> {
        let bytes = case.ssz_bytes(stem)?;
        Ok(T::decode(&bytes).map_err(|source| Rejection::Undecodable { stem, source }))
    }

    /// Runs an operation through the trait every block operation implements.
    fn operation<O: Operation<P> + Ssz>(
        case: &Case,
        stem: &'static str,
        processor: &mut BlockProcessor<'_, P>,
    ) -> Result<Result<(), Rejection>, Failure> {
        Ok(Self::input::<O>(case, stem)?.and_then(|operation| Ok(processor.apply(&operation)?)))
    }
}

impl<P: Preset> Runner for Operations<P> {
    fn name(&self) -> &'static str {
        "operations"
    }

    fn run_case(&self, handler: &str, case: &Case) -> Result<(), Failure> {
        let config = ChainConfig::for_preset::<P>().with_forks_at_genesis();
        let meta = case.meta()?;
        let verification = if meta.bls_ignored() {
            Verification::Skip
        } else {
            Verification::Verify
        };
        let mut state = State::new(case.ssz::<BeaconState<P>>("pre")?);
        let expected = case.ssz_if_present::<BeaconState<P>>("post")?;

        let outcome = {
            let mut processor = BlockProcessor::new(&mut state, &config, verification);
            let applied = match handler {
                "attestation" => {
                    Self::operation::<Attestation<P>>(case, "attestation", &mut processor)?
                }
                "attester_slashing" => Self::operation::<AttesterSlashing<P>>(
                    case,
                    "attester_slashing",
                    &mut processor,
                )?,
                "proposer_slashing" => {
                    Self::operation::<ProposerSlashing>(case, "proposer_slashing", &mut processor)?
                }
                "voluntary_exit" => {
                    Self::operation::<SignedVoluntaryExit>(case, "voluntary_exit", &mut processor)?
                }
                "bls_to_execution_change" => Self::operation::<SignedBlsToExecutionChange>(
                    case,
                    "address_change",
                    &mut processor,
                )?,
                "deposit_request" => {
                    Self::operation::<DepositRequest>(case, "deposit_request", &mut processor)?
                }
                "withdrawal_request" => Self::operation::<WithdrawalRequest>(
                    case,
                    "withdrawal_request",
                    &mut processor,
                )?,
                "consolidation_request" => Self::operation::<ConsolidationRequest>(
                    case,
                    "consolidation_request",
                    &mut processor,
                )?,
                "block_header" => Self::input::<BeaconBlock<P>>(case, "block")?
                    .and_then(|block| Ok(processor.apply(&block.header())?)),
                "sync_aggregate" => Self::input::<SyncAggregate<P>>(case, "sync_aggregate")?
                    .and_then(|aggregate| Ok(processor.apply(&aggregate)?)),
                "withdrawals" => Self::input::<ExecutionPayload<P>>(case, "execution_payload")?
                    .and_then(|payload| Ok(processor.apply(payload.withdrawals.as_slice())?)),
                "execution_payload" => {
                    let valid = case
                        .yaml("execution.yaml")?
                        .get("execution_valid")
                        .and_then(Yaml::as_bool)
                        .ok_or_else(|| Failure::new("execution.yaml has no verdict"))?;
                    Self::input::<BeaconBlockBody<P>>(case, "body")?.and_then(|body| {
                        Ok(processor.apply(&PayloadExecution::new(&body, &KnownVerdict(valid)))?)
                    })
                }
                other => return Err(Failure(format!("unsupported operation {other}"))),
            };
            applied.and_then(|()| Ok(processor.finish()?))
        };

        match (outcome, expected) {
            (Ok(()), Some(expected)) => BEACON_STATE_FIELDS.check(&expected, state.beacon()),
            (Err(_), None) => Ok(()),
            (Ok(()), None) => Err(Failure::new("operation accepted, the vector rejects it")),
            (Err(error), Some(_)) => Err(Failure(format!("operation rejected: {error}"))),
        }
    }
}
