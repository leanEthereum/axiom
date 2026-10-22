//! Rewards vectors: the per-component deltas of an epoch's accounting.

use std::marker::PhantomData;

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, List};
use axiom_state_transition::{
    ActiveBalance, State,
    altair::{
        AltairEpoch,
        epoch::{Deltas, Participation},
    },
    phase0::epoch::{AttestationRewards, PendingParticipation, VotePart},
    rewards::{AttesterReward, AttesterRewards, SignedGwei},
};
use axiom_types::{
    ChainConfig, Gwei, Preset, ValidatorIndex,
    accessors::ParticipationState,
    constants::{TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX},
    phase0,
};

use crate::{Case, Failure, Runner, forks::SpecFork};

/// The deltas container of the rewards test format.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct DeltasVector<P: Preset> {
    /// Rewards per validator.
    rewards: List<Gwei, P::ValidatorRegistryLimit>,
    /// Penalties per validator.
    penalties: List<Gwei, P::ValidatorRegistryLimit>,
}

impl<P: Preset> Container for DeltasVector<P> {
    const FIELDS: &'static [Option<usize>] = &[None, None];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.rewards);
        visitor.field(&self.penalties);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            rewards: fields.field()?,
            penalties: fields.field()?,
        })
    }
}

impl<P: Preset> DeltasVector<P> {
    /// The net amount of one validator in a vector file.
    fn net(&self, index: usize) -> SignedGwei {
        SignedGwei::net(self.rewards[index], self.penalties[index])
    }

    /// Checks the per-validator attestation rewards against the component vectors.
    ///
    /// Each listed validator's components equal its net deltas.
    /// Every validator left out has zero deltas, so the list misses no payment.
    /// Phase0's inclusion vector also holds proposer shares, which are added back first.
    fn check_attesters(
        case: &Case,
        computed: &AttesterRewards,
        inclusion_proposers: Option<&[Gwei]>,
    ) -> Result<(), Failure> {
        let [source, target, head, inactivity] = [
            "source_deltas",
            "target_deltas",
            "head_deltas",
            "inactivity_penalty_deltas",
        ]
        .map(|stem| case.ssz::<Self>(stem));
        let (source, target, head, inactivity) = (source?, target?, head?, inactivity?);
        let inclusion = match inclusion_proposers {
            Some(_) => Some(case.ssz::<Self>("inclusion_delay_deltas")?),
            None => None,
        };
        let mut expected = Vec::new();
        for index in 0..source.rewards.len() {
            let listed = computed
                .validators
                .iter()
                .any(|reward| reward.validator_index.as_usize() == index);
            let inclusion_delay = match (&inclusion, inclusion_proposers) {
                (Some(vector), Some(proposers)) => Some(vector.rewards[index] - proposers[index]),
                _ => None,
            };
            if listed {
                expected.push(AttesterReward {
                    validator_index: ValidatorIndex::from(index),
                    head: head.net(index),
                    target: target.net(index),
                    source: source.net(index),
                    inclusion_delay,
                    inactivity: inactivity.net(index),
                });
            } else if [&source, &target, &head, &inactivity]
                .iter()
                .any(|vector| vector.net(index) != SignedGwei::default())
                || inclusion_delay.is_some_and(|reward| reward != Gwei::ZERO)
            {
                return Err(Failure(format!(
                    "validator {index} has deltas but no attestation reward"
                )));
            }
        }
        if computed.validators != expected {
            return Err(Failure::new("attestation rewards differ from the deltas"));
        }
        Ok(())
    }

    /// Compares computed deltas with a vector file.
    fn check(case: &Case, stem: &str, rewards: &[Gwei], penalties: &[Gwei]) -> Result<(), Failure> {
        let expected = case.ssz::<Self>(stem)?;
        if expected.rewards.as_slice() != rewards {
            return Err(Failure(format!("{stem}: rewards differ")));
        }
        if expected.penalties.as_slice() != penalties {
            return Err(Failure(format!("{stem}: penalties differ")));
        }
        Ok(())
    }
}

/// Computes every component's deltas, and compares each with its vector.
///
/// The components are Altair's participation flags, so this serves Altair and later forks.
#[derive(Debug, Default)]
pub struct Rewards<P, F>(PhantomData<(P, F)>);

impl<P: Preset, F: SpecFork> Rewards<P, F> {
    /// Compares computed deltas with a vector file.
    fn compare(case: &Case, stem: &str, computed: &Deltas) -> Result<(), Failure> {
        DeltasVector::<P>::check(case, stem, &computed.rewards, &computed.penalties)
    }
}

impl<P: Preset, F: SpecFork> Runner for Rewards<P, F>
where
    F::State<P>: ParticipationState,
{
    fn name(&self) -> &'static str {
        "rewards"
    }

    fn run_case(&self, _handler: &str, case: &Case) -> Result<(), Failure> {
        let config = ChainConfig::for_preset::<P>().with_forks_at_genesis(F::FORK);
        let state = case.ssz::<F::State<P>>("pre")?;
        let participation = Participation::new(&state, ActiveBalance::of(&state));
        Self::compare(
            case,
            "source_deltas",
            &Deltas::flag_index(&participation, TIMELY_SOURCE_FLAG_INDEX),
        )?;
        Self::compare(
            case,
            "target_deltas",
            &Deltas::flag_index(&participation, TIMELY_TARGET_FLAG_INDEX),
        )?;
        Self::compare(
            case,
            "head_deltas",
            &Deltas::flag_index(&participation, TIMELY_HEAD_FLAG_INDEX),
        )?;
        Self::compare(
            case,
            "inactivity_penalty_deltas",
            &Deltas::inactivity_penalties(&participation, &config),
        )?;

        // The beacon API's per-validator split must carry exactly these deltas.
        let computed = AltairEpoch::attester_rewards(&state, &config);
        DeltasVector::<P>::check_attesters(case, &computed, None)
    }
}

/// Computes phase0's component deltas from pending attestations, and compares each with its vector.
///
/// Phase0 has no participation flags.
/// It pays the source, target, and head votes, the inclusion delay, and the inactivity leak.
#[derive(Debug, Default)]
pub struct PendingAttestationRewards<P>(PhantomData<P>);

impl<P: Preset> Runner for PendingAttestationRewards<P> {
    fn name(&self) -> &'static str {
        "rewards"
    }

    fn run_case(&self, _handler: &str, case: &Case) -> Result<(), Failure> {
        let mut state = State::new(case.ssz::<phase0::BeaconState<P>>("pre")?);
        let mut typed = state
            .of_fork::<phase0::BeaconState<P>>()
            .ok_or_else(|| Failure::new("pre-state is not a phase0 state"))?;
        let total = ActiveBalance::of(typed.beacon());
        let participation = PendingParticipation::new(&mut typed, total)
            .map_err(|error| Failure(format!("participation: {error}")))?;
        let rewards = AttestationRewards::new(typed.beacon(), &participation);
        for (stem, part) in [
            ("source_deltas", VotePart::Source),
            ("target_deltas", VotePart::Target),
            ("head_deltas", VotePart::Head),
        ] {
            let deltas = rewards.vote_deltas(part);
            DeltasVector::<P>::check(case, stem, &deltas.rewards, &deltas.penalties)?;
        }
        let inclusion = rewards
            .inclusion_delay_deltas()
            .map_err(|error| Failure(format!("inclusion delay: {error}")))?;
        DeltasVector::<P>::check(
            case,
            "inclusion_delay_deltas",
            &inclusion.rewards,
            &inclusion.penalties,
        )?;
        let inactivity = rewards.inactivity_penalty_deltas();
        DeltasVector::<P>::check(
            case,
            "inactivity_penalty_deltas",
            &inactivity.rewards,
            &inactivity.penalties,
        )?;

        // The beacon API's per-validator split must carry exactly these deltas.
        let proposers = rewards
            .inclusion_shares()
            .map_err(|error| Failure(format!("inclusion shares: {error}")))?
            .proposers;
        let computed = AttesterRewards::of_pending(&rewards, typed.beacon())
            .map_err(|error| Failure(format!("attestation rewards: {error}")))?;
        DeltasVector::<P>::check_attesters(case, &computed, Some(&proposers.rewards))
    }
}
