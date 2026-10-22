//! Transition vectors: a chain of blocks that crosses a fork boundary.

use std::marker::PhantomData;

use axiom_state_transition::{KnownVerdict, State, Verification};
use axiom_types::{ChainConfig, Epoch, Preset, accessors::ForkState};
use axiom_yaml::Yaml;

use crate::{Case, Failure, Runner, forks::SpecFork};

/// Applies a chain of blocks that upgrades the state from one fork to the next.
///
/// # Overview
///
/// The pre-state is of the earlier fork, and the post-state of the later one.
/// Every fork up to the earlier one starts at genesis, and the later one at the case's epoch.
/// Blocks up to the case's last pre-fork block are of the earlier fork, the rest of the later.
/// A case naming no such block has only post-fork blocks.
/// A case without a post-state expects a block to be rejected.
#[derive(Debug, Default)]
pub struct Transition<P, Pre, Post>(PhantomData<(P, Pre, Post)>);

impl<P: Preset, Pre: SpecFork, Post: SpecFork> Transition<P, Pre, Post> {
    /// Applies every block in order across the boundary, and checks the post-state.
    fn run_core(case: &Case) -> Result<(), Failure> {
        let meta = case.yaml("meta.yaml")?;
        let post_fork = meta.get("post_fork").and_then(Yaml::as_str);
        if post_fork != Some(Post::FORK.as_str()) {
            return Err(Failure(format!(
                "case upgrades to {post_fork:?}, the runner to {}",
                Post::FORK
            )));
        }
        let fork_epoch = meta
            .get("fork_epoch")
            .and_then(Yaml::as_u64)
            .ok_or_else(|| Failure::new("meta.yaml has no fork epoch"))?;
        let last_pre_fork_block = meta.get("fork_block").and_then(Yaml::as_u64);
        let common = case.meta()?;
        let verification = if common.bls_ignored() {
            Verification::Skip
        } else {
            Verification::Verify
        };
        let config = ChainConfig::for_preset::<P>()
            .with_forks_at_genesis(Pre::FORK)
            .with_fork_epoch(Post::FORK, Epoch(fork_epoch));

        let mut state = State::new(case.ssz::<Pre::State<P>>("pre")?.into_any());
        let expected = case.ssz_if_present::<Post::State<P>>("post")?;
        let engine = KnownVerdict(true);
        let mut outcome = Ok(());
        for index in 0..common.blocks_count {
            let stem = format!("blocks_{index}");
            let pre_fork = last_pre_fork_block.is_some_and(|last| index as u64 <= last);
            let applied = if pre_fork {
                let block = case.ssz::<Pre::SignedBeaconBlock<P>>(&stem)?;
                state.state_transition(&config, &block, verification, &engine)
            } else {
                let block = case.ssz::<Post::SignedBeaconBlock<P>>(&stem)?;
                state.state_transition(&config, &block, verification, &engine)
            };
            if let Err(error) = applied {
                outcome = Err(format!("block {index}: {error}"));
                break;
            }
        }

        // A case without a post-state expects one of its blocks to be rejected.
        let expected = match (outcome, expected) {
            (Ok(()), Some(expected)) => expected,
            (Err(_), None) => return Ok(()),
            (Ok(()), None) => return Err(Failure::new("blocks accepted, the vector rejects them")),
            (Err(error), Some(_)) => return Err(Failure(error)),
        };
        let actual = Post::State::<P>::from_any(state.beacon()).ok_or_else(|| {
            Failure(format!(
                "post-state is {}, the vector's is {}",
                state.fork_name(),
                Post::FORK
            ))
        })?;
        Post::STATE_FIELDS.check(&expected, actual)
    }
}

impl<P: Preset, Pre: SpecFork, Post: SpecFork> Runner for Transition<P, Pre, Post> {
    fn name(&self) -> &'static str {
        "transition"
    }

    fn run_case(&self, handler: &str, case: &Case) -> Result<(), Failure> {
        match handler {
            "core" => Self::run_core(case),
            other => Err(Failure(format!("unsupported handler {other}"))),
        }
    }
}
