//! The chain a light client case runs on, and how its files name forks.

use axiom_light_client::combined::Format;
use axiom_ssz::Root;
use axiom_types::{ChainConfig, Epoch, ForkDigest, ForkName, Version};
use axiom_yaml::Yaml;

use crate::Failure;

/// The configuration and genesis of a case, which turn digests and versions into forks.
///
/// # Overview
///
/// Light client files name their fork by a fork digest or a fork version.
/// A digest mixes in the genesis validators root and, from Fulu, the blob limit.
/// Each candidate epoch where the digest can change is tried until one matches.
#[derive(Clone, Debug)]
pub(super) struct ForkContext {
    /// The chain configuration.
    pub(super) config: ChainConfig,
    /// The root that separates this chain's digests from other chains'.
    pub(super) genesis_validators_root: Root,
}

impl ForkContext {
    /// The fork whose digest a mapping names under a key.
    pub(super) fn fork_of_digest(&self, value: &Yaml, key: &str) -> Result<ForkName, Failure> {
        let digest = value
            .get(key)
            .and_then(Yaml::as_hex_array::<4>)
            .map(ForkDigest)
            .ok_or_else(|| Failure(format!("missing fork digest {key}")))?;
        // The digest changes only at fork epochs and blob limit steps.
        let forks = ForkName::ALL.map(|fork| self.config.fork_epoch(fork));
        let steps = self
            .config
            .blob_schedule
            .entries()
            .iter()
            .map(|entry| entry.epoch);
        forks
            .into_iter()
            .chain(steps)
            .filter(|epoch| *epoch != Epoch::FAR_FUTURE)
            .find(|epoch| {
                self.config
                    .fork_digest(self.genesis_validators_root, *epoch)
                    == digest
            })
            .map(|epoch| self.config.fork_at(epoch))
            .ok_or_else(|| Failure(format!("no scheduled fork has digest {digest}")))
    }

    /// The light client format of the fork whose version a mapping names under a key.
    pub(super) fn format_of_version(&self, value: &Yaml, key: &str) -> Result<Format, Failure> {
        let version = value
            .get(key)
            .and_then(Yaml::as_hex_array::<4>)
            .map(Version)
            .ok_or_else(|| Failure(format!("missing fork version {key}")))?;
        let fork = ForkName::ALL
            .into_iter()
            .find(|fork| self.config.fork_version(*fork) == version)
            .ok_or_else(|| Failure(format!("no fork has version {version}")))?;
        Format::of(fork).map_err(|error| Failure(error.to_string()))
    }
}
