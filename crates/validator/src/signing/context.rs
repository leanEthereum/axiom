//! The chain a validator signs for: its fork schedule and its genesis validators root.

use std::sync::Arc;

use axiom_ssz::Ssz;
use axiom_types::{
    ChainConfig, Domain, Epoch, Preset, Root,
    phase0::{Fork, SigningData},
};

use crate::signing::{DomainScope, SigningRequest};

/// Everything that turns a message into the root a key signs.
///
/// Two chains with the same fork versions still differ in their genesis validators root.
/// Mixing it into every domain stops a signature from one chain replaying on another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningContext {
    /// The fork schedule.
    config: Arc<ChainConfig>,
    /// Root of the validator registry at genesis, which names the chain.
    genesis_validators_root: Root,
}

impl SigningContext {
    /// The context of a chain.
    #[must_use]
    pub const fn new(config: Arc<ChainConfig>, genesis_validators_root: Root) -> Self {
        Self {
            config,
            genesis_validators_root,
        }
    }

    /// The fork schedule.
    #[must_use]
    pub fn config(&self) -> &ChainConfig {
        &self.config
    }

    /// Root of the validator registry at genesis.
    #[must_use]
    pub const fn genesis_validators_root(&self) -> Root {
        self.genesis_validators_root
    }

    /// The signature domain of a message.
    ///
    /// See `compute_domain` and `get_domain` in the phase0 beacon chain spec.
    #[must_use]
    pub fn domain<P: Preset>(&self, request: &SigningRequest<'_, P>) -> Domain {
        let domain_type = request.domain_type();
        let config = &self.config;
        match request.domain_scope() {
            DomainScope::Epoch(epoch) => Domain::compute(
                domain_type,
                config.fork_version_at(epoch),
                self.genesis_validators_root,
            ),
            DomainScope::VoluntaryExit(epoch) => {
                let fork = config.fork_at(epoch).voluntary_exit_fork();
                Domain::compute(
                    domain_type,
                    config.fork_version(fork),
                    self.genesis_validators_root,
                )
            }
            DomainScope::Genesis => Domain::compute(
                domain_type,
                config.genesis_fork_version,
                self.genesis_validators_root,
            ),
            DomainScope::PreGenesis => {
                Domain::compute(domain_type, config.genesis_fork_version, Root::ZERO)
            }
        }
    }

    /// The root a key signs for a message: its object root bound to its domain.
    ///
    /// See `compute_signing_root` in the phase0 beacon chain spec.
    #[must_use]
    pub fn signing_root<P: Preset>(&self, request: &SigningRequest<'_, P>) -> Root {
        SigningData {
            object_root: request.object_root(),
            domain: self.domain(request),
        }
        .hash_tree_root()
    }

    /// The fork record in force at an epoch, as a state at that epoch would hold it.
    ///
    /// A remote signer recomputes the domain from it.
    #[must_use]
    pub fn fork(&self, epoch: Epoch) -> Fork {
        let config = &self.config;
        let current = config.fork_at(epoch);
        let previous = current.previous().unwrap_or(current);
        Fork {
            previous_version: config.fork_version(previous),
            current_version: config.fork_version(current),
            epoch: config.fork_epoch(current),
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{
        Epoch, ForkName, Mainnet, Minimal, Slot, ValidatorIndex,
        bellatrix::ValidatorRegistrationV1,
        constants::{DOMAIN_BEACON_PROPOSER, DOMAIN_VOLUNTARY_EXIT},
        phase0::{BeaconBlockHeader, DepositMessage, VoluntaryExit},
    };

    use super::*;

    /// Mainnet's schedule on a chain whose genesis validators root is 0x11...11.
    fn mainnet() -> SigningContext {
        SigningContext::new(Arc::new(ChainConfig::mainnet()), Root([0x11; 32]))
    }

    #[test]
    fn pre_genesis_domains_match_the_published_mainnet_values() {
        // The deposit domain every mainnet deposit verifies under, with no chain mixed in.
        let deposit = DepositMessage::default();
        let request = SigningRequest::<Mainnet>::Deposit(&deposit);
        assert_eq!(
            mainnet().domain(&request).to_string(),
            "0x03000000f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a9"
        );

        // The builder registration domain shares the genesis fork data root.
        let registration = ValidatorRegistrationV1::default();
        let request = SigningRequest::<Mainnet>::ValidatorRegistration(&registration);
        assert_eq!(
            mainnet().domain(&request).to_string(),
            "0x00000001f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a9"
        );
    }

    #[test]
    fn a_block_signs_under_the_version_its_epoch_schedules() {
        // Fixture state: Altair at epoch 1, so slot 7 is phase0 and slot 8 Altair.
        let config = ChainConfig::minimal().with_fork_epoch(ForkName::Altair, Epoch(1));
        let context = SigningContext::new(Arc::new(config.clone()), Root([0x11; 32]));
        let domain = |slot| {
            let header = BeaconBlockHeader {
                slot: Slot(slot),
                ..BeaconBlockHeader::default()
            };
            context.domain(&SigningRequest::<Minimal>::Block(&header))
        };
        let expected = |fork| {
            Domain::compute(
                DOMAIN_BEACON_PROPOSER,
                config.fork_version(fork),
                Root([0x11; 32]),
            )
        };
        assert_eq!(domain(7), expected(ForkName::Phase0));
        assert_eq!(domain(8), expected(ForkName::Altair));
    }

    #[test]
    fn exits_sign_under_capella_from_deneb_on() {
        let context = mainnet();
        let config = context.config().clone();
        let domain = |epoch| {
            let exit = VoluntaryExit {
                epoch,
                validator_index: ValidatorIndex(9),
            };
            context.domain(&SigningRequest::<Mainnet>::VoluntaryExit(&exit))
        };
        let expected = |version| Domain::compute(DOMAIN_VOLUNTARY_EXIT, version, Root([0x11; 32]));

        // An exit at the Gloas epoch still signs under the Capella version.
        assert_eq!(
            domain(config.gloas_fork_epoch),
            expected(config.capella_fork_version)
        );

        // At Bellatrix, the exit signs under the Bellatrix version.
        assert_eq!(
            domain(config.bellatrix_fork_epoch),
            expected(config.bellatrix_fork_version)
        );
    }

    #[test]
    fn the_fork_record_names_the_previous_and_current_versions() {
        // Mainnet at the Deneb epoch: Capella before, Deneb from that epoch.
        let context = mainnet();
        let config = context.config().clone();
        assert_eq!(
            context.fork(config.deneb_fork_epoch),
            Fork {
                previous_version: config.capella_fork_version,
                current_version: config.deneb_fork_version,
                epoch: config.deneb_fork_epoch,
            }
        );
    }
}
