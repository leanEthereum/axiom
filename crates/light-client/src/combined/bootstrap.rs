//! A light client bootstrap of any format.

use axiom_ssz::Ssz;
use axiom_types::{ChainConfig, ForkName, Preset, Slot, altair, capella, deneb, electra, gloas};

use super::{Format, LightClientHeader};
use crate::{
    Altair, BootstrapData, Capella, Deneb, Electra, Gloas, LightClientError, LightClientFork,
    PostState, Upgrade,
};

/// A bootstrap in the format of one fork.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LightClientBootstrap<P: Preset> {
    /// Altair and Bellatrix.
    Altair(altair::LightClientBootstrap<P>),
    /// Capella.
    Capella(capella::LightClientBootstrap<P>),
    /// Deneb.
    Deneb(deneb::LightClientBootstrap<P>),
    /// Electra and Fulu.
    Electra(electra::LightClientBootstrap<P>),
    /// Gloas.
    Gloas(gloas::LightClientBootstrap<P>),
}

impl<P: Preset> LightClientBootstrap<P> {
    /// Decodes a bootstrap in a fork's format.
    ///
    /// # Errors
    ///
    /// Fails when the fork has no light client data, or the bytes do not decode.
    pub fn decode(bytes: &[u8], fork: ForkName) -> Result<Self, LightClientError> {
        let decode_error = |source| LightClientError::Decode { fork, source };
        Ok(match Format::of(fork)? {
            Format::Altair => Self::Altair(Ssz::decode(bytes).map_err(decode_error)?),
            Format::Capella => Self::Capella(Ssz::decode(bytes).map_err(decode_error)?),
            Format::Deneb => Self::Deneb(Ssz::decode(bytes).map_err(decode_error)?),
            Format::Electra => Self::Electra(Ssz::decode(bytes).map_err(decode_error)?),
            Format::Gloas => Self::Gloas(Ssz::decode(bytes).map_err(decode_error)?),
        })
    }

    /// The bootstrap a full node serves for a block, from the block's post-state.
    ///
    /// The bootstrap takes the format of the block's fork.
    /// See `create_light_client_bootstrap` in the Altair light client full node spec.
    ///
    /// # Errors
    ///
    /// Fails for a phase0 block, which has no sync committee to prove.
    pub fn create(post: &PostState<'_, P>) -> Result<Self, LightClientError> {
        let block = post.block();
        let fork = block.fork_name();
        Format::of(fork)?;
        let committees = post
            .state()
            .sync_committees()
            .ok_or(LightClientError::NoLightClientData(fork))?;
        Self::from_data(BootstrapData {
            header: LightClientHeader::of_block(block),
            current_sync_committee: committees.current_sync_committee().clone(),
            current_sync_committee_branch: post.prove(post.layout().current_sync_committee)?,
        })
    }

    /// The bootstrap's SSZ encoding, which does not record the format.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Altair(bootstrap) => bootstrap.encode(),
            Self::Capella(bootstrap) => bootstrap.encode(),
            Self::Deneb(bootstrap) => bootstrap.encode(),
            Self::Electra(bootstrap) => bootstrap.encode(),
            Self::Gloas(bootstrap) => bootstrap.encode(),
        }
    }

    /// The slot whose fork digest tags the bootstrap on the wire: its header's.
    ///
    /// See `GetLightClientBootstrap` in the Altair light client networking spec.
    #[must_use]
    pub const fn context_slot(&self) -> Slot {
        match self {
            Self::Altair(bootstrap) => bootstrap.header.beacon.slot,
            Self::Capella(bootstrap) => bootstrap.header.beacon.slot,
            Self::Deneb(bootstrap) => bootstrap.header.beacon.slot,
            Self::Electra(bootstrap) => bootstrap.header.beacon.slot,
            Self::Gloas(bootstrap) => bootstrap.header.beacon.slot,
        }
    }

    /// The bootstrap's format.
    #[must_use]
    pub const fn format(&self) -> Format {
        match self {
            Self::Altair(_) => Format::Altair,
            Self::Capella(_) => Format::Capella,
            Self::Deneb(_) => Format::Deneb,
            Self::Electra(_) => Format::Electra,
            Self::Gloas(_) => Format::Gloas,
        }
    }

    /// A bootstrap from its fields, in the format of its header.
    ///
    /// # Errors
    ///
    /// Fails when the branch is longer than the format's.
    pub fn from_data(
        data: BootstrapData<LightClientHeader<P>, P>,
    ) -> Result<Self, LightClientError> {
        Ok(match data.header.format() {
            Format::Altair => Self::Altair(Altair::bootstrap(
                LightClientHeader::unwrap_bootstrap(data, LightClientHeader::into_altair)?,
            )?),
            Format::Capella => Self::Capella(Capella::bootstrap(
                LightClientHeader::unwrap_bootstrap(data, LightClientHeader::into_capella)?,
            )?),
            Format::Deneb => Self::Deneb(Deneb::bootstrap(LightClientHeader::unwrap_bootstrap(
                data,
                LightClientHeader::into_deneb,
            )?)?),
            Format::Electra => Self::Electra(Electra::bootstrap(
                LightClientHeader::unwrap_bootstrap(data, LightClientHeader::into_electra)?,
            )?),
            Format::Gloas => Self::Gloas(Gloas::bootstrap(LightClientHeader::unwrap_bootstrap(
                data,
                LightClientHeader::into_gloas,
            )?)?),
        })
    }

    /// The bootstrap in the next format, or unchanged in the last one.
    ///
    /// # Errors
    ///
    /// Fails when the branch is longer than the next format's.
    pub fn upgrade(self, config: &ChainConfig) -> Result<Self, LightClientError> {
        Ok(match self {
            Self::Altair(pre) => Self::Capella(Capella::upgrade_bootstrap(pre, config)?),
            Self::Capella(pre) => Self::Deneb(Deneb::upgrade_bootstrap(pre, config)?),
            Self::Deneb(pre) => Self::Electra(Electra::upgrade_bootstrap(pre, config)?),
            Self::Electra(pre) => Self::Gloas(Gloas::upgrade_bootstrap(pre, config)?),
            Self::Gloas(bootstrap) => Self::Gloas(bootstrap),
        })
    }

    /// The bootstrap upgraded through every format up to a target.
    ///
    /// # Errors
    ///
    /// Fails when the bootstrap's format is later than the target.
    pub fn upgrade_to(
        mut self,
        target: Format,
        config: &ChainConfig,
    ) -> Result<Self, LightClientError> {
        self.format().upgradable_to(target)?;
        while self.format() < target {
            self = self.upgrade(config)?;
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use axiom_ssz::Root;
    use axiom_types::{Minimal, altair::SyncAggregate, phase0::Checkpoint};

    use super::*;
    use crate::{combined::LightClientStore, fixture::Chain};

    #[test]
    fn a_created_bootstrap_initializes_a_store_in_every_format() {
        for fork in [
            ForkName::Altair,
            ForkName::Bellatrix,
            ForkName::Capella,
            ForkName::Deneb,
            ForkName::Electra,
            ForkName::Fulu,
            ForkName::Gloas,
        ] {
            // Fixture state: every fork up to this one from genesis, and a block at slot 8.
            let chain = Chain::new(fork);
            let (state, block) = chain.block(
                Slot(8),
                Root::ZERO,
                Checkpoint::default(),
                SyncAggregate::default(),
            );
            let post = PostState::new(&state, &block).unwrap();
            let bootstrap = LightClientBootstrap::<Minimal>::create(&post).unwrap();

            // The bootstrap has the block's format, and its slot picks the fork digest.
            let format = Format::of(fork).unwrap();
            assert_eq!(bootstrap.format(), format, "{fork}");
            assert_eq!(bootstrap.context_slot(), Slot(8), "{fork}");
            assert_eq!(
                LightClientBootstrap::decode(&bootstrap.encode(), fork),
                Ok(bootstrap.clone()),
                "{fork}"
            );

            // The store checks the header against the trusted root and the committee branch.
            let store =
                LightClientStore::initialize(format, &chain.config, block.block_root(), bootstrap)
                    .unwrap();
            assert_eq!(
                store.finalized_header(),
                LightClientHeader::of_block(&block),
                "{fork}"
            );
        }
    }

    #[test]
    fn a_phase0_block_has_no_bootstrap() {
        // Fixture state: no fork past phase0, so the state has no sync committee.
        let chain = Chain::new(ForkName::Phase0);
        let (state, block) = chain.block(
            Slot(8),
            Root::ZERO,
            Checkpoint::default(),
            SyncAggregate::default(),
        );
        let post = PostState::new(&state, &block).unwrap();
        assert_eq!(
            LightClientBootstrap::<Minimal>::create(&post),
            Err(LightClientError::NoLightClientData(ForkName::Phase0))
        );
    }
}
