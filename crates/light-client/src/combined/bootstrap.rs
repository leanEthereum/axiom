//! A light client bootstrap of any format.

use axiom_ssz::Ssz;
use axiom_types::{ChainConfig, ForkName, Preset, altair, capella, deneb, electra, gloas};

use super::{Format, LightClientHeader};
use crate::{
    Altair, BootstrapData, Capella, Deneb, Electra, Gloas, LightClientError, LightClientFork,
    Upgrade,
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
