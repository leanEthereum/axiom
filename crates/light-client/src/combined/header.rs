//! A light client header of any format.

use axiom_ssz::{Root, Ssz};
use axiom_types::{
    ChainConfig, Preset, altair, capella, combined::SignedBeaconBlock, deneb, gloas,
    phase0::BeaconBlockHeader,
};

use super::Format;
use crate::{
    BootstrapData, Capella, Deneb, Electra, Execution, Gloas, Header, LightClientBlock,
    LightClientError, UpdateData, Upgrade,
};

/// A light client header in the format of one fork.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LightClientHeader<P: Preset> {
    /// Altair and Bellatrix.
    Altair(altair::LightClientHeader),
    /// Capella.
    Capella(capella::LightClientHeader<P>),
    /// Deneb.
    Deneb(deneb::LightClientHeader<P>),
    /// Electra and Fulu, which keep Deneb's header.
    Electra(deneb::LightClientHeader<P>),
    /// Gloas.
    Gloas(gloas::LightClientHeader),
}

impl<P: Preset> Default for LightClientHeader<P> {
    /// The empty header of the first format.
    fn default() -> Self {
        Self::Altair(altair::LightClientHeader::default())
    }
}

impl<P: Preset> Header<P> for LightClientHeader<P> {
    fn beacon(&self) -> &BeaconBlockHeader {
        match self {
            Self::Altair(header) => Header::<P>::beacon(header),
            Self::Capella(header) => header.beacon(),
            Self::Deneb(header) | Self::Electra(header) => header.beacon(),
            Self::Gloas(header) => Header::<P>::beacon(header),
        }
    }

    fn is_valid(&self, execution: Execution) -> bool {
        match self {
            Self::Altair(header) => Header::<P>::is_valid(header, execution),
            Self::Capella(header) => header.is_valid(execution),
            Self::Deneb(header) | Self::Electra(header) => header.is_valid(execution),
            Self::Gloas(header) => Header::<P>::is_valid(header, execution),
        }
    }

    fn execution_root(&self, execution: Execution) -> Root {
        match self {
            Self::Altair(header) => Header::<P>::execution_root(header, execution),
            Self::Capella(header) => header.execution_root(execution),
            Self::Deneb(header) | Self::Electra(header) => header.execution_root(execution),
            Self::Gloas(header) => Header::<P>::execution_root(header, execution),
        }
    }
}

impl<P: Preset> LightClientHeader<P> {
    /// The header's format.
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

    /// The empty header of a format, as data carries it in place of an absent header.
    #[must_use]
    pub fn empty(format: Format) -> Self {
        match format {
            Format::Altair => Self::Altair(altair::LightClientHeader::default()),
            Format::Capella => Self::Capella(capella::LightClientHeader::default()),
            Format::Deneb => Self::Deneb(deneb::LightClientHeader::default()),
            Format::Electra => Self::Electra(deneb::LightClientHeader::default()),
            Format::Gloas => Self::Gloas(gloas::LightClientHeader::default()),
        }
    }

    /// The light client header of a block, in the format of the block's fork.
    ///
    /// A phase0 block gets an Altair header, the earliest format.
    /// See `block_to_light_client_header` in each fork's light client full node spec.
    #[must_use]
    pub fn of_block(block: &SignedBeaconBlock<P>) -> Self {
        match block {
            SignedBeaconBlock::Phase0(signed) => Self::Altair(signed.message.light_client_header()),
            SignedBeaconBlock::Altair(signed) => Self::Altair(signed.message.light_client_header()),
            SignedBeaconBlock::Bellatrix(signed) => {
                Self::Altair(signed.message.light_client_header())
            }
            SignedBeaconBlock::Capella(signed) => {
                Self::Capella(signed.message.light_client_header())
            }
            SignedBeaconBlock::Deneb(signed) => Self::Deneb(signed.message.light_client_header()),
            SignedBeaconBlock::Electra(signed) | SignedBeaconBlock::Fulu(signed) => {
                Self::Electra(signed.message.light_client_header())
            }
            SignedBeaconBlock::Gloas(signed) => Self::Gloas(signed.message.light_client_header()),
            SignedBeaconBlock::Hstar(signed) => Self::Gloas(signed.message.light_client_header()),
        }
    }

    /// The header in the next format, or unchanged in the last one.
    #[must_use]
    pub fn upgrade(self, config: &ChainConfig) -> Self {
        match self {
            Self::Altair(header) => Self::Capella(Capella::upgrade_header_at(header, config)),
            Self::Capella(header) => Self::Deneb(Deneb::upgrade_header_at(header, config)),
            Self::Deneb(header) => Self::Electra(Electra::upgrade_header_at(header, config)),
            Self::Electra(header) => Self::Gloas(Gloas::upgrade_header_at(header, config)),
            Self::Gloas(header) => Self::Gloas(header),
        }
    }

    /// The header upgraded through every format up to a target.
    ///
    /// # Errors
    ///
    /// Fails when the header's format is later than the target.
    pub fn upgrade_to(
        mut self,
        target: Format,
        config: &ChainConfig,
    ) -> Result<Self, LightClientError> {
        self.format().upgradable_to(target)?;
        while self.format() < target {
            self = self.upgrade(config);
        }
        Ok(self)
    }

    /// The Altair header inside, if the format is Altair's.
    #[must_use]
    pub fn into_altair(self) -> Option<altair::LightClientHeader> {
        match self {
            Self::Altair(header) => Some(header),
            _ => None,
        }
    }

    /// The Capella header inside, if the format is Capella's.
    #[must_use]
    pub fn into_capella(self) -> Option<capella::LightClientHeader<P>> {
        match self {
            Self::Capella(header) => Some(header),
            _ => None,
        }
    }

    /// The Deneb header inside, if the format is Deneb's.
    #[must_use]
    pub fn into_deneb(self) -> Option<deneb::LightClientHeader<P>> {
        match self {
            Self::Deneb(header) => Some(header),
            _ => None,
        }
    }

    /// The Deneb header inside, if the format is Electra's.
    #[must_use]
    pub fn into_electra(self) -> Option<deneb::LightClientHeader<P>> {
        match self {
            Self::Electra(header) => Some(header),
            _ => None,
        }
    }

    /// The Gloas header inside, if the format is Gloas's.
    #[must_use]
    pub fn into_gloas(self) -> Option<gloas::LightClientHeader> {
        match self {
            Self::Gloas(header) => Some(header),
            _ => None,
        }
    }

    /// A bootstrap's fields with the header taken out of its format.
    pub(crate) fn unwrap_bootstrap<H>(
        data: BootstrapData<Self, P>,
        unwrap: fn(Self) -> Option<H>,
    ) -> Result<BootstrapData<H, P>, LightClientError> {
        let fork = data.header.format().fork();
        data.try_map(|header| {
            unwrap(header).ok_or(LightClientError::MixedHeaders {
                attested: fork,
                finalized: fork,
            })
        })
    }

    /// An update's fields with both headers taken out of one format.
    ///
    /// The finalized header must already share the attested header's format.
    pub(crate) fn unwrap_update<H>(
        data: UpdateData<Self, P>,
        unwrap: fn(Self) -> Option<H>,
    ) -> Result<UpdateData<H, P>, LightClientError> {
        let attested = data.attested_header.format().fork();
        let finalized = data.finalized_header.format().fork();
        data.try_map(|header| {
            unwrap(header).ok_or(LightClientError::MixedHeaders {
                attested,
                finalized,
            })
        })
    }

    /// The header's beacon block root.
    #[must_use]
    pub fn beacon_root(&self) -> Root {
        Header::<P>::beacon(self).hash_tree_root()
    }
}
