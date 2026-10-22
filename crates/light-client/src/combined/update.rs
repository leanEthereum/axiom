//! Light client updates of any format: full, finality, and optimistic.

use axiom_ssz::Ssz;
use axiom_types::{ChainConfig, ForkName, Preset, altair, capella, deneb, electra, gloas};

use super::{Format, LightClientHeader};
use crate::{
    Altair, Capella, Deneb, Electra, Gloas, LightClientError, LightClientFork, UpdateData, Upgrade,
};

/// An update in the format of one fork.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LightClientUpdate<P: Preset> {
    /// Altair and Bellatrix.
    Altair(altair::LightClientUpdate<P>),
    /// Capella.
    Capella(capella::LightClientUpdate<P>),
    /// Deneb.
    Deneb(deneb::LightClientUpdate<P>),
    /// Electra and Fulu.
    Electra(electra::LightClientUpdate<P>),
    /// Gloas.
    Gloas(gloas::LightClientUpdate<P>),
}

impl<P: Preset> LightClientUpdate<P> {
    /// Decodes an update in a fork's format.
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

    /// The update's format.
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

    /// An update from its fields, in the format of its attested header.
    ///
    /// # Errors
    ///
    /// Fails when the headers have different formats, or a branch is longer than the format's.
    pub fn from_data(data: UpdateData<LightClientHeader<P>, P>) -> Result<Self, LightClientError> {
        Ok(match data.attested_header.format() {
            Format::Altair => Self::Altair(Altair::update(LightClientHeader::unwrap_update(
                data,
                LightClientHeader::into_altair,
            )?)?),
            Format::Capella => Self::Capella(Capella::update(LightClientHeader::unwrap_update(
                data,
                LightClientHeader::into_capella,
            )?)?),
            Format::Deneb => Self::Deneb(Deneb::update(LightClientHeader::unwrap_update(
                data,
                LightClientHeader::into_deneb,
            )?)?),
            Format::Electra => Self::Electra(Electra::update(LightClientHeader::unwrap_update(
                data,
                LightClientHeader::into_electra,
            )?)?),
            Format::Gloas => Self::Gloas(Gloas::update(LightClientHeader::unwrap_update(
                data,
                LightClientHeader::into_gloas,
            )?)?),
        })
    }

    /// The update's fields, with headers of its format.
    #[must_use]
    pub fn into_data(self) -> UpdateData<LightClientHeader<P>, P> {
        match self {
            Self::Altair(update) => Altair::update_data(update).map(LightClientHeader::Altair),
            Self::Capella(update) => Capella::update_data(update).map(LightClientHeader::Capella),
            Self::Deneb(update) => Deneb::update_data(update).map(LightClientHeader::Deneb),
            Self::Electra(update) => Electra::update_data(update).map(LightClientHeader::Electra),
            Self::Gloas(update) => Gloas::update_data(update).map(LightClientHeader::Gloas),
        }
    }

    /// The update in the next format, or unchanged in the last one.
    ///
    /// # Errors
    ///
    /// Fails when a branch is longer than the next format's.
    pub fn upgrade(self, config: &ChainConfig) -> Result<Self, LightClientError> {
        Ok(match self {
            Self::Altair(pre) => Self::Capella(Capella::upgrade_update(pre, config)?),
            Self::Capella(pre) => Self::Deneb(Deneb::upgrade_update(pre, config)?),
            Self::Deneb(pre) => Self::Electra(Electra::upgrade_update(pre, config)?),
            Self::Electra(pre) => Self::Gloas(Gloas::upgrade_update(pre, config)?),
            Self::Gloas(update) => Self::Gloas(update),
        })
    }

    /// The update upgraded through every format up to a target.
    ///
    /// # Errors
    ///
    /// Fails when the update's format is later than the target.
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

/// A finality update in the format of one fork.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LightClientFinalityUpdate<P: Preset> {
    /// Altair and Bellatrix.
    Altair(altair::LightClientFinalityUpdate<P>),
    /// Capella.
    Capella(capella::LightClientFinalityUpdate<P>),
    /// Deneb.
    Deneb(deneb::LightClientFinalityUpdate<P>),
    /// Electra and Fulu.
    Electra(electra::LightClientFinalityUpdate<P>),
    /// Gloas.
    Gloas(gloas::LightClientFinalityUpdate<P>),
}

impl<P: Preset> LightClientFinalityUpdate<P> {
    /// Decodes a finality update in a fork's format.
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

    /// The finality update's format.
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

    /// A finality update from an update's fields, in the format of its attested header.
    ///
    /// # Errors
    ///
    /// Fails when the headers have different formats, or a branch is longer than the format's.
    pub fn from_data(data: UpdateData<LightClientHeader<P>, P>) -> Result<Self, LightClientError> {
        Ok(match data.attested_header.format() {
            Format::Altair => Self::Altair(Altair::finality_update(
                LightClientHeader::unwrap_update(data, LightClientHeader::into_altair)?,
            )?),
            Format::Capella => Self::Capella(Capella::finality_update(
                LightClientHeader::unwrap_update(data, LightClientHeader::into_capella)?,
            )?),
            Format::Deneb => Self::Deneb(Deneb::finality_update(
                LightClientHeader::unwrap_update(data, LightClientHeader::into_deneb)?,
            )?),
            Format::Electra => Self::Electra(Electra::finality_update(
                LightClientHeader::unwrap_update(data, LightClientHeader::into_electra)?,
            )?),
            Format::Gloas => Self::Gloas(Gloas::finality_update(
                LightClientHeader::unwrap_update(data, LightClientHeader::into_gloas)?,
            )?),
        })
    }
}

/// An optimistic update in the format of one fork.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LightClientOptimisticUpdate<P: Preset> {
    /// Altair and Bellatrix.
    Altair(altair::LightClientOptimisticUpdate<P>),
    /// Capella.
    Capella(capella::LightClientOptimisticUpdate<P>),
    /// Deneb.
    Deneb(deneb::LightClientOptimisticUpdate<P>),
    /// Electra and Fulu.
    Electra(electra::LightClientOptimisticUpdate<P>),
    /// Gloas.
    Gloas(gloas::LightClientOptimisticUpdate<P>),
}

impl<P: Preset> LightClientOptimisticUpdate<P> {
    /// Decodes an optimistic update in a fork's format.
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

    /// The optimistic update's format.
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

    /// An optimistic update from an update's fields, in the format of its attested header.
    ///
    /// # Errors
    ///
    /// Fails when the headers have different formats, or a branch is longer than the format's.
    pub fn from_data(data: UpdateData<LightClientHeader<P>, P>) -> Result<Self, LightClientError> {
        // An optimistic update drops the finalized header, whatever its format.
        let data = UpdateData {
            finalized_header: data.attested_header.clone(),
            ..data
        };
        Ok(match data.attested_header.format() {
            Format::Altair => Self::Altair(Altair::optimistic_update(
                LightClientHeader::unwrap_update(data, LightClientHeader::into_altair)?,
            )),
            Format::Capella => Self::Capella(Capella::optimistic_update(
                LightClientHeader::unwrap_update(data, LightClientHeader::into_capella)?,
            )),
            Format::Deneb => Self::Deneb(Deneb::optimistic_update(
                LightClientHeader::unwrap_update(data, LightClientHeader::into_deneb)?,
            )),
            Format::Electra => Self::Electra(Electra::optimistic_update(
                LightClientHeader::unwrap_update(data, LightClientHeader::into_electra)?,
            )),
            Format::Gloas => Self::Gloas(Gloas::optimistic_update(
                LightClientHeader::unwrap_update(data, LightClientHeader::into_gloas)?,
            )),
        })
    }
}
