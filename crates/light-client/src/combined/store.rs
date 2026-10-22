//! A light client store of any format.

use axiom_ssz::Root;
use axiom_types::{ChainConfig, Preset, Slot};

use super::{Format, LightClientBootstrap, LightClientHeader, LightClientUpdate};
use crate::{Altair, Capella, Deneb, Electra, Gloas, LightClientError, store};

/// A light client store in the format of one fork.
///
/// # Overview
///
/// Data of an earlier format is upgraded to the store's format on the way in.
/// Data of a later format is refused: the store must upgrade first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LightClientStore<P: Preset> {
    /// Altair and Bellatrix.
    Altair(store::LightClientStore<P, Altair>),
    /// Capella.
    Capella(store::LightClientStore<P, Capella>),
    /// Deneb.
    Deneb(store::LightClientStore<P, Deneb>),
    /// Electra and Fulu.
    Electra(store::LightClientStore<P, Electra>),
    /// Gloas.
    Gloas(store::LightClientStore<P, Gloas>),
}

impl<P: Preset> LightClientStore<P> {
    /// A store of a format, bootstrapped from a trusted block.
    ///
    /// # Errors
    ///
    /// Fails when the bootstrap is of a later format, or does not prove the trusted block.
    pub fn initialize(
        format: Format,
        config: &ChainConfig,
        trusted_block_root: Root,
        bootstrap: LightClientBootstrap<P>,
    ) -> Result<Self, LightClientError> {
        let root = trusted_block_root;
        Ok(match bootstrap.upgrade_to(format, config)? {
            LightClientBootstrap::Altair(data) => {
                Self::Altair(store::LightClientStore::initialize(config, root, data)?)
            }
            LightClientBootstrap::Capella(data) => {
                Self::Capella(store::LightClientStore::initialize(config, root, data)?)
            }
            LightClientBootstrap::Deneb(data) => {
                Self::Deneb(store::LightClientStore::initialize(config, root, data)?)
            }
            LightClientBootstrap::Electra(data) => {
                Self::Electra(store::LightClientStore::initialize(config, root, data)?)
            }
            LightClientBootstrap::Gloas(data) => {
                Self::Gloas(store::LightClientStore::initialize(config, root, data)?)
            }
        })
    }

    /// The store's format.
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

    /// Validates an update, upgraded to the store's format, and advances the store with it.
    ///
    /// # Errors
    ///
    /// Fails when the update is of a later format, or invalid.
    pub fn process_update(
        &mut self,
        config: &ChainConfig,
        update: LightClientUpdate<P>,
        current_slot: Slot,
        genesis_validators_root: Root,
    ) -> Result<(), LightClientError> {
        let (slot, root) = (current_slot, genesis_validators_root);
        let update = update.upgrade_to(self.format(), config)?;
        match (self, update) {
            (Self::Altair(store), LightClientUpdate::Altair(update)) => {
                store.process_update(config, update, slot, root)
            }
            (Self::Capella(store), LightClientUpdate::Capella(update)) => {
                store.process_update(config, update, slot, root)
            }
            (Self::Deneb(store), LightClientUpdate::Deneb(update)) => {
                store.process_update(config, update, slot, root)
            }
            (Self::Electra(store), LightClientUpdate::Electra(update)) => {
                store.process_update(config, update, slot, root)
            }
            (Self::Gloas(store), LightClientUpdate::Gloas(update)) => {
                store.process_update(config, update, slot, root)
            }
            // Upgrading stops at the store's format, so the formats always match here.
            (store, update) => Err(LightClientError::LaterData {
                data: update.format().fork(),
                store: store.format().fork(),
            }),
        }
    }

    /// Applies the best update after a timeout without finality.
    ///
    /// # Errors
    ///
    /// Fails when the best update skips a period.
    pub fn force_update(&mut self, current_slot: Slot) -> Result<(), LightClientError> {
        match self {
            Self::Altair(store) => store.force_update(current_slot),
            Self::Capella(store) => store.force_update(current_slot),
            Self::Deneb(store) => store.force_update(current_slot),
            Self::Electra(store) => store.force_update(current_slot),
            Self::Gloas(store) => store.force_update(current_slot),
        }
    }

    /// The store in the next format, or unchanged in the last one.
    ///
    /// # Errors
    ///
    /// Fails when a branch of the best update is longer than the next format's.
    pub fn upgrade(self, config: &ChainConfig) -> Result<Self, LightClientError> {
        Ok(match self {
            Self::Altair(store) => Self::Capella(store.upgrade(config)?),
            Self::Capella(store) => Self::Deneb(store.upgrade(config)?),
            Self::Deneb(store) => Self::Electra(store.upgrade(config)?),
            Self::Electra(store) => Self::Gloas(store.upgrade(config)?),
            Self::Gloas(store) => Self::Gloas(store),
        })
    }

    /// The store upgraded through every format up to a target.
    ///
    /// # Errors
    ///
    /// Fails when the store's format is later than the target.
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

    /// The latest finalized header.
    #[must_use]
    pub fn finalized_header(&self) -> LightClientHeader<P> {
        match self {
            Self::Altair(store) => LightClientHeader::Altair(store.finalized_header.clone()),
            Self::Capella(store) => LightClientHeader::Capella(store.finalized_header.clone()),
            Self::Deneb(store) => LightClientHeader::Deneb(store.finalized_header.clone()),
            Self::Electra(store) => LightClientHeader::Electra(store.finalized_header.clone()),
            Self::Gloas(store) => LightClientHeader::Gloas(store.finalized_header.clone()),
        }
    }

    /// The latest optimistic header.
    #[must_use]
    pub fn optimistic_header(&self) -> LightClientHeader<P> {
        match self {
            Self::Altair(store) => LightClientHeader::Altair(store.optimistic_header.clone()),
            Self::Capella(store) => LightClientHeader::Capella(store.optimistic_header.clone()),
            Self::Deneb(store) => LightClientHeader::Deneb(store.optimistic_header.clone()),
            Self::Electra(store) => LightClientHeader::Electra(store.optimistic_header.clone()),
            Self::Gloas(store) => LightClientHeader::Gloas(store.optimistic_header.clone()),
        }
    }
}
