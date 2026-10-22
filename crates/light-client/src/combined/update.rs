//! Light client updates of any format: full, finality, and optimistic.

use axiom_beacon_json::{ApiJson, ApiJsonError, ForkedJson};
use axiom_json::Json;
use axiom_ssz::{Root, Ssz};
use axiom_types::{
    ChainConfig, ForkName, Preset, Slot, altair, capella, combined::SignedBeaconBlock, deneb,
    electra, gloas,
};

use super::{Format, LightClientHeader};
use crate::{
    Altair, Capella, Deneb, Electra, Gloas, LightClientError, LightClientFork, PostState,
    UpdateData, Upgrade,
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

    /// The update a full node derives from a block, its parent, and the parent's finalized block.
    ///
    /// # Overview
    ///
    /// The signature block carries the sync committee's signature over its parent.
    /// That parent is the attested block.
    /// The attested state proves the next committee and the finalized root.
    ///
    /// - The next committee is included only when both blocks share a sync committee period.
    /// - A finalized block, when available, gives the finalized header and its branch.
    /// - A genesis finalized block stays an empty header; its root in the state is zero.
    ///
    /// The update takes the attested block's format, and the finalized header is upgraded to it.
    /// See `create_light_client_update` in the Altair light client full node spec.
    ///
    /// # Errors
    ///
    /// Fails when a block has no light client data, or too few members signed.
    /// Fails when the blocks are not parent and child.
    /// Fails when the finalized block is not the one the attested state finalized.
    pub fn create(
        config: &ChainConfig,
        signature: &PostState<'_, P>,
        attested: &PostState<'_, P>,
        finalized_block: Option<&SignedBeaconBlock<P>>,
    ) -> Result<Self, LightClientError> {
        let attested_block = attested.block();
        let attested_fork = attested_block.fork_name();
        let format = Format::of(attested_fork)?;
        let block = signature.block();
        let sync_aggregate = block
            .sync_aggregate()
            .ok_or_else(|| LightClientError::NoLightClientData(block.fork_name()))?;
        let participants = sync_aggregate.sync_committee_bits.count_ones() as u64;
        if participants < P::MIN_SYNC_COMMITTEE_PARTICIPANTS {
            return Err(LightClientError::InsufficientParticipants {
                participants,
                minimum: P::MIN_SYNC_COMMITTEE_PARTICIPANTS,
            });
        }
        if block.parent_root() != attested.root() {
            return Err(LightClientError::NotParent {
                parent: block.parent_root(),
                attested: attested.root(),
            });
        }
        let committees = attested
            .state()
            .sync_committees()
            .ok_or(LightClientError::NoLightClientData(attested_fork))?;
        let layout = attested.layout();
        let signature_slot = block.slot();
        let mut update = UpdateData {
            attested_header: LightClientHeader::of_block(attested_block),
            finalized_header: LightClientHeader::empty(format),
            sync_aggregate: sync_aggregate.clone(),
            signature_slot,
            ..UpdateData::default()
        };

        // The next committee helps only a client that verifies with the current one.
        if attested_block.slot().sync_committee_period::<P>()
            == signature_slot.sync_committee_period::<P>()
        {
            update.next_sync_committee = committees.next_sync_committee().clone();
            update.next_sync_committee_branch = attested.prove(layout.next_sync_committee)?;
        }

        // Finality is proven whenever the finalized block is at hand.
        if let Some(finalized) = finalized_block {
            let checkpoint = attested.state().as_core().finalized_checkpoint().root;
            if finalized.slot() == Slot::GENESIS {
                // The genesis checkpoint names the zero root, so the header stays empty.
                if checkpoint != Root::ZERO {
                    return Err(LightClientError::FinalizedMismatch {
                        checkpoint,
                        block: Root::ZERO,
                    });
                }
            } else {
                let header = LightClientHeader::of_block(finalized).upgrade_to(format, config)?;
                let root = header.beacon_root();
                if root != checkpoint {
                    return Err(LightClientError::FinalizedMismatch {
                        checkpoint,
                        block: root,
                    });
                }
                update.finalized_header = header;
            }
            update.finality_branch = attested.prove(layout.finalized_root)?;
        }
        Self::from_data(update)
    }

    /// The update's SSZ encoding, which does not record the format.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Altair(update) => update.encode(),
            Self::Capella(update) => update.encode(),
            Self::Deneb(update) => update.encode(),
            Self::Electra(update) => update.encode(),
            Self::Gloas(update) => update.encode(),
        }
    }

    /// The slot whose fork digest tags the update on the wire: its attested header's.
    ///
    /// The signature may fall in a later fork; the attested header still decides.
    /// See `LightClientUpdatesByRange` in the Altair light client networking spec.
    #[must_use]
    pub const fn context_slot(&self) -> Slot {
        match self {
            Self::Altair(update) => update.attested_header.beacon.slot,
            Self::Capella(update) => update.attested_header.beacon.slot,
            Self::Deneb(update) => update.attested_header.beacon.slot,
            Self::Electra(update) => update.attested_header.beacon.slot,
            Self::Gloas(update) => update.attested_header.beacon.slot,
        }
    }

    /// The finality update the update implies.
    ///
    /// See `create_light_client_finality_update` in the Altair light client full node spec.
    ///
    /// # Errors
    ///
    /// Never fails for an update built by this crate: both headers share its format.
    pub fn finality_update(&self) -> Result<LightClientFinalityUpdate<P>, LightClientError> {
        LightClientFinalityUpdate::from_data(self.clone().into_data())
    }

    /// The optimistic update the update implies.
    ///
    /// See `create_light_client_optimistic_update` in the Altair light client full node spec.
    ///
    /// # Errors
    ///
    /// Never fails for an update built by this crate: both headers share its format.
    pub fn optimistic_update(&self) -> Result<LightClientOptimisticUpdate<P>, LightClientError> {
        LightClientOptimisticUpdate::from_data(self.clone().into_data())
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

impl<P: Preset> ForkedJson for LightClientUpdate<P> {
    fn to_json(&self) -> Json {
        match self {
            Self::Altair(value) => value.to_json(),
            Self::Capella(value) => value.to_json(),
            Self::Deneb(value) => value.to_json(),
            Self::Electra(value) => value.to_json(),
            Self::Gloas(value) => value.to_json(),
        }
    }

    fn from_json_in(fork: ForkName, value: &Json) -> Result<Self, ApiJsonError> {
        let format =
            Format::of(fork).map_err(|_| ApiJsonError::absent(fork, "light client update"))?;
        Ok(match format {
            Format::Altair => Self::Altair(ApiJson::from_json(value)?),
            Format::Capella => Self::Capella(ApiJson::from_json(value)?),
            Format::Deneb => Self::Deneb(ApiJson::from_json(value)?),
            Format::Electra => Self::Electra(ApiJson::from_json(value)?),
            Format::Gloas => Self::Gloas(ApiJson::from_json(value)?),
        })
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

    /// The finality update's SSZ encoding, which does not record the format.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Altair(update) => update.encode(),
            Self::Capella(update) => update.encode(),
            Self::Deneb(update) => update.encode(),
            Self::Electra(update) => update.encode(),
            Self::Gloas(update) => update.encode(),
        }
    }

    /// The slot whose fork digest tags the finality update on the wire: its attested header's.
    ///
    /// The signature may fall in a later fork; the attested header still decides.
    /// See `light_client_finality_update` in the Altair light client networking spec.
    #[must_use]
    pub const fn context_slot(&self) -> Slot {
        match self {
            Self::Altair(update) => update.attested_header.beacon.slot,
            Self::Capella(update) => update.attested_header.beacon.slot,
            Self::Deneb(update) => update.attested_header.beacon.slot,
            Self::Electra(update) => update.attested_header.beacon.slot,
            Self::Gloas(update) => update.attested_header.beacon.slot,
        }
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

impl<P: Preset> ForkedJson for LightClientFinalityUpdate<P> {
    fn to_json(&self) -> Json {
        match self {
            Self::Altair(value) => value.to_json(),
            Self::Capella(value) => value.to_json(),
            Self::Deneb(value) => value.to_json(),
            Self::Electra(value) => value.to_json(),
            Self::Gloas(value) => value.to_json(),
        }
    }

    fn from_json_in(fork: ForkName, value: &Json) -> Result<Self, ApiJsonError> {
        let format = Format::of(fork)
            .map_err(|_| ApiJsonError::absent(fork, "light client finality update"))?;
        Ok(match format {
            Format::Altair => Self::Altair(ApiJson::from_json(value)?),
            Format::Capella => Self::Capella(ApiJson::from_json(value)?),
            Format::Deneb => Self::Deneb(ApiJson::from_json(value)?),
            Format::Electra => Self::Electra(ApiJson::from_json(value)?),
            Format::Gloas => Self::Gloas(ApiJson::from_json(value)?),
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

    /// The optimistic update's SSZ encoding, which does not record the format.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Altair(update) => update.encode(),
            Self::Capella(update) => update.encode(),
            Self::Deneb(update) | Self::Electra(update) => update.encode(),
            Self::Gloas(update) => update.encode(),
        }
    }

    /// The slot whose fork digest tags the optimistic update on the wire: its attested header's.
    ///
    /// The signature may fall in a later fork; the attested header still decides.
    /// See `light_client_optimistic_update` in the Altair light client networking spec.
    #[must_use]
    pub const fn context_slot(&self) -> Slot {
        match self {
            Self::Altair(update) => update.attested_header.beacon.slot,
            Self::Capella(update) => update.attested_header.beacon.slot,
            Self::Deneb(update) | Self::Electra(update) => update.attested_header.beacon.slot,
            Self::Gloas(update) => update.attested_header.beacon.slot,
        }
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

impl<P: Preset> ForkedJson for LightClientOptimisticUpdate<P> {
    fn to_json(&self) -> Json {
        match self {
            Self::Altair(value) => value.to_json(),
            Self::Capella(value) => value.to_json(),
            // Electra kept Deneb's optimistic update.
            Self::Deneb(value) | Self::Electra(value) => value.to_json(),
            Self::Gloas(value) => value.to_json(),
        }
    }

    fn from_json_in(fork: ForkName, value: &Json) -> Result<Self, ApiJsonError> {
        let format = Format::of(fork)
            .map_err(|_| ApiJsonError::absent(fork, "light client optimistic update"))?;
        Ok(match format {
            Format::Altair => Self::Altair(ApiJson::from_json(value)?),
            Format::Capella => Self::Capella(ApiJson::from_json(value)?),
            Format::Deneb => Self::Deneb(ApiJson::from_json(value)?),
            Format::Electra => Self::Electra(ApiJson::from_json(value)?),
            Format::Gloas => Self::Gloas(ApiJson::from_json(value)?),
        })
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{
        Bytes32, Epoch, Minimal,
        altair::{SyncAggregate, SyncCommittee},
        phase0::Checkpoint,
    };

    use super::*;
    use crate::{
        Layout,
        combined::LightClientStore,
        fixture::{Chain, GENESIS_VALIDATORS_ROOT, Pair},
    };

    fn post((state, block): &Pair) -> PostState<'_, Minimal> {
        PostState::new(state, block).unwrap()
    }

    #[test]
    fn a_created_update_advances_a_store_in_every_format() {
        for fork in [
            ForkName::Altair,
            ForkName::Bellatrix,
            ForkName::Capella,
            ForkName::Deneb,
            ForkName::Electra,
            ForkName::Fulu,
            ForkName::Gloas,
        ] {
            // Fixture state: bootstrap at 8, finalized at 16, attested at 26, signed at 27.
            // All four sit in period 0, and all 32 members sign.
            let chain = Chain::new(fork);
            let line = chain.line([8, 16, 26, 27], 32);
            let update = line.update(&chain.config);
            let format = Format::of(fork).unwrap();
            assert_eq!(update.format(), format, "{fork}");
            assert_eq!(update.context_slot(), Slot(26), "{fork}");

            // Same period for both slots, so the next committee comes along with finality.
            let data = update.clone().into_data();
            assert!(data.is_sync_committee_update(), "{fork}");
            assert!(data.is_finality_update(), "{fork}");
            assert_eq!(data.next_sync_committee, chain.next, "{fork}");
            assert_eq!(
                data.finalized_header,
                LightClientHeader::of_block(&line.finalized.1),
                "{fork}"
            );

            // Every container survives its wire encoding in the fork's format.
            let finality = update.finality_update().unwrap();
            let optimistic = update.optimistic_update().unwrap();
            assert_eq!(
                (finality.context_slot(), optimistic.context_slot()),
                (Slot(26), Slot(26))
            );
            assert_eq!(
                LightClientUpdate::decode(&update.encode(), fork),
                Ok(update.clone())
            );
            assert_eq!(
                LightClientFinalityUpdate::decode(&finality.encode(), fork),
                Ok(finality)
            );
            assert_eq!(
                LightClientOptimisticUpdate::decode(&optimistic.encode(), fork),
                Ok(optimistic)
            );

            // The store checks both branches and the signature, then finalizes slot 16.
            let mut store = line.store(&chain.config, format);
            store
                .process_update(&chain.config, update, Slot(27), GENESIS_VALIDATORS_ROOT)
                .unwrap();
            assert_eq!(
                store.finalized_header(),
                LightClientHeader::of_block(&line.finalized.1),
                "{fork}"
            );
            assert_eq!(
                store.optimistic_header(),
                LightClientHeader::of_block(&line.attested.1),
                "{fork}"
            );
        }
    }

    #[test]
    fn the_finalized_header_takes_the_attested_format() {
        // Fixture state: a fork at epoch 2, so slot 12 is before it and slot 20 after it.
        for (before, after) in [
            (ForkName::Bellatrix, ForkName::Capella),
            (ForkName::Fulu, ForkName::Gloas),
        ] {
            let config = ChainConfig::minimal()
                .with_forks_at_genesis(before)
                .with_fork_epoch(after, Epoch(2));
            let chain = Chain::with_config(config);
            let line = chain.line([8, 12, 20, 21], 32);
            let update = line.update(&chain.config);

            // The update is in the attested block's format; the finalized header is upgraded to it.
            let format = Format::of(after).unwrap();
            assert_eq!(update.format(), format, "{after}");
            let upgraded = LightClientHeader::of_block(&line.finalized.1)
                .upgrade_to(format, &chain.config)
                .unwrap();
            assert_eq!(update.clone().into_data().finalized_header, upgraded);

            // A store of the later format proves the upgraded header and finalizes it.
            let mut store = line.store(&chain.config, format);
            store
                .process_update(&chain.config, update, Slot(21), GENESIS_VALIDATORS_ROOT)
                .unwrap();
            assert_eq!(store.finalized_header(), upgraded, "{after}");
        }
    }

    #[test]
    fn a_genesis_finalized_block_leaves_the_header_empty_but_proves_the_zero_root() {
        // Fixture state: the attested state at 20 still finalizes the genesis checkpoint.
        let chain = Chain::new(ForkName::Deneb);
        let line = chain.line([8, 0, 20, 21], 32);
        let update = line.update(&chain.config);
        let data = update.clone().into_data();
        assert_eq!(
            data.finalized_header,
            LightClientHeader::empty(Format::Deneb)
        );
        assert!(data.is_finality_update());

        // The store accepts the zero root, learns the next committee, and stays finalized at 8.
        let mut store = line.store(&chain.config, Format::Deneb);
        store
            .process_update(&chain.config, update, Slot(21), GENESIS_VALIDATORS_ROOT)
            .unwrap();
        let LightClientStore::Deneb(inner) = &store else {
            panic!("a Deneb store stays Deneb");
        };
        assert_eq!(inner.next_sync_committee, chain.next);
        assert_eq!(
            store.finalized_header(),
            LightClientHeader::of_block(&line.bootstrap.1)
        );
    }

    #[test]
    fn without_the_finalized_block_the_update_proves_no_finality() {
        // Fixture state: attested at 20 and signed at 21 by 32 members, finalized block pruned.
        let chain = Chain::new(ForkName::Altair);
        let line = chain.line([8, 16, 20, 21], 32);
        let update = line.update_with(&chain.config, None).unwrap();

        // The Altair finality branch holds 6 nodes, all zero without a finalized block.
        let next_sync_committee_branch = post(&line.attested)
            .prove(Layout::of(ForkName::Altair).next_sync_committee)
            .unwrap();
        assert_eq!(
            update.clone().into_data(),
            UpdateData {
                attested_header: LightClientHeader::of_block(&line.attested.1),
                next_sync_committee: chain.next.clone(),
                next_sync_committee_branch,
                finalized_header: LightClientHeader::empty(Format::Altair),
                finality_branch: vec![Bytes32::ZERO; 6],
                sync_aggregate: chain.sign(&line.attested.1, Slot(21), 32),
                signature_slot: Slot(21),
            }
        );

        // The store learns the attested header optimistically, and keeps its finalized one.
        let mut store = line.store(&chain.config, Format::Altair);
        store
            .process_update(&chain.config, update, Slot(21), GENESIS_VALIDATORS_ROOT)
            .unwrap();
        assert_eq!(
            store.optimistic_header(),
            LightClientHeader::of_block(&line.attested.1)
        );
        assert_eq!(
            store.finalized_header(),
            LightClientHeader::of_block(&line.bootstrap.1)
        );
    }

    #[test]
    fn a_signature_from_the_next_period_carries_no_next_committee() {
        // Fixture state: attested at 63, the last slot of period 0, signed at 64 in period 1.
        let chain = Chain::new(ForkName::Altair);
        let line = chain.line([8, 16, 63, 64], 32);
        let data = line.update(&chain.config).into_data();

        // The committee and its branch stay empty; finality is still proven.
        assert_eq!(data.next_sync_committee, SyncCommittee::default());
        assert_eq!(data.next_sync_committee_branch, vec![Bytes32::ZERO; 5]);
        assert!(data.is_finality_update());
    }

    #[test]
    fn creation_refuses_inconsistent_inputs() {
        // Fixture state: an Altair line, bootstrap 8, finalized 16, attested 26, signed at 27.
        let chain = Chain::new(ForkName::Altair);
        let config = &chain.config;
        let line = chain.line([8, 16, 26, 27], 32);
        let finalized_root = line.finalized.1.block_root();
        let bootstrap_root = line.bootstrap.1.block_root();

        // Mutation: the bootstrap block named as finalized, though the state finalized slot 16.
        assert_eq!(
            line.update_with(config, Some(&line.bootstrap.1)),
            Err(LightClientError::FinalizedMismatch {
                checkpoint: finalized_root,
                block: bootstrap_root,
            })
        );

        // Mutation: the bootstrap block as attested, though the signature block builds on 26.
        assert_eq!(
            LightClientUpdate::create(config, &post(&line.signature), &post(&line.bootstrap), None),
            Err(LightClientError::NotParent {
                parent: line.attested.1.block_root(),
                attested: bootstrap_root,
            })
        );

        // Mutation: nobody signs, below the minimum of 1 signer.
        let unsigned = chain.line([8, 16, 26, 27], 0);
        assert_eq!(
            unsigned.update_with(config, None),
            Err(LightClientError::InsufficientParticipants {
                participants: 0,
                minimum: 1,
            })
        );

        // Mutation: Altair starts at epoch 1, so the attested block at slot 7 is phase0.
        let chain =
            Chain::with_config(ChainConfig::minimal().with_fork_epoch(ForkName::Altair, Epoch(1)));
        let attested = chain.block(
            Slot(7),
            Root::ZERO,
            Checkpoint::default(),
            SyncAggregate::default(),
        );
        let aggregate = chain.sign(&attested.1, Slot(8), 32);
        let signature = chain.block(
            Slot(8),
            attested.1.block_root(),
            Checkpoint::default(),
            aggregate,
        );
        assert_eq!(
            LightClientUpdate::create(&chain.config, &post(&signature), &post(&attested), None),
            Err(LightClientError::NoLightClientData(ForkName::Phase0))
        );
    }
}
