//! A signed beacon block of any fork.

use axiom_ssz::{BYTES_PER_LENGTH_OFFSET, DecodeError, Root, Ssz};

use crate::{
    BlsSignature, ChainConfig, ForkName, Preset, Slot, altair, bellatrix, capella,
    combined::BeaconBlock, deneb, electra, fulu, gloas, phase0,
};

/// Bytes before the block in a signed block's encoding: the block's offset and the signature.
///
/// The block is variable-size, so the fixed part holds its offset, then the 96-byte signature.
const MESSAGE_OFFSET: usize = BYTES_PER_LENGTH_OFFSET + 96;

/// A signed beacon block of whichever fork it belongs to.
///
/// Fulu kept Electra's block, so those two variants hold the same type.
/// Code that runs a fork's rules matches once and works on the concrete block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignedBeaconBlock<P: Preset> {
    /// A signed phase0 block.
    Phase0(phase0::SignedBeaconBlock<P>),
    /// A signed Altair block.
    Altair(altair::SignedBeaconBlock<P>),
    /// A signed Bellatrix block.
    Bellatrix(bellatrix::SignedBeaconBlock<P>),
    /// A signed Capella block.
    Capella(capella::SignedBeaconBlock<P>),
    /// A signed Deneb block.
    Deneb(deneb::SignedBeaconBlock<P>),
    /// A signed Electra block.
    Electra(electra::SignedBeaconBlock<P>),
    /// A signed Fulu block, the same type as a signed Electra block.
    Fulu(fulu::SignedBeaconBlock<P>),
    /// A signed Gloas block.
    Gloas(gloas::SignedBeaconBlock<P>),
}

impl<P: Preset> SignedBeaconBlock<P> {
    /// The fork the block belongs to.
    #[must_use]
    pub const fn fork_name(&self) -> ForkName {
        match self {
            Self::Phase0(_) => ForkName::Phase0,
            Self::Altair(_) => ForkName::Altair,
            Self::Bellatrix(_) => ForkName::Bellatrix,
            Self::Capella(_) => ForkName::Capella,
            Self::Deneb(_) => ForkName::Deneb,
            Self::Electra(_) => ForkName::Electra,
            Self::Fulu(_) => ForkName::Fulu,
            Self::Gloas(_) => ForkName::Gloas,
        }
    }

    /// Slot the block is proposed in.
    #[must_use]
    pub const fn slot(&self) -> Slot {
        match self {
            Self::Phase0(signed) => signed.message.slot,
            Self::Altair(signed) => signed.message.slot,
            Self::Bellatrix(signed) => signed.message.slot,
            Self::Capella(signed) => signed.message.slot,
            Self::Deneb(signed) => signed.message.slot,
            Self::Electra(signed) | Self::Fulu(signed) => signed.message.slot,
            Self::Gloas(signed) => signed.message.slot,
        }
    }

    /// Root of the parent block.
    #[must_use]
    pub const fn parent_root(&self) -> Root {
        match self {
            Self::Phase0(signed) => signed.message.parent_root,
            Self::Altair(signed) => signed.message.parent_root,
            Self::Bellatrix(signed) => signed.message.parent_root,
            Self::Capella(signed) => signed.message.parent_root,
            Self::Deneb(signed) => signed.message.parent_root,
            Self::Electra(signed) | Self::Fulu(signed) => signed.message.parent_root,
            Self::Gloas(signed) => signed.message.parent_root,
        }
    }

    /// The proposer's signature.
    #[must_use]
    pub const fn signature(&self) -> &BlsSignature {
        match self {
            Self::Phase0(signed) => &signed.signature,
            Self::Altair(signed) => &signed.signature,
            Self::Bellatrix(signed) => &signed.signature,
            Self::Capella(signed) => &signed.signature,
            Self::Deneb(signed) => &signed.signature,
            Self::Electra(signed) | Self::Fulu(signed) => &signed.signature,
            Self::Gloas(signed) => &signed.signature,
        }
    }

    /// Root of the unsigned block, which names it in the chain.
    #[must_use]
    pub fn block_root(&self) -> Root {
        match self {
            Self::Phase0(signed) => signed.message.hash_tree_root(),
            Self::Altair(signed) => signed.message.hash_tree_root(),
            Self::Bellatrix(signed) => signed.message.hash_tree_root(),
            Self::Capella(signed) => signed.message.hash_tree_root(),
            Self::Deneb(signed) => signed.message.hash_tree_root(),
            Self::Electra(signed) | Self::Fulu(signed) => signed.message.hash_tree_root(),
            Self::Gloas(signed) => signed.message.hash_tree_root(),
        }
    }

    /// The unsigned block, copied out of its signed wrapper.
    #[must_use]
    pub fn message(&self) -> BeaconBlock<P> {
        match self {
            Self::Phase0(signed) => BeaconBlock::Phase0(signed.message.clone()),
            Self::Altair(signed) => BeaconBlock::Altair(signed.message.clone()),
            Self::Bellatrix(signed) => BeaconBlock::Bellatrix(signed.message.clone()),
            Self::Capella(signed) => BeaconBlock::Capella(signed.message.clone()),
            Self::Deneb(signed) => BeaconBlock::Deneb(signed.message.clone()),
            Self::Electra(signed) => BeaconBlock::Electra(signed.message.clone()),
            Self::Fulu(signed) => BeaconBlock::Fulu(signed.message.clone()),
            Self::Gloas(signed) => BeaconBlock::Gloas(signed.message.clone()),
        }
    }

    /// The signed block's SSZ encoding, which does not record the fork.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Phase0(signed) => signed.encode(),
            Self::Altair(signed) => signed.encode(),
            Self::Bellatrix(signed) => signed.encode(),
            Self::Capella(signed) => signed.encode(),
            Self::Deneb(signed) => signed.encode(),
            Self::Electra(signed) | Self::Fulu(signed) => signed.encode(),
            Self::Gloas(signed) => signed.encode(),
        }
    }

    /// Decodes a signed block of a known fork.
    ///
    /// # Errors
    ///
    /// Fails when the bytes are not the encoding of a signed block of that fork.
    pub fn decode(bytes: &[u8], fork: ForkName) -> Result<Self, DecodeError> {
        Ok(match fork {
            ForkName::Phase0 => Self::Phase0(Ssz::decode(bytes)?),
            ForkName::Altair => Self::Altair(Ssz::decode(bytes)?),
            ForkName::Bellatrix => Self::Bellatrix(Ssz::decode(bytes)?),
            ForkName::Capella => Self::Capella(Ssz::decode(bytes)?),
            ForkName::Deneb => Self::Deneb(Ssz::decode(bytes)?),
            ForkName::Electra => Self::Electra(Ssz::decode(bytes)?),
            ForkName::Fulu => Self::Fulu(Ssz::decode(bytes)?),
            ForkName::Gloas => Self::Gloas(Ssz::decode(bytes)?),
        })
    }

    /// Decodes a signed block of the fork its own slot falls in.
    ///
    /// The block starts right after the fixed part, and every fork encodes its slot first.
    ///
    /// # Errors
    ///
    /// Fails when the bytes are too short to hold a slot, or do not decode as that fork's block.
    pub fn decode_at(bytes: &[u8], config: &ChainConfig) -> Result<Self, DecodeError> {
        let slot = Slot::decode_at(bytes, MESSAGE_OFFSET)?;
        Self::decode(bytes, config.fork_at(slot.epoch::<P>()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Epoch, Minimal};

    #[test]
    fn decode_at_reads_the_slot_after_the_signature() {
        // Fixture state: Capella from epoch 3, so slot 24 of the minimal preset is Capella.
        let config = ChainConfig {
            altair_fork_epoch: Epoch(0),
            bellatrix_fork_epoch: Epoch(0),
            capella_fork_epoch: Epoch(3),
            ..ChainConfig::minimal()
        };
        let mut signed = capella::SignedBeaconBlock::<Minimal>::default();
        signed.message.slot = Slot(24);

        let decoded = SignedBeaconBlock::<Minimal>::decode_at(&signed.encode(), &config).unwrap();

        assert_eq!(decoded.fork_name(), ForkName::Capella);
        assert_eq!(decoded.slot(), Slot(24));
        assert_eq!(decoded.block_root(), signed.message.hash_tree_root());
        assert_eq!(decoded, SignedBeaconBlock::Capella(signed));
    }

    #[test]
    fn decode_at_rejects_input_without_a_slot() {
        // The fixed part is 100 bytes, so the slot needs 108.
        assert_eq!(
            SignedBeaconBlock::<Minimal>::decode_at(&[0; 100], &ChainConfig::minimal()),
            Err(DecodeError::TooShort {
                minimum: 108,
                actual: 100
            })
        );
    }
}
