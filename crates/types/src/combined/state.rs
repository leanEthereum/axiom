//! A beacon state of any fork.

use axiom_ssz::{DecodeError, Root, Ssz};

use crate::{
    ChainConfig, ForkName, Preset, Slot, altair, bellatrix, capella, deneb, electra, fulu, gloas,
    phase0,
};

/// Bytes before the slot in every state's encoding: the genesis time and validators root.
const SLOT_OFFSET: usize = 8 + 32;

/// A beacon state of whichever fork it belongs to.
///
/// Code that runs a fork's rules matches once and works on the concrete state.
/// The methods here are the few that every fork answers the same way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BeaconState<P: Preset> {
    /// A phase0 state.
    Phase0(phase0::BeaconState<P>),
    /// An Altair state.
    Altair(altair::BeaconState<P>),
    /// A Bellatrix state.
    Bellatrix(bellatrix::BeaconState<P>),
    /// A Capella state.
    Capella(capella::BeaconState<P>),
    /// A Deneb state.
    Deneb(deneb::BeaconState<P>),
    /// An Electra state.
    Electra(electra::BeaconState<P>),
    /// A Fulu state.
    Fulu(fulu::BeaconState<P>),
    /// A Gloas state.
    Gloas(gloas::BeaconState<P>),
}

impl<P: Preset> BeaconState<P> {
    /// The fork the state belongs to.
    #[must_use]
    pub const fn fork(&self) -> ForkName {
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

    /// Slot the state is at.
    #[must_use]
    pub const fn slot(&self) -> Slot {
        match self {
            Self::Phase0(state) => state.slot,
            Self::Altair(state) => state.slot,
            Self::Bellatrix(state) => state.slot,
            Self::Capella(state) => state.slot,
            Self::Deneb(state) => state.slot,
            Self::Electra(state) => state.slot,
            Self::Fulu(state) => state.slot,
            Self::Gloas(state) => state.slot,
        }
    }

    /// Merkle commitment to the state, which blocks name as their state root.
    #[must_use]
    pub fn hash_tree_root(&self) -> Root {
        match self {
            Self::Phase0(state) => state.hash_tree_root(),
            Self::Altair(state) => state.hash_tree_root(),
            Self::Bellatrix(state) => state.hash_tree_root(),
            Self::Capella(state) => state.hash_tree_root(),
            Self::Deneb(state) => state.hash_tree_root(),
            Self::Electra(state) => state.hash_tree_root(),
            Self::Fulu(state) => state.hash_tree_root(),
            Self::Gloas(state) => state.hash_tree_root(),
        }
    }

    /// The state's SSZ encoding, which does not record the fork.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Phase0(state) => state.encode(),
            Self::Altair(state) => state.encode(),
            Self::Bellatrix(state) => state.encode(),
            Self::Capella(state) => state.encode(),
            Self::Deneb(state) => state.encode(),
            Self::Electra(state) => state.encode(),
            Self::Fulu(state) => state.encode(),
            Self::Gloas(state) => state.encode(),
        }
    }

    /// Decodes a state of a known fork.
    ///
    /// # Errors
    ///
    /// Fails when the bytes are not the encoding of a state of that fork.
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

    /// Decodes a state of the fork its own slot falls in.
    ///
    /// Every fork puts the slot at the same place, so it can be read before the fork is known.
    ///
    /// # Errors
    ///
    /// Fails when the bytes are too short to hold a slot, or do not decode as that fork's state.
    pub fn decode_at(bytes: &[u8], config: &ChainConfig) -> Result<Self, DecodeError> {
        let slot = Slot::decode_at(bytes, SLOT_OFFSET)?;
        Self::decode(bytes, config.fork_at(slot.epoch::<P>()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Epoch, Minimal};

    #[test]
    fn decode_at_reads_the_fork_from_the_slot() {
        // Fixture state: Altair from epoch 1, so slot 8 of the minimal preset is Altair.
        let config = ChainConfig {
            altair_fork_epoch: Epoch(1),
            ..ChainConfig::minimal()
        };
        let state = altair::BeaconState::<Minimal> {
            slot: Slot(8),
            ..Default::default()
        };

        let decoded = BeaconState::<Minimal>::decode_at(&state.encode(), &config).unwrap();

        assert_eq!(decoded, BeaconState::Altair(state));
        assert_eq!(decoded.fork(), ForkName::Altair);
        assert_eq!(decoded.slot(), Slot(8));
    }

    #[test]
    fn decode_at_rejects_input_without_a_slot() {
        assert_eq!(
            BeaconState::<Minimal>::decode_at(&[0; 47], &ChainConfig::minimal()),
            Err(DecodeError::TooShort {
                minimum: 48,
                actual: 47
            })
        );
    }

    #[test]
    fn encoding_round_trips_through_the_fork() {
        // A default Gloas state, decoded back as Gloas.
        let state = BeaconState::<Minimal>::Gloas(gloas::BeaconState::default());

        let decoded = BeaconState::<Minimal>::decode(&state.encode(), ForkName::Gloas).unwrap();

        assert_eq!(decoded.hash_tree_root(), state.hash_tree_root());
        assert_eq!(decoded, state);
    }
}
