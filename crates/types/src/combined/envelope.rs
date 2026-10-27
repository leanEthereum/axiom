//! A signed execution payload envelope of any fork that reveals payloads apart from blocks.

use axiom_ssz::{DecodeError, Root, Ssz};

use crate::{
    BlsSignature, BuilderIndex, ForkName, Hash32, Preset, Slot, gloas, gloas::ExecutionPayload,
    hstar,
};

/// A signed execution payload envelope of whichever fork it belongs to.
///
/// Forks from Gloas on reveal a block's payload in its own envelope.
/// They differ only in the execution requests the payload carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignedExecutionPayloadEnvelope<P: Preset> {
    /// A Gloas envelope.
    Gloas(gloas::SignedExecutionPayloadEnvelope<P>),
    /// An Hstar envelope, whose requests include key authorizations.
    Hstar(hstar::SignedExecutionPayloadEnvelope<P>),
}

impl<P: Preset> SignedExecutionPayloadEnvelope<P> {
    /// The fork whose format the envelope has.
    #[must_use]
    pub const fn fork_name(&self) -> ForkName {
        match self {
            Self::Gloas(_) => ForkName::Gloas,
            Self::Hstar(_) => ForkName::Hstar,
        }
    }

    /// The revealed payload, whose type every envelope fork shares.
    #[must_use]
    pub const fn payload(&self) -> &ExecutionPayload<P> {
        match self {
            Self::Gloas(signed) => &signed.message.payload,
            Self::Hstar(signed) => &signed.message.payload,
        }
    }

    /// Root of the block whose bid the payload honours.
    #[must_use]
    pub const fn beacon_block_root(&self) -> Root {
        match self {
            Self::Gloas(signed) => signed.message.beacon_block_root,
            Self::Hstar(signed) => signed.message.beacon_block_root,
        }
    }

    /// The builder revealing the payload.
    #[must_use]
    pub const fn builder_index(&self) -> BuilderIndex {
        match self {
            Self::Gloas(signed) => signed.message.builder_index,
            Self::Hstar(signed) => signed.message.builder_index,
        }
    }

    /// The beacon slot the payload names.
    #[must_use]
    pub const fn slot(&self) -> Slot {
        Slot(self.payload().slot_number)
    }

    /// Hash of the revealed execution block.
    #[must_use]
    pub const fn block_hash(&self) -> Hash32 {
        self.payload().block_hash
    }

    /// The builder's signature.
    #[must_use]
    pub const fn signature(&self) -> &BlsSignature {
        match self {
            Self::Gloas(signed) => &signed.signature,
            Self::Hstar(signed) => &signed.signature,
        }
    }

    /// Root of the unsigned envelope, which the builder signs.
    #[must_use]
    pub fn message_root(&self) -> Root {
        match self {
            Self::Gloas(signed) => signed.message.hash_tree_root(),
            Self::Hstar(signed) => signed.message.hash_tree_root(),
        }
    }

    /// The envelope's SSZ encoding, which does not record the fork.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Gloas(signed) => signed.encode(),
            Self::Hstar(signed) => signed.encode(),
        }
    }

    /// Decodes an envelope of the fork in force at its block's slot.
    ///
    /// Forks before Gloas have no envelopes, so their bytes are read in the first envelope format.
    /// Callers check that the fork separates payloads first and never get there.
    ///
    /// # Errors
    ///
    /// Fails when the bytes are not the encoding of that fork's envelope.
    pub fn decode(bytes: &[u8], fork: ForkName) -> Result<Self, DecodeError> {
        Ok(match fork {
            ForkName::Hstar => Self::Hstar(Ssz::decode(bytes)?),
            ForkName::Phase0
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb
            | ForkName::Electra
            | ForkName::Fulu
            | ForkName::Gloas => Self::Gloas(Ssz::decode(bytes)?),
        })
    }
}

impl<P: Preset> From<gloas::SignedExecutionPayloadEnvelope<P>>
    for SignedExecutionPayloadEnvelope<P>
{
    fn from(envelope: gloas::SignedExecutionPayloadEnvelope<P>) -> Self {
        Self::Gloas(envelope)
    }
}

impl<P: Preset> From<hstar::SignedExecutionPayloadEnvelope<P>>
    for SignedExecutionPayloadEnvelope<P>
{
    fn from(envelope: hstar::SignedExecutionPayloadEnvelope<P>) -> Self {
        Self::Hstar(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Minimal;

    #[test]
    fn decoding_follows_the_fork() {
        // Fixture state: an Hstar envelope revealing block hash 0x05.. for slot 12.
        let mut hstar = hstar::SignedExecutionPayloadEnvelope::<Minimal>::default();
        hstar.message.payload.block_hash = Hash32([5; 32]);
        hstar.message.payload.slot_number = 12;
        let envelope = SignedExecutionPayloadEnvelope::from(hstar);

        // The same bytes decode back as Hstar, and the shared fields read through.
        let decoded =
            SignedExecutionPayloadEnvelope::<Minimal>::decode(&envelope.encode(), ForkName::Hstar)
                .unwrap();
        assert_eq!(decoded, envelope);
        assert_eq!(decoded.fork_name(), ForkName::Hstar);
        assert_eq!(decoded.slot(), Slot(12));
        assert_eq!(decoded.block_hash(), Hash32([5; 32]));

        // Gloas's format lacks the key authorization list, so the bytes are not a Gloas envelope.
        assert!(
            SignedExecutionPayloadEnvelope::<Minimal>::decode(&envelope.encode(), ForkName::Gloas)
                .is_err()
        );
    }
}
