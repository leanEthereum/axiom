//! A signed blinded beacon block of any fork that has one.

use axiom_ssz::{Root, Ssz};

use crate::{
    BlsSignature, ForkName, KzgCommitment, Preset, Slot, ValidatorIndex, bellatrix, capella,
    combined::{BlindedBeaconBlock, BlindedBlockError, ExecutionPayload, SignedBeaconBlock},
    deneb, electra, fulu,
    phase0::BeaconBlockHeader,
};

/// A signed blinded beacon block of whichever fork it belongs to.
///
/// Fulu kept Electra's blinded block, so those two variants hold the same type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignedBlindedBeaconBlock<P: Preset> {
    /// A signed blinded Bellatrix block.
    Bellatrix(bellatrix::SignedBlindedBeaconBlock<P>),
    /// A signed blinded Capella block.
    Capella(capella::SignedBlindedBeaconBlock<P>),
    /// A signed blinded Deneb block.
    Deneb(deneb::SignedBlindedBeaconBlock<P>),
    /// A signed blinded Electra block.
    Electra(electra::SignedBlindedBeaconBlock<P>),
    /// A signed blinded Fulu block, the same type as a signed blinded Electra block.
    Fulu(fulu::SignedBlindedBeaconBlock<P>),
}

impl<P: Preset> SignedBlindedBeaconBlock<P> {
    /// A signed block with its payload replaced by the payload's header.
    ///
    /// The header commits to the payload field by field, so the block root and its signature carry over.
    /// Blocks without a payload, before Bellatrix and from Gloas on, have no blinded form.
    #[must_use]
    pub fn blinding(signed: &SignedBeaconBlock<P>) -> Option<Self> {
        Some(match signed {
            SignedBeaconBlock::Phase0(_)
            | SignedBeaconBlock::Altair(_)
            | SignedBeaconBlock::Gloas(_) => return None,
            SignedBeaconBlock::Bellatrix(signed) => {
                Self::Bellatrix(bellatrix::SignedBlindedBeaconBlock {
                    message: signed.message.clone().into(),
                    signature: signed.signature,
                })
            }
            SignedBeaconBlock::Capella(signed) => {
                Self::Capella(capella::SignedBlindedBeaconBlock {
                    message: signed.message.clone().into(),
                    signature: signed.signature,
                })
            }
            SignedBeaconBlock::Deneb(signed) => Self::Deneb(deneb::SignedBlindedBeaconBlock {
                message: signed.message.clone().into(),
                signature: signed.signature,
            }),
            SignedBeaconBlock::Electra(signed) => {
                Self::Electra(electra::SignedBlindedBeaconBlock {
                    message: signed.message.clone().into(),
                    signature: signed.signature,
                })
            }
            SignedBeaconBlock::Fulu(signed) => Self::Fulu(fulu::SignedBlindedBeaconBlock {
                message: signed.message.clone().into(),
                signature: signed.signature,
            }),
        })
    }

    /// A blinded block and its proposer's signature, in the block's fork.
    #[must_use]
    pub fn from_parts(message: BlindedBeaconBlock<P>, signature: BlsSignature) -> Self {
        match message {
            BlindedBeaconBlock::Bellatrix(message) => {
                Self::Bellatrix(bellatrix::SignedBlindedBeaconBlock { message, signature })
            }
            BlindedBeaconBlock::Capella(message) => {
                Self::Capella(capella::SignedBlindedBeaconBlock { message, signature })
            }
            BlindedBeaconBlock::Deneb(message) => {
                Self::Deneb(deneb::SignedBlindedBeaconBlock { message, signature })
            }
            BlindedBeaconBlock::Electra(message) => {
                Self::Electra(electra::SignedBlindedBeaconBlock { message, signature })
            }
            BlindedBeaconBlock::Fulu(message) => {
                Self::Fulu(fulu::SignedBlindedBeaconBlock { message, signature })
            }
        }
    }

    /// The fork the block belongs to.
    #[must_use]
    pub const fn fork_name(&self) -> ForkName {
        match self {
            Self::Bellatrix(_) => ForkName::Bellatrix,
            Self::Capella(_) => ForkName::Capella,
            Self::Deneb(_) => ForkName::Deneb,
            Self::Electra(_) => ForkName::Electra,
            Self::Fulu(_) => ForkName::Fulu,
        }
    }

    /// Slot the block is proposed in.
    #[must_use]
    pub const fn slot(&self) -> Slot {
        match self {
            Self::Bellatrix(signed) => signed.message.slot,
            Self::Capella(signed) => signed.message.slot,
            Self::Deneb(signed) => signed.message.slot,
            Self::Electra(signed) | Self::Fulu(signed) => signed.message.slot,
        }
    }

    /// The proposer.
    #[must_use]
    pub const fn proposer_index(&self) -> ValidatorIndex {
        match self {
            Self::Bellatrix(signed) => signed.message.proposer_index,
            Self::Capella(signed) => signed.message.proposer_index,
            Self::Deneb(signed) => signed.message.proposer_index,
            Self::Electra(signed) | Self::Fulu(signed) => signed.message.proposer_index,
        }
    }

    /// Root of the parent block.
    #[must_use]
    pub const fn parent_root(&self) -> Root {
        match self {
            Self::Bellatrix(signed) => signed.message.parent_root,
            Self::Capella(signed) => signed.message.parent_root,
            Self::Deneb(signed) => signed.message.parent_root,
            Self::Electra(signed) | Self::Fulu(signed) => signed.message.parent_root,
        }
    }

    /// The proposer's signature, which also holds over the full block.
    #[must_use]
    pub const fn signature(&self) -> &BlsSignature {
        match self {
            Self::Bellatrix(signed) => &signed.signature,
            Self::Capella(signed) => &signed.signature,
            Self::Deneb(signed) => &signed.signature,
            Self::Electra(signed) | Self::Fulu(signed) => &signed.signature,
        }
    }

    /// The block's header, the same one the full block has.
    #[must_use]
    pub fn header(&self) -> BeaconBlockHeader {
        match self {
            Self::Bellatrix(signed) => signed.message.header(),
            Self::Capella(signed) => signed.message.header(),
            Self::Deneb(signed) => signed.message.header(),
            Self::Electra(signed) | Self::Fulu(signed) => signed.message.header(),
        }
    }

    /// Root of the unsigned block, which is also the full block's root.
    #[must_use]
    pub fn block_root(&self) -> Root {
        match self {
            Self::Bellatrix(signed) => signed.message.hash_tree_root(),
            Self::Capella(signed) => signed.message.hash_tree_root(),
            Self::Deneb(signed) => signed.message.hash_tree_root(),
            Self::Electra(signed) | Self::Fulu(signed) => signed.message.hash_tree_root(),
        }
    }

    /// Commitments to the blobs the payload carries, from Deneb on.
    #[must_use]
    pub fn blob_kzg_commitments(&self) -> &[KzgCommitment] {
        match self {
            Self::Bellatrix(_) | Self::Capella(_) => &[],
            Self::Deneb(signed) => &signed.message.body.blob_kzg_commitments,
            Self::Electra(signed) | Self::Fulu(signed) => &signed.message.body.blob_kzg_commitments,
        }
    }

    /// The signed block's SSZ encoding, which does not record the fork.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Bellatrix(signed) => signed.encode(),
            Self::Capella(signed) => signed.encode(),
            Self::Deneb(signed) => signed.encode(),
            Self::Electra(signed) | Self::Fulu(signed) => signed.encode(),
        }
    }

    /// Decodes a signed blinded block of a known fork.
    ///
    /// # Errors
    ///
    /// Fails when the fork has no blinded block, or the bytes do not encode one of that fork.
    pub fn decode(bytes: &[u8], fork: ForkName) -> Result<Self, BlindedBlockError> {
        Ok(match fork {
            ForkName::Phase0 | ForkName::Altair | ForkName::Gloas => {
                return Err(BlindedBlockError::NoBlindedBlock { fork });
            }
            ForkName::Bellatrix => Self::Bellatrix(Ssz::decode(bytes)?),
            ForkName::Capella => Self::Capella(Ssz::decode(bytes)?),
            ForkName::Deneb => Self::Deneb(Ssz::decode(bytes)?),
            ForkName::Electra => Self::Electra(Ssz::decode(bytes)?),
            ForkName::Fulu => Self::Fulu(Ssz::decode(bytes)?),
        })
    }

    /// The signed full block, with the payload the header commits to.
    ///
    /// Both blocks share one root, so the signature carries over unchanged.
    ///
    /// # Errors
    ///
    /// Fails when the payload belongs to another fork, or its root differs from the header's.
    pub fn unblind(
        self,
        execution_payload: ExecutionPayload<P>,
    ) -> Result<SignedBeaconBlock<P>, BlindedBlockError> {
        Ok(match (self, execution_payload) {
            (Self::Bellatrix(signed), ExecutionPayload::Bellatrix(payload)) => {
                SignedBeaconBlock::Bellatrix(signed.unblind(payload)?)
            }
            (Self::Capella(signed), ExecutionPayload::Capella(payload)) => {
                SignedBeaconBlock::Capella(signed.unblind(payload)?)
            }
            (Self::Deneb(signed), ExecutionPayload::Deneb(payload)) => {
                SignedBeaconBlock::Deneb(signed.unblind(payload)?)
            }
            (Self::Electra(signed), ExecutionPayload::Electra(payload)) => {
                SignedBeaconBlock::Electra(signed.unblind(payload)?)
            }
            (Self::Fulu(signed), ExecutionPayload::Fulu(payload)) => {
                SignedBeaconBlock::Fulu(signed.unblind(payload)?)
            }
            (signed, payload) => {
                return Err(BlindedBlockError::ForkMismatch {
                    block: signed.fork_name(),
                    payload: payload.fork_name(),
                });
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Hash32, Minimal};

    #[test]
    fn signed_blinded_block_round_trips_through_its_fork() {
        // Fixture state: an Electra blinded block at slot 12, signed with bytes 0x0404...04.
        let block = electra::BlindedBeaconBlock::<Minimal> {
            slot: Slot(12),
            ..electra::BlindedBeaconBlock::default()
        };
        let signed = SignedBlindedBeaconBlock::from_parts(
            BlindedBeaconBlock::Electra(block.clone()),
            BlsSignature([4; 96]),
        );

        let decoded =
            SignedBlindedBeaconBlock::<Minimal>::decode(&signed.encode(), ForkName::Electra)
                .unwrap();

        assert_eq!(decoded, signed);
        assert_eq!(decoded.block_root(), block.hash_tree_root());
    }

    #[test]
    fn unblinding_dispatches_to_the_block_fork() {
        // Fixture state: a Bellatrix block whose payload has block hash 0x0101...01.
        let mut block = bellatrix::BeaconBlock::<Minimal>::default();
        block.body.execution_payload.block_hash = Hash32([1; 32]);
        let payload = block.body.execution_payload.clone();
        let signed = SignedBlindedBeaconBlock::Bellatrix(bellatrix::SignedBlindedBeaconBlock {
            message: block.clone().into(),
            signature: BlsSignature([2; 96]),
        });

        assert_eq!(
            signed.unblind(ExecutionPayload::Bellatrix(payload)),
            Ok(SignedBeaconBlock::Bellatrix(bellatrix::SignedBeaconBlock {
                message: block,
                signature: BlsSignature([2; 96]),
            }))
        );
    }

    #[test]
    fn unblinding_refuses_a_payload_of_another_fork() {
        // Fixture state: an Electra blinded block offered a Fulu payload.
        // Both forks share one payload type, so only the variant tells them apart.
        let signed = SignedBlindedBeaconBlock::<Minimal>::Electra(
            electra::SignedBlindedBeaconBlock::default(),
        );

        assert_eq!(
            signed.unblind(ExecutionPayload::Fulu(fulu::ExecutionPayload::default())),
            Err(BlindedBlockError::ForkMismatch {
                block: ForkName::Electra,
                payload: ForkName::Fulu,
            })
        );
    }
}
