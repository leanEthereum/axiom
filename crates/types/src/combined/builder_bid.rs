//! A signed builder bid of any fork whose builder API sells payloads.

use axiom_ssz::{DecodeError, Root, Ssz, U256};

use crate::{
    BlsPubkey, BlsSignature, ChainConfig, ForkName, Hash32, KzgCommitment, Preset, bellatrix,
    capella, deneb, electra, fulu, phase0::SigningData,
};

/// A signed builder bid of whichever fork it belongs to.
///
/// Fulu kept Electra's bid, so those two variants hold the same type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignedBuilderBid<P: Preset> {
    /// A signed Bellatrix bid.
    Bellatrix(bellatrix::SignedBuilderBid<P>),
    /// A signed Capella bid.
    Capella(capella::SignedBuilderBid<P>),
    /// A signed Deneb bid.
    Deneb(deneb::SignedBuilderBid<P>),
    /// A signed Electra bid.
    Electra(electra::SignedBuilderBid<P>),
    /// A signed Fulu bid, the same type as a signed Electra bid.
    Fulu(fulu::SignedBuilderBid<P>),
}

impl<P: Preset> SignedBuilderBid<P> {
    /// Decodes a signed bid of a known fork from its SSZ encoding, which does not record the fork.
    ///
    /// # Returns
    ///
    /// The bid, or nothing when the fork has no builder bid.
    ///
    /// # Errors
    ///
    /// Fails when the bytes do not encode a bid of the fork.
    pub fn decode(bytes: &[u8], fork: ForkName) -> Result<Option<Self>, DecodeError> {
        Ok(Some(match fork {
            ForkName::Phase0 | ForkName::Altair | ForkName::Gloas | ForkName::Hstar => {
                return Ok(None);
            }
            ForkName::Bellatrix => Self::Bellatrix(Ssz::decode(bytes)?),
            ForkName::Capella => Self::Capella(Ssz::decode(bytes)?),
            ForkName::Deneb => Self::Deneb(Ssz::decode(bytes)?),
            ForkName::Electra => Self::Electra(Ssz::decode(bytes)?),
            ForkName::Fulu => Self::Fulu(Ssz::decode(bytes)?),
        }))
    }

    /// The bid's SSZ encoding, which does not record the fork.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Bellatrix(signed) => signed.encode(),
            Self::Capella(signed) => signed.encode(),
            Self::Deneb(signed) => signed.encode(),
            Self::Electra(signed) | Self::Fulu(signed) => signed.encode(),
        }
    }
    /// The fork the bid belongs to.
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

    /// Wei the proposer's fee recipient receives.
    #[must_use]
    pub const fn value(&self) -> U256 {
        match self {
            Self::Bellatrix(signed) => signed.message.value,
            Self::Capella(signed) => signed.message.value,
            Self::Deneb(signed) => signed.message.value,
            Self::Electra(signed) | Self::Fulu(signed) => signed.message.value,
        }
    }

    /// The bidding builder, whose key must verify the signature.
    #[must_use]
    pub const fn pubkey(&self) -> &BlsPubkey {
        match self {
            Self::Bellatrix(signed) => &signed.message.pubkey,
            Self::Capella(signed) => &signed.message.pubkey,
            Self::Deneb(signed) => &signed.message.pubkey,
            Self::Electra(signed) | Self::Fulu(signed) => &signed.message.pubkey,
        }
    }

    /// The builder's signature.
    #[must_use]
    pub const fn signature(&self) -> &BlsSignature {
        match self {
            Self::Bellatrix(signed) => &signed.signature,
            Self::Capella(signed) => &signed.signature,
            Self::Deneb(signed) => &signed.signature,
            Self::Electra(signed) | Self::Fulu(signed) => &signed.signature,
        }
    }

    /// The execution block the offered payload builds on.
    #[must_use]
    pub const fn parent_hash(&self) -> Hash32 {
        match self {
            Self::Bellatrix(signed) => signed.message.header.parent_hash,
            Self::Capella(signed) => signed.message.header.parent_hash,
            Self::Deneb(signed) => signed.message.header.parent_hash,
            Self::Electra(signed) | Self::Fulu(signed) => signed.message.header.parent_hash,
        }
    }

    /// The execution block the offered payload is.
    #[must_use]
    pub const fn block_hash(&self) -> Hash32 {
        match self {
            Self::Bellatrix(signed) => signed.message.header.block_hash,
            Self::Capella(signed) => signed.message.header.block_hash,
            Self::Deneb(signed) => signed.message.header.block_hash,
            Self::Electra(signed) | Self::Fulu(signed) => signed.message.header.block_hash,
        }
    }

    /// Commitments to the blobs the offered payload carries, from Deneb on.
    #[must_use]
    pub fn blob_kzg_commitments(&self) -> &[KzgCommitment] {
        match self {
            Self::Bellatrix(_) | Self::Capella(_) => &[],
            Self::Deneb(signed) => &signed.message.blob_kzg_commitments,
            Self::Electra(signed) | Self::Fulu(signed) => &signed.message.blob_kzg_commitments,
        }
    }

    /// The root the builder signs: the bid's root in the application builder domain.
    ///
    /// See the signing section of the Bellatrix builder spec.
    #[must_use]
    pub fn signing_root(&self, config: &ChainConfig) -> Root {
        let domain = config.application_builder_domain();
        match self {
            Self::Bellatrix(signed) => SigningData::signing_root(&signed.message, domain),
            Self::Capella(signed) => SigningData::signing_root(&signed.message, domain),
            Self::Deneb(signed) => SigningData::signing_root(&signed.message, domain),
            Self::Electra(signed) | Self::Fulu(signed) => {
                SigningData::signing_root(&signed.message, domain)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Domain, Minimal, Version, constants::DOMAIN_APPLICATION_BUILDER};

    #[test]
    fn accessors_read_the_bid_of_any_fork() {
        // Fixture state: a Deneb bid of 21 wei on parent 0x0101...01 for block 0x0202...02.
        // It commits to one blob.
        let mut bid = deneb::SignedBuilderBid::<Minimal>::default();
        bid.message.header.parent_hash = Hash32([1; 32]);
        bid.message.header.block_hash = Hash32([2; 32]);
        bid.message
            .blob_kzg_commitments
            .push(KzgCommitment([3; 48]))
            .unwrap();
        bid.message.value = U256::from(21);
        bid.message.pubkey = BlsPubkey([4; 48]);
        let bid = SignedBuilderBid::Deneb(bid);

        assert_eq!(bid.fork_name(), ForkName::Deneb);
        assert_eq!(bid.value(), U256::from(21));
        assert_eq!(bid.pubkey(), &BlsPubkey([4; 48]));
        assert_eq!(bid.parent_hash(), Hash32([1; 32]));
        assert_eq!(bid.block_hash(), Hash32([2; 32]));
        assert_eq!(bid.blob_kzg_commitments(), &[KzgCommitment([3; 48])]);
    }

    #[test]
    fn the_signing_root_uses_the_genesis_version_and_a_zero_chain_root() {
        // Fixture state: the minimal config, whose genesis version is 0x00000001.
        // The bid offers 5 wei.
        let config = ChainConfig::minimal();
        let mut capella_bid = capella::SignedBuilderBid::<Minimal>::default();
        capella_bid.message.value = U256::from(5);

        // Domain type 0x00000001, fork version 0x00000001, and no genesis validators root.
        // The domain ignores the fork schedule, so one signature serves every fork.
        let domain = Domain::compute(
            DOMAIN_APPLICATION_BUILDER,
            Version([0, 0, 0, 1]),
            Root::ZERO,
        );
        let expected = SigningData::signing_root(&capella_bid.message, domain);

        assert_eq!(
            SignedBuilderBid::Capella(capella_bid).signing_root(&config),
            expected
        );
    }
}
