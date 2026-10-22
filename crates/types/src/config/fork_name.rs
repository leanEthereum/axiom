//! Names of the beacon chain forks.

use std::fmt;

use super::BlobData;
use crate::{Gwei, Preset};

/// A beacon chain fork, in activation order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ForkName {
    /// The launch of the beacon chain.
    Phase0,
    /// Sync committees and participation flags.
    Altair,
    /// The merge with the execution layer.
    Bellatrix,
    /// Withdrawals.
    Capella,
    /// Blobs, see EIP-4844.
    Deneb,
    /// Larger validators and execution requests, see EIP-7251 and EIP-7685.
    Electra,
    /// Peer data availability sampling, see EIP-7594.
    Fulu,
    /// Enshrined proposer-builder separation, see EIP-7732.
    Gloas,
}

impl ForkName {
    /// Every fork, in activation order.
    pub const ALL: [Self; 8] = [
        Self::Phase0,
        Self::Altair,
        Self::Bellatrix,
        Self::Capella,
        Self::Deneb,
        Self::Electra,
        Self::Fulu,
        Self::Gloas,
    ];

    /// The fork's name in lowercase, as the spec's test vectors spell it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Phase0 => "phase0",
            Self::Altair => "altair",
            Self::Bellatrix => "bellatrix",
            Self::Capella => "capella",
            Self::Deneb => "deneb",
            Self::Electra => "electra",
            Self::Fulu => "fulu",
            Self::Gloas => "gloas",
        }
    }

    /// The fork with the given lowercase name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|fork| fork.as_str() == name)
    }

    /// The fork right before this one.
    #[must_use]
    pub const fn previous(self) -> Option<Self> {
        match self {
            Self::Phase0 => None,
            Self::Altair => Some(Self::Phase0),
            Self::Bellatrix => Some(Self::Altair),
            Self::Capella => Some(Self::Bellatrix),
            Self::Deneb => Some(Self::Capella),
            Self::Electra => Some(Self::Deneb),
            Self::Fulu => Some(Self::Electra),
            Self::Gloas => Some(Self::Fulu),
        }
    }

    /// The fork right after this one.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::Phase0 => Some(Self::Altair),
            Self::Altair => Some(Self::Bellatrix),
            Self::Bellatrix => Some(Self::Capella),
            Self::Capella => Some(Self::Deneb),
            Self::Deneb => Some(Self::Electra),
            Self::Electra => Some(Self::Fulu),
            Self::Fulu => Some(Self::Gloas),
            Self::Gloas => None,
        }
    }

    /// Divides a balance into its per-epoch inactivity penalty, scaled by the inactivity score.
    ///
    /// Altair and then Bellatrix lowered it, so a leak drains non-participants faster.
    /// See the presets of the phase0, Altair, and Bellatrix specs.
    #[must_use]
    pub const fn inactivity_penalty_quotient<P: Preset>(self) -> u64 {
        match self {
            Self::Phase0 => P::INACTIVITY_PENALTY_QUOTIENT,
            Self::Altair => P::INACTIVITY_PENALTY_QUOTIENT_ALTAIR,
            Self::Bellatrix
            | Self::Capella
            | Self::Deneb
            | Self::Electra
            | Self::Fulu
            | Self::Gloas => P::INACTIVITY_PENALTY_QUOTIENT_BELLATRIX,
        }
    }

    /// Divides a slashed validator's effective balance into its initial penalty.
    ///
    /// Altair and Bellatrix raised the penalty in steps, and Electra cut it for large stakes.
    /// See the presets of the phase0, Altair, Bellatrix, and Electra specs.
    #[must_use]
    pub const fn min_slashing_penalty_quotient<P: Preset>(self) -> u64 {
        match self {
            Self::Phase0 => P::MIN_SLASHING_PENALTY_QUOTIENT,
            Self::Altair => P::MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR,
            Self::Bellatrix | Self::Capella | Self::Deneb => {
                P::MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX
            }
            Self::Electra | Self::Fulu | Self::Gloas => P::MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA,
        }
    }

    /// Multiplies the slashed balance of the window into the correlation penalty.
    ///
    /// Bellatrix set it so that slashing a third of the stake burns all of it.
    /// See the presets of the phase0, Altair, and Bellatrix specs.
    #[must_use]
    pub const fn proportional_slashing_multiplier<P: Preset>(self) -> u64 {
        match self {
            Self::Phase0 => P::PROPORTIONAL_SLASHING_MULTIPLIER,
            Self::Altair => P::PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR,
            Self::Bellatrix
            | Self::Capella
            | Self::Deneb
            | Self::Electra
            | Self::Fulu
            | Self::Gloas => P::PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX,
        }
    }

    /// Divides a slashed validator's effective balance into the whistleblower reward.
    ///
    /// Electra raised it with the effective balance cap, keeping the reward bounded.
    /// See the presets of the phase0 and Electra specs.
    #[must_use]
    pub const fn whistleblower_reward_quotient<P: Preset>(self) -> u64 {
        match self {
            Self::Phase0 | Self::Altair | Self::Bellatrix | Self::Capella | Self::Deneb => {
                P::WHISTLEBLOWER_REWARD_QUOTIENT
            }
            Self::Electra | Self::Fulu | Self::Gloas => P::WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA,
        }
    }

    /// Most attestations a block carries.
    ///
    /// Electra let one attestation span every committee of a slot, so far fewer fit.
    /// See the presets of the phase0 and Electra specs.
    #[must_use]
    pub const fn max_attestations<P: Preset>(self) -> u64 {
        match self {
            Self::Phase0 | Self::Altair | Self::Bellatrix | Self::Capella | Self::Deneb => {
                P::MAX_ATTESTATIONS
            }
            Self::Electra | Self::Fulu | Self::Gloas => P::MAX_ATTESTATIONS_ELECTRA,
        }
    }

    /// Most attester slashings a block carries.
    ///
    /// Electra's slashings carry far larger index lists, so fewer fit.
    /// See the presets of the phase0 and Electra specs.
    #[must_use]
    pub const fn max_attester_slashings<P: Preset>(self) -> u64 {
        match self {
            Self::Phase0 | Self::Altair | Self::Bellatrix | Self::Capella | Self::Deneb => {
                P::MAX_ATTESTER_SLASHINGS
            }
            Self::Electra | Self::Fulu | Self::Gloas => P::MAX_ATTESTER_SLASHINGS_ELECTRA,
        }
    }

    /// Bytes of hash output that one balance-weighted draw consumes.
    ///
    /// Electra widened draws from one byte to two, so large stakes are sampled more finely.
    /// See `compute_proposer_index` in the phase0 and Electra beacon chain specs.
    #[must_use]
    pub const fn random_value_bytes(self) -> usize {
        match self {
            Self::Phase0 | Self::Altair | Self::Bellatrix | Self::Capella | Self::Deneb => 1,
            Self::Electra | Self::Fulu | Self::Gloas => 2,
        }
    }

    /// Effective balance a candidate needs to pass every balance-weighted draw.
    ///
    /// Sampling weighs candidates against the largest effective balance a validator may hold.
    /// Electra raised that cap for compounding validators, see EIP-7251.
    #[must_use]
    pub const fn max_sampling_balance<P: Preset>(self) -> Gwei {
        match self {
            Self::Phase0 | Self::Altair | Self::Bellatrix | Self::Capella | Self::Deneb => {
                P::MAX_EFFECTIVE_BALANCE
            }
            Self::Electra | Self::Fulu | Self::Gloas => P::MAX_EFFECTIVE_BALANCE_ELECTRA,
        }
    }

    /// Whether a gossip message identifier on the fork's topics hashes the topic too.
    ///
    /// Altair added the topic, so one payload on two forks' topics gets two identifiers.
    /// See "Topics and messages" in the phase0 and Altair p2p specs.
    #[must_use]
    pub const fn message_id_hashes_topic(self) -> bool {
        match self {
            Self::Phase0 => false,
            Self::Altair
            | Self::Bellatrix
            | Self::Capella
            | Self::Deneb
            | Self::Electra
            | Self::Fulu
            | Self::Gloas => true,
        }
    }

    /// The form the fork's blob data travels in.
    #[must_use]
    pub const fn blob_data(self) -> BlobData {
        match self {
            Self::Phase0 | Self::Altair | Self::Bellatrix | Self::Capella => BlobData::None,
            Self::Deneb | Self::Electra => BlobData::BlobSidecars,
            Self::Fulu => BlobData::BlockColumns,
            Self::Gloas => BlobData::PayloadColumns,
        }
    }

    /// Whether fork choice weighs a block's payload apart from the block itself.
    ///
    /// Gloas blocks commit to a builder's bid, and the payload follows in an envelope.
    /// Fork choice then decides between each block's full and empty variants, see EIP-7732.
    #[must_use]
    pub const fn separates_payloads(self) -> bool {
        match self {
            Self::Phase0
            | Self::Altair
            | Self::Bellatrix
            | Self::Capella
            | Self::Deneb
            | Self::Electra
            | Self::Fulu => false,
            Self::Gloas => true,
        }
    }

    /// Whether an attestation's data names its committee, as before Electra.
    ///
    /// Electra moves the committee out of the data, so one vote spans committees, see EIP-7549.
    /// Gloas reuses the freed index to signal the payload.
    #[must_use]
    pub const fn names_committee_in_vote(self) -> bool {
        match self {
            Self::Phase0 | Self::Altair | Self::Bellatrix | Self::Capella | Self::Deneb => true,
            Self::Electra | Self::Fulu | Self::Gloas => false,
        }
    }

    /// Whether the off-protocol builder API sells the fork's payloads as blinded headers.
    ///
    /// The API starts with the merge and ends where Gloas brings builders into the protocol.
    /// See the builder specs, and EIP-7732 for the in-protocol replacement.
    #[must_use]
    pub const fn has_builder_api(self) -> bool {
        match self {
            Self::Bellatrix | Self::Capella | Self::Deneb | Self::Electra | Self::Fulu => true,
            Self::Phase0 | Self::Altair | Self::Gloas => false,
        }
    }

    /// Whether fork choice checks a merge block against the terminal proof-of-work block.
    ///
    /// Only Bellatrix checks it: Capella drops the check, since the merge is long done.
    /// See `validate_merge_block` in the Bellatrix fork choice spec.
    #[must_use]
    pub const fn validates_merge_block(self) -> bool {
        match self {
            Self::Bellatrix => true,
            Self::Phase0
            | Self::Altair
            | Self::Capella
            | Self::Deneb
            | Self::Electra
            | Self::Fulu
            | Self::Gloas => false,
        }
    }

    /// Whether the state fixes each epoch's proposers one epoch ahead.
    ///
    /// A reorg at an epoch boundary then cannot change who proposes, see EIP-7917.
    /// Fork choice allows late block reorgs at boundaries from then on.
    #[must_use]
    pub const fn fixes_proposers_ahead(self) -> bool {
        match self {
            Self::Phase0
            | Self::Altair
            | Self::Bellatrix
            | Self::Capella
            | Self::Deneb
            | Self::Electra => false,
            Self::Fulu | Self::Gloas => true,
        }
    }
}

impl fmt::Display for ForkName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Mainnet, Minimal};

    #[test]
    fn next_undoes_previous() {
        // Each fork but the last has a successor whose predecessor is that fork.
        for pair in ForkName::ALL.windows(2) {
            assert_eq!(pair[0].next(), Some(pair[1]));
            assert_eq!(pair[1].previous(), Some(pair[0]));
        }
        assert_eq!(ForkName::Gloas.next(), None);
    }

    #[test]
    fn penalty_tables_follow_the_mainnet_presets() {
        // Inactivity quotients: 2^26 in phase0, 3 * 2^24 in Altair, 2^24 from Bellatrix on.
        let inactivity: Vec<u64> = ForkName::ALL
            .map(ForkName::inactivity_penalty_quotient::<Mainnet>)
            .to_vec();
        assert_eq!(
            inactivity,
            [
                67_108_864, 50_331_648, 16_777_216, 16_777_216, 16_777_216, 16_777_216, 16_777_216,
                16_777_216
            ]
        );

        // Initial slashing quotients: 128, 64, 32 through Deneb, then 4096 from Electra on.
        let slashing: Vec<u64> = ForkName::ALL
            .map(ForkName::min_slashing_penalty_quotient::<Mainnet>)
            .to_vec();
        assert_eq!(slashing, [128, 64, 32, 32, 32, 4096, 4096, 4096]);

        // Correlation multipliers: 1, 2, then 3 from Bellatrix on.
        let multiplier: Vec<u64> = ForkName::ALL
            .map(ForkName::proportional_slashing_multiplier::<Mainnet>)
            .to_vec();
        assert_eq!(multiplier, [1, 2, 3, 3, 3, 3, 3, 3]);

        // Whistleblower quotients: 512 through Deneb, then 4096 from Electra on.
        let whistleblower: Vec<u64> = ForkName::ALL
            .map(ForkName::whistleblower_reward_quotient::<Mainnet>)
            .to_vec();
        assert_eq!(whistleblower, [512, 512, 512, 512, 512, 4096, 4096, 4096]);
    }

    #[test]
    fn sampling_widens_at_electra() {
        // One-byte draws against 32 ETH through Deneb, then two-byte draws against 2048 ETH.
        let bytes: Vec<usize> = ForkName::ALL.map(ForkName::random_value_bytes).to_vec();
        assert_eq!(bytes, [1, 1, 1, 1, 1, 2, 2, 2]);

        let ceilings: Vec<u64> = ForkName::ALL
            .map(|fork| fork.max_sampling_balance::<Mainnet>().0)
            .to_vec();
        assert_eq!(
            ceilings,
            [
                32_000_000_000,
                32_000_000_000,
                32_000_000_000,
                32_000_000_000,
                32_000_000_000,
                2_048_000_000_000,
                2_048_000_000_000,
                2_048_000_000_000
            ]
        );
    }

    #[test]
    fn operation_limits_shrink_at_electra() {
        // 128 attestations and 2 slashings per block through Deneb, then 8 and 1.
        let attestations: Vec<u64> = ForkName::ALL
            .map(ForkName::max_attestations::<Minimal>)
            .to_vec();
        assert_eq!(attestations, [128, 128, 128, 128, 128, 8, 8, 8]);

        let slashings: Vec<u64> = ForkName::ALL
            .map(ForkName::max_attester_slashings::<Minimal>)
            .to_vec();
        assert_eq!(slashings, [2, 2, 2, 2, 2, 1, 1, 1]);
    }

    #[test]
    fn the_builder_api_spans_the_merge_to_fulu() {
        // Bellatrix to Fulu sell payloads off-protocol; Gloas bids in the protocol.
        let builder_api: Vec<bool> = ForkName::ALL.map(ForkName::has_builder_api).to_vec();
        // Votes name their committee in the data until Electra.
        let named: Vec<bool> = ForkName::ALL
            .map(ForkName::names_committee_in_vote)
            .to_vec();
        assert_eq!(named, [true, true, true, true, true, false, false, false]);
        assert_eq!(
            builder_api,
            [false, false, true, true, true, true, true, false]
        );
    }
}
