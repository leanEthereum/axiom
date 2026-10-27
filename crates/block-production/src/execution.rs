//! The execution side of a proposal: which payload the block commits to, and its value.

use axiom_ssz::U256;
use axiom_types::{
    ForkName, Preset, bellatrix, capella, combined, deneb, electra, fulu,
    gloas::{self, SignedExecutionPayloadBid},
    hstar,
};

use crate::ProductionError;

/// A payload the node's own execution engine built, with what the engine returned beside it.
///
/// Each fork's engine returns its own payload version and its own extras.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalPayload<P: Preset> {
    /// A Bellatrix payload.
    Bellatrix(bellatrix::ExecutionPayload<P>),
    /// A Capella payload, with withdrawals.
    Capella(capella::ExecutionPayload<P>),
    /// A Deneb payload and its blobs.
    Deneb {
        /// The payload.
        payload: deneb::ExecutionPayload<P>,
        /// Its blobs, commitments, and proofs.
        blobs: deneb::BlobsBundle<P>,
    },
    /// An Electra payload, its blobs, and its requests.
    Electra {
        /// The payload.
        payload: electra::ExecutionPayload<P>,
        /// Its blobs, commitments, and proofs.
        blobs: electra::BlobsBundle<P>,
        /// Its deposit, withdrawal, and consolidation requests.
        requests: electra::ExecutionRequests<P>,
    },
    /// A Fulu payload, its blobs with cell proofs, and its requests.
    Fulu {
        /// The payload.
        payload: fulu::ExecutionPayload<P>,
        /// Its blobs, commitments, and cell proofs.
        blobs: fulu::BlobsBundle<P>,
        /// Its requests.
        requests: fulu::ExecutionRequests<P>,
    },
    /// A Gloas payload, revealed in an envelope after the block.
    Gloas {
        /// The payload.
        payload: gloas::ExecutionPayload<P>,
        /// Its blobs, commitments, and cell proofs.
        blobs: fulu::BlobsBundle<P>,
        /// Its requests, including builder requests.
        requests: gloas::ExecutionRequests,
    },
    /// An Hstar payload, revealed in an envelope after the block.
    Hstar {
        /// The payload.
        payload: gloas::ExecutionPayload<P>,
        /// Its blobs, commitments, and cell proofs.
        blobs: fulu::BlobsBundle<P>,
        /// Its requests, including key authorizations.
        requests: hstar::ExecutionRequests,
    },
}

/// A locally built payload and what it pays the fee recipient, in wei.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalBuild<P: Preset> {
    /// The payload and its extras.
    pub payload: LocalPayload<P>,
    /// The engine's estimate of the payload's value to the proposer.
    pub value: U256,
}

/// Whether a block from Gloas on builds on its parent's payload or on the parent alone.
///
/// See `should_build_on_full` in the Gloas fork choice spec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParentPayload {
    /// The parent's payload is canonical; the block reports its requests.
    Full(RevealedRequests),
    /// The parent's payload is missing or not canonical.
    Empty,
}

/// The execution requests a revealed payload carried, in its envelope's container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevealedRequests {
    /// Requests of a Gloas payload.
    Gloas(gloas::ExecutionRequests),
    /// Requests of an Hstar payload, which may include key authorizations.
    Hstar(hstar::ExecutionRequests),
}

impl<P: Preset> From<&combined::SignedExecutionPayloadEnvelope<P>> for RevealedRequests {
    fn from(envelope: &combined::SignedExecutionPayloadEnvelope<P>) -> Self {
        match envelope {
            combined::SignedExecutionPayloadEnvelope::Gloas(signed) => {
                Self::Gloas(signed.message.execution_requests.clone())
            }
            combined::SignedExecutionPayloadEnvelope::Hstar(signed) => {
                Self::Hstar(signed.message.execution_requests.clone())
            }
        }
    }
}

/// Who builds a Gloas block's payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GloasBid<P: Preset> {
    /// The proposer, from its own engine.
    SelfBuild(Box<LocalBuild<P>>),
    /// A builder, whose signed bid the block commits to.
    Builder(Box<SignedExecutionPayloadBid>),
}

/// The execution side of a proposal, as the slot's fork takes it.
///
/// # Overview
///
/// Up to Fulu the payload sits in the block, local or from a builder's header.
/// Gloas moves it out: the block commits to a bid, and the payload follows in an envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionChoice<P: Preset> {
    /// No payload: the fork predates the merge, or the merge has not happened.
    PreMerge,
    /// A payload built by the node's own engine.
    Local(LocalBuild<P>),
    /// A builder's bid, whose payload the builder reveals once the block is signed.
    Builder(combined::SignedBuilderBid<P>),
    /// A Gloas bid, and the parent payload it builds on.
    Gloas {
        /// The parent's payload, or its absence.
        parent: ParentPayload,
        /// Who builds the payload.
        bid: GloasBid<P>,
    },
}

impl<P: Preset> ExecutionChoice<P> {
    /// A short name for errors.
    #[must_use]
    pub const fn describe(&self) -> &'static str {
        match self {
            Self::PreMerge => "no payload",
            Self::Local(_) => "a local payload",
            Self::Builder(_) => "a builder header",
            Self::Gloas { .. } => "a Gloas bid",
        }
    }

    /// The error for a fork that cannot take this input.
    #[must_use]
    pub const fn mismatch(&self, fork: ForkName) -> ProductionError {
        ProductionError::ExecutionMismatch {
            fork,
            execution: self.describe(),
        }
    }

    /// What the payload pays the proposer, in wei.
    #[must_use]
    pub fn value(&self) -> U256 {
        match self {
            Self::PreMerge => U256::default(),
            Self::Local(build) => build.value,
            Self::Gloas {
                bid: GloasBid::SelfBuild(build),
                ..
            } => build.value,
            Self::Builder(bid) => bid.value(),
            Self::Gloas {
                bid: GloasBid::Builder(bid),
                ..
            } => Wei::from_gwei(bid.message.value.0 + bid.message.execution_payment.0),
        }
    }
}

/// How strongly the proposer prefers a builder's payload over its own.
///
/// A percentage applied to the builder's value: 0 always picks local, 100 picks the richer.
/// The maximum always picks the builder.
/// See the `builder_boost_factor` parameter of the block production route in beacon-APIs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuilderBoost(pub u64);

impl BuilderBoost {
    /// Profit maximisation: whichever payload pays more.
    pub const NEUTRAL: Self = Self(100);

    /// Whether the builder's payload wins over the local one.
    ///
    /// The local payload wins when local >= boost * (builder / 100), so it wins ties.
    /// The product saturates, so a huge boost cannot overflow.
    #[must_use]
    pub fn prefers_builder(self, local: U256, builder: U256) -> bool {
        let weighted = (Wei::saturating(builder) / 100).saturating_mul(u128::from(self.0));
        Wei::saturating(local) < weighted
    }
}

/// Conversions of wei amounts.
#[derive(Clone, Copy, Debug)]
pub struct Wei;

impl Wei {
    /// Wei per Gwei.
    const PER_GWEI: u128 = 1_000_000_000;

    /// An amount as a 128-bit integer, saturating past it.
    ///
    /// No real payload pays near 2^128 wei, about 3.4e20 ether.
    #[must_use]
    pub fn saturating(value: U256) -> u128 {
        let bytes = value.to_le_bytes();
        let (low, high) = bytes.split_at(16);
        if high.iter().any(|byte| *byte != 0) {
            return u128::MAX;
        }
        let mut low_bytes = [0; 16];
        low_bytes.copy_from_slice(low);
        u128::from_le_bytes(low_bytes)
    }

    /// A Gwei amount in wei.
    #[must_use]
    pub const fn from_gwei(gwei: u64) -> U256 {
        U256::from_u128(gwei as u128 * Self::PER_GWEI)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_boost_weighs_the_builder_and_local_wins_ties() {
        // Amounts in tenths of an ether.
        let ether = |tenths: u128| U256::from_u128(tenths * 100_000_000_000_000_000);
        // Neutral: 2 ether from the builder beats 1.9 locally; 2 against 2 stays local.
        assert!(BuilderBoost::NEUTRAL.prefers_builder(ether(19), ether(20)));
        assert!(!BuilderBoost::NEUTRAL.prefers_builder(ether(20), ether(20)));
        // Zero: local always, even when it pays nothing.
        assert!(!BuilderBoost(0).prefers_builder(U256::default(), ether(1000)));
        // The maximum: the builder always, even against a richer local payload.
        assert!(BuilderBoost(u64::MAX).prefers_builder(ether(1000), ether(10)));
        // 50: the builder must pay more than twice as much.
        assert!(!BuilderBoost(50).prefers_builder(ether(10), ether(20)));
        assert!(BuilderBoost(50).prefers_builder(ether(10), ether(30)));
    }
}
