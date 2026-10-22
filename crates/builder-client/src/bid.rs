//! Bid verification: a relay's bid reaches block production only once it is checked.

use axiom_bls::{PublicKey, Signature};
use axiom_ssz::{Root, U256};
use axiom_types::{
    BlsPubkey, Bytes32, ChainConfig, ForkName, Hash32, Preset, Slot, combined::SignedBuilderBid,
};
use thiserror::Error;

use crate::GasLimitTarget;

/// What a proposer asks relays for, and the payload terms it accepts.
///
/// # Overview
///
/// The node fills this from the same state its local payload request uses.
/// A bid whose header disagrees with any term would make the block invalid.
/// Refusing it before signing keeps the local payload as the fallback.
///
/// The proposer must never sign two blocks for one slot.
/// So every check that can fail runs here, before the blinded block is signed.
/// See the proposer slashing section of the Bellatrix builder validator spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BidRequest {
    /// Fork of the proposal slot.
    pub fork: ForkName,

    /// The proposal slot.
    pub slot: Slot,

    /// Block hash of the execution payload the new one builds on.
    pub parent_hash: Hash32,

    /// The proposer's public key.
    pub proposer: BlsPubkey,

    /// Timestamp the payload must carry: the slot's start time.
    pub timestamp: u64,

    /// Randomness the payload must carry: the state's current randao mix.
    pub prev_randao: Bytes32,

    /// Parent gas limit and the proposer's registered target.
    pub gas_limit: GasLimitTarget,

    /// Root of the withdrawals due in the slot, from Capella on, and none before.
    pub withdrawals_root: Option<Root>,
}

/// A bid that passed every check against its request.
///
/// Only verification makes one, so holding one proves the checks ran.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBid<P: Preset> {
    /// The checked bid.
    bid: SignedBuilderBid<P>,
}

/// A bid refused by verification.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum BidError {
    /// The bid belongs to another fork than the slot's.
    #[error("bid is for the {actual} fork, the slot is in {expected}")]
    Fork {
        /// The slot's fork.
        expected: ForkName,
        /// The bid's fork.
        actual: ForkName,
    },

    /// The payload builds on another parent than the requested one.
    #[error("bid builds on parent {actual}, requested {expected}")]
    ParentHash {
        /// The requested parent.
        expected: Hash32,
        /// The header's parent.
        actual: Hash32,
    },

    /// The bid comes from another builder key than the one configured for the relay.
    #[error("bid is signed for builder {actual}, the relay is configured as {expected}")]
    Builder {
        /// The relay's configured key.
        expected: BlsPubkey,
        /// The key the bid names.
        actual: BlsPubkey,
    },

    /// The bid pays nothing.
    #[error("bid pays zero wei")]
    ZeroValue,

    /// The header's timestamp is not the slot's start.
    #[error("bid timestamp {actual}, the slot starts at {expected}")]
    Timestamp {
        /// The slot's start time.
        expected: u64,
        /// The header's timestamp.
        actual: u64,
    },

    /// The header's randomness is not the state's randao mix.
    #[error("bid prev_randao {actual}, the state's mix is {expected}")]
    PrevRandao {
        /// The state's mix.
        expected: Bytes32,
        /// The header's value.
        actual: Bytes32,
    },

    /// The header's gas limit is not the one an honest builder sets.
    #[error("bid gas limit {actual}, expected {expected}")]
    GasLimit {
        /// The reachable limit closest to the target.
        expected: u64,
        /// The header's limit.
        actual: u64,
    },

    /// The header commits to other withdrawals than those due.
    #[error("bid withdrawals root {actual:?}, expected {expected:?}")]
    WithdrawalsRoot {
        /// Root of the withdrawals due, none before Capella.
        expected: Option<Root>,
        /// The header's root, none before Capella.
        actual: Option<Root>,
    },

    /// The builder key is not a valid public key.
    #[error("builder key {pubkey} is not a valid public key")]
    InvalidPubkey {
        /// The key the bid names.
        pubkey: BlsPubkey,
    },

    /// The signature bytes are not a valid signature.
    #[error("bid signature of builder {pubkey} does not decode")]
    InvalidSignature {
        /// The key the bid names.
        pubkey: BlsPubkey,
    },

    /// The signature does not verify under the builder key.
    #[error("bid signature does not verify under builder {pubkey}")]
    BadSignature {
        /// The key the bid names.
        pubkey: BlsPubkey,
    },
}

/// The header members a request constrains, read from a bid of any fork.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HeaderTerms {
    /// The header's timestamp.
    timestamp: u64,
    /// The header's randomness.
    prev_randao: Bytes32,
    /// The header's gas limit.
    gas_limit: u64,
    /// The header's withdrawals root, none before Capella.
    withdrawals_root: Option<Root>,
}

impl HeaderTerms {
    /// The terms of a bid's header.
    const fn of<P: Preset>(bid: &SignedBuilderBid<P>) -> Self {
        match bid {
            SignedBuilderBid::Bellatrix(signed) => {
                let header = &signed.message.header;
                Self {
                    timestamp: header.timestamp,
                    prev_randao: header.prev_randao,
                    gas_limit: header.gas_limit,
                    withdrawals_root: None,
                }
            }
            SignedBuilderBid::Capella(signed) => {
                let header = &signed.message.header;
                Self {
                    timestamp: header.timestamp,
                    prev_randao: header.prev_randao,
                    gas_limit: header.gas_limit,
                    withdrawals_root: Some(header.withdrawals_root),
                }
            }
            SignedBuilderBid::Deneb(signed) => {
                let header = &signed.message.header;
                Self {
                    timestamp: header.timestamp,
                    prev_randao: header.prev_randao,
                    gas_limit: header.gas_limit,
                    withdrawals_root: Some(header.withdrawals_root),
                }
            }
            SignedBuilderBid::Electra(signed) | SignedBuilderBid::Fulu(signed) => {
                let header = &signed.message.header;
                Self {
                    timestamp: header.timestamp,
                    prev_randao: header.prev_randao,
                    gas_limit: header.gas_limit,
                    withdrawals_root: Some(header.withdrawals_root),
                }
            }
        }
    }
}

impl BidRequest {
    /// Checks a bid against this request.
    ///
    /// Cheap comparisons run first, and the pairing check last.
    ///
    /// The header's fee recipient is not compared with the registered one.
    /// A builder pays the proposer by a transfer inside the payload, which the relay verifies.
    /// See block scoring in the Deneb builder spec.
    ///
    /// The chain's genesis version fixes the signing domain.
    /// A builder key configured for the relay must match the bid's.
    ///
    /// # Errors
    ///
    /// Fails on the first term the bid breaks.
    pub fn verify<P: Preset>(
        &self,
        bid: SignedBuilderBid<P>,
        config: &ChainConfig,
        relay_pubkey: Option<&BlsPubkey>,
    ) -> Result<VerifiedBid<P>, BidError> {
        // Phase 1: the bid answers this request, from the expected builder.
        if bid.fork_name() != self.fork {
            return Err(BidError::Fork {
                expected: self.fork,
                actual: bid.fork_name(),
            });
        }
        if bid.parent_hash() != self.parent_hash {
            return Err(BidError::ParentHash {
                expected: self.parent_hash,
                actual: bid.parent_hash(),
            });
        }
        if let Some(&expected) = relay_pubkey
            && *bid.pubkey() != expected
        {
            return Err(BidError::Builder {
                expected,
                actual: *bid.pubkey(),
            });
        }
        // A zero bid is worth less than any local payload, and signals a relay fault.
        if bid.value() == U256::ZERO {
            return Err(BidError::ZeroValue);
        }

        // Phase 2: the header carries the terms a valid block needs.
        self.check_terms(HeaderTerms::of(&bid))?;

        // Phase 3: the builder signed it, in the application builder domain.
        // See verify_bid_signature in the Bellatrix builder validator spec.
        let pubkey = *bid.pubkey();
        let key = PublicKey::from_bytes(pubkey.as_bytes())
            .map_err(|_| BidError::InvalidPubkey { pubkey })?;
        let signature = Signature::from_bytes(&bid.signature().0)
            .map_err(|_| BidError::InvalidSignature { pubkey })?;
        let root = bid.signing_root(config);
        if !signature.verify(&key, root.as_bytes()) {
            return Err(BidError::BadSignature { pubkey });
        }
        Ok(VerifiedBid { bid })
    }

    /// Compares the header's terms with the expected ones.
    fn check_terms(&self, terms: HeaderTerms) -> Result<(), BidError> {
        if terms.timestamp != self.timestamp {
            return Err(BidError::Timestamp {
                expected: self.timestamp,
                actual: terms.timestamp,
            });
        }
        if terms.prev_randao != self.prev_randao {
            return Err(BidError::PrevRandao {
                expected: self.prev_randao,
                actual: terms.prev_randao,
            });
        }
        let gas_limit = self.gas_limit.expected();
        if terms.gas_limit != gas_limit {
            return Err(BidError::GasLimit {
                expected: gas_limit,
                actual: terms.gas_limit,
            });
        }
        if terms.withdrawals_root != self.withdrawals_root {
            return Err(BidError::WithdrawalsRoot {
                expected: self.withdrawals_root,
                actual: terms.withdrawals_root,
            });
        }
        Ok(())
    }
}

impl<P: Preset> VerifiedBid<P> {
    /// The checked bid.
    #[must_use]
    pub const fn bid(&self) -> &SignedBuilderBid<P> {
        &self.bid
    }

    /// Wei the proposer's fee recipient receives.
    #[must_use]
    pub const fn value(&self) -> U256 {
        self.bid.value()
    }

    /// The execution block the payload is.
    #[must_use]
    pub const fn block_hash(&self) -> Hash32 {
        self.bid.block_hash()
    }

    /// The checked bid, for block production.
    #[must_use]
    pub fn into_bid(self) -> SignedBuilderBid<P> {
        self.bid
    }
}

#[cfg(test)]
mod tests {
    use axiom_bls::SecretKey;
    use axiom_types::{BlsSignature, Minimal, capella, deneb};

    use super::*;

    /// The builder's key: the scalar 7.
    fn builder_key() -> SecretKey {
        let mut bytes = [0; 32];
        bytes[31] = 7;
        SecretKey::from_bytes(&bytes).unwrap()
    }

    /// The builder's public key bytes.
    fn builder_pubkey() -> BlsPubkey {
        BlsPubkey(builder_key().public_key().to_bytes())
    }

    /// The request every test bids on: Capella, slot 40, parent 0x11...11.
    fn request() -> BidRequest {
        BidRequest {
            fork: ForkName::Capella,
            slot: Slot(40),
            parent_hash: Hash32([0x11; 32]),
            proposer: BlsPubkey([0x22; 48]),
            timestamp: 1_700_000_480,
            prev_randao: Bytes32([0x33; 32]),
            gas_limit: GasLimitTarget {
                parent: 30_000_000,
                target: 30_000_000,
            },
            withdrawals_root: Some(Root([0x44; 32])),
        }
    }

    /// A Capella bid that meets every term of the request, worth 1 gwei, signed by the builder.
    fn bid_with(
        edit: impl FnOnce(&mut capella::SignedBuilderBid<Minimal>),
    ) -> SignedBuilderBid<Minimal> {
        let mut signed = capella::SignedBuilderBid::<Minimal>::default();
        let header = &mut signed.message.header;
        header.parent_hash = Hash32([0x11; 32]);
        header.timestamp = 1_700_000_480;
        header.prev_randao = Bytes32([0x33; 32]);
        header.gas_limit = 30_000_000;
        header.withdrawals_root = Root([0x44; 32]);
        header.block_hash = Hash32([0x55; 32]);
        signed.message.value = U256::from_u64(1_000_000_000);
        signed.message.pubkey = builder_pubkey();
        edit(&mut signed);

        // Sign after the edit, so each test faces one broken term at a time.
        let bid = SignedBuilderBid::Capella(signed);
        let root = bid.signing_root(&ChainConfig::minimal());
        let signature = builder_key().sign(root.as_bytes()).to_bytes();
        let SignedBuilderBid::Capella(mut signed) = bid else {
            unreachable!("built as Capella above")
        };
        signed.signature = BlsSignature(signature);
        SignedBuilderBid::Capella(signed)
    }

    /// Verifies against the request with no relay key configured.
    fn verify(bid: SignedBuilderBid<Minimal>) -> Result<VerifiedBid<Minimal>, BidError> {
        request().verify(bid, &ChainConfig::minimal(), None)
    }

    #[test]
    fn a_bid_meeting_every_term_verifies() {
        let bid = bid_with(|_| {});
        let verified = verify(bid.clone()).unwrap();
        assert_eq!(verified.into_bid(), bid);
    }

    #[test]
    fn a_bid_of_another_fork_is_refused() {
        // Fixture state: a Deneb bid answers a Capella request.
        let bid = SignedBuilderBid::Deneb(deneb::SignedBuilderBid::<Minimal>::default());
        assert_eq!(
            verify(bid),
            Err(BidError::Fork {
                expected: ForkName::Capella,
                actual: ForkName::Deneb,
            })
        );
    }

    #[test]
    fn a_bid_on_another_parent_is_refused() {
        let bid = bid_with(|signed| signed.message.header.parent_hash = Hash32([0x99; 32]));
        assert_eq!(
            verify(bid),
            Err(BidError::ParentHash {
                expected: Hash32([0x11; 32]),
                actual: Hash32([0x99; 32]),
            })
        );
    }

    #[test]
    fn a_bid_from_another_builder_than_the_relay_is_refused() {
        // Mutation: the relay is configured with key 0x66...66, the bid names the builder.
        let bid = bid_with(|_| {});
        let configured = BlsPubkey([0x66; 48]);
        assert_eq!(
            request().verify(bid.clone(), &ChainConfig::minimal(), Some(&configured)),
            Err(BidError::Builder {
                expected: configured,
                actual: builder_pubkey(),
            })
        );

        // The matching key passes.
        let matching = builder_pubkey();
        assert!(
            request()
                .verify(bid, &ChainConfig::minimal(), Some(&matching))
                .is_ok()
        );
    }

    #[test]
    fn a_zero_bid_is_refused() {
        let bid = bid_with(|signed| signed.message.value = U256::ZERO);
        assert_eq!(verify(bid), Err(BidError::ZeroValue));
    }

    #[test]
    fn a_header_breaking_a_term_is_refused() {
        // Timestamp: one second past the slot's start.
        let bid = bid_with(|signed| signed.message.header.timestamp = 1_700_000_481);
        assert_eq!(
            verify(bid),
            Err(BidError::Timestamp {
                expected: 1_700_000_480,
                actual: 1_700_000_481,
            })
        );

        // Randomness: another mix.
        let bid = bid_with(|signed| signed.message.header.prev_randao = Bytes32([0x34; 32]));
        assert_eq!(
            verify(bid),
            Err(BidError::PrevRandao {
                expected: Bytes32([0x33; 32]),
                actual: Bytes32([0x34; 32]),
            })
        );

        // Gas limit: a parent at the target leaves it unchanged, so 30_000_001 is wrong.
        let bid = bid_with(|signed| signed.message.header.gas_limit = 30_000_001);
        assert_eq!(
            verify(bid),
            Err(BidError::GasLimit {
                expected: 30_000_000,
                actual: 30_000_001,
            })
        );

        // Withdrawals: another root than the one due.
        let bid = bid_with(|signed| signed.message.header.withdrawals_root = Root([0x45; 32]));
        assert_eq!(
            verify(bid),
            Err(BidError::WithdrawalsRoot {
                expected: Some(Root([0x44; 32])),
                actual: Some(Root([0x45; 32])),
            })
        );
    }

    #[test]
    fn a_bid_with_a_broken_key_or_signature_is_refused() {
        // Key: 48 bytes of 0xff are not a compressed point.
        let bid = bid_with(|signed| signed.message.pubkey = BlsPubkey([0xff; 48]));
        assert_eq!(
            verify(bid),
            Err(BidError::InvalidPubkey {
                pubkey: BlsPubkey([0xff; 48]),
            })
        );

        // Signature: 96 zero bytes lack the compression flag.
        let SignedBuilderBid::Capella(mut signed) = bid_with(|_| {}) else {
            unreachable!("built as Capella")
        };
        signed.signature = BlsSignature([0; 96]);
        assert_eq!(
            verify(SignedBuilderBid::Capella(signed)),
            Err(BidError::InvalidSignature {
                pubkey: builder_pubkey(),
            })
        );
    }

    #[test]
    fn a_signature_over_other_terms_is_refused() {
        // Mutation: the value changes after signing, so the signed root no longer matches.
        let SignedBuilderBid::Capella(mut signed) = bid_with(|_| {}) else {
            unreachable!("built as Capella")
        };
        signed.message.value = U256::from_u64(2_000_000_000);
        assert_eq!(
            verify(SignedBuilderBid::Capella(signed)),
            Err(BidError::BadSignature {
                pubkey: builder_pubkey(),
            })
        );
    }
}
