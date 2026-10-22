//! Several relays, asked together: the proposer's view of the builder market.

use std::{
    collections::BTreeMap,
    sync::{Mutex, MutexGuard, PoisonError},
};

use axiom_types::{
    ChainConfig, Hash32, Preset, Slot, bellatrix::SignedValidatorRegistrationV1,
    combined::SignedBlindedBeaconBlock,
};

use crate::{
    BidRequest, BuilderError, RelayClient, RelayFailure, RelayFailures, UnblindedBlock,
    VerifiedBid, concurrent::Concurrent,
};

/// The relays a node buys payloads from.
///
/// # Overview
///
/// Every call goes to the relays concurrently, and each relay's failure is reported apart.
/// One relay down never fails a call the others can serve.
///
/// The set remembers which relays offered the winning payload of each recent slot.
/// The signed blinded block then goes only to them, since no other relay can reveal it.
#[derive(Debug)]
pub struct RelaySet {
    /// The relays, in configuration order.
    relays: Vec<RelayClient>,
    /// Per recent slot, the relays that offered the winning payload.
    winners: Mutex<BTreeMap<Slot, Vec<usize>>>,
}

/// The highest verified bid of an auction, and the relays that offered its payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WinningBid<P: Preset> {
    /// The bid, as the first relay offering it sent it.
    pub bid: VerifiedBid<P>,

    /// Positions of the relays that offered the same payload, in configuration order.
    pub relays: Vec<usize>,
}

/// The outcome of asking every relay for a bid.
#[derive(Debug)]
pub struct Auction<P: Preset> {
    /// The highest verified bid, when any relay offered one.
    pub winner: Option<WinningBid<P>>,

    /// Relays that failed, or whose bid failed verification, in configuration order.
    pub failures: Vec<RelayFailure>,
}

impl RelaySet {
    /// Recent slots whose winning relays the set remembers.
    ///
    /// A reveal follows its bid within the same slot, so a few slots cover any retry.
    const REMEMBERED_SLOTS: usize = 16;

    /// A set of relays.
    #[must_use]
    pub const fn new(relays: Vec<RelayClient>) -> Self {
        Self {
            relays,
            winners: Mutex::new(BTreeMap::new()),
        }
    }

    /// The relays, in configuration order.
    #[must_use]
    pub fn relays(&self) -> &[RelayClient] {
        &self.relays
    }

    /// Hands registrations to every relay.
    ///
    /// # Returns
    ///
    /// The relays that refused or could not be reached, empty when all accepted.
    pub async fn register_validators(
        &self,
        registrations: &[SignedValidatorRegistrationV1],
    ) -> Vec<RelayFailure> {
        let calls = self
            .relays
            .iter()
            .map(|relay| relay.register_validators(registrations));
        let mut calls = Concurrent::new(calls);
        let mut failures = Vec::new();
        while let Some((index, outcome)) = calls.next().await {
            if let Err(error) = outcome {
                failures.push((index, error));
            }
        }
        self.in_order(failures)
    }

    /// Asks every relay for a bid, verifies each, and keeps the highest.
    ///
    /// Each relay answers within its bid deadline, and they run concurrently.
    /// So the auction ends within the longest relay deadline.
    ///
    /// Equal values keep the bid of the earlier relay in configuration order.
    /// That choice only makes the outcome deterministic; any equal bid pays the same.
    pub async fn best_header<P: Preset>(
        &self,
        request: &BidRequest,
        config: &ChainConfig,
    ) -> Auction<P> {
        let calls = self.relays.iter().map(|relay| {
            relay.header::<P>(
                request.fork,
                request.slot,
                request.parent_hash,
                request.proposer,
            )
        });
        let mut calls = Concurrent::new(calls);
        let mut bids = Vec::new();
        let mut failures = Vec::new();
        while let Some((index, outcome)) = calls.next().await {
            let relay = &self.relays[index];
            let verified = outcome.and_then(|bid| {
                bid.map(|bid| request.verify(bid, config, relay.pubkey()))
                    .transpose()
                    .map_err(BuilderError::Bid)
            });
            match verified {
                Ok(Some(bid)) => bids.push((index, bid)),
                Ok(None) => {}
                Err(error) => failures.push((index, error)),
            }
        }

        let winner = Self::highest(bids);
        if let Some(winner) = &winner {
            self.remember(request.slot, winner.relays.clone());
        }
        Auction {
            winner,
            failures: self.in_order(failures),
        }
    }

    /// Hands a signed blinded block to the relays that can reveal it, and completes it.
    ///
    /// The relays that offered the slot's winning payload get it.
    /// When the set does not know them, every relay does.
    /// The first reveal that completes the block wins; the others are dropped.
    ///
    /// # Errors
    ///
    /// Fails when no relay asked reveals a payload that completes the block.
    pub async fn submit_blinded_block<P: Preset>(
        &self,
        block: &SignedBlindedBeaconBlock<P>,
    ) -> Result<UnblindedBlock<P>, BuilderError> {
        let targets = self
            .winners()
            .get(&block.slot())
            .cloned()
            .unwrap_or_else(|| (0..self.relays.len()).collect());
        let calls = targets.iter().map(|&index| {
            let relay = &self.relays[index];
            async move { (index, relay.submit_blinded_block(block).await) }
        });
        let mut calls = Concurrent::new(calls);
        let mut failures = Vec::new();
        while let Some((_, (index, outcome))) = calls.next().await {
            let unblinded = outcome.and_then(|revealed| Ok(revealed.unblind(block.clone())?));
            match unblinded {
                Ok(unblinded) => return Ok(unblinded),
                Err(error) => failures.push((index, error)),
            }
        }
        Err(BuilderError::AllRelaysFailed(RelayFailures(
            self.in_order(failures),
        )))
    }

    /// The highest bid, with every relay offering the same payload.
    fn highest<P: Preset>(bids: Vec<(usize, VerifiedBid<P>)>) -> Option<WinningBid<P>> {
        // Sort by relay position, so the earlier relay wins a tie by value.
        let mut bids = bids;
        bids.sort_by_key(|(index, _)| *index);
        let block_hash: Hash32 = bids
            .iter()
            .reduce(|best, next| {
                if next.1.value() > best.1.value() {
                    next
                } else {
                    best
                }
            })?
            .1
            .block_hash();
        let relays = bids
            .iter()
            .filter(|(_, bid)| bid.block_hash() == block_hash)
            .map(|(index, _)| *index)
            .collect::<Vec<_>>();
        let (_, bid) = bids
            .into_iter()
            .find(|(_, bid)| bid.block_hash() == block_hash)?;
        Some(WinningBid { bid, relays })
    }

    /// Records the relays that can reveal a slot's payload, forgetting the oldest slots.
    fn remember(&self, slot: Slot, relays: Vec<usize>) {
        let mut winners = self.winners();
        winners.insert(slot, relays);
        while winners.len() > Self::REMEMBERED_SLOTS {
            winners.pop_first();
        }
        drop(winners);
    }

    /// The winning relays per slot, locked.
    ///
    /// Poisoning is ignored: no code panics while holding the lock.
    fn winners(&self) -> MutexGuard<'_, BTreeMap<Slot, Vec<usize>>> {
        self.winners.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Failures sorted by relay position and named by relay URL.
    fn in_order(&self, mut failures: Vec<(usize, BuilderError)>) -> Vec<RelayFailure> {
        failures.sort_by_key(|(index, _)| *index);
        failures
            .into_iter()
            .map(|(index, error)| RelayFailure {
                relay: self.relays[index].url().to_owned(),
                error,
            })
            .collect()
    }
}
