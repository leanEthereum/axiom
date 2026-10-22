//! Execution payload bids: the payload a block commits to, and what its builder pays for it.

use axiom_bls::PublicKey;
use axiom_types::{
    Gwei, Preset,
    accessors::BuilderState,
    constants::{
        BUILDER_INDEX_SELF_BUILD, DOMAIN_BEACON_BUILDER, G2_POINT_AT_INFINITY,
        PAYLOAD_BUILDER_VERSION,
    },
    gloas::{BuilderPendingPayment, BuilderPendingWithdrawal, SignedExecutionPayloadBid},
    phase0::SigningData,
};

use crate::{BlockError, BlockProcessor, Fork, Operation, StateError};

impl<S: Fork + BuilderState> Operation<S> for SignedExecutionPayloadBid {
    /// Checks the bid against its builder and the chain, records its payment, and caches it.
    ///
    /// # Algorithm
    ///
    /// 1. A self-built bid is free and unsigned: zero value, the point at infinity as signature.
    /// 2. A builder's bid needs an active payload builder, funds to cover it, and its signature.
    /// 3. The bid must respect the blob limit, and be for this slot, parent block, and randomness.
    /// 4. A bid with a value owes it to the proposer, pending in the slot's payment entry.
    /// 5. The bid becomes the state's latest bid, which the payload must honour.
    ///
    /// A builder must keep the minimum deposit on top of what it already owes.
    /// See EIP-7732 and `process_execution_payload_bid` in the Gloas beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let bid = &self.message;
        let builder_index = bid.builder_index;

        // Phase 1: who pays, and their signature.
        BidRules(self).check_payer(processor)?;

        // Phase 2: the bid fits the chain.
        BidRules(self).check_chain(processor)?;

        // Phase 3: the payment, owed once the payload proves timely.
        if bid.value > Gwei::ZERO {
            let payment = BuilderPendingPayment {
                weight: Gwei::ZERO,
                withdrawal: BuilderPendingWithdrawal {
                    fee_recipient: bid.fee_recipient,
                    amount: bid.value,
                    builder_index,
                },
                proposer_index: processor.proposer()?,
            };
            let entry = S::Preset::SLOTS_PER_EPOCH + bid.slot.index_in_epoch::<S::Preset>();
            processor.state.beacon.builder_pending_payments_mut()[entry as usize] = payment;
        }
        *processor.state.beacon.latest_execution_payload_bid_mut() = bid.clone();
        Ok(())
    }
}

/// The rules a bid must satisfy before its payment is recorded.
#[derive(Clone, Copy, Debug)]
struct BidRules<'a>(&'a SignedExecutionPayloadBid);

impl BidRules<'_> {
    /// Checks who pays for the bid: nobody for a self-built one, or an able builder that signed it.
    fn check_payer<S: Fork + BuilderState>(
        self,
        processor: &mut BlockProcessor<'_, S>,
    ) -> Result<(), BlockError> {
        let signed = self.0;
        let bid = &signed.message;
        let builder_index = bid.builder_index;
        let state = processor.state.beacon();
        let epoch = state.current_epoch();
        let invalid = |reason| BlockError::InvalidBid {
            builder: builder_index,
            reason,
        };
        if builder_index == BUILDER_INDEX_SELF_BUILD {
            if bid.value != Gwei::ZERO {
                return Err(BlockError::SelfBuildBidValue(bid.value));
            }
            if signed.signature != G2_POINT_AT_INFINITY {
                return Err(invalid("self-built bid carries a signature"));
            }
        } else {
            let builders = state.builders();
            let builder =
                builders
                    .get(builder_index.as_usize())
                    .ok_or(StateError::UnknownBuilder {
                        index: builder_index,
                        registry_size: builders.len(),
                    })?;
            if !builder.is_active(state.finalized_checkpoint().epoch) {
                return Err(invalid("builder is not active"));
            }
            if builder.version != PAYLOAD_BUILDER_VERSION {
                return Err(invalid("builder is not a payload builder"));
            }
            // See `can_builder_cover_bid` in the Gloas spec.
            let owed = state.pending_balance_to_withdraw_for_builder(builder_index);
            let reserve = S::Preset::MIN_DEPOSIT_AMOUNT;
            let covered = reserve
                .checked_add(owed)
                .and_then(|kept| builder.balance.checked_sub(kept))
                .is_some_and(|free| free >= bid.value);
            if !covered {
                return Err(BlockError::BidNotCovered {
                    builder: builder_index,
                    value: bid.value,
                    balance: builder.balance,
                    owed,
                    reserve,
                });
            }
            if processor.checks_signatures() {
                let key = PublicKey::from_bytes(&builder.pubkey.0)
                    .map_err(|_| invalid("builder key does not decompress"))?;
                let domain = state.domain(DOMAIN_BEACON_BUILDER, epoch);
                let root = SigningData::signing_root(bid, domain);
                processor.verify_root(key, root, &signed.signature)?;
            }
        }
        Ok(())
    }

    /// Checks the bid against the chain: blob limit, slot, parent block, and randomness.
    fn check_chain<S: Fork + BuilderState>(
        self,
        processor: &BlockProcessor<'_, S>,
    ) -> Result<(), BlockError> {
        let signed = self.0;
        let bid = &signed.message;
        let builder_index = bid.builder_index;
        let state = processor.state.beacon();
        let epoch = state.current_epoch();
        let invalid = |reason| BlockError::InvalidBid {
            builder: builder_index,
            reason,
        };
        let limit = processor.config.blob_parameters(epoch).max_blobs_per_block;
        let blobs = bid.blob_kzg_commitments.len();
        if blobs as u64 > limit {
            return Err(BlockError::TooManyBlobs {
                count: blobs,
                limit,
            });
        }
        if bid.slot != state.slot() {
            return Err(BlockError::BidSlotMismatch {
                bid: bid.slot,
                state: state.slot(),
            });
        }
        if state.slot().0 == 0 {
            return Err(invalid("bid is for the genesis slot"));
        }
        let latest_hash = state.latest_block_hash();
        if bid.parent_block_hash != latest_hash {
            return Err(BlockError::BidParentHashMismatch {
                claimed: bid.parent_block_hash,
                expected: latest_hash,
            });
        }
        if bid.block_hash == bid.parent_block_hash {
            return Err(BlockError::BidBlockHashRepeatsParent(bid.block_hash));
        }
        let previous = state.slot() - 1;
        let parent_root =
            state
                .block_root_at_slot(previous)
                .ok_or_else(|| StateError::BlockRootOutOfRange {
                    slot: previous,
                    state_slot: state.slot(),
                })?;
        if bid.parent_block_root != parent_root {
            return Err(BlockError::BidParentRootMismatch {
                claimed: bid.parent_block_root,
                expected: parent_root,
            });
        }
        let randao_mix = state.randao_mix(epoch);
        if bid.prev_randao != randao_mix {
            return Err(BlockError::BidRandaoMismatch {
                claimed: bid.prev_randao,
                expected: randao_mix,
            });
        }
        Ok(())
    }
}
