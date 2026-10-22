//! The two ways a gossip message fails validation.

use axiom_types::Root;
use thiserror::Error;

use crate::Detail;

/// The ignore verdict of a block whose parent the node has not seen.
///
/// See the beacon block topic rules of the phase0 p2p spec.
pub(crate) const UNSEEN_PARENT: &str = "block's parent has not been seen";

/// The ignore verdict of a vote for a block the node has not seen.
///
/// See the attestation and aggregate topic rules of the phase0 p2p spec.
pub(crate) const UNSEEN_VOTED_BLOCK: &str = "block being voted for has not been seen";

/// Why a gossip message is not forwarded.
///
/// The reason is the spec's own wording, kept for logs and for matching vectors by eye.
/// The detail adds the values the failing rule compared, where it compared any.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum GossipError {
    /// The message is dropped without penalizing its sender.
    #[error("ignore: {reason}{detail}")]
    Ignore {
        /// The rule that failed, in the spec's wording.
        reason: &'static str,
        /// The values the rule compared.
        detail: Detail,
    },
    /// The message is invalid, and its sender is penalized.
    #[error("reject: {reason}{detail}")]
    Reject {
        /// The rule that failed, in the spec's wording.
        reason: &'static str,
        /// The values the rule compared.
        detail: Detail,
    },
}

impl GossipError {
    /// An ignore verdict with no values beyond the rule's wording.
    #[must_use]
    pub const fn ignore(reason: &'static str) -> Self {
        Self::Ignore {
            reason,
            detail: Detail::None,
        }
    }

    /// A reject verdict with no values beyond the rule's wording.
    #[must_use]
    pub const fn reject(reason: &'static str) -> Self {
        Self::Reject {
            reason,
            detail: Detail::None,
        }
    }

    /// The block a message builds on or votes for, when it was ignored for want of that block.
    ///
    /// The p2p spec lets a client fetch that block and handle the message once it arrives.
    #[must_use]
    pub fn unseen_block(&self) -> Option<Root> {
        match *self {
            Self::Ignore {
                reason,
                detail: Detail::Block(root),
            } if reason == UNSEEN_PARENT || reason == UNSEEN_VOTED_BLOCK => Some(root),
            Self::Ignore { .. } | Self::Reject { .. } => None,
        }
    }

    /// The same verdict, carrying the values its rule compared.
    #[must_use]
    pub const fn with(self, detail: Detail) -> Self {
        match self {
            Self::Ignore { reason, .. } => Self::Ignore { reason, detail },
            Self::Reject { reason, .. } => Self::Reject { reason, detail },
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::Slot;

    use super::*;

    #[test]
    fn only_an_unseen_parent_or_voted_block_names_a_block_to_fetch() {
        let root = Root([9; 32]);
        let named = |reason| GossipError::ignore(reason).with(Detail::Block(root));

        // Both unseen block verdicts name the block.
        assert_eq!(named(UNSEEN_PARENT).unseen_block(), Some(root));
        assert_eq!(named(UNSEEN_VOTED_BLOCK).unseen_block(), Some(root));

        // Another rule naming a block, or the same wording as a reject, names none.
        assert_eq!(
            named("dependent block has not been seen").unseen_block(),
            None
        );
        let rejected = GossipError::reject(UNSEEN_PARENT).with(Detail::Block(root));
        assert_eq!(rejected.unseen_block(), None);
    }

    #[test]
    fn the_message_prints_the_rule_then_its_values() {
        // A rule with nothing to compare prints its wording alone.
        assert_eq!(
            GossipError::reject("invalid proposer signature").to_string(),
            "reject: invalid proposer signature"
        );

        // A block at slot 12 arriving at slot 10 prints both slots.
        let future = GossipError::ignore("block is from a future slot").with(Detail::Slot {
            slot: Slot(12),
            reference: Slot(10),
        });
        assert_eq!(
            future,
            GossipError::Ignore {
                reason: "block is from a future slot",
                detail: Detail::Slot {
                    slot: Slot(12),
                    reference: Slot(10),
                },
            }
        );
        assert_eq!(
            future.to_string(),
            "ignore: block is from a future slot: slot 12, reference slot 10"
        );
    }
}
