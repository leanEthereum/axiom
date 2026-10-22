//! The two ways a gossip message fails validation.

use thiserror::Error;

use crate::Detail;

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
