//! What block processing pays the proposer, kept by source as it is paid.

use std::mem;

use axiom_types::Gwei;

/// The proposer's earnings from the block being processed, by source.
///
/// # Overview
///
/// Block processing credits the proposer at three places:
///
/// - each attestation's newly set participation flags,
/// - each sync committee bit,
/// - each slashing, where the proposer is also the whistleblower.
///
/// Each place records its credit here as it pays it, so the ledger equals the payments.
/// A slashing does not know which operation asked for it.
/// The operation settles the slashing credit into its own source once it is done.
///
/// # Invariants
///
/// Block processing starts every block from an empty ledger.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProposerLedger {
    /// Paid for newly set participation flags.
    pub(crate) attestations: Gwei,
    /// Paid for sync committee participation.
    pub(crate) sync_aggregate: Gwei,
    /// Paid for proposer slashings.
    pub(crate) proposer_slashings: Gwei,
    /// Paid for attester slashings.
    pub(crate) attester_slashings: Gwei,
    /// Paid for slashings not yet settled into an operation's source.
    pub(crate) slashing: Gwei,
}

impl ProposerLedger {
    /// Moves the unsettled slashing credit to the proposer slashings.
    pub(crate) fn settle_proposer_slashing(&mut self) {
        self.proposer_slashings += mem::take(&mut self.slashing);
    }

    /// Moves the unsettled slashing credit to the attester slashings.
    pub(crate) fn settle_attester_slashing(&mut self) {
        self.attester_slashings += mem::take(&mut self.slashing);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slashing_credit_settles_into_the_operation_that_caused_it() {
        // Fixture state: 7 gwei from a proposer slashing, then 5 and 3 from one attester slashing.
        let mut ledger = ProposerLedger::default();
        ledger.slashing += Gwei(7);
        ledger.settle_proposer_slashing();
        ledger.slashing += Gwei(5);
        ledger.slashing += Gwei(3);
        ledger.settle_attester_slashing();

        // Each source holds its own sum, and nothing stays unsettled.
        assert_eq!(
            ledger,
            ProposerLedger {
                proposer_slashings: Gwei(7),
                attester_slashings: Gwei(8),
                ..ProposerLedger::default()
            }
        );
    }
}
