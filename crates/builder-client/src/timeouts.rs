//! How long each builder API call may take.

use std::time::Duration;

/// Deadlines of the builder API calls, one per endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayTimeouts {
    /// Deadline of a health probe.
    pub status: Duration,

    /// Deadline of a registration batch.
    pub register: Duration,

    /// Deadline of a bid request.
    pub header: Duration,

    /// Deadline of a blinded block submission.
    pub reveal: Duration,
}

impl RelayTimeouts {
    /// Time builders get to answer a bid request.
    ///
    /// This is BUILDER_PROPOSAL_DELAY_TOLERANCE of the Bellatrix builder validator spec.
    /// Past it the proposer abandons the builder and proposes its local payload.
    pub const BID_DEADLINE: Duration = Duration::from_secs(1);

    /// The deadlines used unless configured otherwise.
    ///
    /// - A health probe gets the bid deadline: a relay slower than that is useless at proposal time.
    /// - Registrations get one mainnet slot, far below the one-epoch resubmission period of the validator spec.
    /// - A reveal gets four seconds, a third of a mainnet slot, when attesters vote.
    ///
    /// A block revealed after attesters vote rarely becomes head, so waiting longer gains little.
    /// The attestation deadline is SECONDS_PER_SLOT / INTERVALS_PER_SLOT, see the phase0 validator spec.
    pub const DEFAULT: Self = Self {
        status: Self::BID_DEADLINE,
        register: Duration::from_secs(12),
        header: Self::BID_DEADLINE,
        reveal: Duration::from_secs(4),
    };
}

impl Default for RelayTimeouts {
    fn default() -> Self {
        Self::DEFAULT
    }
}
