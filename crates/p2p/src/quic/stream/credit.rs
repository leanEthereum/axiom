//! Flow control credit, per RFC 9000, section 4.
//!
//! A receiver advertises how far a sender may write.
//! It raises the limit as its owner consumes data, so a slow owner stalls the sender at the limit.
//! The same rules hold for one stream and for the whole connection.

/// The receiving side's limit and how much of it the owner has consumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecvCredit {
    /// The span of credit kept ahead of consumption.
    window: u64,
    /// The highest offset the peer may send, as advertised.
    limit: u64,
    /// Bytes the owner consumed.
    consumed: u64,
    /// Whether a raised limit must be announced.
    update_due: bool,
}

impl RecvCredit {
    /// Credit of one window, as the transport parameters announce it.
    pub(crate) const fn new(window: u64) -> Self {
        Self {
            window,
            limit: window,
            consumed: 0,
            update_due: false,
        }
    }

    /// The advertised limit.
    pub(crate) const fn limit(&self) -> u64 {
        self.limit
    }

    /// Whether data reaching an offset stays within the limit.
    pub(crate) const fn allows(&self, highest: u64) -> bool {
        highest <= self.limit
    }

    /// Records consumption, raising the limit once half a window is used.
    ///
    /// Raising in half-window steps keeps one update per half window, not one per read.
    pub(crate) fn consume(&mut self, len: u64) {
        self.consumed += len;
        // Threshold: announce when less than half a window of credit remains.
        if self.limit - self.consumed.min(self.limit) < self.window / 2 {
            self.limit = self.consumed + self.window;
            self.update_due = true;
        }
    }

    /// Takes the limit to announce, if an update is due.
    pub(crate) const fn take_update(&mut self) -> Option<u64> {
        if self.update_due {
            self.update_due = false;
            Some(self.limit)
        } else {
            None
        }
    }

    /// Marks a lost update for sending again, with the current limit.
    pub(crate) const fn on_update_lost(&mut self, sent: u64) {
        // A newer update supersedes a lost older one.
        if sent == self.limit {
            self.update_due = true;
        }
    }

    /// Whether an update waits to be sent.
    pub(crate) const fn is_update_due(&self) -> bool {
        self.update_due
    }
}

/// The sending side's view of the peer's limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SendCredit {
    /// The highest offset the peer allows.
    limit: u64,
    /// The limit at which a blocked frame was last sent, so each limit is reported once.
    blocked_reported: Option<u64>,
    /// Whether a blocked frame waits to be sent.
    blocked_due: bool,
}

impl SendCredit {
    /// The peer's initial limit.
    pub(crate) const fn new(limit: u64) -> Self {
        Self {
            limit,
            blocked_reported: None,
            blocked_due: false,
        }
    }

    /// The peer's limit.
    pub(crate) const fn limit(&self) -> u64 {
        self.limit
    }

    /// Raises the limit; limits never shrink, so a lower value is stale and ignored.
    pub(crate) fn raise(&mut self, limit: u64) {
        self.limit = self.limit.max(limit);
    }

    /// Notes that sending stopped at the limit, so a blocked frame reports it once.
    pub(crate) fn on_blocked(&mut self) {
        if self.blocked_reported != Some(self.limit) {
            self.blocked_reported = Some(self.limit);
            self.blocked_due = true;
        }
    }

    /// Takes the limit to report as blocked, if a report is due.
    pub(crate) const fn take_blocked(&mut self) -> Option<u64> {
        if self.blocked_due {
            self.blocked_due = false;
            Some(self.limit)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receive_credit_rises_in_half_windows() {
        // A window of 100: consuming 40 keeps 60 ahead, so no update yet.
        let mut credit = RecvCredit::new(100);
        assert!(credit.allows(100) && !credit.allows(101));
        credit.consume(40);
        assert_eq!(credit.take_update(), None);

        // Consuming 20 more leaves 40, under half: the limit moves to 60 + 100.
        credit.consume(20);
        assert_eq!(credit.take_update(), Some(160));
        assert_eq!(credit.take_update(), None);

        // The update of 160 is lost and still current, so it is due again.
        credit.on_update_lost(160);
        assert!(credit.is_update_due());
        // A lost update of an older limit is not resent.
        credit.take_update();
        credit.on_update_lost(100);
        assert!(!credit.is_update_due());
    }

    #[test]
    fn blocked_is_reported_once_per_limit() {
        let mut credit = SendCredit::new(50);
        credit.on_blocked();
        credit.on_blocked();
        assert_eq!(credit.take_blocked(), Some(50));
        assert_eq!(credit.take_blocked(), None);

        // A stale lower limit is ignored; a higher one allows a new report.
        credit.raise(40);
        assert_eq!(credit.limit(), 50);
        credit.raise(80);
        credit.on_blocked();
        assert_eq!(credit.take_blocked(), Some(80));
    }
}
