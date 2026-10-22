//! Detecting a gateway restart from the epoch time in its responses.
//!
//! A gateway that loses its mappings resets its epoch to zero.
//! The client compares how far the epoch moved with how far its own clock moved.

use std::time::Duration;

/// Which RFC's test an epoch must pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EpochRule {
    /// RFC 6886 section 3.6.
    NatPmp,
    /// RFC 6887 section 8.5.
    Pcp,
}

/// The last epoch a gateway reported, and when it arrived.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct GatewayEpoch {
    /// The local clock and the gateway epoch, both in seconds, at the last response.
    last: Option<(u64, u32)>,
}

impl GatewayEpoch {
    /// Takes a response's epoch, reporting whether the gateway lost its state since the last.
    ///
    /// The first response always passes.
    /// Each protocol has its own rule, applied in whole seconds:
    ///
    /// - NAT-PMP, RFC 6886 section 3.6: the epoch must reach the last one plus 7/8 of the elapsed time, less 2 s.
    /// - PCP, RFC 6887 section 8.5: the epoch may lag 1 s, and its advance must match the clock within 1/16 plus 2 s.
    pub(crate) fn lost_state(&mut self, rule: EpochRule, now: Duration, epoch: u32) -> bool {
        let client = now.as_secs();
        let lost = match self.last {
            None => false,
            Some((prev_client, prev_epoch)) => {
                // The local clock never goes backwards, so the difference cannot wrap.
                let client_delta = client.saturating_sub(prev_client);
                match rule {
                    EpochRule::NatPmp => {
                        // Threshold: the conservative estimate counts 87.5% of the elapsed time.
                        let expected = u64::from(prev_epoch) + client_delta * 7 / 8;
                        u64::from(epoch) + 2 < expected
                    }
                    EpochRule::Pcp => Self::pcp_invalid(client_delta, prev_epoch, epoch),
                }
            }
        };
        self.last = Some((client, epoch));
        lost
    }

    /// The PCP validity test, in unsigned arithmetic as section 8.5 writes it.
    ///
    /// ```text
    /// invalid if epoch < prev_epoch - 1
    /// invalid if client_delta + 2 < server_delta - server_delta / 16
    /// invalid if server_delta + 2 < client_delta - client_delta / 16
    /// ```
    fn pcp_invalid(client_delta: u64, prev_epoch: u32, epoch: u32) -> bool {
        // Time going back by up to one second is reordering, not a restart.
        if u64::from(epoch) + 1 < u64::from(prev_epoch) {
            return true;
        }
        let server_delta = u64::from(epoch.saturating_sub(prev_epoch));
        client_delta + 2 < server_delta - server_delta / 16
            || server_delta + 2 < client_delta - client_delta / 16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feeds one response at a client time in seconds.
    fn observe(epoch: &mut GatewayEpoch, rule: EpochRule, seconds: u64, value: u32) -> bool {
        epoch.lost_state(rule, Duration::from_secs(seconds), value)
    }

    #[test]
    fn nat_pmp_detects_a_reset_epoch() {
        // Fixture state: the gateway reported 1000 at client time 0.
        let mut epoch = GatewayEpoch::default();
        assert!(!observe(&mut epoch, EpochRule::NatPmp, 0, 1000));
        // 800 s later the conservative estimate is 1000 + 700 = 1700; 1698 is within 2 s.
        assert!(!observe(&mut epoch, EpochRule::NatPmp, 800, 1698));
        // 80 s later the estimate is 1698 + 70 = 1768; 1765 is 3 s short: a restart.
        assert!(observe(&mut epoch, EpochRule::NatPmp, 880, 1765));
        // After a reboot the epoch restarts near zero.
        assert!(observe(&mut epoch, EpochRule::NatPmp, 1000, 30));
    }

    #[test]
    fn pcp_tolerates_reordering_and_drift() {
        // Fixture state: epoch 500 at client time 100.
        let mut epoch = GatewayEpoch::default();
        assert!(!observe(&mut epoch, EpochRule::Pcp, 100, 500));
        // One second backwards is reordering.
        assert!(!observe(&mut epoch, EpochRule::Pcp, 100, 499));
        // 1600 s of client time against 1500 of server time: 100 s is within 1/16 plus 2.
        assert!(!observe(&mut epoch, EpochRule::Pcp, 1700, 1999));
    }

    #[test]
    fn pcp_detects_a_restart() {
        // Two seconds backwards is a restart.
        let mut epoch = GatewayEpoch::default();
        observe(&mut epoch, EpochRule::Pcp, 0, 500);
        assert!(observe(&mut epoch, EpochRule::Pcp, 0, 498));
        // A server that advanced 100 s while the client saw 3600 s restarted meanwhile.
        let mut epoch = GatewayEpoch::default();
        observe(&mut epoch, EpochRule::Pcp, 0, 500);
        assert!(observe(&mut epoch, EpochRule::Pcp, 3600, 600));
        // A server racing ahead is as suspect: 3600 s against 100 s of client time.
        let mut epoch = GatewayEpoch::default();
        observe(&mut epoch, EpochRule::Pcp, 0, 500);
        assert!(observe(&mut epoch, EpochRule::Pcp, 100, 4100));
    }
}
