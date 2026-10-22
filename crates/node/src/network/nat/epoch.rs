//! Detecting a gateway restart from the epoch in its NAT-PMP responses.
//!
//! A gateway that loses its mappings resets its epoch to zero.
//! The client compares how far the epoch moved with how far its own clock moved.

use std::time::Duration;

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
    /// Later ones follow RFC 6886 section 3.6, in whole seconds:
    ///
    /// ```text
    /// expected = last_epoch + elapsed * 7 / 8
    /// lost if epoch + 2 < expected
    /// ```
    pub(crate) fn lost_state(&mut self, now: Duration, epoch: u32) -> bool {
        let client = now.as_secs();
        let lost = self.last.is_some_and(|(prev_client, prev_epoch)| {
            // The local clock never goes backwards, so the difference cannot wrap.
            let elapsed = client.saturating_sub(prev_client);
            // Threshold: the conservative estimate counts 87.5% of the elapsed time.
            let expected = u64::from(prev_epoch) + elapsed * 7 / 8;
            u64::from(epoch) + 2 < expected
        });
        self.last = Some((client, epoch));
        lost
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feeds one response at a client time in seconds.
    fn observe(epoch: &mut GatewayEpoch, seconds: u64, value: u32) -> bool {
        epoch.lost_state(Duration::from_secs(seconds), value)
    }

    #[test]
    fn a_reset_epoch_is_a_restart() {
        // Fixture state: the gateway reported 1000 at client time 0.
        let mut epoch = GatewayEpoch::default();
        assert!(!observe(&mut epoch, 0, 1000));
        // 800 s later the conservative estimate is 1000 + 700 = 1700; 1698 is within 2 s.
        assert!(!observe(&mut epoch, 800, 1698));
        // 80 s later the estimate is 1698 + 70 = 1768; 1765 is 3 s short: a restart.
        assert!(observe(&mut epoch, 880, 1765));
        // After a reboot the epoch restarts near zero.
        assert!(observe(&mut epoch, 1000, 30));
    }
}
