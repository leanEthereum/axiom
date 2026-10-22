//! Ping: round-trip probes over a dedicated stream.
//!
//! # Overview
//!
//! The dialer writes 32 random bytes and the listener echoes them back.
//! The dialer may repeat on the same stream; the listener echoes every 32-byte block.
//!
//! ```text
//! dialer ── 32 bytes ──▶ listener
//! dialer ◀── same 32 ── listener      rtt = receive time - send time
//! ```
//!
//! See `libp2p/specs/ping/ping.md`.

use std::{error::Error, fmt, mem, time::Duration};

/// The multistream-select name.
pub const PROTOCOL: &str = "/ipfs/ping/1.0.0";

/// Bytes of one probe.
pub const PING_SIZE: usize = 32;

/// One outstanding probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ping {
    /// The bytes sent, which must come back unchanged.
    payload: [u8; PING_SIZE],
    /// When the probe left, on the caller's clock.
    sent_at: Duration,
}

impl Ping {
    /// A probe carrying caller-chosen random bytes, sent at a given time.
    #[must_use]
    pub const fn new(payload: [u8; PING_SIZE], sent_at: Duration) -> Self {
        Self { payload, sent_at }
    }

    /// The bytes to write.
    #[must_use]
    pub const fn payload(&self) -> &[u8; PING_SIZE] {
        &self.payload
    }

    /// Checks the echo and measures the round trip.
    pub fn verify(&self, echo: &[u8; PING_SIZE], now: Duration) -> Result<Duration, PingError> {
        if *echo != self.payload {
            return Err(PingError::Mismatch);
        }
        // A clock that moves backwards yields zero rather than a panic.
        Ok(now.saturating_sub(self.sent_at))
    }
}

/// The listener side: echoes whole 32-byte blocks.
#[derive(Clone, Debug, Default)]
pub struct PingResponder {
    /// Bytes of an incomplete block.
    buffer: Vec<u8>,
}

impl PingResponder {
    /// Feeds received bytes, returning the echo to write.
    pub fn receive(&mut self, bytes: &[u8]) -> Vec<u8> {
        self.buffer.extend_from_slice(bytes);
        // Echo only complete blocks; a partial block waits for its tail.
        let whole = self.buffer.len() / PING_SIZE * PING_SIZE;
        let tail = self.buffer.split_off(whole);
        mem::replace(&mut self.buffer, tail)
    }
}

/// A failed probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PingError {
    /// The echo differs from the probe.
    Mismatch,
}

impl fmt::Display for PingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mismatch => f.write_str("ping echo does not match the probe"),
        }
    }
}

impl Error for PingError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_and_round_trip_time() {
        // Probe sent at t = 1.000 s.
        let ping = Ping::new([7; PING_SIZE], Duration::from_millis(1000));
        let mut responder = PingResponder::default();

        // 20 bytes arrive: not a full block, nothing to echo yet.
        assert!(responder.receive(&ping.payload()[..20]).is_empty());
        // The other 12 bytes complete the block, which comes back whole.
        let echo = responder.receive(&ping.payload()[20..]);
        assert_eq!(echo, ping.payload());

        // The echo lands at t = 1.042 s → rtt 42 ms.
        let echo: [u8; PING_SIZE] = echo.try_into().unwrap();
        assert_eq!(
            ping.verify(&echo, Duration::from_millis(1042)),
            Ok(Duration::from_millis(42))
        );
    }

    #[test]
    fn corrupted_echo_is_rejected() {
        let ping = Ping::new([7; PING_SIZE], Duration::ZERO);
        // Mutation: the first byte comes back changed.
        let mut echo = [7; PING_SIZE];
        echo[0] = 8;
        assert_eq!(ping.verify(&echo, Duration::ZERO), Err(PingError::Mismatch));
    }
}
