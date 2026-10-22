//! Ping: round-trip probes over a dedicated stream.
//!
//! # Overview
//!
//! The dialer writes 32 random bytes and the listener echoes them back.
//! The dialer may repeat on the same stream; the listener echoes every 32-byte block.
//!
//! 1. The dialer sends 32 bytes to the listener.
//! 2. The listener sends the same 32 bytes back.
//! 3. The dialer measures the round trip:
//!
//! ```text
//! rtt = receive time - send time
//! ```
//!
//! See `libp2p/specs/ping/ping.md`.

use std::{mem, time::Duration};

use thiserror::Error;

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
        // The first differing byte locates the corruption.
        if let Some(offset) = echo.iter().zip(&self.payload).position(|(a, b)| a != b) {
            return Err(PingError::Mismatch { offset });
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum PingError {
    /// The echo differs from the probe.
    #[error("ping echo differs from the probe at byte {offset}")]
    Mismatch {
        /// Position of the first differing byte.
        offset: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_and_round_trip_time() {
        // Probe sent at t = 1.000 s.
        let ping = Ping::new([7; PING_SIZE], Duration::from_millis(1000));
        let mut responder = PingResponder::default();

        // 20 bytes arrive: not a full block, nothing to echo yet.
        assert_eq!(responder.receive(&ping.payload()[..20]), Vec::<u8>::new());
        // The other 12 bytes complete the block, which comes back whole.
        let echo = responder.receive(&ping.payload()[20..]);
        assert_eq!(echo, ping.payload());

        // The echo lands at t = 1.042 s, so the rtt is 42 ms.
        let echo: [u8; PING_SIZE] = echo.try_into().unwrap();
        assert_eq!(
            ping.verify(&echo, Duration::from_millis(1042)),
            Ok(Duration::from_millis(42))
        );
    }

    #[test]
    fn corrupted_echo_is_rejected() {
        let ping = Ping::new([7; PING_SIZE], Duration::ZERO);
        // Mutation: bytes 5 and 9 come back changed; the first one is reported.
        let mut echo = [7; PING_SIZE];
        echo[5] = 8;
        echo[9] = 8;
        assert_eq!(
            ping.verify(&echo, Duration::ZERO),
            Err(PingError::Mismatch { offset: 5 })
        );
    }
}
