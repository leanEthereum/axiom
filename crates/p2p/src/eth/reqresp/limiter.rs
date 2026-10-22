//! Per-peer, per-protocol rate limiting of inbound requests.
//!
//! # Overview
//!
//! Each peer and protocol pair gets a token bucket, implemented as GCRA.
//! A request costs tokens, typically the number of items it asks for.
//!
//! ```text
//! quota: 128 tokens per 10 s  →  one token every 78.125 ms, burst of 128
//!
//! tat = theoretical arrival time of the next conforming token
//! a request of n tokens at time t:
//!   new_tat = max(tat, t) + n * interval
//!   allowed  iff  new_tat - t <= period
//! ```
//!
//! The consensus specs suggest token buckets per protocol without fixing values.
//! See `specs/phase0/p2p-interface.md`, typical rate limiting strategy.

use std::{collections::BTreeMap, error::Error, fmt, time::Duration};

use super::Protocol;
use crate::identity::PeerId;

/// A budget of tokens per period, which is also the largest burst.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quota {
    /// Tokens available per period.
    pub max_tokens: u32,
    /// The period over which the tokens replenish.
    pub period: Duration,
}

/// A request over quota.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RateLimited {
    /// The request would conform after waiting this long.
    RetryAfter(Duration),
    /// The request alone exceeds the whole quota and never conforms.
    TooLarge,
}

impl fmt::Display for RateLimited {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RetryAfter(wait) => write!(f, "rate limited, retry after {wait:?}"),
            Self::TooLarge => f.write_str("request exceeds the whole quota"),
        }
    }
}

impl Error for RateLimited {}

/// Token buckets per peer and protocol.
#[derive(Clone, Debug, Default)]
pub struct RateLimiter {
    /// Quota per protocol; protocols without one are not limited.
    quotas: BTreeMap<Protocol, Quota>,
    /// Theoretical arrival time per peer and protocol.
    buckets: BTreeMap<(PeerId, Protocol), Duration>,
}

impl RateLimiter {
    /// A limiter with no quotas.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            quotas: BTreeMap::new(),
            buckets: BTreeMap::new(),
        }
    }

    /// Quotas in line with what mainnet clients accept.
    ///
    /// Item-counting protocols allow one maximal request per period.
    #[must_use]
    pub fn ethereum() -> Self {
        let quota = |max_tokens, secs| Quota {
            max_tokens,
            period: Duration::from_secs(secs),
        };
        let mut limiter = Self::new();
        for (protocol, quota) in [
            (Protocol::StatusV1, quota(5, 15)),
            (Protocol::StatusV2, quota(5, 15)),
            (Protocol::GoodbyeV1, quota(1, 10)),
            (Protocol::PingV1, quota(2, 10)),
            (Protocol::MetaDataV2, quota(2, 5)),
            (Protocol::MetaDataV3, quota(2, 5)),
            // MAX_REQUEST_BLOCKS_DENEB = 128 blocks.
            (Protocol::BeaconBlocksByRangeV2, quota(128, 10)),
            (Protocol::BeaconBlocksByRootV2, quota(128, 10)),
            (Protocol::BeaconBlocksByHeadV1, quota(128, 10)),
            // MAX_REQUEST_BLOB_SIDECARS_ELECTRA = 1152 sidecars.
            (Protocol::BlobSidecarsByRangeV1, quota(1152, 10)),
            (Protocol::BlobSidecarsByRootV1, quota(1152, 10)),
            // MAX_REQUEST_DATA_COLUMN_SIDECARS = 128 blocks * 128 columns.
            (Protocol::DataColumnSidecarsByRangeV1, quota(16_384, 10)),
            (Protocol::DataColumnSidecarsByRootV1, quota(16_384, 10)),
        ] {
            limiter.set_quota(protocol, quota);
        }
        limiter
    }

    /// Sets or replaces the quota of a protocol.
    pub fn set_quota(&mut self, protocol: Protocol, quota: Quota) {
        self.quotas.insert(protocol, quota);
    }

    /// Charges a request against its bucket, or refuses it.
    pub fn allow(
        &mut self,
        peer: &PeerId,
        protocol: Protocol,
        tokens: u32,
        now: Duration,
    ) -> Result<(), RateLimited> {
        let Some(quota) = self.quotas.get(&protocol).copied() else {
            return Ok(());
        };
        if tokens > quota.max_tokens {
            return Err(RateLimited::TooLarge);
        }
        // Each token is worth one emission interval of the period.
        let interval = quota.period / quota.max_tokens.max(1);
        let tat = self
            .buckets
            .get(&(peer.clone(), protocol))
            .copied()
            .unwrap_or(now)
            .max(now);
        let new_tat = tat + interval * tokens;
        // Conforming when the debt stays within one period.
        let debt = new_tat - now;
        if debt > quota.period {
            return Err(RateLimited::RetryAfter(debt - quota.period));
        }
        self.buckets.insert((peer.clone(), protocol), new_tat);
        Ok(())
    }

    /// Drops buckets that are full again, bounding memory to active peers.
    pub fn prune(&mut self, now: Duration) {
        self.buckets.retain(|_, tat| *tat > now);
    }

    /// Drops every bucket of a disconnected peer.
    pub fn remove_peer(&mut self, peer: &PeerId) {
        self.buckets.retain(|(owner, _), _| owner != peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::PublicKey;

    #[test]
    fn burst_then_steady_rate() {
        let peer = PeerId::from_public_key(&PublicKey::secp256k1([2; 33]));
        let mut limiter = RateLimiter::new();
        // Fixture state: 4 tokens per 4 s → one token per second.
        limiter.set_quota(
            Protocol::PingV1,
            Quota {
                max_tokens: 4,
                period: Duration::from_secs(4),
            },
        );
        let t0 = Duration::from_secs(100);

        // A burst of 4 single-token requests at t0 conforms.
        for _ in 0..4 {
            assert_eq!(limiter.allow(&peer, Protocol::PingV1, 1, t0), Ok(()));
        }
        // The fifth would put the debt at 5 s > 4 s: retry after 1 s.
        assert_eq!(
            limiter.allow(&peer, Protocol::PingV1, 1, t0),
            Err(RateLimited::RetryAfter(Duration::from_secs(1)))
        );
        // One second later one token has come back.
        assert_eq!(
            limiter.allow(&peer, Protocol::PingV1, 1, t0 + Duration::from_secs(1)),
            Ok(())
        );
        // A request for 5 tokens never fits a 4-token quota.
        assert_eq!(
            limiter.allow(&peer, Protocol::PingV1, 5, t0),
            Err(RateLimited::TooLarge)
        );
        // Protocols without a quota pass.
        assert_eq!(limiter.allow(&peer, Protocol::StatusV2, 1000, t0), Ok(()));
    }
}
