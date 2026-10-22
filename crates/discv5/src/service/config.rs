//! Settings of the discovery service.

use std::time::Duration;

use axiom_types::ChainConfig;

use crate::table::TableConfig;

/// Timeouts, concurrency, and maintenance periods of the service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// The routing table settings.
    pub table: TableConfig,
    /// How long a request waits for its response.
    ///
    /// The wire spec suggests 500 ms.
    pub request_timeout: Duration,
    /// How long a challenge waits for its handshake.
    ///
    /// The wire spec suggests 1 s.
    pub handshake_timeout: Duration,
    /// Most sessions kept at once.
    pub session_capacity: usize,
    /// Requests in flight per lookup: alpha.
    pub lookup_parallelism: usize,
    /// Nearest peers a lookup must hear from before it ends: k.
    pub lookup_breadth: usize,
    /// Distances asked for in each lookup request.
    pub lookup_distances: usize,
    /// Most records sent in answer to one FINDNODE.
    ///
    /// The wire spec recommends 16.
    pub max_nodes_response: usize,
    /// How often a table entry is pinged to check it is still alive.
    pub ping_interval: Duration,
    /// How often a lookup for a random id refreshes the table.
    pub refresh_interval: Duration,
    /// The chain parameters custody filters need.
    pub chain: ChainConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            table: TableConfig::default(),
            request_timeout: Duration::from_millis(500),
            handshake_timeout: Duration::from_secs(1),
            session_capacity: 1000,
            lookup_parallelism: 3,
            lookup_breadth: 16,
            lookup_distances: 3,
            max_nodes_response: 16,
            ping_interval: Duration::from_secs(10),
            refresh_interval: Duration::from_secs(60),
            chain: ChainConfig::mainnet(),
        }
    }
}
