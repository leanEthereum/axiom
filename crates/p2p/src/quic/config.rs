//! What every connection of an endpoint shares: identity, limits, and timers.

use std::{sync::Arc, time::Duration};

use super::StreamLimits;
use crate::tls::TlsIdentity;

/// Settings of an endpoint and its connections.
#[derive(Clone, Debug)]
pub struct QuicConfig {
    /// The certificate and key that authenticate this node.
    pub identity: Arc<TlsIdentity>,
    /// Local stream and flow control limits.
    pub limits: StreamLimits,
    /// Idle time after which a connection closes silently.
    pub idle_timeout: Duration,
    /// Quiet time after which a connection sends a PING to stay alive.
    pub keep_alive: Option<Duration>,
    /// The largest UDP payload sent.
    pub max_datagram: usize,
    /// The longest this side delays an acknowledgment.
    pub max_ack_delay: Duration,
}

impl QuicConfig {
    /// Settings suited to the consensus req/resp and gossip traffic.
    #[must_use]
    pub const fn new(identity: Arc<TlsIdentity>) -> Self {
        Self {
            identity,
            limits: StreamLimits {
                // Threshold: a 10 MiB response chunk streams within a few windows.
                stream_window: 1 << 20,
                connection_window: 4 << 20,
                // Threshold: a few hundred concurrent requests, as the yamux streams allow.
                max_inbound_streams: 256,
                send_buffer: 1 << 20,
            },
            idle_timeout: Duration::from_secs(30),
            keep_alive: Some(Duration::from_secs(10)),
            // Threshold: without path MTU discovery, stay a little above the 1200-byte floor.
            // That fits paths through tunnels whose MTU sits below 1500.
            max_datagram: 1252,
            max_ack_delay: Duration::from_millis(25),
        }
    }
}
