//! Router parameters, with the values the consensus p2p spec mandates.

use std::time::Duration;

use crate::eth::{GossipEncoding, MessageIds};

/// Gossipsub parameters.
///
/// Defaults follow the phase0 p2p-interface gossipsub section.
/// The v1.1 and v1.2 extras follow the libp2p reference implementations.
#[derive(Clone, Debug)]
pub struct GossipsubConfig {
    /// D: the target mesh degree.
    pub mesh_n: usize,
    /// D_low: below this, the heartbeat grafts more peers.
    pub mesh_n_low: usize,
    /// D_high: above this, the heartbeat prunes peers.
    pub mesh_n_high: usize,
    /// D_score: peers kept by score when pruning an oversized mesh.
    pub mesh_n_score: usize,
    /// D_out: outbound peers the mesh keeps, against eclipse attacks.
    ///
    /// Must stay below D_low and at most D / 2.
    pub mesh_outbound_min: usize,
    /// D_lazy: minimum peers that receive gossip per topic.
    pub gossip_lazy: usize,
    /// Share of eligible non-mesh peers that receive gossip, when above D_lazy.
    pub gossip_factor: f64,

    /// Time between heartbeats.
    pub heartbeat_interval: Duration,
    /// Time a fanout set lives after the last publish to its topic.
    pub fanout_ttl: Duration,
    /// Heartbeats a message stays in the cache, for IWANT answers.
    pub history_length: usize,
    /// Heartbeats of the cache that IHAVE announcements cover.
    pub history_gossip: usize,
    /// Time a message identifier stays in the seen cache.
    pub seen_ttl: Duration,

    /// Backoff a pruned peer must wait before grafting again.
    pub prune_backoff: Duration,
    /// Backoff announced when leaving a topic.
    pub unsubscribe_backoff: Duration,
    /// A graft this soon after a backoff expires earns an extra penalty.
    pub graft_flood_threshold: Duration,
    /// Peers offered in a PRUNE for peer exchange.
    pub prune_peers: usize,
    /// Most identifiers requested from one peer per heartbeat.
    pub max_ihave_length: usize,
    /// Most IHAVE messages accepted from one peer per heartbeat.
    pub max_ihave_messages: usize,
    /// Time a peer has to deliver a message it announced and was asked for.
    pub iwant_followup_time: Duration,
    /// Most times one message is sent to one peer in IWANT answers.
    pub gossip_retransmission: usize,
    /// Heartbeats between opportunistic grafting rounds.
    pub opportunistic_graft_ticks: u64,
    /// Peers grafted per opportunistic round.
    pub opportunistic_graft_peers: usize,
    /// Whether own messages go to every topic peer above the publish threshold.
    pub flood_publish: bool,
    /// Messages at least this large trigger IDONTWANT to mesh peers.
    pub idontwant_message_size_threshold: usize,
    /// Most IDONTWANT identifiers accepted from one peer per heartbeat.
    pub max_idontwant_messages: usize,
    /// Heartbeats an IDONTWANT entry is honoured.
    pub idontwant_heartbeats: u32,
    /// Time the application has to validate a message before it is dropped.
    pub validation_timeout: Duration,

    /// Largest encoded RPC accepted or sent.
    pub max_transmit_size: usize,
    /// How message identifiers derive from topics and data.
    pub message_id: MessageIds,
}

impl GossipsubConfig {
    /// The Ethereum consensus parameters.
    ///
    /// # Arguments
    ///
    /// - `slot`: the slot duration, which sets the seen cache lifetime.
    /// - `slots_per_epoch`: the preset epoch length.
    /// - `max_payload_size`: the configured MAX_PAYLOAD_SIZE.
    #[must_use]
    pub fn ethereum(slot: Duration, slots_per_epoch: u32, max_payload_size: u64) -> Self {
        Self {
            // Mesh degrees from the phase0 p2p-interface gossipsub parameters.
            mesh_n: 8,
            mesh_n_low: 6,
            mesh_n_high: 12,
            mesh_n_score: 4,
            mesh_outbound_min: 2,
            gossip_lazy: 6,
            gossip_factor: 0.25,
            heartbeat_interval: Duration::from_millis(700),
            fanout_ttl: Duration::from_secs(60),
            history_length: 6,
            history_gossip: 3,
            // seen_ttl = SLOT_DURATION * SLOTS_PER_EPOCH * 2: two epochs.
            seen_ttl: slot * slots_per_epoch * 2,
            prune_backoff: Duration::from_secs(60),
            unsubscribe_backoff: Duration::from_secs(10),
            graft_flood_threshold: Duration::from_secs(10),
            prune_peers: 16,
            max_ihave_length: 5000,
            max_ihave_messages: 10,
            iwant_followup_time: Duration::from_secs(3),
            gossip_retransmission: 3,
            opportunistic_graft_ticks: 60,
            opportunistic_graft_peers: 2,
            flood_publish: true,
            idontwant_message_size_threshold: 1000,
            max_idontwant_messages: 1000,
            idontwant_heartbeats: 3,
            validation_timeout: Duration::from_secs(30),
            max_transmit_size: GossipEncoding::new(max_payload_size).max_message_size(),
            message_id: MessageIds::default(),
        }
    }
}

impl Default for GossipsubConfig {
    /// The mainnet parameters: 12-second slots, 32-slot epochs, 10 MiB payloads.
    fn default() -> Self {
        Self::ethereum(Duration::from_secs(12), 32, 10 * 1024 * 1024)
    }
}
