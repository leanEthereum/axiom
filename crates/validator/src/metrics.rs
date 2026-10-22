//! The metrics a validator client exports.
//!
//! The names follow the validator client dashboards operators already run, so they plot unchanged.
//! Signature counts carry a status label with one of four values:
//!
//! - success: a new message, recorded and signed.
//! - same_data: a message signed before, signed again harmlessly.
//! - slashable: a message slashing protection refused.
//! - unregistered: a key slashing protection does not know.

use axiom_telemetry::{
    Buckets, CounterVec, Gauge, GaugeVec, HistogramVec, Registry, RegistryError,
};
use axiom_types::Preset;

use crate::{
    protection::{ProtectionError, Refusal, Safety},
    signing::{SignError, SigningRequest, ValidatorSigner},
};

/// Bucket count of the signing latency histogram.
///
/// Twelve doublings from half a millisecond reach one second, a remote signer's worst case.
const LATENCY_BUCKETS: usize = 12;

/// Every metric the validator client updates, registered together.
#[derive(Clone, Debug)]
pub struct ValidatorMetrics {
    /// Validators allowed to sign.
    pub validators_enabled: Gauge,
    /// Validators the client runs, allowed to sign or not.
    pub validators_total: Gauge,
    /// Seconds from genesis to now, negative before genesis.
    pub genesis_distance: Gauge,
    /// Block signatures, by status.
    signed_blocks: CounterVec<1>,
    /// Vote signatures, by status.
    signed_attestations: CounterVec<1>,
    /// Aggregate signatures, by status.
    signed_aggregates: CounterVec<1>,
    /// Aggregator selection proofs, by status.
    signed_selection_proofs: CounterVec<1>,
    /// Sync committee message signatures, by status.
    signed_sync_messages: CounterVec<1>,
    /// Sync contribution signatures, by status.
    signed_sync_contributions: CounterVec<1>,
    /// Sync aggregator selection proofs, by status.
    signed_sync_selection_proofs: CounterVec<1>,
    /// Voluntary exit signatures, by status.
    signed_voluntary_exits: CounterVec<1>,
    /// Builder registration signatures, by status.
    signed_registrations: CounterVec<1>,
    /// Seconds to obtain a signature, by where the key lives.
    signing_seconds: HistogramVec<1>,
    /// Beacon nodes that answered their last check.
    pub beacon_nodes_available: Gauge,
    /// Beacon nodes at the head at their last check.
    pub beacon_nodes_synced: Gauge,
    /// Beacon nodes configured.
    pub beacon_nodes_total: Gauge,
    /// Beacon nodes configured beyond the first.
    pub fallbacks_configured: Gauge,
    /// One when a synced beacon node is reachable, else zero.
    pub fallback_connected: Gauge,
    /// Proposal duties this client holds, by epoch.
    pub proposers: GaugeVec<1>,
    /// Attestation duties this client holds, by epoch.
    pub attesters: GaugeVec<1>,
    /// Payload timeliness duties this client holds, by epoch.
    pub ptc_members: GaugeVec<1>,
}

impl ValidatorMetrics {
    /// The epoch label of a count for the epoch at hand.
    pub const CURRENT_EPOCH: &'static str = "current_epoch";

    /// The epoch label of a count for the epoch after.
    pub const NEXT_EPOCH: &'static str = "next_epoch";

    /// Registers every validator client metric in a registry.
    ///
    /// # Errors
    ///
    /// Fails when a name is already taken in the registry.
    pub fn register(registry: &Registry) -> Result<Self, RegistryError> {
        let status = |name: &str, help: &str| registry.counter_vec(name, help, ["status"]);
        let epoch = |name: &str, help: &str| registry.gauge_vec(name, help, ["task"]);
        // Invariant: the start is a positive finite literal, the factor is 2, and the count is 12.
        // The largest bound is 0.0005 * 2^11, about one second, so the series is valid.
        let latency =
            Buckets::exponential(0.0005, 2.0, LATENCY_BUCKETS).expect("a valid doubling series");
        Ok(Self {
            validators_enabled: registry
                .gauge("vc_validators_enabled_count", "Validators allowed to sign.")?,
            validators_total: registry
                .gauge("vc_validators_total_count", "Validators, enabled or not.")?,
            genesis_distance: registry.gauge(
                "vc_genesis_distance_seconds",
                "Seconds from genesis to now.",
            )?,
            signed_blocks: status("vc_signed_beacon_blocks_total", "Block signings attempted.")?,
            signed_attestations: status(
                "vc_signed_attestations_total",
                "Attestation signings attempted.",
            )?,
            signed_aggregates: status(
                "vc_signed_aggregates_total",
                "Aggregate and proof signings attempted.",
            )?,
            signed_selection_proofs: status(
                "vc_signed_selection_proofs_total",
                "Selection proof signings attempted.",
            )?,
            signed_sync_messages: status(
                "vc_signed_sync_committee_messages_total",
                "Sync committee message signings attempted.",
            )?,
            signed_sync_contributions: status(
                "vc_signed_sync_committee_contributions_total",
                "Contribution and proof signings attempted.",
            )?,
            signed_sync_selection_proofs: status(
                "vc_signed_sync_selection_proofs_total",
                "Sync selection proof signings attempted.",
            )?,
            signed_voluntary_exits: status(
                "vc_signed_voluntary_exits_total",
                "Voluntary exit signings attempted.",
            )?,
            signed_registrations: status(
                "builder_validator_registrations_total",
                "Builder registration signings attempted.",
            )?,
            signing_seconds: registry.histogram_vec(
                "vc_signing_times_seconds",
                "Time to obtain a signature.",
                ["type"],
                latency,
            )?,
            beacon_nodes_available: registry.gauge(
                "vc_beacon_nodes_available_count",
                "Beacon nodes that answered.",
            )?,
            beacon_nodes_synced: registry
                .gauge("vc_beacon_nodes_synced_count", "Beacon nodes at the head.")?,
            beacon_nodes_total: registry
                .gauge("vc_beacon_nodes_total_count", "Beacon nodes configured.")?,
            fallbacks_configured: registry.gauge(
                "sync_eth2_fallback_configured",
                "Beacon nodes configured beyond the first.",
            )?,
            fallback_connected: registry.gauge(
                "sync_eth2_fallback_connected",
                "One when a synced beacon node is reachable.",
            )?,
            proposers: epoch(
                "vc_beacon_block_proposer_count",
                "Block proposers on this host.",
            )?,
            attesters: epoch("vc_beacon_attester_count", "Attesters on this host.")?,
            ptc_members: epoch(
                "vc_beacon_ptc_count",
                "Payload timeliness committee members on this host.",
            )?,
        })
    }

    /// Metrics in a registry of their own, which nothing exports.
    #[must_use]
    pub fn detached() -> Self {
        // Invariant: a fresh registry holds no names, and the set's own names are distinct.
        // Registration can only fail on a taken name, so it cannot fail here.
        Self::register(&Registry::new()).expect("a fresh registry takes every validator metric")
    }

    /// Counts one signing attempt by its outcome.
    ///
    /// Outcomes other than the four statuses, such as a remote signer's failure, are not counted.
    pub fn record<P: Preset>(
        &self,
        request: &SigningRequest<'_, P>,
        outcome: Result<Option<Safety>, &SignError>,
    ) {
        let status = match outcome {
            Ok(None | Some(Safety::Fresh)) => "success",
            Ok(Some(Safety::Repeat)) => "same_data",
            Err(SignError::Protection(ProtectionError::Refused(refusal))) => {
                match refusal.as_ref() {
                    Refusal::Unregistered { .. } => "unregistered",
                    _ => "slashable",
                }
            }
            Err(_) => return,
        };
        if let Some(counter) = self.signed(request) {
            counter.with_label_values([status]).inc();
        }
    }

    /// Records the time one signer took.
    pub fn observe_signing(&self, signer: &ValidatorSigner, seconds: f64) {
        let kind = match signer {
            ValidatorSigner::Local(_) => "local_keystore",
            ValidatorSigner::Remote(_) => "remote_signer",
        };
        self.signing_seconds
            .with_label_values([kind])
            .observe(seconds);
    }

    /// The signature count of a message, for the kinds dashboards plot.
    const fn signed<P: Preset>(&self, request: &SigningRequest<'_, P>) -> Option<&CounterVec<1>> {
        match request {
            SigningRequest::Block(_) => Some(&self.signed_blocks),
            SigningRequest::Attestation(_) => Some(&self.signed_attestations),
            SigningRequest::AggregateAndProof(_) => Some(&self.signed_aggregates),
            SigningRequest::AggregationSlot(_) => Some(&self.signed_selection_proofs),
            SigningRequest::SyncCommitteeMessage { .. } => Some(&self.signed_sync_messages),
            SigningRequest::ContributionAndProof(_) => Some(&self.signed_sync_contributions),
            SigningRequest::SyncSelectionProof(_) => Some(&self.signed_sync_selection_proofs),
            SigningRequest::VoluntaryExit(_) => Some(&self.signed_voluntary_exits),
            SigningRequest::ValidatorRegistration(_) => Some(&self.signed_registrations),
            SigningRequest::RandaoReveal(_)
            | SigningRequest::PayloadAttestation(_)
            | SigningRequest::ExecutionPayloadEnvelope(_)
            | SigningRequest::ProposerPreferences(_)
            | SigningRequest::BlsToExecutionChange(_)
            | SigningRequest::Deposit(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{BlsPubkey, Epoch, Minimal, Slot, phase0::BeaconBlockHeader};

    use super::*;

    #[test]
    fn outcomes_count_under_their_status() {
        let registry = Registry::new();
        let metrics = ValidatorMetrics::register(&registry).unwrap();
        let header = BeaconBlockHeader::default();
        let block = SigningRequest::<Minimal>::Block(&header);

        // One new block, one repeat, one refusal, one unknown key, and one remote failure.
        metrics.record(&block, Ok(Some(Safety::Fresh)));
        metrics.record(&block, Ok(Some(Safety::Repeat)));
        let double = SignError::from(Refusal::BlockNotAfterLatest {
            pubkey: BlsPubkey([1; 48]),
            slot: Slot(3),
            latest: Slot(4),
        });
        metrics.record(&block, Err(&double));
        let unknown = SignError::from(Refusal::Unregistered {
            pubkey: BlsPubkey([1; 48]),
        });
        metrics.record(&block, Err(&unknown));
        metrics.record(&block, Err(&SignError::Unavailable("disk full".to_owned())));

        let text = registry.render();
        for status in ["success", "same_data", "slashable", "unregistered"] {
            let line = format!("vc_signed_beacon_blocks_total{{status=\"{status}\"}} 1\n");
            assert!(text.contains(&line), "{line}");
        }

        // A randao reveal is not a kind dashboards count.
        metrics.record(&SigningRequest::<Minimal>::RandaoReveal(Epoch(1)), Ok(None));
        assert_eq!(registry.render(), text);
    }
}
