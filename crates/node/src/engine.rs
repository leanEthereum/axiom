//! The node's side of the engine API: payload verdicts in, fork choice updates out.

use axiom_execution::{
    EngineClient, ForkchoiceState, NewPayload, PayloadAttributes,
    PayloadStatus as EnginePayloadStatus, PayloadStatusKind,
};
use axiom_fork_choice::PayloadStatus;
use axiom_telemetry::NodeMetrics;
use axiom_types::{
    ForkName, Hash32, Preset, combined,
    gloas::{ExecutionPayloadBid, SignedExecutionPayloadEnvelope},
};
use tracing::{debug, warn};

use crate::{ChainHandle, ExecutionHead};

/// The execution layer as the consensus node sees it.
///
/// # Overview
///
/// Each fork speaks its own version of the engine API.
/// The fork of the payload picks the method once, from the execution crate's table.
///
/// Without an engine the node still follows the chain.
/// Every payload then stays optimistic: imported, but never proven valid.
///
/// ```text
///     engine answer           verdict the fork choice gets
///     VALID                   valid
///     INVALID, bad hash       invalid, with the last valid
///     SYNCING, ACCEPTED       not validated (optimistic)
///     unreachable, malformed  not validated (optimistic)
/// ```
///
/// An unreachable engine never makes a block invalid.
/// See the Bellatrix optimistic sync spec.
#[derive(Debug)]
pub struct ExecutionLayer {
    /// The engine, when one is configured.
    engine: Option<EngineClient>,
    /// Request timings, by engine method.
    metrics: NodeMetrics,
}

impl ExecutionLayer {
    /// A layer over an engine.
    #[must_use]
    pub fn new(engine: EngineClient) -> Self {
        Self {
            engine: Some(engine),
            metrics: NodeMetrics::detached(),
        }
    }

    /// A layer with no engine, which judges nothing.
    #[must_use]
    pub fn disconnected() -> Self {
        Self {
            engine: None,
            metrics: NodeMetrics::detached(),
        }
    }

    /// Records request timings into the node's exported metrics.
    #[must_use]
    pub fn with_metrics(mut self, metrics: NodeMetrics) -> Self {
        self.metrics = metrics;
        self
    }

    /// Asks the engine to judge the payload a block carries.
    ///
    /// A block without a payload has nothing to judge, so the engine has nothing against it.
    /// That covers blocks before the merge, and Gloas blocks, whose payload comes apart.
    pub async fn verdict<P: Preset>(
        &self,
        block: &combined::SignedBeaconBlock<P>,
    ) -> PayloadStatus {
        match NewPayload::from_block(&block.message()) {
            Some(request) => self.judge(&request).await,
            None => PayloadStatus::Valid,
        }
    }

    /// Asks the engine to judge the payload an envelope reveals, under its block's bid.
    pub async fn envelope_verdict<P: Preset>(
        &self,
        envelope: &SignedExecutionPayloadEnvelope<P>,
        bid: &ExecutionPayloadBid,
    ) -> PayloadStatus {
        match NewPayload::from_envelope(&envelope.message, bid) {
            Ok(request) => self.judge(&request).await,
            Err(error) => {
                // The block's own checks bound the bid, so this cannot come from a valid block.
                warn!(%error, root = %envelope.message.beacon_block_root, "envelope has no payload request");
                PayloadStatus::NotValidated
            }
        }
    }

    /// Asks the engine to judge an envelope's payload, reading the bid from the chain.
    ///
    /// Without its block's bid there is nothing to check the payload against, so it stays unjudged.
    pub async fn judge_envelope<P: Preset>(
        &self,
        chain: &ChainHandle<P>,
        envelope: &SignedExecutionPayloadEnvelope<P>,
    ) -> PayloadStatus {
        let root = envelope.message.beacon_block_root;
        match chain.run(move |chain| chain.payload_bid(&root)).await {
            Ok(Some(bid)) => self.envelope_verdict(envelope, &bid).await,
            Ok(None) | Err(_) => PayloadStatus::NotValidated,
        }
    }

    /// Sends a payload to the engine in its fork's method version.
    async fn judge<P: Preset>(&self, request: &NewPayload<P>) -> PayloadStatus {
        let Some(engine) = &self.engine else {
            return PayloadStatus::NotValidated;
        };
        let timer = self
            .metrics
            .engine_request_seconds
            .with_label_values(["new_payload"])
            .start_timer();
        let answer = engine.new_payload(request).await;
        drop(timer);
        match answer {
            Ok(status) => Self::to_verdict(&status),
            Err(error) => {
                // Treat an engine failure like a syncing engine: import, but stay optimistic.
                warn!(fork = %request.fork(), %error, "engine did not judge the payload");
                PayloadStatus::NotValidated
            }
        }
    }

    /// Points the engine at the consensus head, in the method version of the head's fork.
    ///
    /// Before the merge the head has no execution block, so the engine is not told anything.
    ///
    /// # Returns
    ///
    /// The engine's verdict on the head's payload, when it gave one.
    pub async fn update_forkchoice<P: Preset>(
        &self,
        fork: ForkName,
        head: ExecutionHead,
    ) -> Option<PayloadStatus> {
        let engine = self.engine.as_ref()?;
        if head.head == Hash32::ZERO {
            return None;
        }
        let state = ForkchoiceState {
            head_block_hash: head.head,
            safe_block_hash: head.safe,
            finalized_block_hash: head.finalized,
        };
        let timer = self
            .metrics
            .engine_request_seconds
            .with_label_values(["forkchoice_updated"])
            .start_timer();
        let answer = engine
            .forkchoice_updated::<P>(fork, &state, None::<&PayloadAttributes<P>>)
            .await;
        drop(timer);
        match answer {
            Ok(updated) => {
                debug!(status = %updated.payload_status.status, "engine followed the head");
                Some(Self::to_verdict(&updated.payload_status))
            }
            Err(error) => {
                warn!(%fork, %error, "engine did not take the fork choice update");
                None
            }
        }
    }

    /// Reduces the engine's answer to what the fork choice consumes.
    const fn to_verdict(status: &EnginePayloadStatus) -> PayloadStatus {
        match status.status {
            PayloadStatusKind::Valid => PayloadStatus::Valid,
            PayloadStatusKind::Invalid | PayloadStatusKind::InvalidBlockHash => {
                PayloadStatus::Invalid {
                    latest_valid_hash: status.latest_valid_hash,
                }
            }
            PayloadStatusKind::Syncing | PayloadStatusKind::Accepted => PayloadStatus::NotValidated,
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_execution::{JwtSecret, mock::MockEngine};
    use axiom_json::Json;
    use axiom_types::{Minimal, capella, phase0};
    use tokio::runtime::Builder;

    use super::*;

    fn status(kind: PayloadStatusKind, latest_valid_hash: Option<Hash32>) -> EnginePayloadStatus {
        EnginePayloadStatus {
            status: kind,
            latest_valid_hash,
            validation_error: None,
        }
    }

    /// A Capella block whose payload names block hash 0x01.
    fn capella_block() -> combined::SignedBeaconBlock<Minimal> {
        let mut block = capella::SignedBeaconBlock::<Minimal>::default();
        block.message.body.execution_payload.block_hash = Hash32([1; 32]);
        combined::SignedBeaconBlock::Capella(block)
    }

    #[test]
    fn engine_answers_map_onto_fork_choice_verdicts() {
        let hash = Some(Hash32([7; 32]));
        let cases = [
            (PayloadStatusKind::Valid, PayloadStatus::Valid),
            (
                PayloadStatusKind::Invalid,
                PayloadStatus::Invalid {
                    latest_valid_hash: hash,
                },
            ),
            (
                PayloadStatusKind::InvalidBlockHash,
                PayloadStatus::Invalid {
                    latest_valid_hash: hash,
                },
            ),
            (PayloadStatusKind::Syncing, PayloadStatus::NotValidated),
            (PayloadStatusKind::Accepted, PayloadStatus::NotValidated),
        ];
        for (kind, expected) in cases {
            assert_eq!(
                ExecutionLayer::to_verdict(&status(kind, hash)),
                expected,
                "{kind}"
            );
        }
    }

    #[test]
    fn without_an_engine_only_payloads_stay_optimistic() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let layer = ExecutionLayer::disconnected();

        // A phase0 block has no payload, so nothing stands against it.
        let phase0 =
            combined::SignedBeaconBlock::Phase0(phase0::SignedBeaconBlock::<Minimal>::default());
        assert_eq!(
            runtime.block_on(layer.verdict(&phase0)),
            PayloadStatus::Valid
        );

        // A Capella payload waits for an engine that never comes.
        assert_eq!(
            runtime.block_on(layer.verdict(&capella_block())),
            PayloadStatus::NotValidated
        );
    }

    #[test]
    fn the_engine_verdict_reaches_the_fork_choice_in_the_fork_version() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            // Fixture state: a mock engine scripted to call Capella payloads valid.
            let secret = JwtSecret::from_hex(&"ab".repeat(32)).unwrap();
            let mock = MockEngine::start(secret.clone()).await.unwrap();
            mock.reply(
                "engine_newPayloadV2",
                Json::parse(r#"{"status":"VALID","latestValidHash":null,"validationError":null}"#)
                    .unwrap(),
            );
            let layer = ExecutionLayer::new(EngineClient::new(mock.url(), secret).unwrap());

            let verdict = layer.verdict(&capella_block()).await;

            // The engine saw exactly one Capella call, and its verdict came back.
            assert_eq!(verdict, PayloadStatus::Valid);
            let methods: Vec<String> = mock.calls().into_iter().map(|call| call.method).collect();
            assert_eq!(methods, ["engine_newPayloadV2"]);
            mock.stop().await;
        });
    }
}
