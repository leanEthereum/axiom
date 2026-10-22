//! The node's side of the engine API: payload verdicts in, fork choice updates out.

use axiom_execution::{
    EngineClient, ForkchoiceState, PayloadStatus as EnginePayloadStatus, PayloadStatusKind,
};
use axiom_fork_choice::PayloadStatus;
use axiom_telemetry::NodeMetrics;
use axiom_types::{BeaconBlock, Preset};
use tracing::{debug, warn};

use crate::ExecutionHead;

/// The execution layer as the consensus node sees it.
///
/// # Overview
///
/// Without an engine the node still follows the chain.
/// Every payload then stays optimistic: imported, but never proven valid.
///
/// | engine answer          | verdict the fork choice gets |
/// |------------------------|------------------------------|
/// | VALID                  | valid                        |
/// | INVALID, bad hash      | invalid, with the last valid |
/// | SYNCING, ACCEPTED      | not validated (optimistic)   |
/// | unreachable, malformed | not validated (optimistic)   |
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

    /// Asks the engine to judge a block's payload.
    pub async fn verdict<P: Preset>(&self, block: &BeaconBlock<P>) -> PayloadStatus {
        let Some(engine) = &self.engine else {
            return PayloadStatus::NotValidated;
        };
        let timer = self
            .metrics
            .engine_request_seconds
            .with_label_values(["new_payload"])
            .start_timer();
        let answer = engine.new_payload(&block.new_payload_request()).await;
        drop(timer);
        match answer {
            Ok(status) => Self::to_verdict(&status),
            Err(error) => {
                // Treat an engine failure like a syncing engine: import, but stay optimistic.
                warn!(slot = %block.slot, %error, "engine did not judge the payload");
                PayloadStatus::NotValidated
            }
        }
    }

    /// Points the engine at the consensus head.
    ///
    /// # Returns
    ///
    /// The engine's verdict on the head's payload, when it gave one.
    pub async fn update_forkchoice<P: Preset>(&self, head: ExecutionHead) -> Option<PayloadStatus> {
        let engine = self.engine.as_ref()?;
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
        let answer = engine.forkchoice_updated::<P>(&state, None).await;
        drop(timer);
        match answer {
            Ok(updated) => {
                debug!(status = %updated.payload_status.status, "engine followed the head");
                Some(Self::to_verdict(&updated.payload_status))
            }
            Err(error) => {
                warn!(%error, "engine did not take the fork choice update");
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
    use axiom_types::{Hash32, Minimal};
    use tokio::runtime::Builder;

    use super::*;

    fn status(kind: PayloadStatusKind, latest_valid_hash: Option<Hash32>) -> EnginePayloadStatus {
        EnginePayloadStatus {
            status: kind,
            latest_valid_hash,
            validation_error: None,
        }
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
    fn without_an_engine_every_payload_stays_optimistic() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let layer = ExecutionLayer::disconnected();

        let verdict = runtime.block_on(layer.verdict(&BeaconBlock::<Minimal>::default()));

        assert_eq!(verdict, PayloadStatus::NotValidated);
    }

    #[test]
    fn the_engine_verdict_reaches_the_fork_choice() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            // Fixture state: a mock engine scripted to call the payload valid.
            let secret = JwtSecret::from_hex(&"ab".repeat(32)).unwrap();
            let mock = MockEngine::start(secret.clone()).await.unwrap();
            mock.reply(
                "engine_newPayloadV4",
                Json::parse(r#"{"status":"VALID","latestValidHash":null,"validationError":null}"#)
                    .unwrap(),
            );
            let layer = ExecutionLayer::new(EngineClient::new(mock.url(), secret).unwrap());

            let verdict = layer.verdict(&BeaconBlock::<Minimal>::default()).await;

            // The engine saw exactly one payload, and its verdict came back.
            assert_eq!(verdict, PayloadStatus::Valid);
            assert_eq!(mock.calls().len(), 1);
            mock.stop().await;
        });
    }
}
