//! The node's side of the engine API: payload verdicts in, fork choice updates out.

use std::sync::Arc;

use axiom_execution::{
    EngineClient, ForkchoiceState, GetPayloadResponse, NewPayload, PayloadAttributes, PayloadId,
    PayloadStatus as EnginePayloadStatus, PayloadStatusKind,
};
use axiom_fork_choice::PayloadStatus;
use axiom_telemetry::NodeMetrics;
use axiom_types::{
    ForkName, Hash32, Preset,
    bellatrix::PowBlock,
    combined,
    gloas::{ExecutionPayloadBid, SignedExecutionPayloadEnvelope},
};
use tracing::{debug, warn};

use crate::{ChainHandle, ExecutionHead, ProposerError};

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
///
/// A merge block also needs the terminal proof-of-work block and its parent.
/// The layer fetches both from the engine and hands them to the chain before the import.
/// Without them, an unvalidated merge block imports only once old enough, per the optimistic rule.
/// A validated one is refused, as the spec asks.
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
    ///
    /// A merge block first gets its terminal proof-of-work blocks handed to the chain.
    pub async fn verdict<P: Preset>(
        &self,
        chain: &ChainHandle<P>,
        block: &Arc<combined::SignedBeaconBlock<P>>,
    ) -> PayloadStatus {
        self.report_terminal_blocks(chain, block).await;
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

    /// Hands the chain the proof-of-work blocks a merge block's terminal check reads.
    ///
    /// Only a Bellatrix block can be a merge block, so other forks cost no chain round trip.
    async fn report_terminal_blocks<P: Preset>(
        &self,
        chain: &ChainHandle<P>,
        block: &Arc<combined::SignedBeaconBlock<P>>,
    ) {
        if self.engine.is_none() || !block.fork_name().validates_merge_block() {
            return;
        }
        let checked = Arc::clone(block);
        let lookup = chain.run(move |chain| chain.terminal_block_lookup(&checked));
        let Ok(Some(hash)) = lookup.await else {
            return;
        };
        let blocks = self.terminal_blocks(hash).await;
        if blocks.is_empty() {
            return;
        }
        // A stopped chain imports nothing either, so its absence needs no handling.
        let _stopped = chain
            .run(move |chain| {
                for block in blocks {
                    chain.on_pow_block(block);
                }
            })
            .await;
    }

    /// The terminal proof-of-work block and its parent, as far as the engine knows them.
    ///
    /// The terminal block must reach the terminal total difficulty, and its parent must not.
    /// The parent is fetched only when the terminal block is known.
    /// See `is_valid_terminal_pow_block` in the Bellatrix fork choice spec.
    async fn terminal_blocks(&self, hash: Hash32) -> Vec<PowBlock> {
        let Some(terminal) = self.pow_block(hash).await else {
            return Vec::new();
        };
        let parent = self.pow_block(terminal.parent_hash).await;
        let mut blocks = vec![terminal];
        blocks.extend(parent);
        blocks
    }

    /// A proof-of-work block from the engine, or nothing when it is unknown or unreachable.
    async fn pow_block(&self, hash: Hash32) -> Option<PowBlock> {
        let engine = self.engine.as_ref()?;
        let timer = self
            .metrics
            .engine_request_seconds
            .with_label_values(["get_block_by_hash"])
            .start_timer();
        let answer = engine.pow_block(hash).await;
        drop(timer);
        match answer {
            Ok(Some(block)) => Some(block),
            Ok(None) => {
                debug!(%hash, "engine does not know the proof-of-work block");
                None
            }
            Err(error) => {
                warn!(%hash, %error, "engine did not return the proof-of-work block");
                None
            }
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
    /// Asks the engine to start building a payload on an execution head.
    ///
    /// # Returns
    ///
    /// The build's identifier, or nothing when the engine started no build.
    ///
    /// # Errors
    ///
    /// Fails when no engine is configured, or the call fails.
    pub async fn start_build<P: Preset>(
        &self,
        fork: ForkName,
        head: ExecutionHead,
        attributes: &PayloadAttributes<P>,
    ) -> Result<Option<PayloadId>, ProposerError> {
        let engine = self.engine.as_ref().ok_or(ProposerError::NoEngine)?;
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
        let updated = engine
            .forkchoice_updated::<P>(fork, &state, Some(attributes))
            .await;
        drop(timer);
        Ok(updated.map_err(ProposerError::Engine)?.payload_id)
    }

    /// Fetches the payload a build produced.
    ///
    /// # Errors
    ///
    /// Fails when no engine is configured, or the call fails.
    pub async fn fetch_payload<P: Preset>(
        &self,
        fork: ForkName,
        id: PayloadId,
    ) -> Result<GetPayloadResponse<P>, ProposerError> {
        let engine = self.engine.as_ref().ok_or(ProposerError::NoEngine)?;
        let timer = self
            .metrics
            .engine_request_seconds
            .with_label_values(["get_payload"])
            .start_timer();
        let payload = engine.get_payload::<P>(fork, id).await;
        drop(timer);
        payload.map_err(ProposerError::Engine)
    }

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
    use axiom_execution::{JsonCodec, JwtSecret, mock::MockEngine};
    use axiom_json::Json;
    use axiom_ssz::U256;
    use axiom_types::{ChainConfig, Minimal, Slot, bellatrix, capella, phase0};
    use tokio::runtime::Builder;

    use super::*;
    use crate::{Chain, ChainDatabase};

    fn status(kind: PayloadStatusKind, latest_valid_hash: Option<Hash32>) -> EnginePayloadStatus {
        EnginePayloadStatus {
            status: kind,
            latest_valid_hash,
            validation_error: None,
        }
    }

    /// A Capella block whose payload names block hash 0x01.
    fn capella_block() -> Arc<combined::SignedBeaconBlock<Minimal>> {
        let mut block = capella::SignedBeaconBlock::<Minimal>::default();
        block.message.body.execution_payload.block_hash = Hash32([1; 32]);
        Arc::new(combined::SignedBeaconBlock::Capella(block))
    }

    /// A chain thread from an empty genesis state of a configuration's genesis fork.
    fn chain(config: ChainConfig, genesis: combined::BeaconState<Minimal>) -> ChainHandle<Minimal> {
        let database = ChainDatabase::in_memory(config.clone()).unwrap();
        let chain = Chain::from_genesis(config, genesis, database).unwrap();
        // The thread ends once the handle drops.
        ChainHandle::spawn(chain).unwrap().0
    }

    /// A Bellatrix chain still before the merge, with Bellatrix from genesis.
    fn bellatrix_chain(config: ChainConfig) -> ChainHandle<Minimal> {
        let genesis = bellatrix::BeaconState::<Minimal>::default();
        chain(
            config.with_forks_at_genesis(ForkName::Bellatrix),
            combined::BeaconState::Bellatrix(genesis),
        )
    }

    /// The merge block on the empty Bellatrix genesis: its payload builds on block 0x0a.
    fn merge_block() -> Arc<combined::SignedBeaconBlock<Minimal>> {
        let genesis =
            combined::BeaconState::Bellatrix(bellatrix::BeaconState::<Minimal>::default());
        let mut block = bellatrix::SignedBeaconBlock::<Minimal>::default();
        block.message.slot = Slot(1);
        block.message.parent_root = combined::BeaconBlock::genesis(&genesis).hash_tree_root();
        block.message.body.execution_payload.parent_hash = Hash32([0x0a; 32]);
        block.message.body.execution_payload.block_hash = Hash32([0x0b; 32]);
        Arc::new(combined::SignedBeaconBlock::Bellatrix(block))
    }

    /// A proof-of-work block with a hash, a parent, and a total difficulty.
    fn pow(hash: u8, parent: u8, total_difficulty: u64) -> PowBlock {
        PowBlock {
            block_hash: Hash32([hash; 32]),
            parent_hash: Hash32([parent; 32]),
            total_difficulty: U256::from_u64(total_difficulty),
        }
    }

    /// A mock engine that calls every Bellatrix payload valid, and a layer over it.
    async fn valid_engine() -> (MockEngine, ExecutionLayer) {
        let secret = JwtSecret::from_hex(&"ab".repeat(32)).unwrap();
        let mock = MockEngine::start(secret.clone()).await.unwrap();
        mock.reply(
            "engine_newPayloadV1",
            Json::parse(r#"{"status":"VALID","latestValidHash":null,"validationError":null}"#)
                .unwrap(),
        );
        mock.reply("eth_getBlockByHash", Json::Null);
        let layer = ExecutionLayer::new(EngineClient::new(mock.url(), secret).unwrap());
        (mock, layer)
    }

    /// The method and first parameter of each call the engine received.
    fn calls(mock: &MockEngine) -> Vec<(String, Json)> {
        mock.calls()
            .into_iter()
            .map(|call| (call.method, call.params[0].clone()))
            .collect()
    }

    /// A lookup of a block hash, as the calls list shows it.
    fn lookup(hash: u8) -> (String, Json) {
        (
            "eth_getBlockByHash".to_owned(),
            Hash32([hash; 32]).to_json(),
        )
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
        let config = ChainConfig::minimal();
        let chain = chain(
            config,
            combined::BeaconState::Phase0(phase0::BeaconState::default()),
        );

        // A phase0 block has no payload, so nothing stands against it.
        let phase0 = Arc::new(combined::SignedBeaconBlock::Phase0(
            phase0::SignedBeaconBlock::<Minimal>::default(),
        ));
        assert_eq!(
            runtime.block_on(layer.verdict(&chain, &phase0)),
            PayloadStatus::Valid
        );

        // A Capella payload waits for an engine that never comes.
        assert_eq!(
            runtime.block_on(layer.verdict(&chain, &capella_block())),
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
            let config = ChainConfig::minimal().with_forks_at_genesis(ForkName::Capella);
            let chain = chain(
                config,
                combined::BeaconState::Capella(capella::BeaconState::default()),
            );

            let verdict = layer.verdict(&chain, &capella_block()).await;

            // The engine saw exactly one Capella call, and its verdict came back.
            assert_eq!(verdict, PayloadStatus::Valid);
            let methods: Vec<String> = mock.calls().into_iter().map(|call| call.method).collect();
            assert_eq!(methods, ["engine_newPayloadV2"]);
            mock.stop().await;
        });
    }

    #[test]
    fn a_merge_block_has_its_terminal_block_and_parent_fetched_first() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            // Fixture state: the engine knows terminal block 0x0a and its parent 0x09.
            let (mock, layer) = valid_engine().await;
            mock.serve_pow_block(&pow(0x0a, 0x09, 100));
            mock.serve_pow_block(&pow(0x09, 0x08, 90));
            let chain = bellatrix_chain(ChainConfig::minimal());

            let verdict = layer.verdict(&chain, &merge_block()).await;

            // The terminal block, then its parent, then the payload itself.
            assert_eq!(verdict, PayloadStatus::Valid);
            let calls = calls(&mock);
            assert_eq!(calls[..2], [lookup(0x0a), lookup(0x09)]);
            assert_eq!(calls[2].0, "engine_newPayloadV1");
            assert_eq!(calls.len(), 3);
            mock.stop().await;
        });
    }

    #[test]
    fn an_unknown_terminal_block_ends_the_lookup() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            // Fixture state: the engine knows no proof-of-work block at all.
            let (mock, layer) = valid_engine().await;
            let chain = bellatrix_chain(ChainConfig::minimal());

            layer.verdict(&chain, &merge_block()).await;

            // Block 0x0a is unknown, so its parent is never asked for.
            let methods: Vec<String> = mock.calls().into_iter().map(|call| call.method).collect();
            assert_eq!(methods, ["eth_getBlockByHash", "engine_newPayloadV1"]);
            assert_eq!(calls(&mock)[0], lookup(0x0a));
            mock.stop().await;
        });
    }

    #[test]
    fn a_hand_fixed_terminal_block_needs_no_lookup() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            // Fixture state: the configuration fixes terminal block 0x0a by hand.
            let (mock, layer) = valid_engine().await;
            let config = ChainConfig {
                terminal_block_hash: Hash32([0x0a; 32]),
                ..ChainConfig::minimal()
            };
            let chain = bellatrix_chain(config);

            layer.verdict(&chain, &merge_block()).await;

            // The hash alone settles the check, so only the payload goes to the engine.
            let methods: Vec<String> = mock.calls().into_iter().map(|call| call.method).collect();
            assert_eq!(methods, ["engine_newPayloadV1"]);
            mock.stop().await;
        });
    }
}
