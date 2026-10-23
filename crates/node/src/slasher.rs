//! The slasher beside the chain: fed verified votes and headers, it hands back evidence.

use std::{
    io,
    marker::PhantomData,
    path::Path,
    sync::{Arc, mpsc as std_mpsc},
    thread,
    time::Duration,
};

use axiom_fork_choice::Store;
use axiom_p2p::eth::GossipKind;
use axiom_slasher::{Slasher, SlasherConfig, SlasherDatabase, SlasherError, Slashing};
use axiom_types::{
    BlsSignature, Epoch, Preset, ValidatorIndex, combined,
    phase0::{AttestationData, SignedBeaconBlockHeader},
    vote::{CommitteeVote, IndexedVote},
};
use tokio::{
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender, error::TrySendError},
    task::{self, JoinHandle},
};
use tracing::{debug, info, warn};

use crate::{NodeError, Publisher, target_committees::TargetCommittees};

/// Observations that may queue for the slasher thread before new ones are dropped.
///
/// A mainnet epoch brings about 32 thousand aggregates, under a thousand a slot.
/// The bound absorbs a pass that runs long without letting the queue grow unbounded.
const FEED_DEPTH: usize = 1 << 16;

/// What the chain thread hands the slasher thread.
#[derive(Debug)]
enum Observation {
    /// A vote whose signature was verified, with its signers.
    Vote(IndexedVote),
    /// A block header whose proposer signature was verified.
    Header(SignedBeaconBlockHeader),
    /// The clock entered a new slot of this epoch: time for a pass.
    Pass(Epoch),
}

/// The chain's end of the slasher: it names each vote's signers and queues what it saw.
///
/// # Overview
///
/// Only verified messages enter, so evidence never rests on a forged signature.
///
/// - Aggregates and single votes enter once the fork choice verified them.
/// - Blocks enter once imported: their header, and every vote in their body.
///
/// Signers come from the committees of the vote's target checkpoint, as the spec computes them.
/// The slasher thread does the rest, so the chain thread never waits on its disk.
/// Evidence comes back the same way, and the chain collects it once a slot.
///
/// The thread ends once the feed is dropped with the chain.
/// Each pass commits atomically, so stopping mid-pass loses only the queue.
#[derive(Debug)]
pub(crate) struct SlasherFeed<P: Preset> {
    /// The slasher thread's queue.
    queue: mpsc::Sender<Observation>,
    /// Evidence the slasher thread found.
    evidence: std_mpsc::Receiver<Slashing>,
    /// Committees of recent targets, to name each vote's signers.
    committees: TargetCommittees,
    /// Least time between two passes, in milliseconds; zero passes at every tick.
    period_ms: u64,
    /// When the last pass was asked for, in Unix milliseconds.
    last_pass_ms: Option<u64>,
    /// Where accepted evidence goes to be gossiped, when the operator broadcasts it.
    broadcasts: Option<UnboundedSender<FoundSlashing>>,
    /// The preset of the states committees come from.
    preset: PhantomData<P>,
}

impl<P: Preset> SlasherFeed<P> {
    /// Opens the slasher's database and starts its thread.
    ///
    /// # Errors
    ///
    /// Fails when the database cannot be opened under the layout, or the thread cannot start.
    pub(crate) fn start(
        config: SlasherConfig,
        directory: Option<&Path>,
    ) -> Result<Self, NodeError> {
        let database = match directory {
            Some(directory) => SlasherDatabase::open(directory),
            None => SlasherDatabase::in_memory(),
        }
        .map_err(NodeError::Slasher)?;
        let slasher = Slasher::<P>::open(config, database).map_err(NodeError::Slasher)?;
        let (queue, observations) = mpsc::channel(FEED_DEPTH);
        // Unbounded: evidence is rare, and the chain never waits on this thread.
        let (found, evidence) = std_mpsc::channel();
        let worker = SlasherWorker { slasher, found };
        thread::Builder::new()
            .name("slasher".to_owned())
            .spawn(move || worker.run(observations))
            .map_err(|error: io::Error| NodeError::Io {
                context: "spawning the slasher thread",
                error,
            })?;
        info!(history = config.history_length, "slasher enabled");
        Ok(Self {
            queue,
            evidence,
            committees: TargetCommittees::default(),
            period_ms: 0,
            last_pass_ms: None,
            broadcasts: None,
            preset: PhantomData,
        })
    }

    /// Passes at most once per period instead of once per slot; none keeps once per slot.
    ///
    /// A longer period batches more votes per pass, trading detection delay for disk reads.
    #[must_use]
    pub(crate) fn with_update_period(mut self, period: Option<Duration>) -> Self {
        self.period_ms = period.map_or(0, |period| {
            u64::try_from(period.as_millis()).unwrap_or(u64::MAX)
        });
        self
    }

    /// Queues an aggregate vote, once its signers are known.
    pub(crate) fn vote(&mut self, store: &Store<P>, vote: &CommitteeVote) {
        let data = &vote.data;
        match self.committees.signers(store, vote) {
            Some(indices) => self.send(Observation::Vote(IndexedVote {
                indices,
                data: data.clone(),
                signature: vote.signature,
            })),
            None => debug!(slot = %data.slot, "vote signers unresolved; slasher skips it"),
        }
    }

    /// Queues one validator's vote.
    pub(crate) fn single(
        &self,
        attester: ValidatorIndex,
        data: &AttestationData,
        signature: BlsSignature,
    ) {
        self.send(Observation::Vote(IndexedVote {
            indices: vec![attester],
            data: data.clone(),
            signature,
        }));
    }

    /// Queues an imported block's header and the votes its body carries.
    pub(crate) fn block(&mut self, store: &Store<P>, block: &combined::SignedBeaconBlock<P>) {
        let message = block.message();
        self.send(Observation::Header(SignedBeaconBlockHeader {
            message: message.header(),
            signature: *block.signature(),
        }));
        for vote in message.committee_votes() {
            self.vote(store, &vote);
        }
    }

    /// Asks for a pass at an epoch, if the update period has run since the last one.
    pub(crate) fn tick(&mut self, now_ms: u64, epoch: Epoch) {
        if self.pass_due(now_ms) {
            self.last_pass_ms = Some(now_ms);
            self.send(Observation::Pass(epoch));
        }
    }

    /// Whether the update period has run since the last pass.
    fn pass_due(&self, now_ms: u64) -> bool {
        self.last_pass_ms
            .is_none_or(|last| now_ms.saturating_sub(last) >= self.period_ms)
    }

    /// Evidence found since the last call.
    pub(crate) fn found(&self) -> Vec<Slashing> {
        self.evidence.try_iter().collect()
    }

    /// Sends the evidence the chain accepts on to a broadcaster.
    pub(crate) fn broadcast_to(&mut self, broadcasts: UnboundedSender<FoundSlashing>) {
        self.broadcasts = Some(broadcasts);
    }

    /// Whether accepted evidence goes out on the network.
    pub(crate) const fn broadcasts(&self) -> bool {
        self.broadcasts.is_some()
    }

    /// Hands encoded evidence to the broadcaster, if there is one.
    pub(crate) fn spread(&self, found: FoundSlashing) {
        if let Some(broadcasts) = &self.broadcasts {
            // A stopped broadcaster means the node is stopping; the evidence stays pooled.
            let _stopped = broadcasts.send(found);
        }
    }

    /// Queues an observation, dropping it when the slasher thread is far behind.
    fn send(&self, observation: Observation) {
        match self.queue.try_send(observation) {
            Err(TrySendError::Full(_)) => warn!("slasher queue full; observation dropped"),
            // A stopped thread already logged why.
            Ok(()) | Err(TrySendError::Closed(_)) => {}
        }
    }
}

/// Evidence the slasher found, encoded for its gossip topic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FoundSlashing {
    /// The attester or proposer slashing topic.
    pub(crate) kind: GossipKind,
    /// The epoch whose fork encoded the evidence, which picks the topic's digest.
    pub(crate) epoch: Epoch,
    /// The evidence, SSZ-encoded in that fork's container.
    pub(crate) message: Vec<u8>,
}

/// Gossips the evidence the slasher found, so every proposer can include it.
///
/// Evidence reaches the network only after the chain pooled it and checked it as gossip would.
/// Evidence already received from a peer is therefore never sent back out.
/// See `validate_attester_slashing_gossip` in the phase0 p2p spec.
#[derive(Debug)]
pub(crate) struct SlashingBroadcaster<P: Preset> {
    /// Evidence from the chain thread.
    found: UnboundedReceiver<FoundSlashing>,
    /// The gossip publisher.
    publisher: Arc<Publisher<P>>,
}

impl<P: Preset> SlashingBroadcaster<P> {
    /// Starts broadcasting the evidence a channel brings, when the chain has one.
    pub(crate) fn spawn(
        found: Option<UnboundedReceiver<FoundSlashing>>,
        publisher: &Arc<Publisher<P>>,
    ) -> Option<JoinHandle<()>> {
        let broadcaster = Self {
            found: found?,
            publisher: Arc::clone(publisher),
        };
        Some(task::spawn(broadcaster.run()))
    }

    /// Publishes evidence until the chain drops its end.
    async fn run(mut self) {
        while let Some(found) = self.found.recv().await {
            info!(kind = %found.kind, "broadcasting slasher evidence");
            self.publisher
                .gossip(found.kind, found.epoch, found.message)
                .await;
        }
    }
}

/// The slasher thread's state: the slasher, and where its evidence goes.
#[derive(Debug)]
struct SlasherWorker<P: Preset> {
    /// The slasher.
    slasher: Slasher<P>,
    /// The chain's end of the evidence channel.
    found: std_mpsc::Sender<Slashing>,
}

impl<P: Preset> SlasherWorker<P> {
    /// Takes observations until the feed is dropped.
    fn run(mut self, mut observations: mpsc::Receiver<Observation>) {
        // Blocking receive is right here: this thread does nothing else.
        while let Some(observation) = observations.blocking_recv() {
            match observation {
                Observation::Vote(vote) => self.slasher.accept_vote(vote),
                Observation::Header(header) => self.slasher.accept_header(header),
                Observation::Pass(epoch) => {
                    if let Err(error) = self.pass(epoch) {
                        warn!(%error, "slasher pass failed; its observations stay queued");
                    }
                }
            }
        }
    }

    /// Runs a pass and sends its evidence to the chain.
    fn pass(&mut self, epoch: Epoch) -> Result<(), SlasherError> {
        let pass = self.slasher.process(epoch)?;
        debug!(
            %epoch,
            votes = pass.votes,
            headers = pass.headers,
            deferred = pass.deferred,
            dropped = pass.dropped,
            pruned = pass.pruned,
            "slasher pass"
        );
        for slashing in pass.slashings {
            // A closed receiver means the chain is gone; the evidence has nowhere to go.
            if self.found.send(slashing).is_err() {
                break;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use axiom_ssz::Ssz;
    use axiom_types::{
        BlsSignature, ChainConfig, Domain, Minimal, Root, Slot,
        constants::DOMAIN_BEACON_PROPOSER,
        phase0::{self, BeaconBlockHeader, ProposerSlashing},
    };
    use tokio::sync::mpsc::unbounded_channel;

    use super::*;
    use crate::{
        Chain, ChainDatabase,
        api::fixture::{BALANCE, TestApi, secret, validator},
    };

    #[test]
    fn found_evidence_goes_out_once_checked_and_pooled() {
        // Fixture state: 8 validators at genesis, a slasher, and a broadcast channel.
        let config = ChainConfig::minimal();
        let registry = (0..8).map(|index| (validator(index), BALANCE));
        let genesis = TestApi::phase0_genesis(registry);
        let database = ChainDatabase::in_memory(config.clone()).unwrap();
        let feed = SlasherFeed::start(SlasherConfig::default(), None).unwrap();
        let (broadcasts, mut found) = unbounded_channel();
        let mut chain = Chain::<Minimal>::from_genesis(config, genesis, database)
            .unwrap()
            .with_slasher(feed)
            .with_slashing_broadcast(broadcasts);

        // Validator 3 signs two different headers for slot 0.
        let domain = Domain::compute(
            DOMAIN_BEACON_PROPOSER,
            chain.config().fork_version_at(Epoch(0)),
            chain.genesis_validators_root(),
        );
        let header = |body: u8| {
            let message = BeaconBlockHeader {
                slot: Slot(0),
                proposer_index: ValidatorIndex(3),
                body_root: Root([body; 32]),
                ..BeaconBlockHeader::default()
            };
            let root = phase0::SigningData::signing_root(&message, domain);
            SignedBeaconBlockHeader {
                message,
                signature: BlsSignature(secret(3).sign(&root.0).to_bytes()),
            }
        };
        let slashing = ProposerSlashing {
            signed_header_1: header(1),
            signed_header_2: header(2),
        };

        // The evidence is pooled, then handed out in its container, under epoch 0.
        chain
            .on_found_slashing(&Slashing::Proposer(slashing.clone()))
            .unwrap();
        assert_eq!(
            found.try_recv(),
            Ok(FoundSlashing {
                kind: GossipKind::ProposerSlashing,
                epoch: Epoch(0),
                message: slashing.encode(),
            })
        );

        // Gossip rules now know the proposer, so the same evidence never goes out twice.
        chain.spread_found(&Slashing::Proposer(slashing));
        assert!(found.try_recv().is_err());
    }

    #[test]
    fn passes_wait_for_the_update_period() {
        // Fixture state: a 12 second period, first ticked at 1000 ms.
        let mut feed = SlasherFeed::<Minimal>::start(SlasherConfig::default(), None)
            .unwrap()
            .with_update_period(Some(Duration::from_secs(12)));
        assert!(feed.pass_due(1000));
        feed.tick(1000, Epoch(0));

        // The next pass waits until 1000 + 12000 = 13000 ms.
        assert!(!feed.pass_due(12_999));
        assert!(feed.pass_due(13_000));

        // Without a period, every tick passes, even at the same instant.
        let mut every = SlasherFeed::<Minimal>::start(SlasherConfig::default(), None).unwrap();
        every.tick(1000, Epoch(0));
        assert!(every.pass_due(1000));
    }
}
