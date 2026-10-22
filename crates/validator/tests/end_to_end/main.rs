//! A validator client running every duty against an in-process beacon node, across every fork.
//!
//! The node serves the beacon API from a chain the chain builder extends.
//! It builds each block around the client's reveal and the votes the client sent.
//! It applies each block with every signature checked, so a bad signature stops the chain.
//!
//! The genesis is the pyspec one from the consensus spec vectors.
//! Point AXIOM_VECTORS at the vectors root, which defaults to the workspace's testing/vectors.

mod chain;
mod routes;

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axiom_bls::SecretKey;
use axiom_ef_tests::{
    Case, Vectors,
    chain_builder::{ChainBuilder, PYSPEC_GENESIS},
};
use axiom_http::{ClientConfig, Server, ServerConfig};
use axiom_node::{Clock, SystemClock};
use axiom_ssz::U256;
use axiom_types::{
    ChainConfig, Epoch, ForkName, Minimal, Slot, SlotClock, accessors::CoreState, phase0,
};
use axiom_validator::{
    beacon::{BeaconClient, BeaconNodes},
    duties::{ClientSettings, DutyContext, SlotTimer, ValidatorClient},
    protection::SlashingDatabase,
    signing::{Bls, LocalKey, SigningContext, SigningGuard, ValidatorSigner},
    validators::{DEFAULT_GAS_LIMIT, ProposerDefaults, ValidatorStore},
};
use tokio::{runtime::Builder, sync::oneshot, task};

use crate::{
    chain::{Tally, TestChain},
    routes::Routes,
};

/// Slots the run covers: nine epochs of eight, the last two and a slot in Gloas.
const SLOTS: u64 = 72;

/// Length of a slot in the test, short enough for a fast run and long enough for every duty.
const SLOT_MS: u64 = 1_500;

/// The real clock, shifted so that the chain's genesis is a moment ago.
#[derive(Debug)]
struct ShiftedClock {
    /// Milliseconds to subtract from the system clock.
    offset_ms: u64,
}

impl Clock for ShiftedClock {
    fn now_ms(&self) -> u64 {
        SystemClock.now_ms() - self.offset_ms
    }
}

/// The minimal configuration with Altair at epoch 1 and each later fork one epoch on.
///
/// The terminal total difficulty is reachable, so the Bellatrix chain merges.
fn schedule() -> ChainConfig {
    let mut config = ChainConfig {
        terminal_total_difficulty: U256::from_u64(1000),
        slot_duration_ms: SLOT_MS,
        ..ChainConfig::minimal()
    };
    for (epoch, fork) in ForkName::ALL.into_iter().enumerate().skip(1) {
        config = config.with_fork_epoch(fork, Epoch(epoch as u64));
    }
    config
}

/// The pyspec key of a validator: the secret is its index plus one.
fn pyspec_key(index: u64) -> LocalKey<Bls> {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&(index + 1).to_be_bytes());
    LocalKey::new(SecretKey::from_bytes(&bytes).expect("small scalars are keys"))
        .expect("BLS keys are stateless")
}

#[test]
fn a_validator_client_finalizes_a_chain_across_every_fork() {
    let Some(vectors) = Vectors::locate() else {
        return;
    };
    let genesis: phase0::BeaconState<Minimal> = Case::new(vectors.consensus().join(PYSPEC_GENESIS))
        .ssz("state")
        .expect("the genesis vector decodes");
    Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("the runtime starts")
        .block_on(run(genesis));
}

/// Runs the node and the client until the last slot, then checks what happened.
async fn run(genesis: phase0::BeaconState<Minimal>) {
    // Fixture state: 64 validators with the pyspec keys, every fork scheduled one epoch apart.
    let config = schedule();
    let validators = genesis.validators.len() as u64;
    let genesis_ms = genesis.genesis_time * 1000;
    let builder =
        ChainBuilder::<Minimal>::new(config.clone(), genesis).expect("the pyspec genesis builds");
    let genesis_validators_root = builder.state().beacon().genesis_validators_root();
    let chain = Arc::new(Mutex::new(TestChain::new(builder)));

    // The node, on a free loopback port.
    let server = Server::bind("127.0.0.1:0", Routes::all(&chain), ServerConfig::default())
        .await
        .expect("a loopback port binds");
    let url = format!(
        "http://{}",
        server.local_addr().expect("the socket has an address")
    );
    let (stop_node, node_stopped) = oneshot::channel::<()>();
    let node = task::spawn(server.serve(async {
        let _stopped = node_stopped.await;
    }));

    // The clock: genesis was half a slot ago, so slot 1 starts in half a slot.
    let offset_ms = SystemClock.now_ms() - genesis_ms - SLOT_MS / 2;
    let clock = Arc::new(ShiftedClock { offset_ms });
    let timer = SlotTimer::new(clock, SlotClock::new(genesis_ms, SLOT_MS));

    // The client: every key local, enabled at once, behind slashing protection in memory.
    let config = Arc::new(config);
    let context = SigningContext::new(Arc::clone(&config), genesis_validators_root);
    let protection = Arc::new(
        SlashingDatabase::in_memory(genesis_validators_root).expect("a memory database opens"),
    );
    let store = Arc::new(ValidatorStore::new(
        SigningGuard::new(context, protection),
        ProposerDefaults {
            gas_limit: DEFAULT_GAS_LIMIT,
            ..ProposerDefaults::default()
        },
    ));
    for index in 0..validators {
        store
            .add(ValidatorSigner::Local(pyspec_key(index)), true)
            .expect("each key registers");
    }
    let client_config = ClientConfig {
        request_timeout: Duration::from_secs(5),
        ..ClientConfig::default()
    };
    let nodes = Arc::new(
        BeaconNodes::new(vec![
            BeaconClient::new(&url, client_config).expect("a loopback URL"),
        ])
        .expect("one node"),
    );
    let settings = ClientSettings {
        doppelganger_epochs: 0,
        ..ClientSettings::default()
    };
    let duties =
        DutyContext::<Minimal>::new(Arc::clone(&store), nodes, config, timer.clone(), settings);
    let (stop_client, client_stopped) = oneshot::channel::<()>();
    let client = task::spawn(ValidatorClient::new(duties).run(async {
        let _stopped = client_stopped.await;
    }));

    // Run until the last slot's duties are done: its payload votes fall due at three quarters.
    timer.wait_until(Slot(SLOTS), 9_500).await;
    let _stopping = stop_client.send(());
    client.await.expect("the client stops cleanly");
    let _stopping = stop_node.send(());
    node.await.expect("the node stops cleanly");

    let chain = chain.lock().expect("no route panicked");
    let state = chain.state().beacon();

    // Every slot from 1 to 72 has its block; the 17 Gloas blocks from slot 56 came with envelopes.
    assert_eq!(chain.head().1, Slot(SLOTS));
    // With every vote included a slot later, epoch 8 is justified and epoch 7 finalized at slot 72.
    assert_eq!(state.current_justified_checkpoint().epoch, Epoch(8));
    assert_eq!(state.finalized_checkpoint().epoch, Epoch(7));

    // Every duty ran, every time.
    //
    // - Votes: 64 validators once an epoch over 9 epochs, and slot 72's 8: 584.
    // - Aggregates: committees of 4 are below the target of 16, so every voter aggregates.
    // - Sync: the 32 members sign at every slot from 9, when the head is Altair, to 72: 64 slots.
    // - Contributions: each member holds seats in one subcommittee and aggregates it, every slot.
    // - Payload votes: 16 seats at each of the 17 Gloas slots.
    // - Preferences: one per Gloas proposal from epoch 7 to epoch 10, published a slot or more ahead.
    assert_eq!(
        chain.tally,
        Tally {
            blocks: 72,
            envelopes: 17,
            votes: 584,
            aggregates: 584,
            sync_messages: 2048,
            contributions: 2048,
            payload_votes: 272,
            preferences: 32,
        }
    );
}
