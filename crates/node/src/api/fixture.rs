//! A beacon API over an in-memory chain, driven without a socket, for the route tests.

use std::sync::Arc;

use axiom_bls::SecretKey;
use axiom_http::{Method, Request, Response, Router, StatusCode};
use axiom_json::Json;
use axiom_types::{
    BlsPubkey, ChainConfig, Epoch, ExecutionAddress, ForkName, Gwei, Minimal, ParticipationFlags,
    Slot, combined, gloas, phase0, phase0::Validator,
};
use tokio::runtime::{Builder, Runtime};

use super::BeaconApi;
use crate::{
    Chain, ChainDatabase, ChainHandle, Clock, ExecutionLayer, ManualClock, ProposerService,
    Publisher,
};

/// Genesis time of every fixture chain, in seconds.
const GENESIS_TIME: u64 = 1_600_000_000;

/// Milliseconds per minimal slot.
const SLOT_MS: u64 = 6_000;

/// The balance of every fixture validator: one full deposit.
pub(crate) const BALANCE: Gwei = Gwei(32_000_000_000);

/// A node's beacon API over a fresh chain, with a clock the test sets.
pub(crate) struct TestApi {
    /// The routes, called directly.
    router: Router,
    /// The chain thread.
    chain: ChainHandle<Minimal>,
    /// The wall clock the gossip rules read.
    clock: Arc<ManualClock>,
    /// Runs the async routes.
    runtime: Runtime,
}

impl TestApi {
    /// An API over a chain from a genesis state, in a configuration.
    pub(crate) fn new(config: ChainConfig, genesis: combined::BeaconState<Minimal>) -> Self {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let database = ChainDatabase::in_memory(config.clone()).unwrap();
        let chain = Chain::from_genesis(config, genesis, database).unwrap();
        // The thread ends once the last handle drops.
        let (chain, _thread) = ChainHandle::spawn(chain).unwrap();
        let clock = Arc::new(ManualClock::at(GENESIS_TIME * 1000));
        let execution = Arc::new(ExecutionLayer::disconnected());
        let publisher = Publisher::new(
            chain.clone(),
            Arc::clone(&execution),
            Arc::clone(&clock) as Arc<dyn Clock>,
            None,
        );
        let proposer =
            ProposerService::new(chain.clone(), execution, ExecutionAddress::default(), None);
        let router =
            BeaconApi::router(chain.clone(), Arc::new(publisher), Arc::new(proposer), None);
        Self {
            router,
            chain,
            clock,
            runtime,
        }
    }

    /// An API over a phase0 genesis of some active validators.
    pub(crate) fn phase0(validators: u64) -> Self {
        Self::phase0_with((0..validators).map(|index| (validator(index), BALANCE)))
    }

    /// An API over a phase0 genesis of given validators and balances.
    pub(crate) fn phase0_with(registry: impl IntoIterator<Item = (Validator, Gwei)>) -> Self {
        let mut state = phase0::BeaconState::<Minimal> {
            genesis_time: GENESIS_TIME,
            ..phase0::BeaconState::default()
        };
        for (record, balance) in registry {
            state.validators.push(record).unwrap();
            state.balances.push(balance).unwrap();
        }
        Self::new(ChainConfig::minimal(), combined::BeaconState::Phase0(state))
    }

    /// An API over a Gloas genesis of some validators.
    ///
    /// The proposer lookahead is all zeros, so validator 0 proposes every slot.
    pub(crate) fn gloas(validators: u64) -> Self {
        let mut state = gloas::BeaconState::<Minimal> {
            genesis_time: GENESIS_TIME,
            ..gloas::BeaconState::default()
        };
        for index in 0..validators {
            state.validators.push(validator(index));
            state.balances.push(BALANCE);
            state
                .previous_epoch_participation
                .push(ParticipationFlags::default());
            state
                .current_epoch_participation
                .push(ParticipationFlags::default());
            state.inactivity_scores.push(0);
        }
        let config = ChainConfig::minimal().with_forks_at_genesis(ForkName::Gloas);
        Self::new(config, combined::BeaconState::Gloas(state))
    }

    /// Sets the clock to the start of a slot, and ticks the chain to it.
    pub(crate) fn at_slot(&self, slot: Slot) {
        let now = GENESIS_TIME * 1000 + slot.0 * SLOT_MS;
        self.clock.set(now);
        self.run(move |chain| chain.on_tick(now).unwrap());
    }

    /// The wall clock the gossip rules read, in milliseconds.
    pub(crate) fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    /// Runs a job on the chain thread.
    pub(crate) fn run<R: Send + 'static>(
        &self,
        job: impl FnOnce(&mut Chain<Minimal>) -> R + Send + 'static,
    ) -> R {
        self.runtime.block_on(self.chain.run(job)).unwrap()
    }

    /// Sends a request to the routes.
    pub(crate) fn send(&self, request: Request) -> Response {
        self.runtime.block_on(self.router.handle(request))
    }

    /// A GET request's status and JSON body, null when the body is empty.
    pub(crate) fn get(&self, path: &str) -> (StatusCode, Json) {
        Self::parsed(&self.send(Request::new(Method::Get, path)))
    }

    /// A JSON POST request's status and JSON body, null when the body is empty.
    pub(crate) fn post(&self, path: &str, body: &str) -> (StatusCode, Json) {
        let request = Request::new(Method::Post, path)
            .with_body("application/json", body.as_bytes().to_vec());
        Self::parsed(&self.send(request))
    }

    /// A response's status and JSON body, null when the body is empty.
    pub(crate) fn parsed(response: &Response) -> (StatusCode, Json) {
        let body = if response.body.is_empty() {
            Json::Null
        } else {
            Json::parse(&response.body).unwrap()
        };
        (response.status, body)
    }
}

/// The secret key of fixture validator i: the scalar i + 1.
pub(crate) fn secret(index: u64) -> SecretKey {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&(index + 1).to_be_bytes());
    SecretKey::from_bytes(&bytes).unwrap()
}

/// The public key of fixture validator i.
pub(crate) fn pubkey(index: u64) -> BlsPubkey {
    BlsPubkey(secret(index).public_key().to_bytes())
}

/// An active fixture validator of one full deposit.
pub(crate) fn validator(index: u64) -> Validator {
    Validator {
        pubkey: pubkey(index),
        effective_balance: BALANCE,
        activation_eligibility_epoch: Epoch(0),
        activation_epoch: Epoch(0),
        exit_epoch: Epoch::FAR_FUTURE,
        withdrawable_epoch: Epoch::FAR_FUTURE,
        ..Validator::default()
    }
}
