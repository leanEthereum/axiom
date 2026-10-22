//! The Gloas consensus spec vectors, for both presets.
//!
//! Each test runs one runner over every handler and case it finds.
//! A handler this client does not know fails the test, so no vector is skipped silently.

use axiom_ef_tests::{Case, Fork, SszStatic, Suite, Vectors, forks::Gloas};
use axiom_state_transition::State;
use axiom_types::{ChainConfig, ForkName, Mainnet, Minimal, Slot, accessors::CoreState, fulu};

#[test]
fn ssz_static_minimal() {
    Suite::run(&SszStatic::<Minimal, Gloas>::default(), "minimal", "gloas");
}

#[test]
fn ssz_static_mainnet() {
    Suite::run(&SszStatic::<Mainnet, Gloas>::default(), "mainnet", "gloas");
}

#[test]
fn fork_minimal() {
    Suite::run(&Fork::<Minimal, Gloas>::default(), "minimal", "gloas");
}

#[test]
fn fork_mainnet() {
    Suite::run(&Fork::<Mainnet, Gloas>::default(), "mainnet", "gloas");
}

#[test]
fn slot_processing_upgrades_at_the_fork_epoch() {
    let Some(vectors) = Vectors::locate() else {
        return;
    };
    // Fixture state: the Fulu pre-state of a Gloas fork vector, in the minimal preset.
    let case = Case::new(
        vectors
            .consensus()
            .join("minimal/gloas/fork/fork/pyspec_tests/fork_next_epoch"),
    );
    let pre = case
        .ssz::<fulu::BeaconState<Minimal>>("pre")
        .expect("the case has a pre-state");
    let next_epoch = pre.current_epoch() + 1;
    let boundary = next_epoch.start_slot::<Minimal>();

    // Path 1: Gloas scheduled at the next epoch, so slot processing upgrades on arrival.
    let scheduled = ChainConfig {
        gloas_fork_epoch: next_epoch,
        ..ChainConfig::minimal().with_forks_at_genesis(ForkName::Fulu)
    };
    let mut through = State::new(pre.clone());
    through.process_slots(&scheduled, boundary).unwrap();
    assert_eq!(through.fork_name(), ForkName::Gloas);
    assert_eq!(through.beacon().slot(), boundary);
    assert_eq!(through.beacon().fork().epoch, next_epoch);

    // Path 2: Fulu slots up to the boundary, then the upgrade on its own.
    let unscheduled = ChainConfig::minimal().with_forks_at_genesis(ForkName::Fulu);
    let mut stepwise = State::new(pre);
    stepwise.process_slots(&unscheduled, boundary).unwrap();
    assert_eq!(stepwise.fork_name(), ForkName::Fulu);
    stepwise.upgrade(&scheduled).unwrap();

    // Both paths reach the same Gloas state.
    assert_eq!(through.hash_tree_root(), stepwise.hash_tree_root());

    // One more slot stays in Gloas, since no later fork exists.
    let after = Slot(boundary.0 + 1);
    through.process_slots(&scheduled, after).unwrap();
    assert_eq!(through.fork_name(), ForkName::Gloas);
    assert_eq!(through.beacon().slot(), after);
    assert_eq!(through.beacon().current_epoch(), next_epoch);
}
