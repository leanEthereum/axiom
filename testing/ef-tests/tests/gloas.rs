//! The Gloas consensus spec vectors, for both presets.
//!
//! Each test runs one runner over every handler and case it finds.
//! A handler this client does not know fails the test, so no vector is skipped silently.

use std::{collections::HashMap, fs};

use axiom_ef_tests::{
    Blocks, Case, EpochProcessing, Fork, Operations, Rewards, SszStatic, Suite, Transition,
    Vectors,
    forks::{Fulu, Gloas},
};
use axiom_ssz::Ssz;
use axiom_state_transition::{KnownVerdict, State, Verification};
use axiom_types::{
    ChainConfig, ForkName, Mainnet, Minimal, Preset, Root, Slot, accessors::CoreState, fulu, gloas,
};
use axiom_yaml::Yaml;

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
fn operations_minimal() {
    Suite::run(&Operations::<Minimal, Gloas>::default(), "minimal", "gloas");
}

#[test]
fn epoch_processing_minimal() {
    Suite::run(
        &EpochProcessing::<Minimal, Gloas>::default(),
        "minimal",
        "gloas",
    );
}

#[test]
fn sanity_minimal() {
    Suite::run(&Blocks::<Minimal, Gloas>::sanity(), "minimal", "gloas");
}

#[test]
fn finality_minimal() {
    Suite::run(&Blocks::<Minimal, Gloas>::finality(), "minimal", "gloas");
}

#[test]
fn random_minimal() {
    Suite::run(&Blocks::<Minimal, Gloas>::random(), "minimal", "gloas");
}

#[test]
fn rewards_minimal() {
    Suite::run(&Rewards::<Minimal, Gloas>::default(), "minimal", "gloas");
}

#[test]
fn transition_minimal() {
    Suite::run(
        &Transition::<Minimal, Fulu, Gloas>::default(),
        "minimal",
        "gloas",
    );
}

#[test]
fn operations_mainnet() {
    Suite::run(&Operations::<Mainnet, Gloas>::default(), "mainnet", "gloas");
}

#[test]
fn epoch_processing_mainnet() {
    Suite::run(
        &EpochProcessing::<Mainnet, Gloas>::default(),
        "mainnet",
        "gloas",
    );
}

#[test]
fn sanity_mainnet() {
    Suite::run(&Blocks::<Mainnet, Gloas>::sanity(), "mainnet", "gloas");
}

#[test]
fn finality_mainnet() {
    Suite::run(&Blocks::<Mainnet, Gloas>::finality(), "mainnet", "gloas");
}

#[test]
fn random_mainnet() {
    Suite::run(&Blocks::<Mainnet, Gloas>::random(), "mainnet", "gloas");
}

#[test]
fn rewards_mainnet() {
    Suite::run(&Rewards::<Mainnet, Gloas>::default(), "mainnet", "gloas");
}

#[test]
fn transition_mainnet() {
    Suite::run(
        &Transition::<Mainnet, Fulu, Gloas>::default(),
        "mainnet",
        "gloas",
    );
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

/// Replays each envelope step of the fork choice vectors against the state of its block.
///
/// Returns how many envelopes it checked; envelopes for unknown blocks are the store's concern.
fn check_envelopes<P: Preset>(vectors: &Vectors, preset: &str) -> usize {
    let config = ChainConfig::for_preset::<P>().with_forks_at_genesis(ForkName::Gloas);
    let dir = vectors.consensus().join(format!(
        "{preset}/gloas/fork_choice/on_execution_payload_envelope/pyspec_tests"
    ));
    let mut checked = 0;
    for entry in fs::read_dir(&dir).expect("the handler has cases") {
        let case = Case::new(entry.expect("a readable entry").path());
        let anchor = case
            .ssz::<gloas::BeaconState<P>>("anchor_state")
            .expect("the case has an anchor state");
        let anchor_root = case
            .ssz::<gloas::BeaconBlock<P>>("anchor_block")
            .expect("the case has an anchor block")
            .hash_tree_root();
        let mut blocks = HashMap::new();
        for file in fs::read_dir(case.path()).expect("a readable case") {
            let name = file.expect("a readable file").file_name();
            let Some(stem) = name
                .to_str()
                .and_then(|name| name.strip_suffix(".ssz_snappy"))
            else {
                continue;
            };
            if stem.starts_with("block_") {
                let block = case
                    .ssz::<gloas::SignedBeaconBlock<P>>(stem)
                    .expect("a block decodes");
                blocks.insert(block.message.hash_tree_root(), block);
            }
        }

        let steps = case.yaml("steps.yaml").expect("the case has steps");
        for step in steps.as_sequence().expect("steps are a sequence") {
            let Some(stem) = step.get("execution_payload").and_then(Yaml::as_str) else {
                continue;
            };
            let valid = step.get("valid").and_then(Yaml::as_bool).unwrap_or(true);
            let envelope = case
                .ssz::<gloas::SignedExecutionPayloadEnvelope<P>>(stem)
                .expect("the envelope decodes");

            // The chain from the anchor to the envelope's block, newest first.
            let mut chain = Vec::new();
            let mut root: Root = envelope.message.beacon_block_root;
            while root != anchor_root {
                let Some(block) = blocks.get(&root) else {
                    break;
                };
                chain.push(block);
                root = block.message.parent_root;
            }
            if root != anchor_root {
                assert!(
                    !valid,
                    "{}: an unknown block's envelope is valid",
                    case.path().display()
                );
                continue;
            }
            let mut state = State::new(anchor.clone());
            for block in chain.iter().rev() {
                state
                    .state_transition(&config, *block, Verification::Verify, &KnownVerdict(true))
                    .expect("the envelope's ancestry is valid");
            }
            let outcome = state.verify_execution_payload_envelope(
                &config,
                &envelope,
                Verification::Verify,
                &KnownVerdict(true),
            );
            assert_eq!(
                outcome.is_ok(),
                valid,
                "{}: {outcome:?}",
                case.path().display()
            );
            checked += 1;
        }
    }
    checked
}

#[test]
fn envelopes_verify_against_their_block_state() {
    let Some(vectors) = Vectors::locate() else {
        return;
    };
    // 15 cases per preset, one of which sends an envelope for a block the store never saw.
    assert_eq!(check_envelopes::<Minimal>(&vectors, "minimal"), 14);
    assert_eq!(check_envelopes::<Mainnet>(&vectors, "mainnet"), 14);
}
