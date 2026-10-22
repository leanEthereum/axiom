//! The Gloas consensus spec vectors, for both presets.
//!
//! Each test runs one runner over every handler and case it finds.
//! A handler this client does not know fails the test, so no vector is skipped silently.
//! Each test pins every handler's case count, so a lost vector directory fails too.

use std::{collections::HashMap, fs};

use axiom_ef_tests::{
    Blocks, Case, ChainReplay, EpochProcessing, Fork, LightClient, Networking, Operations, Rewards,
    SszStatic, StoreReplay, Suite, Transition, Vectors,
    forks::{Fulu, Gloas},
};
use axiom_ssz::Ssz;
use axiom_state_transition::{KnownVerdict, State, Verification};
use axiom_types::{
    ChainConfig, ForkName, Mainnet, Minimal, Preset, Root, Slot, accessors::CoreState, fulu, gloas,
};
use axiom_yaml::Yaml;

/// Every container type the static SSZ vectors of this fork cover.
const CONTAINERS: [&str; 73] = [
    "AggregateAndProof",
    "Attestation",
    "AttestationData",
    "AttesterSlashing",
    "BLSToExecutionChange",
    "BeaconBlock",
    "BeaconBlockBody",
    "BeaconBlockHeader",
    "BeaconState",
    "Builder",
    "BuilderDepositRequest",
    "BuilderExitRequest",
    "BuilderPendingPayment",
    "BuilderPendingWithdrawal",
    "Checkpoint",
    "ConsolidationRequest",
    "ContributionAndProof",
    "DataColumnSidecar",
    "DataColumnsByRootIdentifier",
    "Deposit",
    "DepositData",
    "DepositMessage",
    "DepositRequest",
    "Eth1Block",
    "Eth1Data",
    "ExecutionPayload",
    "ExecutionPayloadBid",
    "ExecutionPayloadEnvelope",
    "ExecutionRequests",
    "Fork",
    "ForkData",
    "HistoricalSummary",
    "IndexedAttestation",
    "IndexedPayloadAttestation",
    "LightClientBootstrap",
    "LightClientFinalityUpdate",
    "LightClientHeader",
    "LightClientOptimisticUpdate",
    "LightClientUpdate",
    "MatrixEntry",
    "NewPayloadRequest",
    "PartialDataColumnGroupID",
    "PartialDataColumnPartsMetadata",
    "PartialDataColumnSidecar",
    "PayloadAttestation",
    "PayloadAttestationData",
    "PayloadAttestationMessage",
    "PendingConsolidation",
    "PendingDeposit",
    "PendingPartialWithdrawal",
    "PowBlock",
    "ProposerPreferences",
    "ProposerSlashing",
    "SignedAggregateAndProof",
    "SignedBLSToExecutionChange",
    "SignedBeaconBlock",
    "SignedBeaconBlockHeader",
    "SignedContributionAndProof",
    "SignedExecutionPayloadBid",
    "SignedExecutionPayloadEnvelope",
    "SignedProposerPreferences",
    "SignedVoluntaryExit",
    "SigningData",
    "SingleAttestation",
    "SyncAggregate",
    "SyncAggregatorSelectionData",
    "SyncCommittee",
    "SyncCommitteeContribution",
    "SyncCommitteeMessage",
    "Validator",
    "VoluntaryExit",
    "Withdrawal",
    "WithdrawalRequest",
];

/// Fork choice cases per handler, replayed by the store and by the node's chain.
const FORK_CHOICE_MINIMAL: &[(&str, usize)] = &[
    ("deposit_with_reorg", 1),
    ("ex_ante", 3),
    ("filter_node_tree_variants", 3),
    ("get_head", 12),
    ("get_parent_payload_status", 1),
    ("on_attestation", 5),
    ("on_block", 25),
    ("on_execution_payload_envelope", 15),
    ("on_payload_attestation_message", 7),
    ("payload_data_availability", 3),
    ("payload_timeliness", 3),
    ("reorg", 8),
    ("should_apply_proposer_boost", 4),
    ("withholding", 2),
];

/// Fork choice cases per handler on the mainnet preset.
const FORK_CHOICE_MAINNET: &[(&str, usize)] = &[
    ("ex_ante", 5),
    ("get_head", 8),
    ("get_parent_payload_status", 1),
    ("on_attestation", 5),
    ("on_block", 8),
    ("on_execution_payload_envelope", 15),
    ("on_payload_attestation_message", 7),
    ("payload_data_availability", 3),
    ("payload_timeliness", 3),
];

#[test]
fn ssz_static_minimal() {
    let runner = SszStatic::<Minimal, Gloas>::default();
    let expected = CONTAINERS.map(|container| (container, 123));
    Suite::check(&runner, "minimal", "gloas", &expected);
}

#[test]
fn ssz_static_mainnet() {
    let runner = SszStatic::<Mainnet, Gloas>::default();
    let expected = CONTAINERS.map(|container| (container, 5));
    Suite::check(&runner, "mainnet", "gloas", &expected);
}

#[test]
fn fork_minimal() {
    let runner = Fork::<Minimal, Gloas>::default();
    let expected = [("fork", 37)];
    Suite::check(&runner, "minimal", "gloas", &expected);
}

#[test]
fn fork_mainnet() {
    let runner = Fork::<Mainnet, Gloas>::default();
    let expected = [("fork", 35)];
    Suite::check(&runner, "mainnet", "gloas", &expected);
}

#[test]
fn operations_minimal() {
    let runner = Operations::<Minimal, Gloas>::default();
    let expected = [
        ("attestation", 66),
        ("attester_slashing", 31),
        ("block_header", 6),
        ("bls_to_execution_change", 14),
        ("builder_deposit_request", 28),
        ("builder_exit_request", 7),
        ("consolidation_request", 37),
        ("deposit_request", 16),
        ("execution_payload_bid", 20),
        ("parent_execution_payload", 24),
        ("payload_attestation", 11),
        ("proposer_slashing", 39),
        ("sync_aggregate", 24),
        ("voluntary_exit", 22),
        ("voluntary_exit_churn", 3),
        ("withdrawal_request", 29),
        ("withdrawals", 86),
    ];
    Suite::check(&runner, "minimal", "gloas", &expected);
}

#[test]
fn epoch_processing_minimal() {
    let runner = EpochProcessing::<Minimal, Gloas>::default();
    let expected = [
        ("builder_pending_payments", 7),
        ("effective_balance_updates", 2),
        ("eth1_data_reset", 2),
        ("historical_summaries_update", 1),
        ("inactivity_updates", 21),
        ("justification_and_finalization", 10),
        ("participation_flag_updates", 12),
        ("pending_consolidations", 13),
        ("pending_deposits", 45),
        ("pending_deposits_churn", 4),
        ("proposer_lookahead", 4),
        ("ptc_window", 1),
        ("randao_mixes_reset", 1),
        ("registry_updates", 23),
        ("rewards_and_penalties", 15),
        ("slashings", 5),
        ("slashings_reset", 1),
        ("sync_committee_updates", 5),
    ];
    Suite::check(&runner, "minimal", "gloas", &expected);
}

#[test]
fn sanity_minimal() {
    let runner = Blocks::<Minimal, Gloas>::sanity();
    let expected = [("blocks", 96), ("slots", 17)];
    Suite::check(&runner, "minimal", "gloas", &expected);
}

#[test]
fn finality_minimal() {
    let runner = Blocks::<Minimal, Gloas>::finality();
    let expected = [("finality", 5)];
    Suite::check(&runner, "minimal", "gloas", &expected);
}

#[test]
fn random_minimal() {
    let runner = Blocks::<Minimal, Gloas>::random();
    let expected = [("random", 16)];
    Suite::check(&runner, "minimal", "gloas", &expected);
}

#[test]
fn rewards_minimal() {
    let runner = Rewards::<Minimal, Gloas>::default();
    let expected = [
        ("basic", 11),
        ("inactivity_scores", 12),
        ("leak", 13),
        ("random", 10),
    ];
    Suite::check(&runner, "minimal", "gloas", &expected);
}

#[test]
fn transition_minimal() {
    let runner = Transition::<Minimal, Fulu, Gloas>::default();
    let expected = [("core", 34)];
    Suite::check(&runner, "minimal", "gloas", &expected);
}

#[test]
fn operations_mainnet() {
    let runner = Operations::<Mainnet, Gloas>::default();
    let expected = [
        ("attestation", 61),
        ("attester_slashing", 30),
        ("block_header", 6),
        ("bls_to_execution_change", 14),
        ("builder_deposit_request", 28),
        ("builder_exit_request", 7),
        ("consolidation_request", 10),
        ("deposit_request", 16),
        ("execution_payload_bid", 20),
        ("parent_execution_payload", 24),
        ("payload_attestation", 9),
        ("proposer_slashing", 39),
        ("sync_aggregate", 26),
        ("voluntary_exit", 26),
        ("voluntary_exit_churn", 1),
        ("withdrawal_request", 19),
        ("withdrawals", 85),
    ];
    Suite::check(&runner, "mainnet", "gloas", &expected);
}

#[test]
fn epoch_processing_mainnet() {
    let runner = EpochProcessing::<Mainnet, Gloas>::default();
    let expected = [
        ("builder_pending_payments", 7),
        ("effective_balance_updates", 2),
        ("eth1_data_reset", 2),
        ("historical_summaries_update", 1),
        ("inactivity_updates", 21),
        ("justification_and_finalization", 10),
        ("participation_flag_updates", 10),
        ("pending_consolidations", 13),
        ("pending_deposits", 44),
        ("pending_deposits_churn", 1),
        ("proposer_lookahead", 4),
        ("ptc_window", 1),
        ("randao_mixes_reset", 1),
        ("registry_updates", 16),
        ("rewards_and_penalties", 15),
        ("slashings", 5),
        ("slashings_reset", 1),
    ];
    Suite::check(&runner, "mainnet", "gloas", &expected);
}

#[test]
fn sanity_mainnet() {
    let runner = Blocks::<Mainnet, Gloas>::sanity();
    let expected = [("blocks", 81), ("slots", 17)];
    Suite::check(&runner, "mainnet", "gloas", &expected);
}

#[test]
fn finality_mainnet() {
    let runner = Blocks::<Mainnet, Gloas>::finality();
    let expected = [("finality", 5)];
    Suite::check(&runner, "mainnet", "gloas", &expected);
}

#[test]
fn random_mainnet() {
    let runner = Blocks::<Mainnet, Gloas>::random();
    let expected = [("random", 16)];
    Suite::check(&runner, "mainnet", "gloas", &expected);
}

#[test]
fn rewards_mainnet() {
    let runner = Rewards::<Mainnet, Gloas>::default();
    let expected = [
        ("basic", 11),
        ("inactivity_scores", 12),
        ("leak", 13),
        ("random", 10),
    ];
    Suite::check(&runner, "mainnet", "gloas", &expected);
}

#[test]
fn transition_mainnet() {
    let runner = Transition::<Mainnet, Fulu, Gloas>::default();
    let expected = [("core", 28)];
    Suite::check(&runner, "mainnet", "gloas", &expected);
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

#[test]
fn networking_minimal() {
    let runner = Networking::<Minimal, Gloas>::default();
    let expected = [
        ("compute_columns_for_custody_group", 5),
        ("get_custody_groups", 11),
        ("gossip_attester_slashing", 12),
        ("gossip_beacon_aggregate_and_proof", 39),
        ("gossip_beacon_attestation", 30),
        ("gossip_beacon_block", 46),
        ("gossip_bls_to_execution_change", 6),
        ("gossip_data_column_sidecar", 10),
        ("gossip_execution_payload_bid", 44),
        ("gossip_execution_payload_envelope", 20),
        ("gossip_partial_data_column_sidecar", 5),
        ("gossip_payload_attestation_message", 13),
        ("gossip_proposer_preferences", 26),
        ("gossip_proposer_slashing", 9),
        ("gossip_sync_committee_contribution_and_proof", 14),
        ("gossip_sync_committee_message", 7),
        ("gossip_voluntary_exit", 14),
    ];
    Suite::check(&runner, "minimal", "gloas", &expected);
}

#[test]
fn networking_mainnet() {
    let runner = Networking::<Mainnet, Gloas>::default();
    let expected = [
        ("compute_columns_for_custody_group", 5),
        ("get_custody_groups", 11),
        ("gossip_attester_slashing", 12),
        ("gossip_beacon_aggregate_and_proof", 39),
        ("gossip_beacon_attestation", 30),
        ("gossip_beacon_block", 46),
        ("gossip_bls_to_execution_change", 6),
        ("gossip_data_column_sidecar", 10),
        ("gossip_execution_payload_bid", 44),
        ("gossip_execution_payload_envelope", 20),
        ("gossip_partial_data_column_sidecar", 5),
        ("gossip_payload_attestation_message", 13),
        ("gossip_proposer_preferences", 26),
        ("gossip_proposer_slashing", 9),
        ("gossip_sync_committee_contribution_and_proof", 15),
        ("gossip_sync_committee_message", 7),
        ("gossip_voluntary_exit", 14),
    ];
    Suite::check(&runner, "mainnet", "gloas", &expected);
}

#[test]
fn light_client_minimal() {
    let runner = LightClient::<Minimal, Gloas>::default();
    let expected = [
        ("data_collection", 1),
        ("single_merkle_proof", 4),
        ("sync", 4),
        ("update_ranking", 1),
    ];
    Suite::check(&runner, "minimal", "gloas", &expected);
}

#[test]
fn light_client_mainnet() {
    let runner = LightClient::<Mainnet, Gloas>::default();
    let expected = [("single_merkle_proof", 4)];
    Suite::check(&runner, "mainnet", "gloas", &expected);
}

#[test]
fn fork_choice_minimal() {
    let runner = StoreReplay::<Minimal, Gloas>::fork_choice();
    Suite::check(&runner, "minimal", "gloas", FORK_CHOICE_MINIMAL);
}

#[test]
fn chain_replay_minimal() {
    let runner = ChainReplay::<Minimal, Gloas>::new();
    Suite::check(&runner, "minimal", "gloas", FORK_CHOICE_MINIMAL);
}

#[test]
fn fork_choice_mainnet() {
    let runner = StoreReplay::<Mainnet, Gloas>::fork_choice();
    Suite::check(&runner, "mainnet", "gloas", FORK_CHOICE_MAINNET);
}

#[test]
fn chain_replay_mainnet() {
    let runner = ChainReplay::<Mainnet, Gloas>::new();
    Suite::check(&runner, "mainnet", "gloas", FORK_CHOICE_MAINNET);
}

#[test]
fn fast_confirmation_minimal() {
    let runner = StoreReplay::<Minimal, Gloas>::fast_confirmation();
    let expected = [
        ("basic", 3),
        ("current_epoch", 22),
        ("empty_slots", 5),
        ("ffg", 2),
        ("is_one_confirmed", 20),
        ("previous_epoch", 108),
        ("reconfirmation", 3),
        ("restart_gu", 6),
        ("revert_finality", 8),
        ("variables", 8),
    ];
    Suite::check(&runner, "minimal", "gloas", &expected);
}
