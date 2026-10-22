//! The EIP-3076 interchange test suite, run against the slashing protection database.
//!
//! The suite lives outside the repository and comes from make -C testing/ef-tests.
//! Point AXIOM_VECTORS at the vectors root, which defaults to the workspace's testing/vectors.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use axiom_json::{Data, Json};
use axiom_types::{BlsPubkey, Epoch, Root, Slot};
use axiom_validator::protection::{
    Interchange, ProtectionError, Safety, SlashingDatabase, VoteCheck,
};

/// Totals the suite must reach exactly, so no case is skipped silently.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Tally {
    /// Test files run.
    files: usize,
    /// Interchange imports attempted.
    steps: usize,
    /// Invalid interchanges refused, as the case requires.
    refused_invalid: usize,
    /// Slashable interchanges refused, as the case allows; the rest of the case is then moot.
    refused_slashable: usize,
    /// Block signings checked.
    blocks: usize,
    /// Vote signings checked.
    attestations: usize,
    /// Signings where both strategies agree, and so does the database.
    agreed: usize,
    /// Signings only the complete strategy allows, allowed here as exact repeats.
    repeats: usize,
    /// Signings only the complete strategy allows, refused here as not moving forward.
    refused_forward: usize,
}

/// The directory of the generated test cases, or none when it is absent.
#[expect(
    clippy::print_stderr,
    reason = "a skipped suite says why in the test output"
)]
fn cases() -> Option<PathBuf> {
    let root = env::var_os("AXIOM_VECTORS").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing/vectors"),
        PathBuf::from,
    );
    let directory = root.join("slashing-protection-interchange/tests/generated");
    let found = directory.is_dir();
    assert!(
        found || env::var_os("AXIOM_REQUIRE_VECTORS").is_none(),
        "vectors required but missing under {}; run make -C testing/ef-tests",
        directory.display()
    );
    if !found {
        eprintln!(
            "skipping: {} not found (set AXIOM_VECTORS)",
            directory.display()
        );
    }
    found.then_some(directory)
}

/// A string member of a case object.
fn text<'a>(json: &'a Json, field: &str) -> &'a str {
    json.get(field)
        .and_then(Json::as_str)
        .unwrap_or_else(|| panic!("case field {field} is a string"))
}

/// A decimal-string member of a case object.
fn number(json: &Json, field: &str) -> u64 {
    text(json, field).parse().expect("a decimal string")
}

/// A hex member of a case object.
fn hex<const N: usize>(json: &Json, field: &str) -> [u8; N] {
    <[u8; N]>::from_data(text(json, field)).expect("valid hex")
}

/// Checks one signing outcome against the case, counting how it was judged.
///
/// The database follows the suite's minimal strategy: messages must move forward.
/// It also allows an exact repeat, by signing root, as EIP-3076 permits.
/// So where the minimal and complete answers differ, the complete answer holds only for a repeat.
fn judge(name: &str, case: &Json, outcome: &Result<Safety, ProtectionError>, tally: &mut Tally) {
    let minimal = flag(case, "should_succeed");
    let complete = case
        .get("should_succeed_complete")
        .and_then(Json::as_bool)
        .unwrap_or(minimal);
    match (minimal, complete, outcome) {
        (true, true, Ok(_)) | (false, false, Err(_)) => tally.agreed += 1,
        (false, true, Ok(Safety::Repeat)) => tally.repeats += 1,
        (false, true, Err(_)) => tally.refused_forward += 1,
        _ => panic!("{name}: {case} gave {outcome:?}"),
    }
}

/// A boolean member of a case object.
fn flag(json: &Json, field: &str) -> bool {
    json.get(field)
        .and_then(Json::as_bool)
        .unwrap_or_else(|| panic!("case field {field} is a boolean"))
}

/// Runs one case file, adding to the tally.
fn run(path: &Path, tally: &mut Tally) {
    let name = path.display().to_string();
    let case = Json::parse(fs::read(path).expect("case is readable")).expect("case is JSON");
    let database = SlashingDatabase::in_memory(Root(hex(&case, "genesis_validators_root")))
        .expect("an empty database opens");
    tally.files += 1;
    let steps = case
        .get("steps")
        .and_then(Json::as_array)
        .expect("case has steps");
    for step in steps {
        tally.steps += 1;
        let interchange = Interchange::from_json(step.get("interchange").expect("an interchange"));
        let imported = interchange
            .map_err(|error| error.to_string())
            .and_then(|interchange| database.import(&interchange).map_err(|e| e.to_string()));
        match (imported, flag(step, "should_succeed")) {
            (Ok(_), true) => {}
            (Err(error), true) => {
                // Refusing slashable data is allowed, and the rest of the case is then moot.
                assert!(
                    flag(step, "contains_slashable_data"),
                    "{name}: import failed: {error}"
                );
                tally.refused_slashable += 1;
                return;
            }
            (Err(_), false) => {
                tally.refused_invalid += 1;
                continue;
            }
            (Ok(_), false) => panic!("{name}: an invalid interchange was imported"),
        }
        for block in step.get("blocks").and_then(Json::as_array).unwrap_or(&[]) {
            tally.blocks += 1;
            let outcome = database.check_block(
                &BlsPubkey(hex(block, "pubkey")),
                Slot(number(block, "slot")),
                Root(hex(block, "signing_root")),
            );
            judge(&name, block, &outcome, tally);
        }
        for vote in step
            .get("attestations")
            .and_then(Json::as_array)
            .unwrap_or(&[])
        {
            tally.attestations += 1;
            let outcome = database.check_vote(VoteCheck {
                pubkey: BlsPubkey(hex(vote, "pubkey")),
                source: Epoch(number(vote, "source_epoch")),
                target: Epoch(number(vote, "target_epoch")),
                signing_root: Root(hex(vote, "signing_root")),
            });
            judge(&name, vote, &outcome, tally);
        }
    }
}

#[test]
fn interchange_suite() {
    let Some(directory) = cases() else {
        return;
    };
    let mut paths: Vec<PathBuf> = fs::read_dir(&directory)
        .expect("the case directory is readable")
        .map(|entry| entry.expect("a directory entry").path())
        .collect();
    paths.sort();
    let mut tally = Tally::default();
    for path in &paths {
        run(path, &mut tally);
    }
    // 38 cases of 49 steps.
    //
    // - 1 import is invalid and refused.
    // - 12 imports hold slashable data and are refused whole, ending their case.
    // - 70 block and 61 vote signings run on the steps that remain.
    // - 115 of them match both strategies of the suite.
    // - 4 exact repeats are allowed, as only the complete strategy allows.
    // - 12 signings behind the latest message are refused, as only the minimal strategy refuses.
    assert_eq!(
        tally,
        Tally {
            files: 38,
            steps: 49,
            refused_invalid: 1,
            refused_slashable: 12,
            blocks: 70,
            attestations: 61,
            agreed: 115,
            repeats: 4,
            refused_forward: 12,
        }
    );
}
