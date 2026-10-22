//! The Wycheproof file format and the rules that turn its verdicts into pass or fail.
//!
//! Every case carries a result: valid, invalid, or acceptable.
//!
//! - A valid case must be accepted, with the published output.
//! - An invalid case must be rejected.
//! - An acceptable case may go either way, but a computed output must still match.
//!
//! A case whose parameters the API cannot express is counted as unsupported, never dropped.
//! Each suite asserts its whole tally, so a shrinking file or a changed policy fails loudly.

use std::{collections::BTreeMap, fs};

use axiom_json::Json;

use crate::vectors::{Vectors, hex};

/// The verdict Wycheproof publishes for a case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Expected {
    /// The input is correct and must be accepted.
    Valid,
    /// The input is malformed or forged and must be rejected.
    Invalid,
    /// The input is legal but unusual, so either behaviour is allowed.
    Acceptable,
}

/// What the implementation did with one case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The input was accepted, and any computed output matched.
    Accepted,
    /// The input was rejected.
    Rejected,
    /// The input was accepted, but the computed output differs from the published one.
    WrongOutput(String),
    /// The input was refused by a documented policy stricter than the standard.
    ///
    /// The check proves the refusal comes from the policy alone, such as a canonical form verifying.
    Refused(&'static str),
    /// The API cannot express the case's parameters.
    Unsupported(&'static str),
}

/// The count of cases by how they ended.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Tally {
    /// Valid cases accepted.
    pub(crate) valid: usize,
    /// Invalid cases rejected, by the implementation or by a stricter policy.
    pub(crate) invalid: usize,
    /// Acceptable cases accepted.
    pub(crate) acceptable_accepted: usize,
    /// Acceptable cases rejected.
    pub(crate) acceptable_rejected: usize,
    /// Valid cases refused by a documented stricter policy.
    pub(crate) refused: usize,
    /// Cases whose parameters the API cannot express.
    pub(crate) unsupported: usize,
}

/// One parsed Wycheproof vector file.
#[derive(Debug)]
pub(crate) struct VectorFile {
    /// The file name, for messages.
    name: String,
    /// The whole document.
    document: Json,
}

impl VectorFile {
    /// Loads a file of testvectors_v1, or none when the vectors are absent.
    pub(crate) fn load(name: &str) -> Option<Self> {
        let vectors = Vectors::locate("wycheproof/testvectors_v1")?;
        let path = vectors.path(name);
        let text = fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let document = Json::parse(text).unwrap_or_else(|error| panic!("{name}: {error}"));
        Some(Self {
            name: name.to_owned(),
            document,
        })
    }

    /// Runs a check on every case and returns the tally.
    ///
    /// # Panics
    ///
    /// Panics listing every case whose outcome breaks its verdict.
    /// Panics when the cases seen differ from the count the file declares.
    #[expect(
        clippy::print_stderr,
        reason = "the suite reports its tally and unsupported reasons to the test output"
    )]
    pub(crate) fn run(&self, mut check: impl FnMut(&Case<'_>) -> Outcome) -> Tally {
        let mut tally = Tally::default();
        let mut unsupported: BTreeMap<&'static str, usize> = BTreeMap::new();
        let mut refused: BTreeMap<&'static str, usize> = BTreeMap::new();
        let mut failures = Vec::new();
        let mut seen = 0_u64;

        for group in self.array(&self.document, "testGroups") {
            for test in self.array(group, "tests") {
                seen += 1;
                let case = Case::new(group, test);
                let outcome = check(&case);
                match (case.expected, outcome) {
                    // Unsupported cases are counted whatever their verdict.
                    (_, Outcome::Unsupported(reason)) => {
                        tally.unsupported += 1;
                        *unsupported.entry(reason).or_default() += 1;
                    }
                    (Expected::Valid, Outcome::Accepted) => tally.valid += 1,
                    (Expected::Valid, Outcome::Refused(reason)) => {
                        tally.refused += 1;
                        *refused.entry(reason).or_default() += 1;
                    }
                    (Expected::Invalid, Outcome::Rejected | Outcome::Refused(_)) => {
                        tally.invalid += 1;
                    }
                    (Expected::Acceptable, Outcome::Accepted) => tally.acceptable_accepted += 1,
                    (Expected::Acceptable, Outcome::Rejected | Outcome::Refused(_)) => {
                        tally.acceptable_rejected += 1;
                    }
                    (expected, outcome) => failures.push(format!(
                        "tcId {} ({}): expected {expected:?}, got {outcome:?}",
                        case.id,
                        case.str("comment"),
                    )),
                }
            }
        }

        assert!(
            failures.is_empty(),
            "{}: {} failures:\n{}",
            self.name,
            failures.len(),
            failures.join("\n")
        );
        let declared = self
            .document
            .get("numberOfTests")
            .and_then(Json::as_u64)
            .expect("numberOfTests");
        assert_eq!(seen, declared, "{}: cases seen", self.name);
        eprintln!(
            "{}: {tally:?}, refused {refused:?}, unsupported {unsupported:?}",
            self.name
        );
        tally
    }

    /// The array under a key of an object, failing on a malformed file.
    fn array<'a>(&self, object: &'a Json, key: &str) -> &'a [Json] {
        object
            .get(key)
            .and_then(Json::as_array)
            .unwrap_or_else(|| panic!("{}: missing array {key}", self.name))
    }
}

/// One test of a group, with access to the group's shared parameters.
#[derive(Debug)]
pub(crate) struct Case<'a> {
    /// The group the test belongs to.
    group: &'a Json,
    /// The test itself.
    test: &'a Json,
    /// The test's identifier, for messages.
    pub(crate) id: u64,
    /// The published verdict.
    pub(crate) expected: Expected,
}

impl<'a> Case<'a> {
    /// Reads the identifier and verdict of a test.
    fn new(group: &'a Json, test: &'a Json) -> Self {
        let id = test.get("tcId").and_then(Json::as_u64).expect("tcId");
        let expected = match test.get("result").and_then(Json::as_str) {
            Some("valid") => Expected::Valid,
            Some("invalid") => Expected::Invalid,
            Some("acceptable") => Expected::Acceptable,
            other => panic!("tcId {id}: unknown result {other:?}"),
        };
        Self {
            group,
            test,
            id,
            expected,
        }
    }

    /// A string field of the test.
    pub(crate) fn str(&self, field: &str) -> &'a str {
        self.test
            .get(field)
            .and_then(Json::as_str)
            .unwrap_or_else(|| panic!("tcId {}: missing string {field}", self.id))
    }

    /// A hex field of the test, decoded.
    pub(crate) fn hex(&self, field: &str) -> Vec<u8> {
        hex(self.str(field)).unwrap_or_else(|| panic!("tcId {}: bad hex in {field}", self.id))
    }

    /// An integer field of the test.
    pub(crate) fn u64(&self, field: &str) -> u64 {
        self.test
            .get(field)
            .and_then(Json::as_u64)
            .unwrap_or_else(|| panic!("tcId {}: missing integer {field}", self.id))
    }

    /// A field of the test, of any shape.
    pub(crate) fn field(&self, field: &str) -> &'a Json {
        self.test
            .get(field)
            .unwrap_or_else(|| panic!("tcId {}: missing field {field}", self.id))
    }

    /// A field of the group, of any shape.
    pub(crate) fn group_field(&self, field: &str) -> &'a Json {
        self.group
            .get(field)
            .unwrap_or_else(|| panic!("tcId {}: missing group field {field}", self.id))
    }
}
