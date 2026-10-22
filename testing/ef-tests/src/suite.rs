//! Locating the vectors, and running every case of a runner in parallel.

use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    sync::Mutex,
    thread,
};

use crate::{Case, Failure};

/// One kind of test, the spec's "runner", such as operations or sanity.
///
/// A runner owns every handler under it.
/// An unknown handler is a failure, so a new kind of vector cannot be skipped silently.
pub trait Runner: Sync {
    /// The runner's directory name.
    fn name(&self) -> &'static str;

    /// Runs one case of a handler.
    ///
    /// # Errors
    ///
    /// Fails when the case's expected outcome is not met.
    fn run_case(&self, handler: &str, case: &Case) -> Result<(), Failure>;

    /// Why a handler is deliberately not run, if it is not.
    fn skip_handler(&self, _handler: &str) -> Option<&'static str> {
        None
    }

    /// Why a single case is deliberately not run, if it is not.
    fn skip_case(&self, _handler: &str, _case: &Case) -> Option<&'static str> {
        None
    }
}

/// The directory holding every downloaded vector set.
#[derive(Clone, Debug)]
pub struct Vectors {
    /// Root of the vectors.
    root: PathBuf,
}

impl Vectors {
    /// The vectors named by `AXIOM_VECTORS`, or those under `testing/vectors`.
    ///
    /// Returns nothing when they have not been downloaded, so a local run can skip them.
    ///
    /// # Panics
    ///
    /// Panics when they are missing and `AXIOM_REQUIRE_VECTORS` is set, as in CI.
    /// A suite that silently skips there would pass without testing anything.
    #[must_use]
    pub fn locate() -> Option<Self> {
        let root = env::var_os("AXIOM_VECTORS").map_or_else(
            || Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors"),
            PathBuf::from,
        );
        let found = root.join("consensus-spec-tests/tests").is_dir();
        assert!(
            found || env::var_os("AXIOM_REQUIRE_VECTORS").is_none(),
            "vectors required but missing under {}; run `make -C testing/ef-tests`",
            root.display()
        );
        found.then_some(Self { root })
    }

    /// Root of the consensus spec vectors.
    #[must_use]
    pub fn consensus(&self) -> PathBuf {
        self.root.join("consensus-spec-tests/tests")
    }

    /// Root of the BLS vectors.
    #[must_use]
    pub fn bls(&self) -> PathBuf {
        self.root.join("bls12-381-tests")
    }

    /// Root of the general vectors of the older release that still ships the generic SSZ runner.
    #[must_use]
    pub fn general(&self) -> PathBuf {
        self.root.join("consensus-spec-general/tests/general")
    }
}

/// The tally of one runner over one preset and fork.
#[derive(Debug, Default)]
pub struct Report {
    /// Cases that passed.
    pub passed: usize,
    /// Cases that passed, counted per handler, in name order.
    pub per_handler: BTreeMap<String, usize>,
    /// Cases deliberately not run, with their reason.
    pub skipped: Vec<(String, &'static str)>,
    /// Cases that failed, with why.
    pub failed: Vec<(String, Failure)>,
}

/// What happened to one case.
#[derive(Debug)]
enum Outcome {
    /// The case met its expected outcome.
    Passed,
    /// The case was deliberately not run.
    Skipped(&'static str),
    /// The case did not meet its expected outcome.
    Failed(Failure),
}

impl Report {
    /// Tallies one case of a handler.
    fn record(&mut self, handler: &str, label: String, outcome: Outcome) {
        match outcome {
            Outcome::Passed => {
                self.passed += 1;
                *self.per_handler.entry(handler.to_owned()).or_default() += 1;
            }
            Outcome::Skipped(reason) => self.skipped.push((label, reason)),
            Outcome::Failed(failure) => self.failed.push((label, failure)),
        }
    }
}

/// Every case of one runner, for one preset and one fork.
#[derive(Clone, Debug)]
pub struct Suite {
    /// Directory of the runner, holding one directory per handler.
    dir: PathBuf,
    /// The one handler to run, or every handler when empty.
    handler: Option<String>,
}

impl Suite {
    /// The suite of a runner, or nothing when the vectors are absent.
    ///
    /// # Panics
    ///
    /// Panics when the runner is missing and `AXIOM_REQUIRE_VECTORS` is set, as in CI.
    #[must_use]
    pub fn new(preset: &str, fork: &str, runner: &str) -> Option<Self> {
        let dir = Vectors::locate()?
            .consensus()
            .join(preset)
            .join(fork)
            .join(runner);
        let found = dir.is_dir();
        assert!(
            found || env::var_os("AXIOM_REQUIRE_VECTORS").is_none(),
            "vectors required but {} is missing; run `make -C testing/ef-tests`",
            dir.display()
        );
        found.then_some(Self { dir, handler: None })
    }

    /// One handler of a runner from the general vectors, or nothing when they are absent.
    ///
    /// # Panics
    ///
    /// Panics when the handler is missing and `AXIOM_REQUIRE_VECTORS` is set, as in CI.
    #[must_use]
    pub fn general(fork: &str, runner: &str, handler: &str) -> Option<Self> {
        let dir = Vectors::locate()?.general().join(fork).join(runner);
        let found = dir.join(handler).is_dir();
        assert!(
            found || env::var_os("AXIOM_REQUIRE_VECTORS").is_none(),
            "vectors required but {} is missing; run `make -C testing/ef-tests`",
            dir.join(handler).display()
        );
        found.then(|| Self {
            dir,
            handler: Some(handler.to_owned()),
        })
    }

    /// Runs every case of one handler of the general vectors, panicking when any fails.
    ///
    /// Returns the tally, so a test can pin the number of cases, or nothing when the vectors are absent.
    ///
    /// # Panics
    ///
    /// Panics when a case fails, listing every failure.
    #[expect(clippy::print_stderr, reason = "the report is the test's output")]
    pub fn run_general(runner: &impl Runner, fork: &str, handler: &str) -> Option<Report> {
        let label = format!("general/{fork}/{}/{handler}", runner.name());
        let Some(suite) = Self::general(fork, runner.name(), handler) else {
            eprintln!("skipping {label}: vectors not found, run `make -C testing/ef-tests`");
            return None;
        };
        let report = suite.execute(runner);
        Self::conclude(&label, &report);
        Some(report)
    }

    /// Runs every case, then pins each handler's case count.
    ///
    /// The expected counts list every handler once, in name order.
    /// A lost, added, or shrunken handler directory fails, and so does any skipped case.
    /// Nothing is checked when the vectors are absent and not required.
    ///
    /// # Panics
    ///
    /// Panics when a case fails or is skipped, or when the counts differ.
    pub fn check(runner: &impl Runner, preset: &str, fork: &str, expected: &[(&str, usize)]) {
        let Some(report) = Self::run(runner, preset, fork) else {
            return;
        };
        let label = format!("{preset}/{fork}/{}", runner.name());
        assert!(
            report.skipped.is_empty(),
            "{label}: skipped {:?}",
            report.skipped
        );
        let actual: Vec<(&str, usize)> = report
            .per_handler
            .iter()
            .map(|(handler, passed)| (handler.as_str(), *passed))
            .collect();
        assert_eq!(actual, expected, "{label}: cases per handler");
    }

    /// Runs every case, panicking with a report when any fails.
    ///
    /// Returns the tally, or nothing when the vectors are absent.
    ///
    /// # Panics
    ///
    /// Panics when a case fails, listing every failure.
    #[expect(clippy::print_stderr, reason = "the report is the test's output")]
    fn run(runner: &impl Runner, preset: &str, fork: &str) -> Option<Report> {
        let Some(suite) = Self::new(preset, fork, runner.name()) else {
            eprintln!(
                "skipping {preset}/{fork}/{}: vectors not found, run `make -C testing/ef-tests`",
                runner.name()
            );
            return None;
        };
        let report = suite.execute(runner);
        Self::conclude(&format!("{preset}/{fork}/{}", runner.name()), &report);
        Some(report)
    }

    /// Prints the tally, then panics when any case failed.
    #[expect(clippy::print_stderr, reason = "the report is the test's output")]
    fn conclude(label: &str, report: &Report) {
        eprintln!(
            "{label}: {} passed, {} skipped, {} failed",
            report.passed,
            report.skipped.len(),
            report.failed.len()
        );
        if !report.failed.is_empty() {
            let mut lines: Vec<String> = report
                .failed
                .iter()
                .map(|(case, failure)| format!("  {case}: {failure}"))
                .collect();
            lines.sort();
            panic!("{} cases failed:\n{}", lines.len(), lines.join("\n"));
        }
    }

    /// Runs every case, spread over all cores, and tallies the outcomes.
    #[must_use]
    pub fn execute(&self, runner: &impl Runner) -> Report {
        let cases = self.cases();
        let report = Mutex::new(Report::default());
        let next = Mutex::new(cases.iter());
        let workers = thread::available_parallelism().map_or(4, usize::from);

        // The queue's lock is held only while popping, never while a case runs.
        let take = || next.lock().ok().and_then(|mut cases| cases.next());

        thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| {
                    while let Some((handler, case)) = take() {
                        let label = format!("{handler}/{}", case.path().display());
                        let skip = runner
                            .skip_handler(handler)
                            .or_else(|| runner.skip_case(handler, case));
                        let outcome = match skip {
                            Some(reason) => Outcome::Skipped(reason),
                            None => match runner.run_case(handler, case) {
                                Ok(()) => Outcome::Passed,
                                Err(failure) => Outcome::Failed(failure),
                            },
                        };
                        if let Ok(mut report) = report.lock() {
                            report.record(handler, label, outcome);
                        }
                    }
                });
            }
        });

        report.into_inner().unwrap_or_default()
    }

    /// Every case, paired with its handler name.
    fn cases(&self) -> Vec<(String, Case)> {
        let mut cases = Vec::new();
        for handler in Self::subdirectories(&self.dir) {
            let handler_name = Self::file_name(&handler);
            if self
                .handler
                .as_ref()
                .is_some_and(|only| *only != handler_name)
            {
                continue;
            }
            for suite in Self::subdirectories(&handler) {
                for case in Self::subdirectories(&suite) {
                    cases.push((handler_name.clone(), Case::new(case)));
                }
            }
        }
        cases
    }

    /// Subdirectories of a directory, sorted by name.
    fn subdirectories(dir: &Path) -> Vec<PathBuf> {
        let mut entries: Vec<PathBuf> = fs::read_dir(dir)
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .filter(|path| path.is_dir())
                    .collect()
            })
            .unwrap_or_default();
        entries.sort();
        entries
    }

    /// The last component of a path.
    fn file_name(path: &Path) -> String {
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    }
}
