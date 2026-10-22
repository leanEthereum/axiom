//! The database command: inspect, migrate, prune, and compact a stopped node's database.

use std::{
    fmt, fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use axiom_node::{ChainDatabase, ChainError, Clock, SchemaVersion, SystemClock, TableUsage};
use axiom_types::{ChainConfig, Gnosis, Mainnet, Minimal, Preset, SlotClock, accessors::CoreState};
use thiserror::Error;

use crate::{
    cli::{Cli, CliError, arguments::Arguments},
    network::{BuiltInNetwork, Network},
    run::PresetName,
};

/// The usage text of the database command.
pub(crate) const DATABASE_USAGE: &str = "\
axiom db: maintain the database of a stopped beacon node

USAGE:
    axiom db <COMMAND> --datadir <DIR> [OPTIONS]

COMMANDS:
    inspect                      entries and bytes of each table, or one table's records
    version                      the database's layout version
    migrate                      bring the layout to this build's version
    prune-blobs                  delete sidecars past their retention window
    prune-states                 delete archived state snapshots; changes nothing without --confirm
    compact                      give back the space of deleted records

OPTIONS:
    --datadir <DIR>              the node's data directory
    --network <NAME>             the chain whose records the database holds [default: mainnet]
    --testnet-dir <DIR>          a network directory instead of a name
    --config <FILE>              a chain config YAML instead of a name
    --table <NAME>               inspect: blocks, states, blobs, columns, envelopes, canonical,
                                 snapshots, state_roots, light_client, or meta
    --output <KIND>              inspect: summary, sizes, or values [default: summary]
    --output-dir <DIR>           inspect: where values are written, one file per key
    --to <VERSION>               migrate: the version to reach [default: this build's]
    --confirm                    prune-states: delete for real
    -h, --help                   print this help
";

/// What the database command does.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Action {
    /// Prints table usage, or one table's records.
    Inspect(Inspection),
    /// Prints the layout version.
    Version,
    /// Migrates the layout.
    Migrate {
        /// The version asked for, when one was.
        to: Option<SchemaVersion>,
    },
    /// Deletes expired sidecars.
    PruneBlobs,
    /// Deletes archived states.
    PruneStates {
        /// Whether to delete for real.
        confirm: bool,
    },
    /// Compacts the store.
    Compact,
}

/// What an inspection prints.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Inspection {
    /// Entries and bytes of every table.
    Summary,
    /// The size of each record of one table.
    Sizes(String),
    /// Each record of one table, written to a file named by its key.
    Values {
        /// The table.
        table: String,
        /// The directory the files go to.
        directory: PathBuf,
    },
}

/// A parsed database command line.
#[derive(Debug)]
pub(crate) enum DatabaseCommand {
    /// Print the usage text.
    Help,
    /// Run an action on a database.
    Run(Box<DatabaseRun>),
}

/// An action on one node's database.
#[derive(Debug)]
pub(crate) struct DatabaseRun {
    /// What to do.
    action: Action,
    /// The node's data directory.
    datadir: PathBuf,
    /// The preset the records follow.
    preset: PresetName,
    /// The fork schedule the records decode under.
    chain: ChainConfig,
}

/// Why a database command failed.
#[derive(Debug, Error)]
pub(crate) enum DatabaseError {
    /// The database refused an operation.
    #[error("{0}")]
    Chain(#[from] ChainError),
    /// The terminal or an output file could not be written.
    #[error("writing output: {0}")]
    Io(#[from] io::Error),
    /// The database holds no chain yet.
    #[error("the database at {} holds no chain", .0.display())]
    Empty(PathBuf),
    /// A migration was asked for a version this build cannot reach.
    #[error("this build migrates to version {supported} only, not {asked}")]
    UnreachableVersion {
        /// The version asked for.
        asked: SchemaVersion,
        /// The version this build writes.
        supported: SchemaVersion,
    },
}

impl DatabaseCommand {
    /// Parses the words after the word db.
    ///
    /// # Errors
    ///
    /// Fails on an unknown command or flag, a missing value, or a missing data directory.
    pub(crate) fn parse<I: Iterator<Item = String>>(
        mut words: Arguments<I>,
    ) -> Result<Self, CliError> {
        let Some(command) = words.next_flag() else {
            return Err(CliError::MissingCommand("db"));
        };
        let command = match command.as_str() {
            "-h" | "--help" => return Ok(Self::Help),
            "inspect" | "version" | "migrate" | "prune-blobs" | "prune-states" | "compact" => {
                command
            }
            _ => return Err(CliError::UnknownCommand(command)),
        };
        let mut flags = DatabaseFlags::default();
        while let Some(flag) = words.next_flag() {
            if matches!(flag.as_str(), "-h" | "--help") {
                return Ok(Self::Help);
            }
            flags.read(flag, &mut words)?;
        }
        flags.resolve(&command).map(|run| Self::Run(Box::new(run)))
    }
}

/// The database command's flags as given.
#[derive(Debug, Default)]
struct DatabaseFlags {
    /// The data directory.
    datadir: Option<PathBuf>,
    /// The network name.
    network: Option<BuiltInNetwork>,
    /// A network directory.
    testnet_dir: Option<PathBuf>,
    /// A configuration file.
    config: Option<PathBuf>,
    /// The table to inspect.
    table: Option<String>,
    /// What an inspection prints.
    output: Option<String>,
    /// Where values are written.
    output_dir: Option<PathBuf>,
    /// The version to migrate to.
    to: Option<u64>,
    /// Whether states are deleted for real.
    confirm: bool,
}

impl DatabaseFlags {
    /// Takes one flag.
    fn read<I: Iterator<Item = String>>(
        &mut self,
        flag: String,
        words: &mut Arguments<I>,
    ) -> Result<(), CliError> {
        match flag.as_str() {
            "--datadir" => self.datadir = Some(words.path("--datadir")?),
            "--network" => self.network = Some(words.parsed("--network")?),
            "--testnet-dir" => self.testnet_dir = Some(words.path("--testnet-dir")?),
            "--config" => self.config = Some(words.path("--config")?),
            "--table" => self.table = Some(words.value("--table")?),
            "--output" => self.output = Some(words.value("--output")?),
            "--output-dir" => self.output_dir = Some(words.path("--output-dir")?),
            "--to" => self.to = Some(words.parsed("--to")?),
            "--confirm" => self.confirm = true,
            _ => return Err(CliError::UnknownFlag(flag)),
        }
        Ok(())
    }

    /// The run a command word and these flags describe.
    fn resolve(self, command: &str) -> Result<DatabaseRun, CliError> {
        let datadir = self.datadir.ok_or(CliError::MissingFlag("--datadir"))?;
        let (preset, chain) = match (self.testnet_dir, self.config, self.network) {
            (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
                return Err(CliError::ConflictingNetworks);
            }
            (Some(directory), None, None) => {
                let network = Network::load(&directory)?;
                (network.preset, network.chain)
            }
            (None, Some(path), _) => Cli::choose_chain(None, None, Some(&path))?,
            (None, None, name) => {
                let network = Network::built_in(name.unwrap_or_default())?;
                (network.preset, network.chain)
            }
        };
        let action = match command {
            "inspect" => Action::Inspect(Self::inspection(
                self.table,
                self.output.as_deref(),
                self.output_dir,
            )?),
            "version" => Action::Version,
            "migrate" => Action::Migrate {
                to: self.to.map(SchemaVersion),
            },
            "prune-blobs" => Action::PruneBlobs,
            "prune-states" => Action::PruneStates {
                confirm: self.confirm,
            },
            _ => Action::Compact,
        };
        Ok(DatabaseRun {
            action,
            datadir,
            preset,
            chain,
        })
    }

    /// The inspection the flags ask for.
    fn inspection(
        table: Option<String>,
        output: Option<&str>,
        directory: Option<PathBuf>,
    ) -> Result<Inspection, CliError> {
        match (output.unwrap_or("summary"), table, directory) {
            ("summary", _, _) => Ok(Inspection::Summary),
            ("sizes", Some(table), _) => Ok(Inspection::Sizes(table)),
            ("values", Some(table), Some(directory)) => Ok(Inspection::Values { table, directory }),
            ("sizes" | "values", None, _) => Err(CliError::MissingFlag("--table")),
            ("values", Some(_), None) => Err(CliError::MissingFlag("--output-dir")),
            (other, _, _) => Err(CliError::InvalidValue {
                flag: "--output",
                value: other.to_owned(),
            }),
        }
    }
}

impl DatabaseRun {
    /// Runs the action, printing what it found or did.
    ///
    /// # Errors
    ///
    /// Fails when the database cannot open, holds no chain, or refuses the action.
    pub(crate) fn execute(self) -> Result<(), DatabaseError> {
        self.write_to(&mut io::stdout().lock())
    }

    /// Runs the action, writing its report to a sink.
    fn write_to(self, out: &mut impl Write) -> Result<(), DatabaseError> {
        // The preset is a compile-time choice, so each one decodes its own records.
        match self.preset {
            PresetName::Mainnet => self.run::<Mainnet>(out),
            PresetName::Minimal => self.run::<Minimal>(out),
            PresetName::Gnosis => self.run::<Gnosis>(out),
        }
    }

    /// Runs the action under one preset.
    fn run<P: Preset>(self, out: &mut impl Write) -> Result<(), DatabaseError> {
        let directory = self.datadir.join("chain");
        // Opening would create an empty database where an operator mistyped a path.
        if !directory.is_dir() {
            return Err(DatabaseError::Empty(directory));
        }
        if self.action == Action::Version {
            let database = ChainDatabase::<P>::open_unmigrated(&directory, self.chain)?;
            writeln!(out, "database version: {}", database.schema_version()?)?;
            return Ok(());
        }
        if let Action::Migrate { to: Some(asked) } = self.action
            && asked != SchemaVersion::CURRENT
        {
            return Err(DatabaseError::UnreachableVersion {
                asked,
                supported: SchemaVersion::CURRENT,
            });
        }
        let before = ChainDatabase::<P>::open_unmigrated(&directory, self.chain.clone())?
            .schema_version()?;
        // Opening migrates to the current layout, one atomic step per version.
        let database = ChainDatabase::<P>::open(&directory, self.chain)?;
        match self.action {
            Action::Inspect(inspection) => Self::inspect(&database, &inspection, out)?,
            Action::Version => {}
            Action::Migrate { .. } => {
                writeln!(
                    out,
                    "database version: {before} -> {}",
                    SchemaVersion::CURRENT
                )?;
            }
            Action::PruneBlobs => {
                let blocks = Self::prune_blobs(&database, &directory)?;
                writeln!(out, "pruned the sidecars of {blocks} blocks")?;
            }
            Action::PruneStates { confirm } => {
                let snapshots = Self::snapshots(&database)?;
                if confirm {
                    let deleted = database.prune_states()?;
                    database.compact()?;
                    writeln!(out, "deleted {deleted} archived states")?;
                } else {
                    writeln!(
                        out,
                        "{snapshots} archived states would be deleted; run again with --confirm"
                    )?;
                }
            }
            Action::Compact => {
                database.compact()?;
                writeln!(out, "compacted")?;
            }
        }
        Ok(())
    }

    /// Prints what an inspection asks for.
    fn inspect<P: Preset>(
        database: &ChainDatabase<P>,
        inspection: &Inspection,
        out: &mut impl Write,
    ) -> Result<(), DatabaseError> {
        match inspection {
            Inspection::Summary => {
                writeln!(
                    out,
                    "{:<14}{:>12}{:>16}{:>16}",
                    "table", "entries", "key bytes", "value bytes"
                )?;
                for usage in database.usage()? {
                    let TableUsage {
                        name,
                        entries,
                        key_bytes,
                        value_bytes,
                    } = usage;
                    writeln!(
                        out,
                        "{name:<14}{entries:>12}{key_bytes:>16}{value_bytes:>16}"
                    )?;
                }
            }
            Inspection::Sizes(table) => {
                for (key, value) in database.entries(table)? {
                    writeln!(out, "{} {}", Hex(&key), value.len())?;
                }
            }
            Inspection::Values { table, directory } => {
                fs::create_dir_all(directory)?;
                let entries = database.entries(table)?;
                for (key, value) in &entries {
                    fs::write(directory.join(format!("{}.ssz", Hex(key))), value)?;
                }
                writeln!(
                    out,
                    "wrote {} values to {}",
                    entries.len(),
                    directory.display()
                )?;
            }
        }
        Ok(())
    }

    /// Deletes expired sidecars until a pass catches up with the wall clock's epoch.
    fn prune_blobs<P: Preset>(
        database: &ChainDatabase<P>,
        directory: &Path,
    ) -> Result<usize, DatabaseError> {
        let (_, state) = database
            .finalized()?
            .ok_or_else(|| DatabaseError::Empty(directory.to_path_buf()))?;
        let slots = SlotClock::new(
            state.genesis_time().saturating_mul(1000),
            database.config().slot_duration_ms.max(1),
        );
        let current = slots.slot_at(SystemClock.now_ms()).epoch::<P>();
        let mut blocks = 0;
        loop {
            let pass = database.prune_sidecars(current, 0)?;
            blocks += pass.blocks;
            if pass.complete {
                return Ok(blocks);
            }
        }
    }

    /// Archived state snapshots in the database.
    fn snapshots<P: Preset>(database: &ChainDatabase<P>) -> Result<u64, DatabaseError> {
        Ok(database
            .usage()?
            .iter()
            .find(|usage| usage.name == "snapshots")
            .map_or(0, |usage| usage.entries))
    }
}

/// Bytes printed as lowercase hex, for keys.
struct Hex<'a>(&'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{env, process};

    use super::*;

    fn parse(words: &[&str]) -> Result<DatabaseCommand, CliError> {
        DatabaseCommand::parse(Arguments::new(words.iter().map(|word| (*word).to_owned())))
    }

    fn run(words: &[&str]) -> DatabaseRun {
        match parse(words).unwrap() {
            DatabaseCommand::Run(run) => *run,
            DatabaseCommand::Help => panic!("expected a run"),
        }
    }

    /// A data directory holding a fresh minimal-preset database, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path = env::temp_dir().join(format!("axiom-db-cli-{name}-{}", process::id()));
            let _stale = fs::remove_dir_all(&path);
            let database =
                ChainDatabase::<Minimal>::open(&path.join("chain"), ChainConfig::minimal());
            drop(database.unwrap());
            Self(path)
        }

        /// Runs a command against the directory and returns what it printed.
        fn report(&self, words: &[&str]) -> Result<String, DatabaseError> {
            let datadir = self.0.display().to_string();
            let mut words = words.to_vec();
            words.extend(["--datadir", &datadir, "--network", "minimal"]);
            let mut out = Vec::new();
            run(&words).write_to(&mut out)?;
            Ok(String::from_utf8(out).unwrap())
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _removed = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn commands_parse_into_actions() {
        let inspect = run(&[
            "inspect",
            "--datadir",
            "/data",
            "--network",
            "gnosis",
            "--table",
            "blocks",
            "--output",
            "values",
            "--output-dir",
            "/dump",
        ]);
        assert_eq!(
            inspect.action,
            Action::Inspect(Inspection::Values {
                table: "blocks".to_owned(),
                directory: "/dump".into(),
            })
        );
        assert_eq!(inspect.datadir, PathBuf::from("/data"));
        assert_eq!(inspect.preset, PresetName::Gnosis);

        let migrate = run(&["migrate", "--datadir", "/data", "--to", "2"]);
        assert_eq!(
            migrate.action,
            Action::Migrate {
                to: Some(SchemaVersion(2))
            }
        );
        let prune = run(&["prune-states", "--datadir", "/data", "--confirm"]);
        assert_eq!(prune.action, Action::PruneStates { confirm: true });
        assert!(matches!(parse(&["--help"]), Ok(DatabaseCommand::Help)));
    }

    #[test]
    fn incomplete_commands_are_refused() {
        assert!(matches!(parse(&[]), Err(CliError::MissingCommand("db"))));
        assert!(matches!(
            parse(&["vacuum"]),
            Err(CliError::UnknownCommand(command)) if command == "vacuum"
        ));
        assert!(matches!(
            parse(&["compact"]),
            Err(CliError::MissingFlag("--datadir"))
        ));
        assert!(matches!(
            parse(&["inspect", "--datadir", "d", "--output", "sizes"]),
            Err(CliError::MissingFlag("--table"))
        ));
        assert!(matches!(
            parse(&[
                "inspect",
                "--datadir",
                "d",
                "--table",
                "blocks",
                "--output",
                "values"
            ]),
            Err(CliError::MissingFlag("--output-dir"))
        ));
        assert!(matches!(
            parse(&["inspect", "--datadir", "d", "--output", "pie"]),
            Err(CliError::InvalidValue {
                flag: "--output",
                ..
            })
        ));
    }

    #[test]
    fn a_fresh_database_reports_its_version_and_tables() {
        let scratch = Scratch::new("fresh");

        // A fresh database records the current layout at once.
        assert_eq!(
            scratch.report(&["version"]).unwrap(),
            format!("database version: {}\n", SchemaVersion::CURRENT)
        );

        // Ten tables; only the metadata table holds a record, the layout version.
        let summary = scratch.report(&["inspect"]).unwrap();
        let lines: Vec<&str> = summary.lines().collect();
        assert_eq!(lines.len(), 11, "{summary}");
        assert_eq!(
            lines[10].split_whitespace().collect::<Vec<_>>(),
            ["meta", "1", "6", "8"]
        );

        // Its one record is the version: key "schema", eight bytes of value.
        assert_eq!(
            scratch
                .report(&["inspect", "--table", "meta", "--output", "sizes"])
                .unwrap(),
            "736368656d61 8\n"
        );
    }

    #[test]
    fn maintenance_commands_report_what_they_did() {
        let scratch = Scratch::new("maintenance");

        assert_eq!(
            scratch.report(&["prune-states"]).unwrap(),
            "0 archived states would be deleted; run again with --confirm\n"
        );
        assert_eq!(
            scratch.report(&["prune-states", "--confirm"]).unwrap(),
            "deleted 0 archived states\n"
        );
        assert_eq!(scratch.report(&["compact"]).unwrap(), "compacted\n");
        assert_eq!(
            scratch.report(&["migrate"]).unwrap(),
            format!("database version: {0} -> {0}\n", SchemaVersion::CURRENT)
        );

        // A version this build cannot write is refused.
        assert!(matches!(
            scratch.report(&["migrate", "--to", "1"]),
            Err(DatabaseError::UnreachableVersion {
                asked: SchemaVersion(1),
                supported: SchemaVersion::CURRENT,
            })
        ));
        // A database without a finalized chain has no clock to prune sidecars against.
        assert!(matches!(
            scratch.report(&["prune-blobs"]),
            Err(DatabaseError::Empty(_))
        ));
    }

    #[test]
    fn a_missing_database_is_never_created() {
        let missing = env::temp_dir().join(format!("axiom-db-cli-missing-{}", process::id()));
        let datadir = missing.display().to_string();
        let mut out = Vec::new();
        let outcome = run(&["version", "--datadir", &datadir]).write_to(&mut out);
        assert!(
            matches!(outcome, Err(DatabaseError::Empty(path)) if path == missing.join("chain"))
        );
        assert!(!missing.exists());
    }
}
