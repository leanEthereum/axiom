//! The validator manager: create validators in bulk, and move them in and out of running clients.
//!
//! # Overview
//!
//! Every command but create speaks the keymanager API of a running validator client.
//!
//! - create derives validators from a mnemonic into a validators file and a deposits file.
//! - import uploads a validators file, or one keystore, with its settings.
//! - list shows a client's keys, and their chain status when a beacon node is given.
//! - delete removes keys from a client.
//! - move deletes keys from one client and imports them, with their history, into another.

mod create;
mod spec;
mod transfer;

use std::{
    collections::BTreeSet,
    fs, io,
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
};

use axiom_http::HttpError;
use axiom_json::{Data, ParseError};
use axiom_types::{BlsPubkey, ExecutionAddress, Gwei};
use axiom_validator::{
    beacon::BeaconError,
    keymanager::KeymanagerClientError,
    keys::{KeyError, KeystoreError, MnemonicError},
};
use thiserror::Error;

pub(crate) use self::{
    create::Create,
    spec::ValidatorSpec,
    transfer::{Delete, Import, List, Move},
};
use crate::{
    account::AccountError,
    cli::{Cli, CliError},
};

/// The usage text of the validator manager.
pub(crate) const MANAGER_USAGE: &str = "\
axiom validator-manager: create validators, and manage them through the keymanager API

USAGE:
    axiom validator-manager <COMMAND> [OPTIONS]

COMMANDS:
    create      derive validators into validators.json and deposits.json
    import      upload a validators file, or one keystore, to a validator client
    list        list a validator client's keys
    delete      delete keys from a validator client
    move        move keys and their slashing protection from one client to another

OPTIONS (create):
    --output-path <DIR>              where validators.json and deposits.json go
    --mnemonic-path <FILE>           the mnemonic
    --first-index <INDEX>            first EIP-2334 validator index [default: 0]
    --count <N>                      validators to create
    --deposit-gwei <GWEI>            deposit amount [default: 32000000000]
    --disable-deposits               write no deposits.json
    --eth1-withdrawal-address <ADDR> 0x01 credentials to an execution address
    --compounding                    0x02 credentials, with --eth1-withdrawal-address
    --pbkdf2                         encrypt with PBKDF2 instead of scrypt
    --network <NAME>                 a built-in network, as for the beacon node [default: mainnet]
    --testnet-dir <DIR>              a network's directory, as for the beacon node
    --config <FILE>                  chain config YAML

OPTIONS (settings, for create and for import of one keystore):
    --suggested-fee-recipient <ADDR> the validators' fee recipient
    --gas-limit <GAS>                the validators' gas limit
    --builder-proposals <BOOL>       whether they use builders
    --builder-boost-factor <N>       the boost factor of their block requests
    --prefer-builder-proposals <BOOL>
                                     whether a builder's bid always wins
    --enabled <BOOL>                 whether they run

OPTIONS (import):
    --validators-file <FILE>         a validators file
    --keystore-file <FILE>           one keystore, instead of a validators file
    --password <TEXT>                the keystore's password
    --ignore-duplicates              skip keys the client already runs
    --vc-url <URL>                   the client's keymanager API [default: http://localhost:5062]
    --vc-token <FILE>                the client's API token

OPTIONS (list, delete):
    --vc-url <URL>, --vc-token <FILE>
    --validators <KEYS>              comma-separated keys, or all
    --beacon-node <URL>              show each listed key's status on the chain

OPTIONS (move):
    --src-vc-url <URL>               the client keys leave [default: http://localhost:5062]
    --src-vc-token <FILE>            its API token
    --src-datadir <DIR>              its data directory, where the keystores and passwords are
    --dest-vc-url <URL>              the client keys join
    --dest-vc-token <FILE>           its API token
    --validators <KEYS>              comma-separated keys, or all
    --count <N>                      the first N keys instead
";

/// Default keymanager API of a local validator client.
const DEFAULT_VC_URL: &str = "http://localhost:5062";

/// Gwei a full validator deposit carries: 32 ETH, `MIN_ACTIVATION_BALANCE` in the Electra spec.
const DEFAULT_DEPOSIT: Gwei = Gwei(32_000_000_000);

/// What a validator manager command does.
#[derive(Debug)]
pub(crate) enum Manager {
    /// Print the usage text.
    Help,
    /// Derives validators into files.
    Create(Box<Create>),
    /// Uploads validators to a client.
    Import(Box<Import>),
    /// Lists a client's keys.
    List(List),
    /// Deletes keys from a client.
    Delete(Delete),
    /// Moves keys between clients.
    Move(Box<Move>),
}

/// Why a validator manager command failed.
#[derive(Debug, Error)]
pub(crate) enum ManagerError {
    /// A file could not be read or written.
    #[error("{}: {source}", path.display())]
    File {
        /// The file.
        path: PathBuf,
        /// The operating system's error.
        #[source]
        source: io::Error,
    },
    /// An output file exists, and overwriting it could lose keys.
    #[error("{} exists; remove it or choose another output path", .0.display())]
    Exists(PathBuf),
    /// The validators file is not JSON.
    #[error("validators file is not JSON: {0}")]
    Json(#[from] ParseError),
    /// The validators file is not a list.
    #[error("validators file is not a JSON array")]
    NotAList,
    /// A validators file entry has a missing or malformed field.
    #[error("validators file entry {index}: invalid {field}")]
    Spec {
        /// The entry.
        index: usize,
        /// The field.
        field: &'static str,
    },
    /// A setting has no keymanager API route, so it cannot be applied.
    #[error(
        "validator {pubkey} sets {field}, which the keymanager API cannot set; remove it from the file"
    )]
    Unsupported {
        /// The validator.
        pubkey: BlsPubkey,
        /// The setting.
        field: &'static str,
    },
    /// The client already runs a key.
    #[error("validator {0} already runs on the client; pass --ignore-duplicates to skip it")]
    Duplicate(BlsPubkey),
    /// The client does not run a key.
    #[error("validator {0} does not run on the client")]
    Unknown(BlsPubkey),
    /// The client refused one key.
    #[error("validator {pubkey}: the client answered {outcome}")]
    Refused {
        /// The key.
        pubkey: BlsPubkey,
        /// The outcome the client reported.
        outcome: String,
    },
    /// The keys left the source client but did not join the destination.
    #[error("{source}; the keys were saved to {}", path.display())]
    Stranded {
        /// The recovery file, a validators file of the stranded keys.
        path: PathBuf,
        /// Why the import failed.
        #[source]
        source: Box<Self>,
    },
    /// The keymanager API failed.
    #[error("keymanager API: {0}")]
    Keymanager(#[from] KeymanagerClientError),
    /// The beacon node failed.
    #[error("beacon node: {0}")]
    Beacon(#[from] BeaconError),
    /// A URL is malformed.
    #[error("URL: {0}")]
    Url(#[from] HttpError),
    /// A keystore is malformed or does not open.
    #[error("keystore: {0}")]
    Keystore(#[from] KeystoreError),
    /// A key could not be derived.
    #[error("key derivation: {0}")]
    Key(#[from] KeyError),
    /// The mnemonic is malformed.
    #[error("mnemonic: {0}")]
    Mnemonic(#[from] MnemonicError),
    /// Key generation failed.
    #[error("{0}")]
    Account(#[from] AccountError),
    /// The runtime or randomness failed.
    #[error("{0}")]
    Io(#[from] io::Error),
}

impl ManagerError {
    /// A malformed validators file entry.
    pub(crate) const fn spec(index: usize, field: &'static str) -> Self {
        Self::Spec { index, field }
    }
}

/// Which keys a command acts on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Selection {
    /// Every key the client runs.
    All,
    /// These keys.
    Keys(Vec<BlsPubkey>),
    /// The first keys the client lists.
    Count(usize),
}

impl Selection {
    /// The chosen keys among those a client runs, in its order.
    ///
    /// # Errors
    ///
    /// Fails on a key the client does not run.
    pub(crate) fn pick(&self, running: &[BlsPubkey]) -> Result<Vec<BlsPubkey>, ManagerError> {
        match self {
            Self::All => Ok(running.to_vec()),
            Self::Count(count) => Ok(running.iter().take(*count).copied().collect()),
            Self::Keys(keys) => keys
                .iter()
                .map(|key| {
                    running
                        .contains(key)
                        .then_some(*key)
                        .ok_or(ManagerError::Unknown(*key))
                })
                .collect(),
        }
    }
}

/// A switch the validator manager takes without a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Switch {
    /// Print the usage text.
    Help,
    /// Write no deposits file.
    DisableDeposits,
    /// Use 0x02 credentials.
    Compounding,
    /// Encrypt with PBKDF2.
    Pbkdf2,
    /// Skip keys the client already runs.
    IgnoreDuplicates,
}

/// The validator manager's flags, as given.
#[derive(Debug, Default)]
struct ManagerFlags {
    /// The switches given.
    switches: BTreeSet<Switch>,
    /// Every flag with a value, by name.
    values: Vec<(&'static str, String)>,
}

impl ManagerFlags {
    /// Flags that take a value.
    const VALUED: [&'static str; 27] = [
        "--output-path",
        "--mnemonic-path",
        "--first-index",
        "--count",
        "--deposit-gwei",
        "--eth1-withdrawal-address",
        "--network",
        "--testnet-dir",
        "--config",
        "--suggested-fee-recipient",
        "--gas-limit",
        "--builder-proposals",
        "--builder-boost-factor",
        "--prefer-builder-proposals",
        "--enabled",
        "--validators-file",
        "--keystore-file",
        "--password",
        "--vc-url",
        "--vc-token",
        "--validators",
        "--beacon-node",
        "--src-vc-url",
        "--src-vc-token",
        "--src-datadir",
        "--dest-vc-url",
        "--dest-vc-token",
    ];

    /// Reads the flags after the command name.
    fn parse(arguments: impl Iterator<Item = String>) -> Result<Self, CliError> {
        let mut flags = Self::default();
        let mut arguments = arguments;
        while let Some(flag) = arguments.next() {
            let switch = match flag.as_str() {
                "-h" | "--help" => Some(Switch::Help),
                "--disable-deposits" => Some(Switch::DisableDeposits),
                "--compounding" => Some(Switch::Compounding),
                "--pbkdf2" => Some(Switch::Pbkdf2),
                "--ignore-duplicates" => Some(Switch::IgnoreDuplicates),
                _ => None,
            };
            if let Some(switch) = switch {
                flags.switches.insert(switch);
                continue;
            }
            let name = Self::VALUED
                .into_iter()
                .find(|name| *name == flag)
                .ok_or_else(|| CliError::UnknownFlag(flag.clone()))?;
            let value = arguments.next().ok_or(CliError::MissingValue(name))?;
            flags.values.push((name, value));
        }
        Ok(flags)
    }

    /// Whether a switch was given.
    fn has(&self, switch: Switch) -> bool {
        self.switches.contains(&switch)
    }

    /// The last value of a flag, if given.
    fn text(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .rev()
            .find(|(flag, _)| *flag == name)
            .map(|(_, value)| value.as_str())
    }

    /// A flag the command needs.
    fn required(&self, name: &'static str) -> Result<&str, CliError> {
        self.text(name).ok_or(CliError::MissingValue(name))
    }

    /// A flag whose value parses from text.
    fn parsed<T: FromStr>(&self, name: &'static str) -> Result<Option<T>, CliError> {
        self.text(name)
            .map(|text| {
                text.parse().map_err(|_| CliError::InvalidValue {
                    flag: name,
                    value: text.to_owned(),
                })
            })
            .transpose()
    }

    /// A path flag.
    fn path(&self, name: &'static str) -> Option<PathBuf> {
        self.text(name).map(PathBuf::from)
    }

    /// An execution address flag.
    fn address(&self, name: &'static str) -> Result<Option<ExecutionAddress>, CliError> {
        self.text(name)
            .map(|text| {
                <[u8; 20]>::from_data(text)
                    .map(ExecutionAddress)
                    .map_err(|_| CliError::InvalidValue {
                        flag: name,
                        value: text.to_owned(),
                    })
            })
            .transpose()
    }

    /// The keys a command acts on, from the validators flag, or the count flag where allowed.
    fn selection(&self, count_allowed: bool) -> Result<Option<Selection>, CliError> {
        let count = if count_allowed {
            self.parsed::<usize>("--count")?
        } else {
            None
        };
        let keys = self
            .text("--validators")
            .map(|text| {
                if text.trim() == "all" {
                    return Ok(Selection::All);
                }
                text.split(',')
                    .map(|key| {
                        <[u8; 48]>::from_data(key.trim())
                            .map(BlsPubkey)
                            .map_err(|_| CliError::InvalidValue {
                                flag: "--validators",
                                value: key.to_owned(),
                            })
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map(Selection::Keys)
            })
            .transpose()?;
        match (keys, count) {
            (Some(_), Some(_)) => Err(CliError::Conflicts {
                flag: "--validators",
                other: "--count",
            }),
            (Some(keys), None) => Ok(Some(keys)),
            (None, count) => Ok(count.map(Selection::Count)),
        }
    }

    /// The per-validator settings flags.
    fn settings(&self) -> Result<SettingsFlags, CliError> {
        Ok(SettingsFlags {
            fee_recipient: self.address("--suggested-fee-recipient")?,
            gas_limit: self.parsed("--gas-limit")?,
            builder_proposals: self.parsed("--builder-proposals")?,
            builder_boost_factor: self.parsed("--builder-boost-factor")?,
            prefer_builder_proposals: self.parsed("--prefer-builder-proposals")?,
            enabled: self.parsed("--enabled")?,
        })
    }
}

/// Per-validator settings given on the command line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SettingsFlags {
    /// The fee recipient.
    pub(crate) fee_recipient: Option<ExecutionAddress>,
    /// The gas limit.
    pub(crate) gas_limit: Option<u64>,
    /// Whether builders are used.
    pub(crate) builder_proposals: Option<bool>,
    /// The boost factor.
    pub(crate) builder_boost_factor: Option<u64>,
    /// Whether builders always win.
    pub(crate) prefer_builder_proposals: Option<bool>,
    /// Whether the validators run.
    pub(crate) enabled: Option<bool>,
}

impl SettingsFlags {
    /// A validator entry with these settings.
    pub(crate) const fn spec(self, keystore: String, password: String) -> ValidatorSpec {
        ValidatorSpec {
            keystore,
            password,
            slashing_protection: None,
            fee_recipient: self.fee_recipient,
            gas_limit: self.gas_limit,
            builder_proposals: self.builder_proposals,
            builder_boost_factor: self.builder_boost_factor,
            prefer_builder_proposals: self.prefer_builder_proposals,
            enabled: self.enabled,
        }
    }
}

impl Manager {
    /// Parses a validator manager command, after the word validator-manager.
    ///
    /// # Errors
    ///
    /// Fails on an unknown command or flag, a missing value, or a value that does not parse.
    pub(crate) fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Self, CliError> {
        let mut arguments = arguments.into_iter();
        let command = arguments.next().unwrap_or_else(|| "--help".to_owned());
        let flags = ManagerFlags::parse(arguments)?;
        if flags.has(Switch::Help) {
            return Ok(Self::Help);
        }
        let vc_url = || flags.text("--vc-url").unwrap_or(DEFAULT_VC_URL).to_owned();
        match command.as_str() {
            "-h" | "--help" | "help" => Ok(Self::Help),
            "create" => {
                let (_, chain) = Cli::choose_chain(
                    flags.text("--network"),
                    flags.path("--testnet-dir").as_deref(),
                    flags.path("--config").as_deref(),
                )?;
                let withdrawal_address = flags.address("--eth1-withdrawal-address")?;
                if flags.has(Switch::Compounding) && withdrawal_address.is_none() {
                    return Err(CliError::Requires {
                        flag: "--compounding",
                        needs: "--eth1-withdrawal-address",
                    });
                }
                Ok(Self::Create(Box::new(Create {
                    output: flags.required("--output-path")?.into(),
                    mnemonic: flags.required("--mnemonic-path")?.into(),
                    first_index: flags.parsed("--first-index")?.unwrap_or(0),
                    count: flags
                        .parsed("--count")?
                        .ok_or(CliError::MissingValue("--count"))?,
                    amount: flags
                        .parsed("--deposit-gwei")?
                        .map_or(DEFAULT_DEPOSIT, Gwei),
                    deposits: !flags.has(Switch::DisableDeposits),
                    withdrawal_address,
                    compounding: flags.has(Switch::Compounding),
                    pbkdf2: flags.has(Switch::Pbkdf2),
                    settings: flags.settings()?,
                    chain,
                })))
            }
            "import" => {
                let source = match (
                    flags.path("--validators-file"),
                    flags.path("--keystore-file"),
                ) {
                    (Some(_), Some(_)) => {
                        return Err(CliError::Conflicts {
                            flag: "--validators-file",
                            other: "--keystore-file",
                        });
                    }
                    (Some(file), None) => transfer::ImportSource::File(file),
                    (None, Some(keystore)) => transfer::ImportSource::Keystore {
                        keystore,
                        password: flags.required("--password")?.to_owned(),
                        settings: flags.settings()?,
                    },
                    (None, None) => {
                        return Err(CliError::MissingValue("--validators-file"));
                    }
                };
                Ok(Self::Import(Box::new(Import {
                    source,
                    vc_url: vc_url(),
                    vc_token: flags.required("--vc-token")?.into(),
                    ignore_duplicates: flags.has(Switch::IgnoreDuplicates),
                })))
            }
            "list" => Ok(Self::List(List {
                vc_url: vc_url(),
                vc_token: flags.required("--vc-token")?.into(),
                beacon_node: flags.text("--beacon-node").map(str::to_owned),
                selection: flags.selection(false)?.unwrap_or(Selection::All),
            })),
            "delete" => Ok(Self::Delete(Delete {
                vc_url: vc_url(),
                vc_token: flags.required("--vc-token")?.into(),
                selection: flags
                    .selection(false)?
                    .ok_or(CliError::MissingValue("--validators"))?,
            })),
            "move" => Ok(Self::Move(Box::new(Move {
                src_url: flags
                    .text("--src-vc-url")
                    .unwrap_or(DEFAULT_VC_URL)
                    .to_owned(),
                src_token: flags.required("--src-vc-token")?.into(),
                src_datadir: flags.required("--src-datadir")?.into(),
                dest_url: flags.required("--dest-vc-url")?.to_owned(),
                dest_token: flags.required("--dest-vc-token")?.into(),
                selection: flags
                    .selection(true)?
                    .ok_or(CliError::MissingValue("--validators"))?,
            }))),
            _ => Err(CliError::UnknownFlag(command)),
        }
    }

    /// Runs the command.
    ///
    /// # Errors
    ///
    /// Fails when a file, a key, or a client fails.
    pub(crate) fn execute(self) -> Result<(), ManagerError> {
        match self {
            Self::Help => {
                let _unwritable = write!(io::stdout(), "{MANAGER_USAGE}");
                Ok(())
            }
            Self::Create(create) => create.execute(),
            Self::Import(import) => import.execute(),
            Self::List(list) => list.execute(),
            Self::Delete(delete) => delete.execute(),
            Self::Move(transfer) => transfer.execute(),
        }
    }
}

/// Reads a text file.
fn read_file(path: &Path) -> Result<String, ManagerError> {
    fs::read_to_string(path).map_err(|source| ManagerError::File {
        path: path.to_owned(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(arguments: &[&str]) -> Result<Manager, CliError> {
        Manager::parse(arguments.iter().map(|argument| (*argument).to_owned()))
    }

    #[test]
    fn a_network_directory_is_read_for_the_chain() {
        // A directory that does not exist fails on its config file, so the flag reached the chain.
        assert!(matches!(
            parse(&[
                "create",
                "--output-path",
                "o",
                "--mnemonic-path",
                "m",
                "--count",
                "1",
                "--testnet-dir",
                "/nonexistent/axiom-devnet",
            ]),
            Err(CliError::Network(_))
        ));
    }

    #[test]
    fn selections_read_keys_all_or_a_count() {
        let key = format!("0x{}", "a".repeat(96));
        let Manager::Delete(delete) = parse(&[
            "delete",
            "--vc-token",
            "t",
            "--validators",
            &format!("{key},{key}"),
        ])
        .unwrap() else {
            panic!("delete parses to a deletion");
        };
        assert_eq!(
            delete.selection,
            Selection::Keys(vec![BlsPubkey([0xaa; 48]); 2])
        );
        let Manager::Move(transfer) = parse(&[
            "move",
            "--src-vc-token",
            "s",
            "--src-datadir",
            "vc",
            "--dest-vc-url",
            "http://10.0.0.2:5062",
            "--dest-vc-token",
            "d",
            "--count",
            "3",
        ])
        .unwrap() else {
            panic!("move parses to a move");
        };
        assert_eq!(transfer.selection, Selection::Count(3));
        assert_eq!(transfer.src_url, DEFAULT_VC_URL);

        // A count and keys together are refused; delete takes no count.
        assert!(matches!(
            parse(&[
                "move",
                "--src-vc-token",
                "s",
                "--src-datadir",
                "vc",
                "--dest-vc-url",
                "u",
                "--dest-vc-token",
                "d",
                "--count",
                "1",
                "--validators",
                "all"
            ]),
            Err(CliError::Conflicts {
                flag: "--validators",
                other: "--count"
            })
        ));
        assert!(matches!(
            parse(&["delete", "--vc-token", "t", "--count", "1"]),
            Err(CliError::MissingValue("--validators"))
        ));
    }

    #[test]
    fn picking_keys_refuses_one_the_client_does_not_run() {
        let running = [BlsPubkey([1; 48]), BlsPubkey([2; 48]), BlsPubkey([3; 48])];
        assert_eq!(Selection::All.pick(&running).unwrap(), running);
        assert_eq!(Selection::Count(2).pick(&running).unwrap(), running[..2]);
        assert_eq!(
            Selection::Keys(vec![BlsPubkey([3; 48])])
                .pick(&running)
                .unwrap(),
            [BlsPubkey([3; 48])]
        );
        assert!(matches!(
            Selection::Keys(vec![BlsPubkey([9; 48])]).pick(&running),
            Err(ManagerError::Unknown(key)) if key == BlsPubkey([9; 48])
        ));
    }

    #[test]
    fn create_reads_every_flag() {
        let Manager::Create(create) = parse(&[
            "create",
            "--output-path",
            "out",
            "--mnemonic-path",
            "m.txt",
            "--first-index",
            "4",
            "--count",
            "2",
            "--deposit-gwei",
            "2048000000000",
            "--eth1-withdrawal-address",
            "0x00000000219ab540356cbb839cbe05303d7705fa",
            "--compounding",
            "--pbkdf2",
            "--suggested-fee-recipient",
            "0x00000000219ab540356cbb839cbe05303d7705fa",
            "--gas-limit",
            "36000000",
            "--builder-proposals",
            "true",
            "--network",
            "minimal",
        ])
        .unwrap() else {
            panic!("create parses to a creation");
        };
        assert_eq!((create.first_index, create.count), (4, 2));
        assert_eq!(create.amount, Gwei(2_048_000_000_000));
        assert!(create.deposits && create.compounding && create.pbkdf2);
        assert_eq!(create.settings.gas_limit, Some(36_000_000));
        assert_eq!(create.settings.builder_proposals, Some(true));

        // Compounding names the address its withdrawals go to.
        assert!(matches!(
            parse(&[
                "create",
                "--output-path",
                "o",
                "--mnemonic-path",
                "m",
                "--count",
                "1",
                "--compounding"
            ]),
            Err(CliError::Requires {
                flag: "--compounding",
                needs: "--eth1-withdrawal-address"
            })
        ));
    }
}
