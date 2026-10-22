//! The account commands: keys from a mnemonic, deposits, and slashing protection files.

use std::{
    fs, io,
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use axiom_http::{ClientConfig, HttpError};
use axiom_json::{Data, Json};
use axiom_node::{Clock, SystemClock};
use axiom_types::{
    BlsPubkey, BlsSignature, ChainConfig, Epoch, ExecutionAddress, Gwei, Mainnet, Minimal, Root,
    SlotClock, ValidatorIndex,
    capella::{BlsToExecutionChange, SignedBlsToExecutionChange},
    phase0::{SignedVoluntaryExit, VoluntaryExit},
};
use axiom_validator::{
    beacon::{BeaconClient, BeaconError},
    keymanager::{DirectoryError, KeyDirectory},
    keys::{
        DepositEntry, DerivationPath, EncryptionParams, Kdf, KeyError, Keystore, KeystoreError,
        Mnemonic, MnemonicError, Password, WithdrawalTarget, WordCount,
    },
    protection::{Interchange, InterchangeError, ProtectionError, SlashingDatabase},
    signing::{SigningContext, SigningRequest, ValidatorSigner},
};
use thiserror::Error;
use tokio::runtime::Builder;

use crate::{
    cli::{Cli, CliError},
    run::PresetName,
};

/// The usage text of the account commands.
pub(crate) const ACCOUNT_USAGE: &str = "\
axiom account: keys, deposits, and slashing protection files

USAGE:
    axiom account <COMMAND> [OPTIONS]

COMMANDS:
    new-mnemonic                 create a mnemonic, then keystores and deposit data from it
    existing-mnemonic            keystores and deposit data from a mnemonic in a file
    export-slashing-protection   write the EIP-3076 interchange of a slashing protection database
    import-slashing-protection   merge an EIP-3076 interchange into a slashing protection database
    bls-change                   move a validator's withdrawals to an execution address
    import                       copy keystores into a validator data directory
    exit                         sign and submit a validator's voluntary exit

OPTIONS (key generation):
    --count <N>                  validators to create [default: 1]
    --start <INDEX>              first EIP-2334 validator index [default: 0]
    --words <N>                  mnemonic length, 12 to 24 [default: 24]
    --mnemonic-file <FILE>       the mnemonic, for existing-mnemonic and bls-change
    --password-file <FILE>       keystore password
    --output <DIR>               where keystores and deposit data go
    --withdrawal-address <ADDR>  0x01 credentials to an execution address [default: BLS credentials]
    --compounding                0x02 credentials, with --withdrawal-address
    --amount <GWEI>              deposit amount [default: 32000000000]
    --pbkdf2                     encrypt with PBKDF2 instead of scrypt
    --network <NAME>             mainnet or minimal [default: mainnet]
    --config <FILE>              chain config YAML

OPTIONS (slashing protection):
    --database <DIR>             the slashing protection database
    --file <FILE>                the interchange file to read or write
    --genesis-validators-root <ROOT>  the chain, when importing into a new database

OPTIONS (import, exit):
    --datadir <DIR>              the validator data directory [default: validator]
    --keystore <FILE>            a keystore to import, repeatable
    --validator <PUBKEY>         the validator to exit
    --epoch <EPOCH>              the exit epoch [default: the current epoch]

OPTIONS (bls-change):
    --validator-index <INDEX>    the validator's registry index
    --key-index <INDEX>          the validator's EIP-2334 index
    --to <ADDR>                  the execution address to withdraw to
    --beacon-node <URL>          where to submit the change [default: http://127.0.0.1:5052]
";

/// Gwei a full validator deposit carries: 32 ETH.
const DEFAULT_AMOUNT: Gwei = Gwei(32_000_000_000);

/// What an account command does.
#[derive(Debug)]
pub(crate) enum Account {
    /// Print the usage text.
    Help,
    /// Creates a mnemonic and keys from it.
    NewMnemonic(KeyGeneration),
    /// Creates keys from a mnemonic in a file.
    ExistingMnemonic {
        /// The file holding the mnemonic.
        mnemonic_file: PathBuf,
        /// What to create.
        generation: KeyGeneration,
    },
    /// Exports a database's interchange.
    ExportSlashingProtection {
        /// The database directory.
        database: PathBuf,
        /// The interchange file to write.
        file: PathBuf,
    },
    /// Imports an interchange into a database.
    ImportSlashingProtection {
        /// The database directory.
        database: PathBuf,
        /// The interchange file to read.
        file: PathBuf,
        /// The chain, for a database that does not exist yet.
        genesis_validators_root: Option<Root>,
    },
    /// Signs and submits a withdrawal credential change.
    BlsChange(BlsChange),
    /// Copies keystores into a data directory, with their password.
    Import {
        /// The data directory.
        datadir: PathBuf,
        /// The keystores.
        keystores: Vec<PathBuf>,
        /// Their password.
        password_file: PathBuf,
    },
    /// Signs and submits a voluntary exit.
    Exit(Exit),
}

/// A voluntary exit to sign and submit.
#[derive(Debug)]
pub(crate) struct Exit {
    /// The data directory holding the key.
    datadir: PathBuf,
    /// The validator.
    pubkey: BlsPubkey,
    /// The exit epoch, the current one when absent.
    epoch: Option<Epoch>,
    /// The beacon node to submit to.
    beacon_node: String,
    /// The preset.
    preset: PresetName,
    /// The chain.
    chain: ChainConfig,
}

/// What to create from a mnemonic.
#[derive(Debug)]
pub(crate) struct KeyGeneration {
    /// Mnemonic length, for a new mnemonic.
    words: WordCount,
    /// Validators to create.
    count: u32,
    /// First EIP-2334 validator index.
    start: u32,
    /// Keystore password file.
    password_file: PathBuf,
    /// Output directory.
    output: PathBuf,
    /// Where withdrawals go, when not to a BLS withdrawal key.
    withdrawal_address: Option<ExecutionAddress>,
    /// Whether the credentials compound.
    compounding: bool,
    /// Deposit amount.
    amount: Gwei,
    /// Whether keystores use PBKDF2 rather than scrypt.
    pbkdf2: bool,
    /// The chain, for the deposit fork version.
    chain: ChainConfig,
}

/// A withdrawal credential change to sign and submit.
#[derive(Debug)]
pub(crate) struct BlsChange {
    /// The file holding the mnemonic of the withdrawal key.
    mnemonic_file: PathBuf,
    /// The validator.
    validator_index: ValidatorIndex,
    /// Its EIP-2334 index, which locates its withdrawal key.
    key_index: u32,
    /// Where withdrawals go.
    to: ExecutionAddress,
    /// The beacon node to submit to.
    beacon_node: String,
    /// The chain.
    chain: ChainConfig,
}

/// Why an account command failed.
#[derive(Debug, Error)]
pub(crate) enum AccountError {
    /// A file could not be read or written.
    #[error("{}: {source}", .path.display())]
    File {
        /// The file.
        path: PathBuf,
        /// The operating system's error.
        #[source]
        source: io::Error,
    },
    /// The mnemonic is malformed.
    #[error("mnemonic: {0}")]
    Mnemonic(#[from] MnemonicError),
    /// A key could not be derived.
    #[error("key derivation: {0}")]
    Key(#[from] KeyError),
    /// A keystore could not be built.
    #[error("keystore: {0}")]
    Keystore(#[from] KeystoreError),
    /// The interchange file is malformed.
    #[error("interchange: {0}")]
    Interchange(#[from] InterchangeError),
    /// The slashing protection database failed.
    #[error("slashing protection: {0}")]
    Protection(#[from] ProtectionError),
    /// The beacon node URL is malformed.
    #[error("beacon node URL: {0}")]
    Url(#[from] HttpError),
    /// The beacon node refused or failed.
    #[error("beacon node: {0}")]
    Beacon(#[from] BeaconError),
    /// The operating system's randomness or runtime failed.
    #[error("{0}")]
    Io(#[from] io::Error),
    /// The key directory failed to load.
    #[error("keys: {0}")]
    Directory(#[from] DirectoryError),
    /// No local key, or no registry entry, for the validator.
    #[error("no local key or registry entry for validator {0}")]
    UnknownKey(BlsPubkey),
    /// The key refused to sign.
    #[error("signing: {0}")]
    Sign(String),
}

impl Account {
    /// Parses an account command, after the word account.
    ///
    /// # Errors
    ///
    /// Fails on an unknown command or flag, a missing value, or a value that does not parse.
    pub(crate) fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Self, CliError> {
        let mut arguments = arguments.into_iter();
        let command = arguments.next().unwrap_or_else(|| "--help".to_owned());
        let flags = AccountFlags::parse(arguments)?;
        if flags.help {
            return Ok(Self::Help);
        }
        match command.as_str() {
            "-h" | "--help" | "help" => Ok(Self::Help),
            "new-mnemonic" => Ok(Self::NewMnemonic(flags.generation()?)),
            "existing-mnemonic" => Ok(Self::ExistingMnemonic {
                mnemonic_file: AccountFlags::required(
                    flags.mnemonic_file.clone(),
                    "--mnemonic-file",
                )?,
                generation: flags.generation()?,
            }),
            "export-slashing-protection" => Ok(Self::ExportSlashingProtection {
                database: AccountFlags::required(flags.database.clone(), "--database")?,
                file: AccountFlags::required(flags.file, "--file")?,
            }),
            "import-slashing-protection" => Ok(Self::ImportSlashingProtection {
                database: AccountFlags::required(flags.database.clone(), "--database")?,
                file: AccountFlags::required(flags.file.clone(), "--file")?,
                genesis_validators_root: flags.genesis_validators_root,
            }),
            "bls-change" => {
                let (_, chain) = flags.chain()?;
                Ok(Self::BlsChange(BlsChange {
                    mnemonic_file: AccountFlags::required(
                        flags.mnemonic_file.clone(),
                        "--mnemonic-file",
                    )?,
                    validator_index: AccountFlags::required(
                        flags.validator_index,
                        "--validator-index",
                    )?,
                    key_index: AccountFlags::required(flags.key_index, "--key-index")?,
                    to: AccountFlags::required(flags.to, "--to")?,
                    beacon_node: flags
                        .beacon_node
                        .unwrap_or_else(|| "http://127.0.0.1:5052".to_owned()),
                    chain,
                }))
            }
            "import" => Ok(Self::Import {
                datadir: flags.datadir.clone(),
                keystores: flags.keystores.clone(),
                password_file: AccountFlags::required(flags.password_file, "--password-file")?,
            }),
            "exit" => {
                let (preset, chain) = flags.chain()?;
                Ok(Self::Exit(Exit {
                    datadir: flags.datadir.clone(),
                    pubkey: AccountFlags::required(flags.validator, "--validator")?,
                    epoch: flags.epoch,
                    beacon_node: flags
                        .beacon_node
                        .unwrap_or_else(|| "http://127.0.0.1:5052".to_owned()),
                    preset,
                    chain,
                }))
            }
            _ => Err(CliError::UnknownFlag(command)),
        }
    }

    /// Runs the command.
    ///
    /// # Errors
    ///
    /// Fails when a file, a key, the database, or the beacon node fails.
    pub(crate) fn execute(self) -> Result<(), AccountError> {
        match self {
            Self::Help => {
                let _unwritable = write!(io::stdout(), "{ACCOUNT_USAGE}");
                Ok(())
            }
            Self::NewMnemonic(generation) => {
                let mnemonic = Mnemonic::generate(generation.words)?;
                // The mnemonic is the only backup of every key: it goes to the operator once.
                let _unwritable = writeln!(
                    io::stdout(),
                    "Write this mnemonic down and keep it offline; it is shown once:\n\n{}\n",
                    mnemonic.phrase()
                );
                generation.create(&mnemonic)
            }
            Self::ExistingMnemonic {
                mnemonic_file,
                generation,
            } => generation.create(&read_mnemonic(&mnemonic_file)?),
            Self::ExportSlashingProtection { database, file } => {
                let database = SlashingDatabase::open_existing(&database)?;
                let text = database.export(None).to_json().to_string();
                write_file(&file, text.as_bytes())
            }
            Self::ImportSlashingProtection {
                database,
                file,
                genesis_validators_root,
            } => {
                let text = read_file(&file)?;
                let interchange = Interchange::parse(&text)?;
                let root = genesis_validators_root.unwrap_or(interchange.genesis_validators_root);
                let database = match SlashingDatabase::open_existing(&database) {
                    Ok(database) => database,
                    Err(ProtectionError::Uninitialized) => SlashingDatabase::open(&database, root)?,
                    Err(error) => return Err(error.into()),
                };
                let summary = database.import(&interchange)?;
                let _unwritable = writeln!(
                    io::stdout(),
                    "imported {} validators, {} blocks, {} votes",
                    summary.validators,
                    summary.blocks,
                    summary.votes
                );
                Ok(())
            }
            Self::BlsChange(change) => change.execute(),
            Self::Import {
                datadir,
                keystores,
                password_file,
            } => {
                let password = read_file(&password_file)?;
                let password = password.trim_end_matches(['\n', '\r']);
                let directory =
                    KeyDirectory::open(&datadir).map_err(|source| AccountError::File {
                        path: datadir.clone(),
                        source,
                    })?;
                for path in keystores {
                    let keystore = Keystore::parse(&read_file(&path)?)?;
                    // A keystore the password does not open is refused before it is saved.
                    keystore.decrypt(&Password::new(password))?;
                    directory
                        .save_keystore(&keystore, password)
                        .map_err(|source| AccountError::File { path, source })?;
                    let _unwritable = writeln!(io::stdout(), "imported {}", keystore.pubkey());
                }
                Ok(())
            }
            Self::Exit(exit) => exit.execute(),
        }
    }
}

impl KeyGeneration {
    /// Writes a keystore and a deposit for each validator, and the deposit data file.
    fn create(&self, mnemonic: &Mnemonic) -> Result<(), AccountError> {
        let password =
            Password::new(read_file(&self.password_file)?.trim_end_matches(['\n', '\r']));
        let seed = mnemonic.to_seed("");
        let kdf = if self.pbkdf2 {
            Kdf::pbkdf2(Kdf::PBKDF2_ROUNDS)?
        } else {
            Kdf::default()
        };
        fs::create_dir_all(&self.output).map_err(|source| AccountError::File {
            path: self.output.clone(),
            source,
        })?;
        let mut deposits = Vec::new();
        for index in self.start..self.start + self.count {
            let path = DerivationPath::validator_signing(index);
            let key = path.derive(seed.as_bytes())?;
            let withdrawal = match (self.withdrawal_address, self.compounding) {
                (Some(address), false) => WithdrawalTarget::Execution(address),
                (Some(address), true) => WithdrawalTarget::Compounding(address),
                // Without an address, withdrawals go to the EIP-2334 withdrawal key.
                (None, _) => WithdrawalTarget::Bls(
                    DerivationPath::validator_withdrawal(index)
                        .derive(seed.as_bytes())?
                        .public_key(),
                ),
            };
            let keystore = Keystore::encrypt(&key, &password, &EncryptionParams::random(kdf)?)
                .with_path(path.clone());
            let name = format!(
                "keystore-m_{}.json",
                path.to_string().replace('/', "_").trim_start_matches("m_")
            );
            write_file(
                &self.output.join(name),
                keystore.to_json().to_string().as_bytes(),
            )?;
            let network = self.chain.config_name.clone();
            deposits.push(
                DepositEntry::sign(
                    &key,
                    withdrawal,
                    self.amount,
                    self.chain.genesis_fork_version,
                    network,
                )
                .to_json(),
            );
        }
        let file = self.output.join("deposit_data.json");
        write_file(&file, Json::Array(deposits).to_string().as_bytes())?;
        let _unwritable = writeln!(
            io::stdout(),
            "{} keystores and {} written",
            self.count,
            file.display()
        );
        Ok(())
    }
}

impl Exit {
    /// Signs the exit with the validator's key and submits it.
    ///
    /// From Deneb on, the exit signs under the Capella version, so it never expires (EIP-7044).
    fn execute(self) -> Result<(), AccountError> {
        let directory = KeyDirectory::open(&self.datadir).map_err(|source| AccountError::File {
            path: self.datadir.clone(),
            source,
        })?;
        let key = directory
            .load()?
            .into_iter()
            .find(|key| key.signer.pubkey() == self.pubkey)
            .ok_or(AccountError::UnknownKey(self.pubkey))?;
        let client = BeaconClient::new(&self.beacon_node, ClientConfig::default())?;
        let runtime = Builder::new_current_thread().enable_all().build()?;
        runtime.block_on(async {
            let genesis = client.beacon().genesis().await?;
            let summary = client
                .beacon()
                .validators(&[self.pubkey])
                .await?
                .into_iter()
                .next()
                .ok_or(AccountError::UnknownKey(self.pubkey))?;
            let slots = SlotClock::new(
                genesis.genesis_time * 1000,
                self.chain.slot_duration_ms.max(1),
            );
            let slot = slots.slot_at(SystemClock.now_ms());
            let context =
                SigningContext::new(Arc::new(self.chain), genesis.genesis_validators_root);
            let (epoch, root) = match self.preset {
                PresetName::Mainnet => {
                    let epoch = self.epoch.unwrap_or_else(|| slot.epoch::<Mainnet>());
                    let message = VoluntaryExit {
                        epoch,
                        validator_index: summary.index,
                    };
                    (
                        epoch,
                        context.signing_root::<Mainnet>(&SigningRequest::VoluntaryExit(&message)),
                    )
                }
                PresetName::Minimal => {
                    let epoch = self.epoch.unwrap_or_else(|| slot.epoch::<Minimal>());
                    let message = VoluntaryExit {
                        epoch,
                        validator_index: summary.index,
                    };
                    (
                        epoch,
                        context.signing_root::<Minimal>(&SigningRequest::VoluntaryExit(&message)),
                    )
                }
            };
            let ValidatorSigner::Local(local) = key.signer else {
                return Err(AccountError::UnknownKey(self.pubkey));
            };
            let signature = local
                .sign(root)
                .map_err(|error| AccountError::Sign(error.to_string()))?;
            let exit = SignedVoluntaryExit {
                message: VoluntaryExit {
                    epoch,
                    validator_index: summary.index,
                },
                signature,
            };
            client.beacon().submit_exit(&exit).await?;
            let _unwritable = writeln!(io::stdout(), "exit at epoch {} submitted", epoch.0);
            Ok(())
        })
    }
}

impl BlsChange {
    /// Signs the change with the withdrawal key and submits it.
    ///
    /// The change signs in the genesis fork's domain on this chain, see the Capella spec.
    fn execute(self) -> Result<(), AccountError> {
        let mnemonic = read_mnemonic(&self.mnemonic_file)?;
        let seed = mnemonic.to_seed("");
        let key = DerivationPath::validator_withdrawal(self.key_index).derive(seed.as_bytes())?;
        let client = BeaconClient::new(&self.beacon_node, ClientConfig::default())?;
        let runtime = Builder::new_current_thread().enable_all().build()?;
        runtime.block_on(async {
            let genesis = client.beacon().genesis().await?;
            let change = BlsToExecutionChange {
                validator_index: self.validator_index,
                from_bls_pubkey: key.public_key(),
                to_execution_address: self.to,
            };
            let context =
                SigningContext::new(Arc::new(self.chain), genesis.genesis_validators_root);
            // The change signs in the genesis domain, which no preset parameter enters.
            let request = SigningRequest::<Mainnet>::BlsToExecutionChange(&change);
            let root = context.signing_root(&request);
            let signature = BlsSignature(key.secret_key().sign(&root.0).to_bytes());
            client
                .beacon()
                .submit_bls_changes(&[SignedBlsToExecutionChange {
                    message: change,
                    signature,
                }])
                .await?;
            let _unwritable = writeln!(io::stdout(), "change submitted");
            Ok(())
        })
    }
}

/// The flags of an account command, as given.
#[derive(Debug, Default)]
struct AccountFlags {
    /// Whether help was asked for.
    help: bool,
    /// Validators to create.
    count: Option<u32>,
    /// First EIP-2334 index.
    start: Option<u32>,
    /// Mnemonic length.
    words: Option<usize>,
    /// Mnemonic file.
    mnemonic_file: Option<PathBuf>,
    /// Password file.
    password_file: Option<PathBuf>,
    /// Output directory.
    output: Option<PathBuf>,
    /// Withdrawal address.
    withdrawal_address: Option<ExecutionAddress>,
    /// Whether credentials compound.
    compounding: bool,
    /// Deposit amount.
    amount: Option<Gwei>,
    /// Whether keystores use PBKDF2.
    pbkdf2: bool,
    /// Network name.
    network: Option<String>,
    /// Config file.
    config: Option<PathBuf>,
    /// Database directory.
    database: Option<PathBuf>,
    /// Interchange file.
    file: Option<PathBuf>,
    /// Chain of a new database.
    genesis_validators_root: Option<Root>,
    /// Validator index.
    validator_index: Option<ValidatorIndex>,
    /// EIP-2334 index.
    key_index: Option<u32>,
    /// Withdrawal target address.
    to: Option<ExecutionAddress>,
    /// Beacon node URL.
    beacon_node: Option<String>,
    /// Validator data directory.
    datadir: PathBuf,
    /// Keystores to import.
    keystores: Vec<PathBuf>,
    /// Validator to exit.
    validator: Option<BlsPubkey>,
    /// Exit epoch.
    epoch: Option<Epoch>,
}

impl AccountFlags {
    /// Parses the flags after the command name.
    fn parse(arguments: impl Iterator<Item = String>) -> Result<Self, CliError> {
        let mut flags = Self {
            datadir: PathBuf::from("validator"),
            ..Self::default()
        };
        let mut arguments = arguments;
        while let Some(flag) = arguments.next() {
            let mut value =
                |name: &'static str| arguments.next().ok_or(CliError::MissingValue(name));
            match flag.as_str() {
                "-h" | "--help" => flags.help = true,
                "--count" => flags.count = Some(parsed("--count", value("--count")?)?),
                "--start" => flags.start = Some(parsed("--start", value("--start")?)?),
                "--words" => flags.words = Some(parsed("--words", value("--words")?)?),
                "--mnemonic-file" => flags.mnemonic_file = Some(value("--mnemonic-file")?.into()),
                "--password-file" => flags.password_file = Some(value("--password-file")?.into()),
                "--output" => flags.output = Some(value("--output")?.into()),
                "--withdrawal-address" => {
                    flags.withdrawal_address = Some(address(
                        "--withdrawal-address",
                        value("--withdrawal-address")?,
                    )?);
                }
                "--compounding" => flags.compounding = true,
                "--amount" => flags.amount = Some(Gwei(parsed("--amount", value("--amount")?)?)),
                "--pbkdf2" => flags.pbkdf2 = true,
                "--network" => flags.network = Some(value("--network")?),
                "--config" => flags.config = Some(value("--config")?.into()),
                "--database" => flags.database = Some(value("--database")?.into()),
                "--file" => flags.file = Some(value("--file")?.into()),
                "--genesis-validators-root" => {
                    let text = value("--genesis-validators-root")?;
                    let bytes =
                        <[u8; 32]>::from_data(&text).map_err(|_| CliError::InvalidValue {
                            flag: "--genesis-validators-root",
                            value: text,
                        })?;
                    flags.genesis_validators_root = Some(Root(bytes));
                }
                "--validator-index" => {
                    flags.validator_index = Some(ValidatorIndex(parsed(
                        "--validator-index",
                        value("--validator-index")?,
                    )?));
                }
                "--key-index" => {
                    flags.key_index = Some(parsed("--key-index", value("--key-index")?)?);
                }
                "--to" => flags.to = Some(address("--to", value("--to")?)?),
                "--beacon-node" => flags.beacon_node = Some(value("--beacon-node")?),
                "--datadir" => flags.datadir = value("--datadir")?.into(),
                "--keystore" => flags.keystores.push(value("--keystore")?.into()),
                "--validator" => {
                    let text = value("--validator")?;
                    let bytes =
                        <[u8; 48]>::from_data(&text).map_err(|_| CliError::InvalidValue {
                            flag: "--validator",
                            value: text,
                        })?;
                    flags.validator = Some(BlsPubkey(bytes));
                }
                "--epoch" => flags.epoch = Some(Epoch(parsed("--epoch", value("--epoch")?)?)),
                _ => return Err(CliError::UnknownFlag(flag)),
            }
        }
        Ok(flags)
    }

    /// The chain the flags name.
    fn chain(&self) -> Result<(PresetName, ChainConfig), CliError> {
        Cli::choose_chain(self.network.as_deref(), self.config.as_deref())
    }

    /// The key generation the flags describe.
    fn generation(&self) -> Result<KeyGeneration, CliError> {
        let words = match self.words.unwrap_or(24) {
            12 => WordCount::Twelve,
            15 => WordCount::Fifteen,
            18 => WordCount::Eighteen,
            21 => WordCount::TwentyOne,
            24 => WordCount::TwentyFour,
            other => {
                return Err(CliError::InvalidValue {
                    flag: "--words",
                    value: other.to_string(),
                });
            }
        };
        let (_, chain) = self.chain()?;
        Ok(KeyGeneration {
            words,
            count: self.count.unwrap_or(1),
            start: self.start.unwrap_or(0),
            password_file: Self::required(self.password_file.clone(), "--password-file")?,
            output: Self::required(self.output.clone(), "--output")?,
            withdrawal_address: self.withdrawal_address,
            compounding: self.compounding,
            amount: self.amount.unwrap_or(DEFAULT_AMOUNT),
            pbkdf2: self.pbkdf2,
            chain,
        })
    }

    /// A flag the command needs.
    fn required<T>(value: Option<T>, flag: &'static str) -> Result<T, CliError> {
        value.ok_or(CliError::MissingValue(flag))
    }
}

/// A flag's value parsed from text.
fn parsed<T: FromStr>(flag: &'static str, value: String) -> Result<T, CliError> {
    value
        .parse()
        .map_err(|_| CliError::InvalidValue { flag, value })
}

/// An execution address flag.
fn address(flag: &'static str, value: String) -> Result<ExecutionAddress, CliError> {
    <[u8; 20]>::from_data(&value)
        .map(ExecutionAddress)
        .map_err(|_| CliError::InvalidValue { flag, value })
}

/// Reads a text file.
fn read_file(path: &Path) -> Result<String, AccountError> {
    fs::read_to_string(path).map_err(|source| AccountError::File {
        path: path.to_owned(),
        source,
    })
}

/// Writes a file.
fn write_file(path: &Path, bytes: &[u8]) -> Result<(), AccountError> {
    fs::write(path, bytes).map_err(|source| AccountError::File {
        path: path.to_owned(),
        source,
    })
}

/// Reads a mnemonic from a file.
fn read_mnemonic(path: &Path) -> Result<Mnemonic, AccountError> {
    Ok(Mnemonic::parse(read_file(path)?.trim())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(arguments: &[&str]) -> Result<Account, CliError> {
        Account::parse(arguments.iter().map(|argument| (*argument).to_owned()))
    }

    #[test]
    fn key_generation_reads_every_flag() {
        let Account::NewMnemonic(generation) = parse(&[
            "new-mnemonic",
            "--count",
            "3",
            "--start",
            "7",
            "--words",
            "12",
            "--password-file",
            "pw",
            "--output",
            "keys",
            "--withdrawal-address",
            "0x00000000219ab540356cbb839cbe05303d7705fa",
            "--compounding",
            "--amount",
            "2048000000000",
            "--pbkdf2",
            "--network",
            "minimal",
        ])
        .unwrap() else {
            panic!("new-mnemonic parses to key generation");
        };
        assert_eq!(generation.words, WordCount::Twelve);
        assert_eq!((generation.count, generation.start), (3, 7));
        assert_eq!(generation.password_file, PathBuf::from("pw"));
        assert_eq!(generation.output, PathBuf::from("keys"));
        assert_eq!(
            generation.withdrawal_address,
            Some(ExecutionAddress(
                <[u8; 20]>::from_data("0x00000000219ab540356cbb839cbe05303d7705fa").unwrap()
            ))
        );
        assert!(generation.compounding && generation.pbkdf2);
        assert_eq!(generation.amount, Gwei(2_048_000_000_000));
        assert_eq!(generation.chain, ChainConfig::minimal());
    }

    #[test]
    fn missing_and_malformed_values_are_named() {
        // Key generation needs a password file.
        assert!(matches!(
            parse(&["new-mnemonic", "--output", "keys"]),
            Err(CliError::MissingValue("--password-file"))
        ));
        // Thirteen words is no BIP-39 length.
        assert!(matches!(
            parse(&[
                "new-mnemonic",
                "--words",
                "13",
                "--password-file",
                "pw",
                "--output",
                "o"
            ]),
            Err(CliError::InvalidValue {
                flag: "--words",
                ..
            })
        ));
        // An exit names its validator by a 48-byte key.
        assert!(matches!(
            parse(&["exit", "--validator", "0x1234"]),
            Err(CliError::InvalidValue {
                flag: "--validator",
                ..
            })
        ));
        assert!(matches!(
            parse(&["frobnicate"]),
            Err(CliError::UnknownFlag(command)) if command == "frobnicate"
        ));
    }

    #[test]
    fn no_command_asks_for_help() {
        assert!(matches!(parse(&[]), Ok(Account::Help)));
    }
}
