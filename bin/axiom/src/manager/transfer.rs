//! The commands over a running client's keymanager API: import, list, delete, and move.

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::{Path, PathBuf},
    process, slice,
};

use axiom_http::ClientConfig;
use axiom_types::{BlsPubkey, ExecutionAddress};
use axiom_validator::{
    beacon::BeaconClient,
    keymanager::{DeleteStatus, ImportStatus, KeyDirectory, KeymanagerClient},
};
use tokio::runtime::Builder;

use crate::manager::{ManagerError, Selection, SettingsFlags, ValidatorSpec, read_file};

/// Where import finds its validators.
#[derive(Debug)]
pub(crate) enum ImportSource {
    /// A validators file.
    File(PathBuf),
    /// One keystore, with its password and settings.
    Keystore {
        /// The keystore file.
        keystore: PathBuf,
        /// Its password.
        password: String,
        /// Its settings.
        settings: SettingsFlags,
    },
}

/// Validators to upload to a client.
#[derive(Debug)]
pub(crate) struct Import {
    /// Where the validators come from.
    pub(crate) source: ImportSource,
    /// The client's keymanager API.
    pub(crate) vc_url: String,
    /// The file holding its token.
    pub(crate) vc_token: PathBuf,
    /// Whether keys the client already runs are skipped rather than refused.
    pub(crate) ignore_duplicates: bool,
}

/// A listing of a client's keys.
#[derive(Debug)]
pub(crate) struct List {
    /// The client's keymanager API.
    pub(crate) vc_url: String,
    /// The file holding its token.
    pub(crate) vc_token: PathBuf,
    /// A beacon node to read each key's status from.
    pub(crate) beacon_node: Option<String>,
    /// The keys to show.
    pub(crate) selection: Selection,
}

/// Keys to delete from a client.
#[derive(Debug)]
pub(crate) struct Delete {
    /// The client's keymanager API.
    pub(crate) vc_url: String,
    /// The file holding its token.
    pub(crate) vc_token: PathBuf,
    /// The keys.
    pub(crate) selection: Selection,
}

/// Keys to move from one client to another.
#[derive(Debug)]
pub(crate) struct Move {
    /// The source client's keymanager API.
    pub(crate) src_url: String,
    /// The file holding its token.
    pub(crate) src_token: PathBuf,
    /// The source client's data directory, which holds the keystores and passwords.
    pub(crate) src_datadir: PathBuf,
    /// The destination client's keymanager API.
    pub(crate) dest_url: String,
    /// The file holding its token.
    pub(crate) dest_token: PathBuf,
    /// The keys.
    pub(crate) selection: Selection,
}

/// A connection to one client's keymanager API.
#[derive(Debug)]
struct Session {
    /// The client.
    client: KeymanagerClient,
}

impl Session {
    /// Connects with the token in a file.
    fn open(url: &str, token: &Path) -> Result<Self, ManagerError> {
        Ok(Self {
            client: KeymanagerClient::new(url, &read_file(token)?)?,
        })
    }

    /// Every key the client runs, local then remote.
    async fn running(&self) -> Result<Vec<BlsPubkey>, ManagerError> {
        let mut keys: Vec<BlsPubkey> = self
            .client
            .keystores()
            .await?
            .into_iter()
            .map(|key| key.pubkey)
            .collect();
        keys.extend(
            self.client
                .remote_keys()
                .await?
                .into_iter()
                .map(|key| key.pubkey),
        );
        Ok(keys)
    }

    /// Uploads one validator with its history, then applies its settings.
    ///
    /// # Returns
    ///
    /// Whether the client took it, rather than skipping it as a duplicate.
    async fn upload(
        &self,
        spec: &ValidatorSpec,
        ignore_duplicates: bool,
    ) -> Result<bool, ManagerError> {
        let pubkey = spec.pubkey()?;
        let outcome = self
            .client
            .import_keystores(
                slice::from_ref(&spec.keystore),
                slice::from_ref(&spec.password),
                spec.slashing_protection.as_deref(),
            )
            .await?;
        match outcome.as_slice() {
            [ImportStatus::Imported] => {}
            [ImportStatus::Duplicate] if ignore_duplicates => return Ok(false),
            [ImportStatus::Duplicate] => return Err(ManagerError::Duplicate(pubkey)),
            other => {
                return Err(ManagerError::Refused {
                    pubkey,
                    outcome: format!("{other:?}"),
                });
            }
        }
        if let Some(address) = spec.fee_recipient {
            self.client.set_fee_recipient(&pubkey, address).await?;
        }
        if let Some(gas_limit) = spec.gas_limit {
            self.client.set_gas_limit(&pubkey, gas_limit).await?;
        }
        Ok(true)
    }
}

impl Import {
    /// Uploads every validator, one at a time, refusing settings no route can apply first.
    pub(crate) fn execute(self) -> Result<(), ManagerError> {
        let specs = match &self.source {
            ImportSource::File(path) => ValidatorSpec::parse_list(&read_file(path)?)?,
            ImportSource::Keystore {
                keystore,
                password,
                settings,
            } => vec![settings.spec(read_file(keystore)?, password.clone())],
        };
        for spec in &specs {
            Self::check(spec)?;
        }
        let session = Session::open(&self.vc_url, &self.vc_token)?;
        block_on(async {
            let running = session.running().await?;
            let mut imported = 0;
            for spec in &specs {
                let pubkey = spec.pubkey()?;
                if running.contains(&pubkey) {
                    if !self.ignore_duplicates {
                        return Err(ManagerError::Duplicate(pubkey));
                    }
                    let _unwritable = writeln!(io::stderr(), "skipping {pubkey}: already running");
                    continue;
                }
                if session.upload(spec, self.ignore_duplicates).await? {
                    imported += 1;
                }
            }
            let _unwritable = writeln!(io::stdout(), "{imported} validators imported");
            Ok(())
        })
    }

    /// Refuses a validator the operator wants stopped, and warns of builder settings left out.
    ///
    /// The keymanager API can neither disable a key nor set its builder preferences.
    /// A key meant to stay stopped must not start, since it may run elsewhere.
    fn check(spec: &ValidatorSpec) -> Result<(), ManagerError> {
        let pubkey = spec.pubkey()?;
        if spec.enabled == Some(false) {
            return Err(ManagerError::Unsupported {
                pubkey,
                field: "enabled: false",
            });
        }
        let builder = [
            ("builder_proposals", spec.builder_proposals.is_some()),
            ("builder_boost_factor", spec.builder_boost_factor.is_some()),
            (
                "prefer_builder_proposals",
                spec.prefer_builder_proposals.is_some(),
            ),
        ];
        for (field, set) in builder {
            if set {
                let _unwritable = writeln!(
                    io::stderr(),
                    "warning: {pubkey}: {field} is not applied; the keymanager API has no route for it"
                );
            }
        }
        Ok(())
    }
}

impl List {
    /// Prints the chosen keys, and their status on the chain when a beacon node is given.
    pub(crate) fn execute(self) -> Result<(), ManagerError> {
        let session = Session::open(&self.vc_url, &self.vc_token)?;
        let beacon = self
            .beacon_node
            .as_deref()
            .map(|url| BeaconClient::new(url, ClientConfig::default()))
            .transpose()?;
        block_on(async {
            let running = session.running().await?;
            let chosen = self.selection.pick(&running)?;
            let mut out = io::stdout().lock();
            let _unwritable = writeln!(out, "List of validators ({}):", chosen.len());
            for pubkey in &chosen {
                let _unwritable = writeln!(out, "{pubkey}");
            }
            let Some(beacon) = beacon else {
                return Ok(());
            };
            for validator in beacon.beacon().validators(&chosen).await? {
                let _unwritable = writeln!(
                    out,
                    "{} index {} {} exit epoch {} withdrawable epoch {}",
                    validator.validator.pubkey,
                    validator.index.0,
                    validator.status.as_str(),
                    validator.validator.exit_epoch.0,
                    validator.validator.withdrawable_epoch.0,
                );
            }
            Ok(())
        })
    }
}

impl Delete {
    /// Deletes the chosen keys, local and remote, and fails on any key not deleted.
    pub(crate) fn execute(self) -> Result<(), ManagerError> {
        let session = Session::open(&self.vc_url, &self.vc_token)?;
        block_on(async {
            let local: Vec<BlsPubkey> = session
                .client
                .keystores()
                .await?
                .into_iter()
                .map(|key| key.pubkey)
                .collect();
            let chosen = self.selection.pick(&session.running().await?)?;
            let (local, remote): (Vec<BlsPubkey>, Vec<BlsPubkey>) =
                chosen.iter().partition(|pubkey| local.contains(pubkey));
            let mut outcomes = Vec::new();
            if !local.is_empty() {
                let (statuses, _history) = session.client.delete_keystores(&local).await?;
                outcomes.extend(local.iter().copied().zip(statuses));
            }
            if !remote.is_empty() {
                let statuses = session.client.delete_remote_keys(&remote).await?;
                outcomes.extend(remote.iter().copied().zip(statuses));
            }
            Self::confirm(&outcomes)?;
            let _unwritable = writeln!(io::stdout(), "{} validators deleted", outcomes.len());
            Ok(())
        })
    }

    /// Fails on the first key the client reports as anything but deleted.
    fn confirm(outcomes: &[(BlsPubkey, DeleteStatus)]) -> Result<(), ManagerError> {
        for (pubkey, status) in outcomes {
            if *status != DeleteStatus::Deleted {
                return Err(ManagerError::Refused {
                    pubkey: *pubkey,
                    outcome: format!("{status:?}"),
                });
            }
        }
        Ok(())
    }
}

/// A validator read out of the source client before it is deleted there.
#[derive(Debug)]
struct Outgoing {
    /// The validator's file entry, without its history yet.
    spec: ValidatorSpec,
    /// Its key.
    pubkey: BlsPubkey,
}

impl Move {
    /// Moves the chosen local keys, with their slashing protection history.
    ///
    /// # Algorithm
    ///
    /// 1. Read each keystore and password from the source data directory, and its settings.
    /// 2. Delete the keys from the source, which stops them and returns their history.
    /// 3. Import keystores, passwords, and history into the destination together.
    /// 4. Apply each key's fee recipient and gas limit at the destination.
    ///
    /// The standard API exports no secret, so the keystores come from the source's disk.
    /// A key never signs in both clients: the source stops it before the destination starts it.
    /// When step 3 fails, the keys and their history go to a recovery file in the source directory.
    pub(crate) fn execute(self) -> Result<(), ManagerError> {
        let src = Session::open(&self.src_url, &self.src_token)?;
        let dest = Session::open(&self.dest_url, &self.dest_token)?;
        let directory =
            KeyDirectory::open(&self.src_datadir).map_err(|source| ManagerError::File {
                path: self.src_datadir.clone(),
                source,
            })?;
        block_on(async {
            let local: Vec<BlsPubkey> = src
                .client
                .keystores()
                .await?
                .into_iter()
                .filter(|key| !key.readonly)
                .map(|key| key.pubkey)
                .collect();
            let chosen = self.selection.pick(&local)?;
            let at_destination = dest.running().await?;
            if let Some(pubkey) = chosen.iter().find(|pubkey| at_destination.contains(pubkey)) {
                return Err(ManagerError::Duplicate(*pubkey));
            }

            // Phase 1: everything the destination needs, read while the source still runs the keys.
            let mut outgoing = Vec::with_capacity(chosen.len());
            for pubkey in chosen {
                outgoing.push(self.read(&src, &directory, pubkey).await?);
            }
            if outgoing.is_empty() {
                let _unwritable = writeln!(io::stdout(), "no validators to move");
                return Ok(());
            }

            // Phase 2: the source stops the keys and hands over their history.
            let keys: Vec<BlsPubkey> = outgoing.iter().map(|out| out.pubkey).collect();
            let (statuses, history) = src.client.delete_keystores(&keys).await?;
            Delete::confirm(&keys.iter().copied().zip(statuses).collect::<Vec<_>>())?;
            for out in &mut outgoing {
                out.spec.slashing_protection = Some(history.clone());
            }

            // Phase 3: the destination starts them, or the recovery file keeps them.
            if let Err(error) = Self::import(&dest, &outgoing).await {
                let path = self.recover(&outgoing)?;
                return Err(ManagerError::Stranded {
                    path,
                    source: Box::new(error),
                });
            }
            let _unwritable = writeln!(io::stdout(), "{} validators moved", outgoing.len());
            Ok(())
        })
    }

    /// Reads one key's keystore, password, and settings from the source.
    async fn read(
        &self,
        src: &Session,
        directory: &KeyDirectory,
        pubkey: BlsPubkey,
    ) -> Result<Outgoing, ManagerError> {
        let keystore = read_file(&directory.keystore_path(&pubkey))?;
        let password = read_file(&directory.secret_path(&pubkey))?;
        let fee_recipient: ExecutionAddress = src.client.fee_recipient(&pubkey).await?;
        let gas_limit = src.client.gas_limit(&pubkey).await?;
        let settings = SettingsFlags {
            fee_recipient: Some(fee_recipient)
                .filter(|address| *address != ExecutionAddress::default()),
            gas_limit: Some(gas_limit),
            ..SettingsFlags::default()
        };
        Ok(Outgoing {
            spec: settings.spec(keystore, password),
            pubkey,
        })
    }

    /// Imports the keys into the destination with their history, then their settings.
    async fn import(dest: &Session, outgoing: &[Outgoing]) -> Result<(), ManagerError> {
        for out in outgoing {
            dest.upload(&out.spec, false).await?;
        }
        Ok(())
    }

    /// Writes the stranded keys as a validators file only their owner may read.
    fn recover(&self, outgoing: &[Outgoing]) -> Result<PathBuf, ManagerError> {
        let specs: Vec<ValidatorSpec> = outgoing.iter().map(|out| out.spec.clone()).collect();
        let path = self
            .src_datadir
            .join(format!("moved-validators-{}.json", process::id()));
        let write = || -> io::Result<()> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            let mut file = options.open(&path)?;
            file.write_all(ValidatorSpec::list_to_text(&specs).as_bytes())?;
            file.sync_all()
        };
        write().map_err(|source| ManagerError::File {
            path: path.clone(),
            source,
        })?;
        Ok(path)
    }
}

/// Runs a future on a fresh single-threaded runtime.
fn block_on<T>(future: impl Future<Output = Result<T, ManagerError>>) -> Result<T, ManagerError> {
    Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(future)
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use axiom_http::Cors;
    use axiom_node::ManualClock;
    use axiom_types::{ChainConfig, Minimal, Root, Slot, SlotClock, phase0::BeaconBlockHeader};
    use axiom_validator::{
        duties::SlotTimer,
        keymanager::Keymanager,
        keys::{EncryptionParams, Kdf, Keystore, Password, SecretKeyBytes},
        protection::{ProtectionError, SlashingDatabase},
        signing::{SignError, SigningContext, SigningGuard, SigningRequest},
        validators::{DEFAULT_GAS_LIMIT, ProposerDefaults, ValidatorStore},
    };
    use tokio::{runtime::Runtime, sync::oneshot};

    use super::*;

    /// The token both clients accept.
    const TOKEN: &str = "0123456789abcdef";

    /// One running validator client, with its keymanager API on a loopback port.
    struct Client {
        /// Its keys.
        store: Arc<ValidatorStore>,
        /// Its data directory.
        datadir: PathBuf,
        /// Its keymanager API.
        url: String,
        /// The file holding its token.
        token: PathBuf,
        /// Stops its server when dropped.
        _stop: oneshot::Sender<()>,
    }

    impl Client {
        /// A client with an empty store, serving on a runtime.
        fn start(runtime: &Runtime, name: &str) -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let datadir =
                env::temp_dir().join(format!("axiom-manager-{name}-{}-{id}", process::id()));
            let _stale = fs::remove_dir_all(&datadir);
            let directory = Arc::new(KeyDirectory::open(&datadir).unwrap());
            let config = Arc::new(ChainConfig::minimal());
            let protection = Arc::new(SlashingDatabase::in_memory(Root([1; 32])).unwrap());
            let store = Arc::new(ValidatorStore::new(
                SigningGuard::new(SigningContext::new(config, Root([1; 32])), protection),
                ProposerDefaults {
                    gas_limit: DEFAULT_GAS_LIMIT,
                    ..ProposerDefaults::default()
                },
            ));
            let timer = SlotTimer::new(Arc::new(ManualClock::at(0)), SlotClock::new(0, 6_000));
            let keymanager =
                Keymanager::<Minimal>::new(Arc::clone(&store), directory, TOKEN, timer, false);
            let server = runtime
                .block_on(
                    keymanager.bind("127.0.0.1:0".parse().unwrap(), Cors::parse("*").unwrap()),
                )
                .unwrap();
            let url = format!("http://{}", server.local_addr().unwrap());
            let (stop, stopped) = oneshot::channel::<()>();
            runtime.spawn(server.serve(async {
                let _stopped = stopped.await;
            }));
            let token = datadir.join("token.txt");
            fs::write(&token, TOKEN).unwrap();
            Self {
                store,
                datadir,
                url,
                token,
                _stop: stop,
            }
        }
    }

    impl Drop for Client {
        fn drop(&mut self) {
            // A failed removal only leaves a scratch directory behind.
            let _removed = fs::remove_dir_all(&self.datadir);
        }
    }

    /// A validators file entry of the secret key n, under a one-round PBKDF2 keystore.
    fn spec(n: u8) -> ValidatorSpec {
        let mut bytes = [0; 32];
        bytes[31] = n;
        let secret = SecretKeyBytes::from_bytes(&bytes).unwrap();
        let params = EncryptionParams::random(Kdf::pbkdf2(1).unwrap()).unwrap();
        let keystore = Keystore::encrypt(&secret, &Password::new("pw"), &params);
        SettingsFlags {
            fee_recipient: Some(ExecutionAddress([0x5f; 20])),
            gas_limit: Some(36_000_000),
            ..SettingsFlags::default()
        }
        .spec(keystore.to_json().to_string(), "pw".to_owned())
    }

    /// An import of a validators file into a client.
    fn import(client: &Client, file: &Path, ignore_duplicates: bool) -> Import {
        Import {
            source: ImportSource::File(file.to_owned()),
            vc_url: client.url.clone(),
            vc_token: client.token.clone(),
            ignore_duplicates,
        }
    }

    #[test]
    fn import_move_and_delete_through_two_clients() {
        let runtime = Runtime::new().unwrap();
        let src = Client::start(&runtime, "src");
        let dest = Client::start(&runtime, "dest");
        let (one, two) = (spec(1), spec(2));
        let (a, b) = (one.pubkey().unwrap(), two.pubkey().unwrap());
        let file = src.datadir.join("validators.json");
        fs::write(&file, ValidatorSpec::list_to_text(&[one, two])).unwrap();

        // Both keys run at the source with their settings; a second import refuses a duplicate.
        import(&src, &file, false).execute().unwrap();
        assert_eq!(src.store.pubkeys().len(), 2);
        assert_eq!(src.store.settings(&a).gas_limit, 36_000_000);
        assert!(matches!(
            import(&src, &file, false).execute(),
            Err(ManagerError::Duplicate(key)) if key == a
        ));
        import(&src, &file, true).execute().unwrap();
        List {
            vc_url: src.url.clone(),
            vc_token: src.token.clone(),
            beacon_node: None,
            selection: Selection::All,
        }
        .execute()
        .unwrap();

        // Fixture state: key a signs a block at slot 5 at the source before it moves.
        let header = BeaconBlockHeader {
            slot: Slot(5),
            ..BeaconBlockHeader::default()
        };
        runtime
            .block_on(
                src.store
                    .sign::<Minimal>(&a, SigningRequest::Block(&header)),
            )
            .unwrap();

        // Key a moves: it stops at the source and runs at the destination with its settings.
        Move {
            src_url: src.url.clone(),
            src_token: src.token.clone(),
            src_datadir: src.datadir.clone(),
            dest_url: dest.url.clone(),
            dest_token: dest.token.clone(),
            selection: Selection::Keys(vec![a]),
        }
        .execute()
        .unwrap();
        assert_eq!(src.store.pubkeys(), [b]);
        assert_eq!(dest.store.pubkeys(), [a]);
        let settings = dest.store.settings(&a);
        assert_eq!(
            (settings.fee_recipient, settings.gas_limit),
            (ExecutionAddress([0x5f; 20]), 36_000_000)
        );

        // Its history came along: a different block at slot 5 is refused at the destination.
        let other = BeaconBlockHeader {
            slot: Slot(5),
            body_root: Root([9; 32]),
            ..BeaconBlockHeader::default()
        };
        assert!(matches!(
            runtime.block_on(
                dest.store
                    .sign::<Minimal>(&a, SigningRequest::Block(&other))
            ),
            Err(SignError::Protection(ProtectionError::Refused(_)))
        ));

        // Deleting key b leaves the source empty; deleting it again names it.
        let delete = |key| Delete {
            vc_url: src.url.clone(),
            vc_token: src.token.clone(),
            selection: Selection::Keys(vec![key]),
        };
        delete(b).execute().unwrap();
        assert_eq!(src.store.pubkeys(), Vec::<BlsPubkey>::new());
        assert!(matches!(
            delete(b).execute(),
            Err(ManagerError::Unknown(key)) if key == b
        ));
    }

    #[test]
    fn a_key_meant_to_stay_stopped_is_refused_before_any_upload() {
        let runtime = Runtime::new().unwrap();
        let client = Client::start(&runtime, "disabled");
        let mut stopped = spec(3);
        stopped.enabled = Some(false);
        let pubkey = stopped.pubkey().unwrap();
        let file = client.datadir.join("validators.json");
        fs::write(&file, ValidatorSpec::list_to_text(&[stopped])).unwrap();
        assert!(matches!(
            import(&client, &file, false).execute(),
            Err(ManagerError::Unsupported { pubkey: key, field: "enabled: false" }) if key == pubkey
        ));
        assert_eq!(client.store.pubkeys(), Vec::<BlsPubkey>::new());
    }
}
