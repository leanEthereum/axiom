//! The directory the client keeps its keys in, durable across restarts.

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::{
    collections::BTreeMap,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, ErrorKind, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use axiom_http::{Client, ClientConfig, Endpoint};
use axiom_json::Data;
use axiom_types::BlsPubkey;

use crate::{
    keymanager::{Definitions, DirectoryError, SignerKind, ValidatorDefinition, sealed::SealedKey},
    keys::{DerivationPath, Keystore, OsEntropy, Password},
    signing::{RemoteSigner, ValidatorSigner},
    validators::ValidatorSettings,
};

/// Where a loaded key came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeySource {
    /// A keystore file, decrypted into this process.
    Keystore(PathBuf),
    /// A remote signer, by its URL.
    Remote(String),
}

/// A key read from the directory, ready to sign.
#[derive(Debug)]
pub struct LoadedKey {
    /// The key.
    pub signer: ValidatorSigner,
    /// Where it came from.
    pub source: KeySource,
    /// Its overrides of the client's defaults.
    pub settings: ValidatorSettings,
}

/// A directory holding the client's keys.
///
/// # Overview
///
/// The directory holds four kinds of entries.
///
/// - Each local key is an EIP-2335 keystore, named after its public key, in the keystores folder.
/// - Its password sits in the secrets folder, in a file of the same name, for its owner only.
/// - The definitions file says, per key, whether it runs, where it lives, and its overrides.
/// - The keymanager API token is one file of hex text, for its owner only.
///
/// A keystore placed in the folder without a definition is found on load, and defined enabled.
///
/// # Invariants
///
/// Every file is written to a temporary name, flushed, then renamed over the old one.
/// A crash leaves either the old file or the new one, never a torn one.
/// A password is written before its keystore, so a keystore on disk always has its password.
#[derive(Debug)]
pub struct KeyDirectory {
    /// The directory.
    root: PathBuf,
    /// Serializes edits of the definitions file, which are reads then writes.
    definitions: Mutex<()>,
}

impl KeyDirectory {
    /// Folder of keystore files.
    const KEYSTORES: &'static str = "keystores";

    /// Folder of password files.
    const SECRETS: &'static str = "secrets";

    /// File of validator definitions.
    const DEFINITIONS: &'static str = "validator_definitions.yml";

    /// File holding the keymanager API token.
    const TOKEN: &'static str = "api-token.txt";

    /// Bytes of a fresh token: the keymanager API asks for at least 256 bits.
    const TOKEN_BYTES: usize = 32;

    /// Opens a directory, creating it and its folders when absent.
    ///
    /// # Errors
    ///
    /// Fails when a folder cannot be created.
    pub fn open(path: impl Into<PathBuf>) -> io::Result<Self> {
        let root = path.into();
        fs::create_dir_all(root.join(Self::KEYSTORES))?;
        let mut secrets = DirBuilder::new();
        secrets.recursive(true);
        // Only the owner may list or open the passwords.
        #[cfg(unix)]
        secrets.mode(0o700);
        secrets.create(root.join(Self::SECRETS))?;
        Ok(Self {
            root,
            definitions: Mutex::new(()),
        })
    }

    /// The directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.root
    }

    /// Where a key's keystore lives.
    #[must_use]
    pub fn keystore_path(&self, pubkey: &BlsPubkey) -> PathBuf {
        self.root
            .join(Self::KEYSTORES)
            .join(format!("{pubkey}.json"))
    }

    /// Where a key's password lives.
    #[must_use]
    pub fn secret_path(&self, pubkey: &BlsPubkey) -> PathBuf {
        self.root.join(Self::SECRETS).join(pubkey.to_string())
    }

    /// Whether the directory holds a keystore for a key.
    #[must_use]
    pub fn holds_keystore(&self, pubkey: &BlsPubkey) -> bool {
        self.keystore_path(pubkey).is_file()
    }

    /// The derivation path a stored keystore records, if any.
    #[must_use]
    pub fn derivation_path(&self, pubkey: &BlsPubkey) -> Option<DerivationPath> {
        let text = fs::read_to_string(self.keystore_path(pubkey)).ok()?;
        Keystore::parse(&text).ok()?.path().cloned()
    }

    /// Every validator definition, ordered by key.
    ///
    /// # Errors
    ///
    /// Fails when the file exists but cannot be read or parsed.
    pub fn definitions(&self) -> Result<Definitions, DirectoryError> {
        let path = self.root.join(Self::DEFINITIONS);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Definitions::default()),
            Err(source) => return Err(DirectoryError::Io { path, source }),
        };
        Definitions::parse(&text).map_err(|source| DirectoryError::Definitions { path, source })
    }

    /// Applies a change to the definitions and writes them back, as one edit.
    ///
    /// # Errors
    ///
    /// Fails when the file cannot be read, parsed, or written.
    pub fn edit_definitions<T>(
        &self,
        change: impl FnOnce(&mut Definitions) -> T,
    ) -> Result<T, DirectoryError> {
        let _edit = self.lock_definitions();
        let mut definitions = self.definitions()?;
        let result = change(&mut definitions);
        let path = self.root.join(Self::DEFINITIONS);
        Self::write_atomically(&path, definitions.to_text().as_bytes(), false)
            .map_err(|source| DirectoryError::Io { path, source })?;
        Ok(result)
    }

    /// Stores a keystore and its password, and defines the key as an enabled local key.
    ///
    /// A key defined before keeps its overrides.
    ///
    /// # Errors
    ///
    /// Fails when a file cannot be written.
    pub fn save_keystore(&self, keystore: &Keystore, password: &str) -> Result<(), DirectoryError> {
        let pubkey = keystore.pubkey();
        let secret = self.secret_path(&pubkey);
        Self::write_atomically(&secret, password.as_bytes(), true).map_err(|source| {
            DirectoryError::Io {
                path: secret,
                source,
            }
        })?;
        let path = self.keystore_path(&pubkey);
        let text = keystore.to_json().to_string();
        Self::write_atomically(&path, text.as_bytes(), false)
            .map_err(|source| DirectoryError::Io { path, source })?;
        self.edit_definitions(|definitions| {
            let mut definition = definitions
                .remove(&pubkey)
                .unwrap_or_else(|| ValidatorDefinition::local(pubkey));
            definition.enabled = true;
            definition.signer = SignerKind::LocalKeystore;
            definitions.insert(definition);
        })
    }

    /// Removes a keystore, its password, and its definition, when present.
    ///
    /// # Errors
    ///
    /// Fails when a file exists but cannot be removed.
    pub fn remove_keystore(&self, pubkey: &BlsPubkey) -> Result<(), DirectoryError> {
        // The definition goes first, so a crash never leaves an enabled key without its keystore.
        self.edit_definitions(|definitions| {
            if definitions
                .get(pubkey)
                .is_some_and(|definition| definition.signer == SignerKind::LocalKeystore)
            {
                definitions.remove(pubkey);
            }
        })?;
        // The keystore goes before the password, so a crash leaves at worst an orphan password.
        for path in [self.keystore_path(pubkey), self.secret_path(pubkey)] {
            Self::remove_if_present(&path).map_err(|source| DirectoryError::Io { path, source })?;
        }
        Ok(())
    }

    /// The remote keys, with their signer URLs.
    ///
    /// # Errors
    ///
    /// Fails when the definitions exist but cannot be read or parsed.
    pub fn remotes(&self) -> Result<BTreeMap<BlsPubkey, String>, DirectoryError> {
        Ok(self
            .definitions()?
            .iter()
            .filter_map(|definition| match &definition.signer {
                SignerKind::Remote { url } => Some((definition.pubkey, url.clone())),
                SignerKind::LocalKeystore => None,
            })
            .collect())
    }

    /// Defines a remote key and its signer URL, replacing any earlier definition's signer.
    ///
    /// # Errors
    ///
    /// Fails when the definitions cannot be read or written.
    pub fn save_remote(&self, pubkey: BlsPubkey, url: &str) -> Result<(), DirectoryError> {
        self.edit_definitions(|definitions| {
            let mut definition = definitions
                .remove(&pubkey)
                .unwrap_or_else(|| ValidatorDefinition::remote(pubkey, url));
            definition.enabled = true;
            definition.signer = SignerKind::Remote {
                url: url.to_owned(),
            };
            definitions.insert(definition);
        })
    }

    /// Forgets a remote key.
    ///
    /// # Returns
    ///
    /// Whether a remote definition of the key existed.
    ///
    /// # Errors
    ///
    /// Fails when the definitions cannot be read or written.
    pub fn remove_remote(&self, pubkey: &BlsPubkey) -> Result<bool, DirectoryError> {
        self.edit_definitions(|definitions| {
            let remote = definitions
                .get(pubkey)
                .is_some_and(|definition| matches!(definition.signer, SignerKind::Remote { .. }));
            if remote {
                definitions.remove(pubkey);
            }
            remote
        })
    }

    /// Changes a defined key's overrides.
    ///
    /// # Returns
    ///
    /// Whether the key is defined.
    ///
    /// # Errors
    ///
    /// Fails when the definitions cannot be read or written.
    pub fn edit_settings(
        &self,
        pubkey: &BlsPubkey,
        change: impl FnOnce(&mut ValidatorSettings),
    ) -> Result<bool, DirectoryError> {
        self.edit_definitions(|definitions| {
            definitions
                .get_mut(pubkey)
                .map(|definition| change(&mut definition.settings))
                .is_some()
        })
    }

    /// Enables or disables a defined key, which takes effect on the next start.
    ///
    /// # Returns
    ///
    /// Whether the key is defined.
    ///
    /// # Errors
    ///
    /// Fails when the definitions cannot be read or written.
    pub fn set_enabled(&self, pubkey: &BlsPubkey, enabled: bool) -> Result<bool, DirectoryError> {
        self.edit_definitions(|definitions| {
            definitions
                .get_mut(pubkey)
                .map(|definition| definition.enabled = enabled)
                .is_some()
        })
    }

    /// Reads every enabled key, decrypting the keystores in parallel.
    ///
    /// A keystore without a definition is defined first, enabled and without overrides.
    /// Keys come back local first, each kind ordered by public key.
    ///
    /// # Errors
    ///
    /// Fails on the first file that cannot be read, parsed, or decrypted.
    pub fn load(&self) -> Result<Vec<LoadedKey>, DirectoryError> {
        // Phase 1: every keystore in the folder, each named after the key it holds.
        let mut keystores = BTreeMap::new();
        for path in self.keystore_files()? {
            let text = fs::read_to_string(&path).map_err(|source| DirectoryError::Io {
                path: path.clone(),
                source,
            })?;
            let keystore = Keystore::parse(&text).map_err(|source| DirectoryError::Keystore {
                path: path.clone(),
                source: Box::new(source),
            })?;
            // A file named after another key would let one key pose as another in listings.
            let pubkey = keystore.pubkey();
            if path != self.keystore_path(&pubkey) {
                return Err(DirectoryError::Misnamed {
                    path,
                    actual: pubkey.to_string(),
                });
            }
            keystores.insert(pubkey, (path, keystore));
        }

        // Phase 2: keystores copied in by hand become enabled definitions.
        let mut definitions = self.definitions()?;
        if keystores
            .keys()
            .any(|pubkey| definitions.get(pubkey).is_none())
        {
            definitions = self.edit_definitions(|stored| {
                for pubkey in keystores.keys() {
                    if stored.get(pubkey).is_none() {
                        stored.insert(ValidatorDefinition::local(*pubkey));
                    }
                }
                stored.clone()
            })?;
        }

        // Phase 3: the enabled local keys, decrypted together.
        let mut sealed = Vec::new();
        let mut opened_from = Vec::new();
        for definition in definitions.iter().filter(|definition| definition.enabled) {
            if definition.signer != SignerKind::LocalKeystore {
                continue;
            }
            let pubkey = definition.pubkey;
            let Some((path, keystore)) = keystores.remove(&pubkey) else {
                return Err(DirectoryError::MissingKeystore {
                    pubkey,
                    path: self.keystore_path(&pubkey),
                });
            };
            let secret = self.secret_path(&pubkey);
            let password = fs::read_to_string(&secret).map_err(|source| DirectoryError::Io {
                path: secret,
                source,
            })?;
            sealed.push(SealedKey::new(keystore, Password::new(&password)));
            opened_from.push((path, definition.settings.clone()));
        }
        let mut loaded = Vec::with_capacity(sealed.len());
        for (opened, (path, settings)) in SealedKey::open_all(&sealed).into_iter().zip(opened_from)
        {
            let key = opened.map_err(|source| DirectoryError::Unlock {
                path: path.clone(),
                source: Box::new(source),
            })?;
            loaded.push(LoadedKey {
                signer: ValidatorSigner::Local(key),
                source: KeySource::Keystore(path),
                settings,
            });
        }

        // Phase 4: the enabled remote keys; keys behind one signer share its connections.
        let mut clients: BTreeMap<String, Arc<Client>> = BTreeMap::new();
        for definition in definitions.iter().filter(|definition| definition.enabled) {
            let SignerKind::Remote { url } = &definition.signer else {
                continue;
            };
            let client = match clients.get(url) {
                Some(client) => Arc::clone(client),
                None => {
                    let endpoint = Endpoint::parse(url).map_err(|source| DirectoryError::Url {
                        url: url.clone(),
                        source,
                    })?;
                    let client = Arc::new(Client::new(endpoint, ClientConfig::default()));
                    clients.insert(url.clone(), Arc::clone(&client));
                    client
                }
            };
            loaded.push(LoadedKey {
                signer: ValidatorSigner::Remote(RemoteSigner::new(client, definition.pubkey)),
                source: KeySource::Remote(url.clone()),
                settings: definition.settings.clone(),
            });
        }
        Ok(loaded)
    }

    /// The keymanager API token, created on first use.
    ///
    /// The keymanager API asks for a hex token of at least 256 bits, reused across restarts.
    ///
    /// # Errors
    ///
    /// Fails when the file cannot be read or created, or holds no token.
    pub fn api_token(&self) -> io::Result<String> {
        Self::token_at(&self.root.join(Self::TOKEN))
    }

    /// The keymanager API token in a file, created on first use.
    ///
    /// # Errors
    ///
    /// Fails when the file cannot be read or created, or holds no token.
    pub fn token_at(path: &Path) -> io::Result<String> {
        match fs::read_to_string(path) {
            Ok(text) => {
                let token = text.trim();
                if token.is_empty() {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        format!("{} holds no token", path.display()),
                    ));
                }
                Ok(token.to_owned())
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                let bytes: [u8; Self::TOKEN_BYTES] = OsEntropy::array()?;
                // The token file holds bare hex, without the 0x prefix.
                let data = bytes.to_data();
                let token = data.strip_prefix("0x").unwrap_or(&data).to_owned();
                Self::write_atomically(path, token.as_bytes(), true)?;
                Ok(token)
            }
            Err(error) => Err(error),
        }
    }

    /// The keystore files, in name order, which is public key order.
    fn keystore_files(&self) -> Result<Vec<PathBuf>, DirectoryError> {
        let folder = self.root.join(Self::KEYSTORES);
        let io = |source| DirectoryError::Io {
            path: folder.clone(),
            source,
        };
        let mut files = Vec::new();
        for entry in fs::read_dir(&folder).map_err(io)? {
            let path = entry.map_err(io)?.path();
            // Temporary files from an interrupted write carry another extension.
            if path
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                files.push(path);
            }
        }
        files.sort();
        Ok(files)
    }

    /// The lock serializing edits of the definitions file.
    fn lock_definitions(&self) -> MutexGuard<'_, ()> {
        // The lock guards no data, so a poisoned one is as good as a clean one.
        self.definitions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Replaces a file with new contents, so a crash never leaves half of them.
    ///
    /// A private file is readable and writable by its owner only, from its first byte.
    fn write_atomically(path: &Path, contents: &[u8], private: bool) -> io::Result<()> {
        let temporary = path.with_extension("tmp");
        // Why: a mode applies only at creation, so a leftover file must not be reused.
        Self::remove_if_present(&temporary)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(if private { 0o600 } else { 0o644 });
        #[cfg(not(unix))]
        let _ = private;
        let mut file = options.open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        // Why: the rename is durable only once the directory entry itself reaches the disk.
        if let Some(parent) = path.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    }

    /// Removes a file, treating an absent one as removed.
    fn remove_if_present(path: &Path) -> io::Result<()> {
        match fs::remove_file(path) {
            Err(error) if error.kind() != ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::{env, process};

    use super::*;
    use crate::keys::{EncryptionParams, Kdf, SecretKeyBytes};

    /// An empty scratch directory for one test.
    fn scratch(name: &str) -> PathBuf {
        let path = env::temp_dir().join(format!("axiom-key-directory-{name}-{}", process::id()));
        // A directory left by an interrupted run would leak its keys into this one.
        if path.exists() {
            fs::remove_dir_all(&path).unwrap();
        }
        path
    }

    /// The secret key n, as raw bytes.
    fn secret(n: u8) -> SecretKeyBytes {
        let mut bytes = [0; 32];
        bytes[31] = n;
        SecretKeyBytes::from_bytes(&bytes).unwrap()
    }

    /// A one-round PBKDF2 keystore of the secret key n.
    fn keystore(n: u8, password: &str) -> Keystore {
        let params = EncryptionParams::random(Kdf::pbkdf2(1).unwrap()).unwrap();
        Keystore::encrypt(&secret(n), &Password::new(password), &params)
    }

    /// The public key and source of each loaded key.
    fn summary(loaded: &[LoadedKey]) -> Vec<(BlsPubkey, KeySource)> {
        loaded
            .iter()
            .map(|key| (key.signer.pubkey(), key.source.clone()))
            .collect()
    }

    #[test]
    fn keys_survive_a_reopen() {
        let path = scratch("reopen");
        // Fixture state: local keys 1 and 2 under their own passwords, remote key 3.
        let (one, two) = (keystore(1, "one"), keystore(2, "two"));
        let remote = secret(3).public_key();
        let directory = KeyDirectory::open(&path).unwrap();
        directory.save_keystore(&two, "two").unwrap();
        directory.save_keystore(&one, "one").unwrap();
        directory
            .save_remote(remote, "http://127.0.0.1:9000")
            .unwrap();
        drop(directory);

        // A fresh handle decrypts both keystores and finds the remote key.
        // Local keys come first, in file name order, which is public key order.
        let reopened = KeyDirectory::open(&path).unwrap();
        let mut local = [one.pubkey(), two.pubkey()];
        local.sort_by_key(ToString::to_string);
        let mut expected: Vec<(BlsPubkey, KeySource)> = local
            .iter()
            .map(|pubkey| (*pubkey, KeySource::Keystore(reopened.keystore_path(pubkey))))
            .collect();
        expected.push((
            remote,
            KeySource::Remote("http://127.0.0.1:9000".to_owned()),
        ));
        assert_eq!(summary(&reopened.load().unwrap()), expected);

        // Removing key 1 and the remote key leaves only key 2.
        reopened.remove_keystore(&one.pubkey()).unwrap();
        assert!(reopened.remove_remote(&remote).unwrap());
        assert!(!reopened.remove_remote(&remote).unwrap());
        assert_eq!(
            summary(&reopened.load().unwrap()),
            [(
                two.pubkey(),
                KeySource::Keystore(reopened.keystore_path(&two.pubkey()))
            )]
        );
        fs::remove_dir_all(&path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn passwords_and_the_token_are_private() {
        let path = scratch("private");
        let directory = KeyDirectory::open(&path).unwrap();
        let key = keystore(1, "pw");
        directory.save_keystore(&key, "pw").unwrap();

        // The token is 32 random bytes as 64 hex digits, created once and then reused.
        let token = directory.api_token().unwrap();
        assert_eq!(token.len(), 64);
        assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(directory.api_token().unwrap(), token);

        // Only the owner may read or write the password and the token.
        let mode = |path: PathBuf| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(directory.secret_path(&key.pubkey())), 0o600);
        assert_eq!(mode(path.join("api-token.txt")), 0o600);
        assert_eq!(mode(path.join("secrets")), 0o700);
        fs::remove_dir_all(&path).unwrap();
    }

    #[test]
    fn a_keystore_under_another_key_name_is_refused() {
        let path = scratch("misnamed");
        let directory = KeyDirectory::open(&path).unwrap();
        let (one, two) = (keystore(1, "pw"), keystore(2, "pw"));
        directory.save_keystore(&one, "pw").unwrap();

        // Mutation: key 1's keystore moves to the name of key 2.
        let misnamed = directory.keystore_path(&two.pubkey());
        fs::rename(directory.keystore_path(&one.pubkey()), &misnamed).unwrap();

        let error = directory.load().unwrap_err();
        assert_eq!(
            error.to_string(),
            DirectoryError::Misnamed {
                path: misnamed,
                actual: one.pubkey().to_string(),
            }
            .to_string()
        );
        fs::remove_dir_all(&path).unwrap();
    }

    #[test]
    fn a_keystore_copied_in_is_defined_and_a_disabled_key_stays_unloaded() {
        let path = scratch("discover");
        let directory = KeyDirectory::open(&path).unwrap();
        let (one, two) = (keystore(1, "one"), keystore(2, "two"));

        // Fixture state: key 1 saved through the directory, key 2 copied in by hand.
        directory.save_keystore(&one, "one").unwrap();
        fs::write(directory.secret_path(&two.pubkey()), "two").unwrap();
        fs::write(
            directory.keystore_path(&two.pubkey()),
            two.to_json().to_string(),
        )
        .unwrap();
        assert_eq!(directory.definitions().unwrap().iter().count(), 1);

        // Loading defines key 2 enabled, and both keys load.
        assert_eq!(directory.load().unwrap().len(), 2);
        let definitions = directory.definitions().unwrap();
        assert_eq!(
            definitions.get(&two.pubkey()),
            Some(&ValidatorDefinition::local(two.pubkey()))
        );

        // Mutation: key 1 is disabled, so only key 2 loads, while key 1 stays defined.
        assert!(directory.set_enabled(&one.pubkey(), false).unwrap());
        let loaded = directory.load().unwrap();
        assert_eq!(
            summary(&loaded),
            [(
                two.pubkey(),
                KeySource::Keystore(directory.keystore_path(&two.pubkey()))
            )]
        );
        assert!(
            !directory
                .definitions()
                .unwrap()
                .get(&one.pubkey())
                .unwrap()
                .enabled
        );
        fs::remove_dir_all(&path).unwrap();
    }

    #[test]
    fn overrides_survive_a_reopen_and_reach_the_loaded_key() {
        let path = scratch("overrides");
        let directory = KeyDirectory::open(&path).unwrap();
        let key = keystore(1, "pw");
        directory.save_keystore(&key, "pw").unwrap();
        assert!(
            directory
                .edit_settings(&key.pubkey(), |settings| settings.gas_limit =
                    Some(30_000_000))
                .unwrap()
        );
        // An undefined key has no settings to change.
        assert!(
            !directory
                .edit_settings(&secret(9).public_key(), |_| {})
                .unwrap()
        );
        drop(directory);

        let reopened = KeyDirectory::open(&path).unwrap();
        let loaded = reopened.load().unwrap();
        assert_eq!(
            loaded[0].settings,
            ValidatorSettings {
                gas_limit: Some(30_000_000),
                ..ValidatorSettings::default()
            }
        );

        // Saving the keystore again keeps the override; removing it forgets the definition.
        reopened.save_keystore(&key, "pw").unwrap();
        let definitions = reopened.definitions().unwrap();
        let definition = definitions.get(&key.pubkey()).unwrap();
        assert_eq!(definition.settings.gas_limit, Some(30_000_000));
        reopened.remove_keystore(&key.pubkey()).unwrap();
        assert_eq!(reopened.definitions().unwrap(), Definitions::default());
        fs::remove_dir_all(&path).unwrap();
    }

    #[test]
    fn an_enabled_key_without_its_keystore_is_refused() {
        let path = scratch("missing");
        let directory = KeyDirectory::open(&path).unwrap();
        let pubkey = secret(4).public_key();
        directory
            .edit_definitions(|definitions| definitions.insert(ValidatorDefinition::local(pubkey)))
            .unwrap();
        assert_eq!(
            directory.load().unwrap_err().to_string(),
            DirectoryError::MissingKeystore {
                pubkey,
                path: directory.keystore_path(&pubkey),
            }
            .to_string()
        );
        fs::remove_dir_all(&path).unwrap();
    }
}
