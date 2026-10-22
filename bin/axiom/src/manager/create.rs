//! Creating validators in bulk: a validators file to import, and a deposits file to submit.

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use axiom_json::{Data, Json};
use axiom_types::{ChainConfig, ExecutionAddress, Gwei};
use axiom_validator::keys::{Kdf, Mnemonic, OsEntropy, Password};

use crate::{
    account::Derivation,
    manager::{ManagerError, SettingsFlags, ValidatorSpec, read_file},
};

/// Validators to derive from a mnemonic.
#[derive(Debug)]
pub(crate) struct Create {
    /// Where the files go.
    pub(crate) output: PathBuf,
    /// The file holding the mnemonic.
    pub(crate) mnemonic: PathBuf,
    /// The first EIP-2334 validator index.
    pub(crate) first_index: u32,
    /// Validators to derive.
    pub(crate) count: u32,
    /// Each deposit's amount.
    pub(crate) amount: Gwei,
    /// Whether a deposits file is written.
    pub(crate) deposits: bool,
    /// Where withdrawals go, when not to a BLS withdrawal key.
    pub(crate) withdrawal_address: Option<ExecutionAddress>,
    /// Whether the credentials compound.
    pub(crate) compounding: bool,
    /// Whether keystores use PBKDF2 rather than scrypt.
    pub(crate) pbkdf2: bool,
    /// The settings every validator carries.
    pub(crate) settings: SettingsFlags,
    /// The chain, for the deposit fork version.
    pub(crate) chain: ChainConfig,
}

impl Create {
    /// Name of the validators file.
    const VALIDATORS: &'static str = "validators.json";

    /// Name of the deposits file.
    const DEPOSITS: &'static str = "deposits.json";

    /// Bytes of each random keystore password, written as hex.
    const PASSWORD_BYTES: usize = 32;

    /// Derives the validators and writes the validators file, then the deposits file.
    ///
    /// Each keystore gets its own random password, kept beside it in the validators file.
    /// That file holds secrets, so only its owner may read it.
    pub(crate) fn execute(self) -> Result<(), ManagerError> {
        let validators = self.output.join(Self::VALIDATORS);
        let deposits = self.output.join(Self::DEPOSITS);
        // Overwriting a file of keys could destroy the only copy of a validator's key.
        for path in [&validators, &deposits] {
            if path.exists() {
                return Err(ManagerError::Exists(path.clone()));
            }
        }
        let mnemonic = Mnemonic::parse(read_file(&self.mnemonic)?.trim())?;
        let seed = mnemonic.to_seed("");
        let derivation = Derivation {
            withdrawal_address: self.withdrawal_address,
            compounding: self.compounding,
            amount: self.amount,
            kdf: if self.pbkdf2 {
                Kdf::pbkdf2(Kdf::PBKDF2_ROUNDS)?
            } else {
                Kdf::default()
            },
            chain: &self.chain,
        };
        let mut specs = Vec::new();
        let mut entries = Vec::new();
        for index in self.first_index..self.first_index + self.count {
            let bytes: [u8; Self::PASSWORD_BYTES] = OsEntropy::array()?;
            let hex = bytes.to_data();
            let password = hex.strip_prefix("0x").unwrap_or(&hex).to_owned();
            let derived = derivation.derive(seed.as_bytes(), index, &Password::new(&password))?;
            specs.push(
                self.settings
                    .spec(derived.keystore.to_json().to_string(), password),
            );
            entries.push(derived.deposit.to_json());
        }
        fs::create_dir_all(&self.output).map_err(|source| ManagerError::File {
            path: self.output.clone(),
            source,
        })?;
        Self::write(&validators, &ValidatorSpec::list_to_text(&specs), true)?;
        if self.deposits {
            Self::write(&deposits, &Json::Array(entries).to_string(), false)?;
        }
        let _unwritable = writeln!(
            io::stdout(),
            "{} validators written to {}",
            self.count,
            validators.display()
        );
        Ok(())
    }

    /// Writes a new file, private to its owner when it holds secrets.
    fn write(path: &Path, text: &str, private: bool) -> Result<(), ManagerError> {
        let file = || -> io::Result<()> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(if private { 0o600 } else { 0o644 });
            #[cfg(not(unix))]
            let _ = private;
            let mut file = options.open(path)?;
            file.write_all(text.as_bytes())?;
            file.sync_all()
        };
        file().map_err(|source| ManagerError::File {
            path: path.to_owned(),
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{env, process};

    use axiom_validator::keys::{DepositEntry, Keystore};

    use super::*;

    #[test]
    fn create_writes_importable_keystores_and_verifiable_deposits() {
        let output = env::temp_dir().join(format!("axiom-manager-create-{}", process::id()));
        let _stale = fs::remove_dir_all(&output);
        fs::create_dir_all(&output).unwrap();
        // The BIP-39 test mnemonic of the EIP-2333 vectors' tooling.
        let mnemonic = output.join("mnemonic.txt");
        fs::write(
            &mnemonic,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let create = Create {
            output: output.clone(),
            mnemonic,
            first_index: 3,
            count: 2,
            amount: Gwei(32_000_000_000),
            deposits: true,
            withdrawal_address: Some(ExecutionAddress([0x11; 20])),
            compounding: false,
            pbkdf2: true,
            settings: SettingsFlags {
                gas_limit: Some(36_000_000),
                ..SettingsFlags::default()
            },
            chain: ChainConfig::minimal(),
        };
        create.execute().unwrap();

        // Two validators, each keystore opening with its own password, at indices 3 and 4.
        let specs =
            ValidatorSpec::parse_list(&fs::read_to_string(output.join("validators.json")).unwrap())
                .unwrap();
        assert_eq!(specs.len(), 2);
        let deposits =
            Json::parse(fs::read_to_string(output.join("deposits.json")).unwrap()).unwrap();
        let deposits = deposits.as_array().unwrap();
        for (index, (spec, deposit)) in specs.iter().zip(deposits).enumerate() {
            let keystore = Keystore::parse(&spec.keystore).unwrap();
            keystore.decrypt(&Password::new(&spec.password)).unwrap();
            assert_eq!(
                keystore.path().unwrap().to_string(),
                format!("m/12381/3600/{}/0/0", index + 3)
            );
            assert_eq!(spec.gas_limit, Some(36_000_000));
            // The deposit is for the same key, and its signature verifies.
            let deposit = DepositEntry::from_json(deposit).unwrap();
            deposit.verify().unwrap();
            assert_eq!(
                deposit.to_json().get("pubkey"),
                Some(&Json::from(
                    keystore.pubkey().0.to_data().trim_start_matches("0x")
                ))
            );
        }

        // A second run refuses to overwrite the files.
        let again = Create {
            output: output.clone(),
            mnemonic: output.join("mnemonic.txt"),
            first_index: 0,
            count: 1,
            amount: Gwei(32_000_000_000),
            deposits: false,
            withdrawal_address: None,
            compounding: false,
            pbkdf2: true,
            settings: SettingsFlags::default(),
            chain: ChainConfig::minimal(),
        };
        assert!(
            matches!(again.execute(), Err(ManagerError::Exists(path)) if path == output.join("validators.json"))
        );
        fs::remove_dir_all(&output).unwrap();
    }
}
