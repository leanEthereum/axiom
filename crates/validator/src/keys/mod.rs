//! Validator keys: mnemonics, derivation, keystores, and deposit data.
//!
//! # Overview
//!
//! A validator's keys grow from one secret, in the order the standards chain them.
//!
//! 1. BIP-39 writes 128 to 256 bits of entropy as English words.
//! 2. The words and a passphrase stretch into a 64-byte seed.
//! 3. EIP-2333 grows a tree of BLS keys from the seed, through Lamport keys.
//! 4. EIP-2334 names the signing and withdrawal keys of validator i by their tree paths.
//! 5. EIP-2335 stores a key encrypted under a password, in a JSON keystore.
//! 6. A deposit signs the key into the deposit contract, with its withdrawal credentials.
//!
//! Passwords and passphrases are normalized to Unicode NFKD first.
//! So the same password typed on two keyboards opens the same keystore.
//!
//! # Invariants
//!
//! Every type holding secret bytes overwrites them with zero on drop.
//! None prints them in debug output, and none implements cloning.

mod deposit;
mod entropy;
mod error;
mod fields;
mod hex;
mod kdf;
mod keystore;
mod lamport;
mod mnemonic;
mod nfkd;
mod password;
mod path;
mod residue;
mod secret;
mod seed;
mod uuid;
mod wipe;
mod wordlist;

pub use deposit::{DepositEntry, WithdrawalTarget};
pub use entropy::OsEntropy;
pub use error::{
    DepositError, FieldError, HexError, KeyError, KeystoreError, MnemonicError, PathError,
    UuidError,
};
pub use kdf::Kdf;
pub use keystore::{EncryptionParams, Keystore};
pub use mnemonic::{Mnemonic, WordCount};
pub use nfkd::nfkd;
pub use password::Password;
pub use path::DerivationPath;
pub use secret::SecretKeyBytes;
pub use seed::Seed;
pub use uuid::Uuid;
