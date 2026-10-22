//! Why a key, mnemonic, path, keystore, or deposit was refused.
//!
//! No variant carries secret material: a mnemonic word or a key byte never reaches a log.
//! The one exception is a word missing from the wordlist, which the operator must see to fix.

use axiom_crypto::scrypt::ScryptError;
use axiom_json::ParseError;
use axiom_types::{BlsPubkey, Root, Version};
use thiserror::Error;

/// A key that cannot be derived or used.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum KeyError {
    /// The seed is shorter than the 256 bits EIP-2333 requires.
    #[error("seed of {len} bytes is shorter than the minimum of {min}")]
    SeedTooShort {
        /// Bytes given.
        len: usize,
        /// Fewest bytes allowed.
        min: usize,
    },

    /// The bytes encode zero or an integer not below the group order.
    #[error("secret key is zero or not below the BLS12-381 group order")]
    InvalidSecretKey,
}

/// A derivation path that does not follow the EIP-2333 notation.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum PathError {
    /// The path does not start at the master node m.
    #[error("path {path:?} does not start at the master node m")]
    MissingMaster {
        /// The text given.
        path: String,
    },

    /// A level is not a canonical decimal index below 2^32.
    #[error("level {level} of path {path:?} is not a decimal index below 2^32")]
    InvalidIndex {
        /// The text given.
        path: String,
        /// Position of the level, counting the first child of m as 1.
        level: usize,
    },
}

/// A BIP-39 mnemonic that cannot be built or parsed.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum MnemonicError {
    /// The entropy is not 128, 160, 192, 224, or 256 bits long.
    #[error("entropy of {len} bytes is not one of 16, 20, 24, 28, or 32")]
    EntropyLength {
        /// Bytes given.
        len: usize,
    },

    /// The phrase is not 12, 15, 18, 21, or 24 words long.
    #[error("phrase of {count} words is not one of 12, 15, 18, 21, or 24")]
    WordCount {
        /// Words given.
        count: usize,
    },

    /// A word is not in the English wordlist.
    #[error("word {index} of the phrase, {word:?}, is not in the English wordlist")]
    UnknownWord {
        /// Position of the word, counting from zero.
        index: usize,
        /// The word as given.
        word: String,
    },

    /// The checksum bits do not match the entropy, so a word is wrong or misplaced.
    #[error("checksum bits {actual:#04x} do not match the expected {expected:#04x}")]
    Checksum {
        /// Checksum the entropy implies.
        expected: u8,
        /// Checksum the last word carries.
        actual: u8,
    },
}

/// A hex string that does not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum HexError {
    /// An odd number of digits leaves the last byte half written.
    #[error("odd number of hex digits: {digits}")]
    OddLength {
        /// Digits given.
        digits: usize,
    },

    /// A character that is not a hex digit.
    #[error("invalid hex digit at byte {offset}")]
    InvalidDigit {
        /// Byte offset of the character.
        offset: usize,
    },

    /// The decoded bytes have the wrong length.
    #[error("{actual} bytes where {expected} are required")]
    Length {
        /// Bytes required.
        expected: usize,
        /// Bytes decoded.
        actual: usize,
    },
}

/// A UUID that is not in the 8-4-4-4-12 hex form of RFC 9562.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum UuidError {
    /// The text is not 36 characters long.
    #[error("UUID of {actual} bytes where {expected} are required")]
    Length {
        /// Bytes required.
        expected: usize,
        /// Bytes given.
        actual: usize,
    },

    /// A hyphen is missing at one of the four group boundaries.
    #[error("UUID lacks a hyphen at byte {offset}")]
    Hyphen {
        /// Byte offset where the hyphen belongs.
        offset: usize,
    },

    /// A character that is not a hex digit.
    #[error("invalid UUID hex digit at byte {offset}")]
    Digit {
        /// Byte offset of the character.
        offset: usize,
    },
}

/// A JSON document whose shape is wrong.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum FieldError {
    /// The document or a member is not an object.
    #[error("{object} is not a JSON object")]
    NotObject {
        /// The value, as a dotted path from the document root.
        object: &'static str,
    },

    /// A member is absent.
    #[error("{object} lacks the member {field}")]
    Missing {
        /// The object, as a dotted path from the document root.
        object: &'static str,
        /// The member name.
        field: &'static str,
    },

    /// A value has the wrong type or range.
    #[error("{object}.{field} is not {expected}")]
    Type {
        /// The object, as a dotted path from the document root.
        object: &'static str,
        /// The member name.
        field: &'static str,
        /// What the value must be.
        expected: &'static str,
    },

    /// A hex member does not decode.
    #[error("{object}.{field}: {source}")]
    Hex {
        /// The object, as a dotted path from the document root.
        object: &'static str,
        /// The member name.
        field: &'static str,
        /// Why it does not decode.
        source: HexError,
    },
}

/// An EIP-2335 keystore that cannot be read, built, or opened.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum KeystoreError {
    /// The text is not JSON.
    #[error("keystore is not JSON: {0}")]
    Json(#[from] ParseError),

    /// The JSON does not have the keystore's shape.
    #[error("keystore: {0}")]
    Field(#[from] FieldError),

    /// The version is not 4.
    #[error("keystore version {version} is not the supported {expected}")]
    Version {
        /// Version given.
        version: u64,
        /// The one version EIP-2335 defines.
        expected: u64,
    },

    /// A module names a function this client does not implement.
    #[error("{module} function {function:?} is not one of {expected}")]
    Function {
        /// The module: kdf, checksum, or cipher.
        module: &'static str,
        /// Function given.
        function: String,
        /// Functions supported.
        expected: &'static str,
    },

    /// PBKDF2 names a pseudorandom function other than HMAC-SHA256.
    #[error("PBKDF2 function {prf:?} is not {expected:?}")]
    Prf {
        /// Function given.
        prf: String,
        /// The one function EIP-2335 defines.
        expected: &'static str,
    },

    /// The derived key length is not 32 bytes.
    #[error("derived key length {dklen} is not the required {expected}")]
    DerivedKeyLength {
        /// Length given.
        dklen: u64,
        /// Length the checksum and cipher need.
        expected: u64,
    },

    /// The KDF salt is empty.
    #[error("KDF salt is empty")]
    EmptySalt,

    /// The scrypt parameters are invalid or need too much memory.
    #[error("scrypt parameters: {0}")]
    Scrypt(#[from] ScryptError),

    /// The scrypt parameters need too much time.
    #[error("scrypt work 128 N r p = {work} bytes mixed exceeds the cap of {max}")]
    ScryptWork {
        /// Bytes the parameters mix.
        work: u128,
        /// Most bytes one derivation may mix.
        max: u128,
    },

    /// The PBKDF2 round count is outside the accepted range.
    #[error("PBKDF2 round count {rounds} is outside {min} to {max}")]
    Pbkdf2Rounds {
        /// Rounds given.
        rounds: u64,
        /// Fewest rounds allowed.
        min: u32,
        /// Most rounds allowed.
        max: u32,
    },

    /// The path member is not an EIP-2334 path.
    #[error("keystore path: {0}")]
    Path(#[from] PathError),

    /// The uuid member is not a UUID.
    #[error("keystore uuid: {0}")]
    Uuid(#[from] UuidError),

    /// The checksum does not match, so the password is wrong.
    #[error("wrong password: the keystore checksum does not match")]
    WrongPassword,

    /// The decrypted bytes are not a valid secret key.
    #[error("decrypted secret is zero or not below the BLS12-381 group order")]
    InvalidSecretKey,

    /// The decrypted key does not belong to the stored public key.
    #[error("decrypted key has public key {derived}, but the keystore names {stored}")]
    PublicKeyMismatch {
        /// Public key in the keystore.
        stored: BlsPubkey,
        /// Public key of the decrypted secret.
        derived: BlsPubkey,
    },
}

/// A deposit data entry that cannot be read or does not verify.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum DepositError {
    /// The JSON does not have the entry's shape.
    #[error("deposit data: {0}")]
    Field(#[from] FieldError),

    /// The stored deposit message root is not the root of the message.
    #[error("deposit message root {stored} differs from the computed {computed}")]
    MessageRoot {
        /// Root in the entry.
        stored: Root,
        /// Root of the entry's message.
        computed: Root,
    },

    /// The stored deposit data root is not the root of the data.
    #[error("deposit data root {stored} differs from the computed {computed}")]
    DataRoot {
        /// Root in the entry.
        stored: Root,
        /// Root of the entry's data.
        computed: Root,
    },

    /// The public key is not a point of the BLS12-381 G1 subgroup.
    #[error("deposit public key {pubkey} is not a valid BLS key")]
    InvalidPubkey {
        /// The key.
        pubkey: BlsPubkey,
    },

    /// The signature does not verify for the key under the deposit domain.
    #[error("deposit signature of {pubkey} does not verify under fork version {fork_version}")]
    Signature {
        /// The key.
        pubkey: BlsPubkey,
        /// The fork version of the deposit domain.
        fork_version: Version,
    },
}
