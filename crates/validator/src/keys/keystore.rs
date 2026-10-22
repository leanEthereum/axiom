//! EIP-2335 keystores: a secret key encrypted under a password.

use std::io;

use axiom_crypto::aes::Aes128Ctr;
use axiom_json::{Json, Object};
use axiom_types::BlsPubkey;

use crate::keys::{
    DerivationPath, Kdf, KeystoreError, OsEntropy, Password, SecretKeyBytes, Uuid, fields::Fields,
    hex::BareHex, wipe::Wipe,
};

/// An EIP-2335 keystore holding one BLS secret key.
///
/// # Overview
///
/// ```text
/// DK         = KDF(password, salt)
/// ciphertext = AES-128-CTR(key = DK[0..16], iv, secret)
/// checksum   = SHA256(DK[16..32] || ciphertext)
/// ```
///
/// The checksum tells a wrong password apart from a corrupt file before anything is decrypted.
///
/// # Invariants
///
/// The parameters were validated when read or built: version 4, known functions, bounded cost.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Keystore {
    /// The password hashing function and its cost.
    kdf: Kdf,
    /// The KDF salt, never empty.
    salt: Vec<u8>,
    /// SHA256(DK[16..32] || ciphertext).
    checksum: [u8; 32],
    /// The AES-128-CTR initial counter block.
    iv: [u8; 16],
    /// The encrypted secret key.
    ciphertext: [u8; 32],
    /// A label for people, not necessarily unique.
    description: Option<String>,
    /// The public key of the secret.
    pubkey: BlsPubkey,
    /// Where in the EIP-2333 tree the key sits, when known.
    path: Option<DerivationPath>,
    /// A random name for the keystore.
    uuid: Uuid,
}

/// The random inputs and cost of one keystore encryption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncryptionParams {
    /// The password hashing function and its cost.
    pub kdf: Kdf,
    /// The KDF salt.
    pub salt: [u8; 32],
    /// The AES-128-CTR initial counter block.
    pub iv: [u8; 16],
    /// The keystore's name.
    pub uuid: Uuid,
}

impl EncryptionParams {
    /// Fresh salt, IV, and UUID from the operating system, under a chosen function.
    ///
    /// # Errors
    ///
    /// Fails when the entropy source cannot be read.
    pub fn random(kdf: Kdf) -> io::Result<Self> {
        Ok(Self {
            kdf,
            salt: OsEntropy::array()?,
            iv: OsEntropy::array()?,
            uuid: Uuid::random()?,
        })
    }
}

impl Keystore {
    /// The one keystore version EIP-2335 defines.
    pub const VERSION: u64 = 4;

    /// The checksum function name.
    const CHECKSUM: &'static str = "sha256";

    /// The cipher function name.
    const CIPHER: &'static str = "aes-128-ctr";

    /// Encrypts a secret key under a password.
    ///
    /// The keystore has no path or description until they are set.
    #[must_use]
    pub fn encrypt(
        secret: &SecretKeyBytes,
        password: &Password,
        params: &EncryptionParams,
    ) -> Self {
        let key = params.kdf.derive(password.as_bytes(), &params.salt);
        let mut ciphertext = *secret.as_bytes();
        Aes128Ctr::new(key.cipher_key(), &params.iv).apply_keystream(&mut ciphertext);
        Self {
            kdf: params.kdf,
            salt: params.salt.to_vec(),
            checksum: key.checksum(&ciphertext),
            iv: params.iv,
            ciphertext,
            description: None,
            pubkey: secret.public_key(),
            path: None,
            uuid: params.uuid,
        }
    }

    /// The keystore with a derivation path.
    #[must_use]
    pub fn with_path(mut self, path: DerivationPath) -> Self {
        self.path = Some(path);
        self
    }

    /// The keystore with a description.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Decrypts the secret key.
    ///
    /// # Errors
    ///
    /// Fails on a wrong password, or when the secret is not a valid key for the stored public key.
    pub fn decrypt(&self, password: &Password) -> Result<SecretKeyBytes, KeystoreError> {
        let key = self.kdf.derive(password.as_bytes(), &self.salt);
        if !key.verifies(&self.ciphertext, &self.checksum) {
            return Err(KeystoreError::WrongPassword);
        }
        let mut plaintext = self.ciphertext;
        Aes128Ctr::new(key.cipher_key(), &self.iv).apply_keystream(&mut plaintext);
        let secret = SecretKeyBytes::from_bytes(&plaintext);
        plaintext.wipe();
        let secret = secret.map_err(|_| KeystoreError::InvalidSecretKey)?;

        // A file whose public key names another validator must not load under that name.
        let derived = secret.public_key();
        if derived != self.pubkey {
            return Err(KeystoreError::PublicKeyMismatch {
                stored: self.pubkey,
                derived,
            });
        }
        Ok(secret)
    }

    /// Reads a keystore from its JSON text.
    ///
    /// Members outside the EIP-2335 schema are ignored.
    ///
    /// # Errors
    ///
    /// Fails on text that is not JSON, a missing or malformed member, or unsupported parameters.
    pub fn parse(text: &str) -> Result<Self, KeystoreError> {
        let json = Json::parse(text)?;
        let root = Fields::of(&json, "keystore")?;

        let version = root.number("version")?;
        if version != Self::VERSION {
            return Err(KeystoreError::Version {
                version,
                expected: Self::VERSION,
            });
        }

        let crypto = root.object("crypto", "crypto")?;
        let (kdf, salt) = Kdf::from_module(crypto.object("kdf", "crypto.kdf")?)?;

        let checksum = crypto.object("checksum", "crypto.checksum")?;
        Self::expect_function(checksum, "checksum", Self::CHECKSUM, "sha256")?;
        checksum.object("params", "crypto.checksum.params")?;

        let cipher = crypto.object("cipher", "crypto.cipher")?;
        Self::expect_function(cipher, "cipher", Self::CIPHER, "aes-128-ctr")?;
        let cipher_params = cipher.object("params", "crypto.cipher.params")?;

        let path = match root.text("path")? {
            "" => None,
            text => Some(text.parse()?),
        };
        let description = if root.has("description") {
            Some(root.text("description")?.to_owned())
        } else {
            None
        };

        Ok(Self {
            kdf,
            salt,
            checksum: checksum.hex_array("message")?,
            iv: cipher_params.hex_array("iv")?,
            ciphertext: cipher.hex_array("message")?,
            description,
            pubkey: BlsPubkey(root.hex_array("pubkey")?),
            path,
            uuid: root.text("uuid")?.parse()?,
        })
    }

    /// The keystore as JSON, members in the order of the EIP-2335 vectors.
    #[must_use]
    pub fn to_json(&self) -> Json {
        let mut checksum = Object::new();
        checksum.insert("function", Json::from(Self::CHECKSUM));
        checksum.insert("params", Json::from(Object::new()));
        checksum.insert("message", Json::from(BareHex::encode(&self.checksum)));

        let mut cipher_params = Object::new();
        cipher_params.insert("iv", Json::from(BareHex::encode(&self.iv)));
        let mut cipher = Object::new();
        cipher.insert("function", Json::from(Self::CIPHER));
        cipher.insert("params", Json::from(cipher_params));
        cipher.insert("message", Json::from(BareHex::encode(&self.ciphertext)));

        let mut crypto = Object::new();
        crypto.insert("kdf", self.kdf.to_module(&self.salt));
        crypto.insert("checksum", Json::from(checksum));
        crypto.insert("cipher", Json::from(cipher));

        let mut root = Object::new();
        root.insert("crypto", Json::from(crypto));
        if let Some(description) = &self.description {
            root.insert("description", Json::from(description.as_str()));
        }
        root.insert("pubkey", Json::from(BareHex::encode(&self.pubkey.0)));
        let path = self
            .path
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default();
        root.insert("path", Json::from(path));
        root.insert("uuid", Json::from(self.uuid.to_string()));
        root.insert("version", Json::from(Self::VERSION));
        Json::from(root)
    }

    /// The public key of the secret.
    #[must_use]
    pub const fn pubkey(&self) -> BlsPubkey {
        self.pubkey
    }

    /// Where in the EIP-2333 tree the key sits, when known.
    #[must_use]
    pub const fn path(&self) -> Option<&DerivationPath> {
        self.path.as_ref()
    }

    /// The keystore's name.
    #[must_use]
    pub const fn uuid(&self) -> Uuid {
        self.uuid
    }

    /// The label for people, when set.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// The password hashing function and its cost.
    #[must_use]
    pub const fn kdf(&self) -> Kdf {
        self.kdf
    }

    /// Checks that a module names the one function this client implements for it.
    fn expect_function(
        module: Fields<'_>,
        name: &'static str,
        function: &str,
        expected: &'static str,
    ) -> Result<(), KeystoreError> {
        // The message is checked by the caller where it carries data.
        let given = module.text("function")?;
        if given == function {
            Ok(())
        } else {
            Err(KeystoreError::Function {
                module: name,
                function: given.to_owned(),
                expected,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_crypto::scrypt::ScryptError;
    use proptest::prelude::*;

    use super::*;
    use crate::keys::{FieldError, HexError, PathError, UuidError};

    /// The EIP-2335 password: "testpassword" in fraktur, then a key emoji.
    const PASSWORD: &str = "\u{1D531}\u{1D522}\u{1D530}\u{1D531}\u{1D52D}\u{1D51E}\u{1D530}\u{1D530}\u{1D534}\u{1D52C}\u{1D52F}\u{1D521}\u{1F511}";

    /// The secret both EIP-2335 vectors encrypt.
    const SECRET: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0xd6, 0x68, 0x9c, 0x08, 0x5a, 0xe1, 0x65, 0x83, 0x1e,
        0x93, 0x4f, 0xf7, 0x63, 0xae, 0x46, 0xa2, 0xa6, 0xc1, 0x72, 0xb3, 0xf1, 0xb6, 0x0a, 0x8c,
        0xe2, 0x6f,
    ];

    /// The EIP-2335 PBKDF2 test vector.
    const PBKDF2_VECTOR: &str = r#"{
    "crypto": {
        "kdf": {
            "function": "pbkdf2",
            "params": {
                "dklen": 32,
                "c": 262144,
                "prf": "hmac-sha256",
                "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
            },
            "message": ""
        },
        "checksum": {
            "function": "sha256",
            "params": {},
            "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"
        },
        "cipher": {
            "function": "aes-128-ctr",
            "params": {
                "iv": "264daa3f303d7259501c93d997d84fe6"
            },
            "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"
        }
    },
    "description": "This is a test keystore that uses PBKDF2 to secure the secret.",
    "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
    "path": "m/12381/60/0/0",
    "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
    "version": 4
}"#;

    /// The EIP-2335 scrypt test vector.
    const SCRYPT_VECTOR: &str = r#"{
    "crypto": {
        "kdf": {
            "function": "scrypt",
            "params": {
                "dklen": 32,
                "n": 262144,
                "p": 1,
                "r": 8,
                "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
            },
            "message": ""
        },
        "checksum": {
            "function": "sha256",
            "params": {},
            "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"
        },
        "cipher": {
            "function": "aes-128-ctr",
            "params": {
                "iv": "264daa3f303d7259501c93d997d84fe6"
            },
            "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"
        }
    },
    "description": "This is a test keystore that uses scrypt to secure the secret.",
    "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
    "path": "m/12381/60/3141592653/589793238",
    "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
    "version": 4
}"#;

    /// The vector with one member replaced, to test a single defect.
    fn mutated(vector: &str, from: &str, to: &str) -> String {
        assert!(vector.contains(from), "the mutation applies");
        vector.replacen(from, to, 1)
    }

    #[test]
    fn eip_2335_scrypt_vector() {
        // The one production-cost scrypt derivation of this suite, which needs 256 MiB.
        let keystore = Keystore::parse(SCRYPT_VECTOR).unwrap();
        assert_eq!(keystore.kdf(), Kdf::default());
        assert_eq!(
            keystore.path().map(ToString::to_string).as_deref(),
            Some("m/12381/60/3141592653/589793238")
        );
        let secret = keystore.decrypt(&Password::new(PASSWORD)).unwrap();
        assert_eq!(*secret.as_bytes(), SECRET);

        // Serializing gives back the vector's JSON, member for member and in order.
        assert_eq!(keystore.to_json(), Json::parse(SCRYPT_VECTOR).unwrap());
    }

    #[test]
    fn eip_2335_pbkdf2_vector() {
        let keystore = Keystore::parse(PBKDF2_VECTOR).unwrap();
        assert_eq!(keystore.kdf(), Kdf::pbkdf2(262_144).unwrap());
        assert_eq!(
            keystore.uuid().to_string(),
            "64625def-3331-4eea-ab6f-782f3ed16a83"
        );
        assert_eq!(
            keystore.description(),
            Some("This is a test keystore that uses PBKDF2 to secure the secret.")
        );
        assert_eq!(
            keystore.pubkey(),
            SecretKeyBytes::from_bytes(&SECRET).unwrap().public_key()
        );
        let secret = keystore.decrypt(&Password::new(PASSWORD)).unwrap();
        assert_eq!(*secret.as_bytes(), SECRET);
        assert_eq!(keystore.to_json(), Json::parse(PBKDF2_VECTOR).unwrap());

        // Re-encrypting with the vector's salt, IV, and UUID reproduces it exactly.
        let params = EncryptionParams {
            kdf: keystore.kdf(),
            salt: keystore.salt.clone().try_into().unwrap(),
            iv: keystore.iv,
            uuid: keystore.uuid(),
        };
        let rebuilt = Keystore::encrypt(&secret, &Password::new(PASSWORD), &params)
            .with_path("m/12381/60/0/0".parse().unwrap())
            .with_description("This is a test keystore that uses PBKDF2 to secure the secret.");
        assert_eq!(rebuilt, keystore);
    }

    /// Cheap encryption inputs: one PBKDF2 round and fixed salt, IV, and UUID.
    fn cheap() -> EncryptionParams {
        EncryptionParams {
            kdf: Kdf::pbkdf2(1).unwrap(),
            salt: [1; 32],
            iv: [2; 16],
            uuid: Uuid::from_random_bytes([3; 16]),
        }
    }

    #[test]
    fn a_wrong_password_is_told_apart() {
        // The password differs from the one that encrypted only in its case.
        let secret = SecretKeyBytes::from_bytes(&SECRET).unwrap();
        let keystore = Keystore::encrypt(&secret, &Password::new("password"), &cheap());
        assert_eq!(
            keystore.decrypt(&Password::new("Password")).err(),
            Some(KeystoreError::WrongPassword)
        );
    }

    #[test]
    fn a_keystore_naming_another_public_key_is_refused() {
        // Fixture state: a keystore for key 1, built with one PBKDF2 round.
        // Mutation: its public key member names the EIP vector key instead.
        let mut one = [0; 32];
        one[31] = 1;
        let secret = SecretKeyBytes::from_bytes(&one).unwrap();
        let password = Password::new("password");
        let mut keystore = Keystore::encrypt(&secret, &password, &cheap());
        let stored = SecretKeyBytes::from_bytes(&SECRET).unwrap().public_key();
        keystore.pubkey = stored;
        assert_eq!(
            keystore.decrypt(&password).err(),
            Some(KeystoreError::PublicKeyMismatch {
                stored,
                derived: secret.public_key()
            })
        );
    }

    #[test]
    fn a_secret_that_is_no_key_is_refused() {
        // Fixture state: a ciphertext that decrypts to zero under the right password.
        // The checksum covers the ciphertext, so it still verifies.
        let params = cheap();
        let password = Password::new("password");
        let key = params.kdf.derive(password.as_bytes(), &params.salt);
        let mut ciphertext = [0; 32];
        Aes128Ctr::new(key.cipher_key(), &params.iv).apply_keystream(&mut ciphertext);
        let keystore = Keystore {
            kdf: params.kdf,
            salt: params.salt.to_vec(),
            checksum: key.checksum(&ciphertext),
            iv: params.iv,
            ciphertext,
            description: None,
            pubkey: BlsPubkey::ZERO,
            path: None,
            uuid: params.uuid,
        };
        assert_eq!(
            keystore.decrypt(&password).err(),
            Some(KeystoreError::InvalidSecretKey)
        );
    }

    /// The error reading the PBKDF2 vector with one member replaced.
    fn refused(from: &str, to: &str) -> Option<KeystoreError> {
        Keystore::parse(&mutated(PBKDF2_VECTOR, from, to)).err()
    }

    #[test]
    fn unsupported_versions_and_functions_are_refused() {
        // Each mutation names something this client does not implement; the error names it.

        assert_eq!(
            refused("\"version\": 4", "\"version\": 3"),
            Some(KeystoreError::Version {
                version: 3,
                expected: 4
            })
        );
        assert_eq!(
            refused("\"function\": \"pbkdf2\"", "\"function\": \"argon2id\""),
            Some(KeystoreError::Function {
                module: "kdf",
                function: "argon2id".to_owned(),
                expected: "scrypt or pbkdf2"
            })
        );
        assert_eq!(
            refused("\"function\": \"sha256\"", "\"function\": \"keccak256\""),
            Some(KeystoreError::Function {
                module: "checksum",
                function: "keccak256".to_owned(),
                expected: "sha256"
            })
        );
        assert_eq!(
            refused(
                "\"function\": \"aes-128-ctr\"",
                "\"function\": \"aes-256-ctr\""
            ),
            Some(KeystoreError::Function {
                module: "cipher",
                function: "aes-256-ctr".to_owned(),
                expected: "aes-128-ctr"
            })
        );
        assert_eq!(
            refused("\"prf\": \"hmac-sha256\"", "\"prf\": \"hmac-sha512\""),
            Some(KeystoreError::Prf {
                prf: "hmac-sha512".to_owned(),
                expected: "hmac-sha256"
            })
        );
    }

    #[test]
    fn malformed_parameters_are_refused() {
        // Each mutation breaks one rule of the schema; the error names it.
        assert_eq!(
            refused("\"dklen\": 32", "\"dklen\": 16"),
            Some(KeystoreError::DerivedKeyLength {
                dklen: 16,
                expected: 32
            })
        );
        assert_eq!(
            refused("\"c\": 262144", "\"c\": 4294967296"),
            Some(KeystoreError::Pbkdf2Rounds {
                rounds: 4_294_967_296,
                min: 1,
                max: 1 << 24
            })
        );
        assert_eq!(
            refused(
                "\"salt\": \"d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3\"",
                "\"salt\": \"\""
            ),
            Some(KeystoreError::EmptySalt)
        );
        // A 15-byte IV: AES-128-CTR needs a full 16-byte counter block.
        assert_eq!(
            refused(
                "264daa3f303d7259501c93d997d84fe6",
                "264daa3f303d7259501c93d997d84f"
            ),
            Some(KeystoreError::Field(FieldError::Hex {
                object: "crypto.cipher.params",
                field: "iv",
                source: HexError::Length {
                    expected: 16,
                    actual: 15
                }
            }))
        );
        assert_eq!(
            refused("\"uuid\": \"64625def", "\"uuid\": \"64625de"),
            Some(KeystoreError::Uuid(UuidError::Length {
                expected: 36,
                actual: 35
            }))
        );
        assert_eq!(
            refused("\"path\": \"m/12381/60/0/0\"", "\"path\": \"12381/60/0/0\""),
            Some(KeystoreError::Path(PathError::MissingMaster {
                path: "12381/60/0/0".to_owned()
            }))
        );
        assert_eq!(
            refused("\"pubkey\"", "\"public_key\""),
            Some(KeystoreError::Field(FieldError::Missing {
                object: "keystore",
                field: "pubkey"
            }))
        );
        assert_eq!(
            refused("\"params\": {}", "\"params\": []"),
            Some(KeystoreError::Field(FieldError::NotObject {
                object: "crypto.checksum.params"
            }))
        );
    }

    #[test]
    fn hostile_scrypt_parameters_are_refused_before_any_work() {
        // N = 2^30 with r = 8 asks for 1 TiB; the refusal happens at parse time.
        let vector = mutated(SCRYPT_VECTOR, "\"n\": 262144", "\"n\": 1073741824");
        assert_eq!(
            Keystore::parse(&vector).err(),
            Some(KeystoreError::Scrypt(ScryptError::MemoryTooLarge {
                bytes: 128 * 8 * ((1 << 30) + 1),
                max: 1 << 30
            }))
        );
    }

    #[test]
    fn an_empty_path_and_a_missing_description_round_trip() {
        // EIP-2335: the empty string means no path; the description is optional.
        let vector = mutated(PBKDF2_VECTOR, "\"m/12381/60/0/0\"", "\"\"");
        let vector = mutated(
            &vector,
            "\"description\": \"This is a test keystore that uses PBKDF2 to secure the secret.\",",
            "",
        );
        let keystore = Keystore::parse(&vector).unwrap();
        assert_eq!(keystore.path(), None);
        assert_eq!(keystore.description(), None);
        assert_eq!(keystore.to_json(), Json::parse(&vector).unwrap());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn encryption_round_trips_under_cheap_parameters(
            secret in any::<[u8; 32]>(),
            password in "\\PC{0,16}",
            salt in any::<[u8; 32]>(),
            iv in any::<[u8; 16]>(),
            use_scrypt in any::<bool>(),
        ) {
            // Cheap costs keep each case fast: scrypt N = 16, r = 1, or one PBKDF2 round.
            let Ok(secret) = SecretKeyBytes::from_bytes(&secret) else {
                return Ok(());
            };
            let kdf = if use_scrypt {
                Kdf::scrypt(16, 1, 1).unwrap()
            } else {
                Kdf::pbkdf2(1).unwrap()
            };
            let params = EncryptionParams { kdf, salt, iv, uuid: Uuid::from_random_bytes([9; 16]) };
            let password = Password::new(&password);
            let keystore = Keystore::encrypt(&secret, &password, &params);

            // The JSON text reads back to the same keystore, which opens to the same secret.
            let reread = Keystore::parse(&keystore.to_json().to_string()).unwrap();
            prop_assert_eq!(&reread, &keystore);
            let opened = reread.decrypt(&password).unwrap();
            prop_assert_eq!(opened.as_bytes(), secret.as_bytes());

            // Appending one character to the password breaks the checksum.
            let wrong = Password::new(&format!("{}x", String::from_utf8_lossy(password.as_bytes())));
            prop_assert_eq!(reread.decrypt(&wrong).err(), Some(KeystoreError::WrongPassword));
        }
    }
}
