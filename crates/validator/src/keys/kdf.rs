//! The password hashing step of a keystore: scrypt or PBKDF2, with bounded cost.

use std::hint::black_box;

use axiom_crypto::{pbkdf2::Pbkdf2, scrypt::ScryptParams};
use axiom_json::{Json, Object};
use sha2::{Digest, Sha256};

use crate::keys::{KeystoreError, fields::Fields, hex::BareHex, wipe::Wipe};

/// A key derivation function and its cost, as EIP-2335 names them.
///
/// The cost is bounded at construction, so a hostile keystore cannot pin a core or exhaust memory.
/// The defaults are the parameters of the EIP-2335 test vectors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kdf {
    /// The function and its validated parameters.
    function: Function,
}

/// The functions EIP-2335 defines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Function {
    /// scrypt of RFC 7914.
    Scrypt(ScryptParams),
    /// PBKDF2-HMAC-SHA256 of RFC 8018.
    Pbkdf2 {
        /// The iteration count c.
        rounds: u32,
    },
}

impl Kdf {
    /// Bytes of derived key: half keys the cipher, half keys the checksum.
    pub const DERIVED_KEY_LEN: usize = 32;

    /// The scrypt cost N of the EIP-2335 vectors: 2^18.
    pub const SCRYPT_N: u64 = 262_144;

    /// The scrypt block size r of the EIP-2335 vectors.
    pub const SCRYPT_R: u32 = 8;

    /// The scrypt parallelization p of the EIP-2335 vectors.
    pub const SCRYPT_P: u32 = 1;

    /// The PBKDF2 iteration count c of the EIP-2335 vectors: 2^18.
    pub const PBKDF2_ROUNDS: u32 = 262_144;

    /// Most PBKDF2 iterations a keystore may ask for: 64 times the EIP-2335 default.
    pub const MAX_PBKDF2_ROUNDS: u32 = 1 << 24;

    /// Most bytes one scrypt derivation may mix, 128 N r p: 64 times the EIP-2335 default.
    ///
    /// The memory cap of the scrypt implementation bounds N r alone.
    /// A large p reuses that memory, so the time it costs needs this second bound.
    pub const MAX_SCRYPT_WORK: u128 = 1 << 34;

    /// The function name of scrypt in a keystore.
    const SCRYPT: &'static str = "scrypt";

    /// The function name of PBKDF2 in a keystore.
    const PBKDF2: &'static str = "pbkdf2";

    /// The one PBKDF2 pseudorandom function EIP-2335 defines.
    const PRF: &'static str = "hmac-sha256";

    /// scrypt with cost N, block size r, and parallelization p.
    ///
    /// # Errors
    ///
    /// Fails when RFC 7914 refuses the parameters, or when they exceed the memory or work cap.
    pub fn scrypt(n: u64, r: u32, p: u32) -> Result<Self, KeystoreError> {
        let params = ScryptParams::from_n(n, r, p)?;
        // Invariant: the parameters passed RFC 7914, so N r p fits 128 bits with room.
        let work = 128 * u128::from(n) * u128::from(r) * u128::from(p);
        if work > Self::MAX_SCRYPT_WORK {
            return Err(KeystoreError::ScryptWork {
                work,
                max: Self::MAX_SCRYPT_WORK,
            });
        }
        Ok(Self {
            function: Function::Scrypt(params),
        })
    }

    /// PBKDF2-HMAC-SHA256 with an iteration count.
    ///
    /// # Errors
    ///
    /// Fails on zero rounds, or on more than the cap.
    pub fn pbkdf2(rounds: u32) -> Result<Self, KeystoreError> {
        Self::check_rounds(u64::from(rounds))?;
        Ok(Self {
            function: Function::Pbkdf2 { rounds },
        })
    }

    /// Stretches a processed password and a salt into the decryption key.
    pub(crate) fn derive(&self, password: &[u8], salt: &[u8]) -> DecryptionKey {
        let mut key = DecryptionKey {
            bytes: [0; Self::DERIVED_KEY_LEN],
        };
        // Invariant: 32 bytes of output and a positive round count are within both limits.
        match self.function {
            Function::Scrypt(params) => params
                .derive(password, salt, &mut key.bytes)
                .expect("32 bytes is within the scrypt output limit"),
            Function::Pbkdf2 { rounds } => Pbkdf2::sha256(password, salt, rounds, &mut key.bytes)
                .expect("a positive count and 32 bytes are within PBKDF2 limits"),
        }
        key
    }

    /// Reads the kdf module of a keystore: the function, its parameters, and the salt.
    pub(crate) fn from_module(module: Fields<'_>) -> Result<(Self, Vec<u8>), KeystoreError> {
        let function = module.text("function")?;
        // The message is empty for both functions, but the schema requires the member.
        module.text("message")?;
        let params = module.object("params", "crypto.kdf.params")?;

        let dklen = params.number("dklen")?;
        if dklen != Self::DERIVED_KEY_LEN as u64 {
            return Err(KeystoreError::DerivedKeyLength {
                dklen,
                expected: Self::DERIVED_KEY_LEN as u64,
            });
        }
        let salt = params.hex("salt")?;
        if salt.is_empty() {
            return Err(KeystoreError::EmptySalt);
        }

        let kdf = match function {
            Self::SCRYPT => Self::scrypt(
                params.number("n")?,
                params.number_u32("r")?,
                params.number_u32("p")?,
            )?,
            Self::PBKDF2 => {
                let prf = params.text("prf")?;
                if prf != Self::PRF {
                    return Err(KeystoreError::Prf {
                        prf: prf.to_owned(),
                        expected: Self::PRF,
                    });
                }
                let rounds = params.number("c")?;
                Self::check_rounds(rounds)?;
                // Invariant: the check bounds the count by a 32-bit cap.
                Self::pbkdf2(rounds as u32)?
            }
            other => {
                return Err(KeystoreError::Function {
                    module: "kdf",
                    function: other.to_owned(),
                    expected: "scrypt or pbkdf2",
                });
            }
        };
        Ok((kdf, salt))
    }

    /// The kdf module of a keystore, members in the order of the EIP-2335 vectors.
    pub(crate) fn to_module(self, salt: &[u8]) -> Json {
        let mut params = Object::new();
        params.insert("dklen", Json::from(Self::DERIVED_KEY_LEN as u64));
        let function = match self.function {
            Function::Scrypt(scrypt) => {
                params.insert("n", Json::from(scrypt.n()));
                params.insert("p", Json::from(u64::from(scrypt.p())));
                params.insert("r", Json::from(u64::from(scrypt.r())));
                Self::SCRYPT
            }
            Function::Pbkdf2 { rounds } => {
                params.insert("c", Json::from(u64::from(rounds)));
                params.insert("prf", Json::from(Self::PRF));
                Self::PBKDF2
            }
        };
        params.insert("salt", Json::from(BareHex::encode(salt)));

        let mut module = Object::new();
        module.insert("function", Json::from(function));
        module.insert("params", Json::from(params));
        module.insert("message", Json::from(""));
        Json::from(module)
    }

    /// Checks a PBKDF2 iteration count against the floor of RFC 8018 and the cap.
    fn check_rounds(rounds: u64) -> Result<(), KeystoreError> {
        if (1..=u64::from(Self::MAX_PBKDF2_ROUNDS)).contains(&rounds) {
            Ok(())
        } else {
            Err(KeystoreError::Pbkdf2Rounds {
                rounds,
                min: 1,
                max: Self::MAX_PBKDF2_ROUNDS,
            })
        }
    }
}

impl Default for Kdf {
    /// scrypt with N = 2^18, r = 8, p = 1: 256 MiB and well within both caps.
    fn default() -> Self {
        // Invariant: 128 * 2^18 * 8 = 2^28 bytes, under the 1 GiB memory cap and the work cap.
        Self::scrypt(Self::SCRYPT_N, Self::SCRYPT_R, Self::SCRYPT_P)
            .expect("the EIP-2335 parameters are within the caps")
    }
}

/// The key a password derives: the cipher key, then the checksum key.
///
/// The bytes are overwritten with zero on drop.
pub(crate) struct DecryptionKey {
    /// The derived key.
    bytes: [u8; Kdf::DERIVED_KEY_LEN],
}

impl DecryptionKey {
    /// The AES-128 key: the first 16 bytes, per EIP-2335, section "Secret decryption".
    pub(crate) fn cipher_key(&self) -> &[u8; 16] {
        // Invariant: 16 bytes fit within the 32 derived.
        self.bytes[..16].try_into().expect("16 of 32 bytes")
    }

    /// The checksum SHA256(DK[16..32] || cipher message), per EIP-2335, "Password verification".
    pub(crate) fn checksum(&self, cipher_message: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.bytes[16..]);
        hasher.update(cipher_message);
        hasher.finalize().into()
    }

    /// Whether a stored checksum matches, compared in constant time.
    ///
    /// The computed checksum depends on the password, so the comparison reads every byte.
    pub(crate) fn verifies(&self, cipher_message: &[u8], stored: &[u8; 32]) -> bool {
        let mut computed = self.checksum(cipher_message);
        let difference = computed
            .iter()
            .zip(stored)
            .fold(0_u8, |acc, (a, b)| acc | (a ^ b));
        computed.wipe();
        // The barrier keeps the fold from being cut short at the first differing byte.
        black_box(difference) == 0
    }
}

impl Drop for DecryptionKey {
    fn drop(&mut self) {
        self.bytes.wipe();
    }
}

#[cfg(test)]
mod tests {
    use axiom_crypto::scrypt::ScryptError;

    use super::*;

    #[test]
    fn the_defaults_are_the_eip_parameters() {
        assert_eq!(Kdf::default(), Kdf::scrypt(262_144, 8, 1).unwrap());
    }

    #[test]
    fn pbkdf2_rounds_are_bounded_on_both_sides() {
        // Threshold: 1 to 2^24 rounds.
        assert!(Kdf::pbkdf2(1).is_ok());
        assert!(Kdf::pbkdf2(1 << 24).is_ok());
        assert_eq!(
            Kdf::pbkdf2(0),
            Err(KeystoreError::Pbkdf2Rounds {
                rounds: 0,
                min: 1,
                max: 1 << 24
            })
        );
        assert_eq!(
            Kdf::pbkdf2((1 << 24) + 1),
            Err(KeystoreError::Pbkdf2Rounds {
                rounds: (1 << 24) + 1,
                min: 1,
                max: 1 << 24
            })
        );
    }

    #[test]
    fn scrypt_memory_and_work_are_bounded() {
        // Memory: N = 2^21 with r = 8 needs 2 GiB, over the 1 GiB cap.
        assert_eq!(
            Kdf::scrypt(1 << 21, 8, 1),
            Err(KeystoreError::Scrypt(ScryptError::MemoryTooLarge {
                bytes: 128 * 8 * ((1 << 21) + 1),
                max: 1 << 30
            }))
        );

        // Work: p = 64 at the default N and r mixes 2^34 bytes, the cap; p = 65 is over.
        // The memory stays at 256 MiB either way, since the p blocks share one table.
        assert!(Kdf::scrypt(1 << 18, 8, 64).is_ok());
        assert_eq!(
            Kdf::scrypt(1 << 18, 8, 65),
            Err(KeystoreError::ScryptWork {
                work: 128 * (1 << 18) * 8 * 65,
                max: 1 << 34
            })
        );

        // RFC 7914 itself: N must be a power of two.
        assert_eq!(
            Kdf::scrypt(1000, 8, 1),
            Err(KeystoreError::Scrypt(ScryptError::CostNotPowerOfTwo {
                n: 1000
            }))
        );
    }

    #[test]
    fn a_checksum_differing_in_any_byte_fails() {
        // Fixture state: a cheap PBKDF2 key over a 32-byte cipher message.
        let key = Kdf::pbkdf2(1).unwrap().derive(b"password", b"salt");
        let message = [0x5a; 32];
        let checksum = key.checksum(&message);
        assert!(key.verifies(&message, &checksum));

        // Mutation: flip one bit of the first, then the last byte.
        for index in [0, 31] {
            let mut wrong = checksum;
            wrong[index] ^= 1;
            assert!(!key.verifies(&message, &wrong));
        }
    }
}
