//! Keystores paired with their passwords, opened in parallel.

use std::{num::NonZero, panic, thread};

use crate::{
    keymanager::UnlockError,
    keys::{Keystore, Password},
    signing::{Bls, LocalKey},
};

/// A keystore with the password that should open it.
#[derive(Debug)]
pub(crate) struct SealedKey {
    /// The encrypted key.
    keystore: Keystore,
    /// Its password, processed as EIP-2335 requires.
    password: Password,
}

impl SealedKey {
    /// Pairs a keystore with its password.
    pub(crate) const fn new(keystore: Keystore, password: Password) -> Self {
        Self { keystore, password }
    }

    /// The encrypted key.
    pub(crate) const fn keystore(&self) -> &Keystore {
        &self.keystore
    }

    /// Decrypts the key.
    ///
    /// # Errors
    ///
    /// Fails on a wrong password, or a secret that does not match the stored public key.
    pub(crate) fn open(&self) -> Result<LocalKey<Bls>, UnlockError> {
        let secret = self.keystore.decrypt(&self.password)?;
        Ok(LocalKey::new(secret.secret_key())?)
    }

    /// Decrypts every key, one result per key in input order.
    ///
    /// # Performance
    ///
    /// Opening a production scrypt keystore mixes 128 N r = 256 MiB, so it is slow.
    /// The keys split into one contiguous share per core, so a restart scales with the cores.
    /// Peak memory is then one scrypt buffer per core.
    pub(crate) fn open_all(sealed: &[Self]) -> Vec<Result<LocalKey<Bls>, UnlockError>> {
        let cores = thread::available_parallelism().map_or(1, NonZero::get);
        let share = sealed.len().div_ceil(cores).max(1);
        thread::scope(|scope| {
            // Every worker starts before the first join, so the shares run at once.
            #[expect(
                clippy::needless_collect,
                reason = "a lazy spawn would join each worker before starting the next"
            )]
            let workers: Vec<_> = sealed
                .chunks(share)
                .map(|chunk| scope.spawn(|| chunk.iter().map(Self::open).collect::<Vec<_>>()))
                .collect();
            // Joining in spawn order keeps the results in input order.
            workers
                .into_iter()
                .flat_map(|worker| {
                    worker
                        .join()
                        .unwrap_or_else(|panic| panic::resume_unwind(panic))
                })
                .collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{EncryptionParams, Kdf, KeystoreError, SecretKeyBytes};

    /// A one-round PBKDF2 keystore of the secret key n, under the password "pw".
    fn keystore(n: u8) -> Keystore {
        let mut bytes = [0; 32];
        bytes[31] = n;
        let secret = SecretKeyBytes::from_bytes(&bytes).unwrap();
        let params = EncryptionParams::random(Kdf::pbkdf2(1).unwrap()).unwrap();
        Keystore::encrypt(&secret, &Password::new("pw"), &params)
    }

    #[test]
    fn keys_open_in_input_order_and_wrong_passwords_fail_alone() {
        // Fixture state: keys 1 to 5, the third one paired with a wrong password.
        let sealed: Vec<SealedKey> = (1..=5)
            .map(|n| {
                let password = if n == 3 { "wrong" } else { "pw" };
                SealedKey::new(keystore(n), Password::new(password))
            })
            .collect();

        let opened = SealedKey::open_all(&sealed);

        // Each result sits at its key's position; only the third fails.
        let outcomes: Vec<Result<_, String>> = opened
            .iter()
            .map(|key| {
                key.as_ref()
                    .map(|key| *key.public_key())
                    .map_err(ToString::to_string)
            })
            .collect();
        let expected: Vec<Result<_, String>> = sealed
            .iter()
            .enumerate()
            .map(|(i, key)| {
                if i == 2 {
                    Err(UnlockError::Keystore(KeystoreError::WrongPassword).to_string())
                } else {
                    Ok(key.keystore().pubkey())
                }
            })
            .collect();
        assert_eq!(outcomes, expected);
    }

    #[test]
    fn no_keys_open_to_nothing() {
        assert!(SealedKey::open_all(&[]).is_empty());
    }
}
