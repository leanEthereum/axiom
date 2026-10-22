//! Where a validator's key lives: in this process, or behind a remote signer.

use axiom_types::{BlsPubkey, BlsSignature, Preset};
use thiserror::Error;

use crate::{
    protection::{ProtectionError, Refusal},
    signing::{Bls, Cleared, LocalKey, LocalKeyError, RemoteError, RemoteSigner, SigningContext},
};

/// A validator's signing key, wherever it lives.
#[derive(Debug)]
pub enum ValidatorSigner {
    /// A key decrypted into this process.
    Local(LocalKey<Bls>),
    /// A key a remote signer holds.
    Remote(RemoteSigner),
}

impl ValidatorSigner {
    /// The validator's public key.
    #[must_use]
    pub const fn pubkey(&self) -> BlsPubkey {
        match self {
            Self::Local(key) => *key.public_key(),
            Self::Remote(signer) => signer.pubkey(),
        }
    }

    /// Signs a message protection has cleared.
    ///
    /// # Errors
    ///
    /// Fails when the local scheme or the remote signer refuses.
    pub async fn sign<P: Preset>(
        &self,
        cleared: &Cleared<'_, P>,
        context: &SigningContext,
    ) -> Result<BlsSignature, SignError> {
        match self {
            Self::Local(key) => Ok(key.sign(cleared.root())?),
            Self::Remote(signer) => Ok(signer
                .sign(cleared.request(), cleared.root(), context)
                .await?),
        }
    }
}

/// Why a validator could not sign.
#[derive(Debug, Error)]
pub enum SignError {
    /// The client holds no key for the validator.
    #[error("no key for validator {0}")]
    UnknownKey(BlsPubkey),
    /// The key is held but disabled, such as during doppelganger detection.
    #[error("validator {0} is not allowed to sign yet")]
    Disabled(BlsPubkey),
    /// Slashing protection could not record a batch, so none of it may be signed.
    #[error("slashing protection unavailable: {0}")]
    Unavailable(String),
    /// Slashing protection refused the message or failed.
    #[error("slashing protection: {0}")]
    Protection(#[from] ProtectionError),
    /// The local key failed.
    #[error("local key: {0}")]
    Local(#[from] LocalKeyError),
    /// The remote signer failed.
    #[error("remote signer: {0}")]
    Remote(#[from] RemoteError),
}

impl From<Refusal> for SignError {
    fn from(refusal: Refusal) -> Self {
        Self::Protection(refusal.into())
    }
}
