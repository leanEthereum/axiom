//! The validators this client runs: their signers, settings, and registry indices.

use std::{
    collections::BTreeMap,
    sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use axiom_types::{
    BlsPubkey, BlsSignature, Bytes32, ExecutionAddress, Preset, ValidatorIndex,
    phase0::AttestationData,
};

use crate::signing::{SignError, SigningGuard, SigningRequest, ValidatorSigner};

/// Gas limit a proposer asks for when none is configured.
///
/// It matches the execution layer's default target at the time of writing.
pub const DEFAULT_GAS_LIMIT: u64 = 60_000_000;

/// Proposal settings that apply to every validator unless overridden.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProposerDefaults {
    /// Where execution fees go.
    pub fee_recipient: ExecutionAddress,
    /// The gas limit to ask builders and the engine for.
    pub gas_limit: u64,
    /// Bytes written into each block.
    pub graffiti: Bytes32,
    /// Whether the validator registers with external builders.
    pub builder: bool,
}

/// What a validator's proposals use, after overrides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposerSettings {
    /// Where execution fees go.
    pub fee_recipient: ExecutionAddress,
    /// The gas limit to ask for.
    pub gas_limit: u64,
    /// Bytes written into each block.
    pub graffiti: Bytes32,
    /// Whether the validator registers with external builders.
    pub builder: bool,
}

/// One validator this client runs.
#[derive(Debug)]
struct Entry {
    /// Its key.
    signer: Arc<ValidatorSigner>,
    /// Its registry index, once a beacon node has reported it.
    index: Option<ValidatorIndex>,
    /// A fee recipient overriding the default.
    fee_recipient: Option<ExecutionAddress>,
    /// A gas limit overriding the default.
    gas_limit: Option<u64>,
    /// Graffiti overriding the default.
    graffiti: Option<Bytes32>,
    /// Whether it may sign; doppelganger detection holds new keys back.
    enabled: bool,
}

/// Every validator this client runs, and the guard all their signatures pass.
///
/// # Overview
///
/// Keys may come and go while the client runs, through the keymanager API.
/// A lookup clones the signer out of a short read lock, so no lock is held across a signature.
#[derive(Debug)]
pub struct ValidatorStore {
    /// The signing context and slashing protection.
    guard: SigningGuard,
    /// The validators, by key.
    entries: RwLock<BTreeMap<BlsPubkey, Entry>>,
    /// Settings for validators without overrides.
    defaults: RwLock<ProposerDefaults>,
}

impl ValidatorStore {
    /// An empty store signing through a guard.
    #[must_use]
    pub const fn new(guard: SigningGuard, defaults: ProposerDefaults) -> Self {
        Self {
            guard,
            entries: RwLock::new(BTreeMap::new()),
            defaults: RwLock::new(defaults),
        }
    }

    /// The signing context and slashing protection.
    #[must_use]
    pub const fn guard(&self) -> &SigningGuard {
        &self.guard
    }

    /// Adds a validator, which may sign at once or only once enabled.
    ///
    /// Its key is registered with slashing protection first.
    ///
    /// # Errors
    ///
    /// Fails when slashing protection cannot record the key.
    pub fn add(&self, signer: ValidatorSigner, enabled: bool) -> Result<BlsPubkey, SignError> {
        let pubkey = signer.pubkey();
        self.guard.protection().register([pubkey])?;
        let entry = Entry {
            signer: Arc::new(signer),
            index: None,
            fee_recipient: None,
            gas_limit: None,
            graffiti: None,
            enabled,
        };
        self.write().insert(pubkey, entry);
        Ok(pubkey)
    }

    /// Removes a validator, so it never signs again in this process.
    ///
    /// # Returns
    ///
    /// Whether the store held it.
    pub fn remove(&self, pubkey: &BlsPubkey) -> bool {
        self.write().remove(pubkey).is_some()
    }

    /// Every validator's key.
    #[must_use]
    pub fn pubkeys(&self) -> Vec<BlsPubkey> {
        self.read().keys().copied().collect()
    }

    /// Whether the store holds a key.
    #[must_use]
    pub fn contains(&self, pubkey: &BlsPubkey) -> bool {
        self.read().contains_key(pubkey)
    }

    /// The key's signer, for listing where it lives.
    #[must_use]
    pub fn signer(&self, pubkey: &BlsPubkey) -> Option<Arc<ValidatorSigner>> {
        self.read()
            .get(pubkey)
            .map(|entry| Arc::clone(&entry.signer))
    }

    /// Keys whose registry index is not yet known.
    #[must_use]
    pub fn unindexed(&self) -> Vec<BlsPubkey> {
        self.read()
            .iter()
            .filter(|(_, entry)| entry.index.is_none())
            .map(|(pubkey, _)| *pubkey)
            .collect()
    }

    /// Records a key's registry index.
    pub fn set_index(&self, pubkey: &BlsPubkey, index: ValidatorIndex) {
        if let Some(entry) = self.write().get_mut(pubkey) {
            entry.index = Some(index);
        }
    }

    /// The registry index of a key, if known.
    #[must_use]
    pub fn index(&self, pubkey: &BlsPubkey) -> Option<ValidatorIndex> {
        self.read().get(pubkey).and_then(|entry| entry.index)
    }

    /// Every known registry index, with its key.
    #[must_use]
    pub fn indices(&self) -> Vec<(ValidatorIndex, BlsPubkey)> {
        self.read()
            .iter()
            .filter_map(|(pubkey, entry)| Some((entry.index?, *pubkey)))
            .collect()
    }

    /// Lets a validator sign, or stops it.
    pub fn set_enabled(&self, pubkey: &BlsPubkey, enabled: bool) {
        if let Some(entry) = self.write().get_mut(pubkey) {
            entry.enabled = enabled;
        }
    }

    /// Whether a validator may sign.
    #[must_use]
    pub fn is_enabled(&self, pubkey: &BlsPubkey) -> bool {
        self.read().get(pubkey).is_some_and(|entry| entry.enabled)
    }

    /// Keys not yet allowed to sign.
    #[must_use]
    pub fn disabled(&self) -> Vec<BlsPubkey> {
        self.read()
            .iter()
            .filter(|(_, entry)| !entry.enabled)
            .map(|(pubkey, _)| *pubkey)
            .collect()
    }

    /// The proposal settings of a validator, overrides applied.
    #[must_use]
    pub fn settings(&self, pubkey: &BlsPubkey) -> ProposerSettings {
        let defaults = *self.defaults.read().unwrap_or_else(PoisonError::into_inner);
        let overrides = self
            .read()
            .get(pubkey)
            .map(|entry| (entry.fee_recipient, entry.gas_limit, entry.graffiti));
        let (fee_recipient, gas_limit, graffiti) = overrides.unwrap_or_default();
        ProposerSettings {
            fee_recipient: fee_recipient.unwrap_or(defaults.fee_recipient),
            gas_limit: gas_limit.unwrap_or(defaults.gas_limit),
            graffiti: graffiti.unwrap_or(defaults.graffiti),
            builder: defaults.builder,
        }
    }

    /// Overrides a validator's fee recipient, or clears the override.
    ///
    /// # Returns
    ///
    /// Whether the store holds the key.
    pub fn set_fee_recipient(&self, pubkey: &BlsPubkey, value: Option<ExecutionAddress>) -> bool {
        self.update(pubkey, |entry| entry.fee_recipient = value)
    }

    /// Overrides a validator's gas limit, or clears the override.
    ///
    /// # Returns
    ///
    /// Whether the store holds the key.
    pub fn set_gas_limit(&self, pubkey: &BlsPubkey, value: Option<u64>) -> bool {
        self.update(pubkey, |entry| entry.gas_limit = value)
    }

    /// Overrides a validator's graffiti, or clears the override.
    ///
    /// # Returns
    ///
    /// Whether the store holds the key.
    pub fn set_graffiti(&self, pubkey: &BlsPubkey, value: Option<Bytes32>) -> bool {
        self.update(pubkey, |entry| entry.graffiti = value)
    }

    /// Whether a validator overrides each setting.
    #[must_use]
    pub fn overrides(&self, pubkey: &BlsPubkey) -> Option<(bool, bool, bool)> {
        self.read().get(pubkey).map(|entry| {
            (
                entry.fee_recipient.is_some(),
                entry.gas_limit.is_some(),
                entry.graffiti.is_some(),
            )
        })
    }

    /// Signs a message for a validator, through slashing protection.
    ///
    /// # Errors
    ///
    /// Fails when the key is unknown or disabled, protection refuses, or the signer fails.
    pub async fn sign<P: Preset>(
        &self,
        pubkey: &BlsPubkey,
        request: SigningRequest<'_, P>,
    ) -> Result<BlsSignature, SignError> {
        let signer = self.enabled_signer(pubkey)?;
        let cleared = self.guard.clear(pubkey, request)?;
        signer.sign(&cleared, self.guard.context()).await
    }

    /// Signs many votes, clearing all of them in one durable write first.
    ///
    /// A slot's votes are one flush to disk, however many validators the client runs.
    ///
    /// # Errors
    ///
    /// Each vote fails on its own when its key is unknown, disabled, or refused.
    /// All fail when slashing protection cannot write.
    pub async fn sign_votes<P: Preset>(
        &self,
        votes: &[(BlsPubkey, &AttestationData)],
    ) -> Vec<Result<BlsSignature, SignError>> {
        // Phase 1: keys that may sign at all.
        let signers: Vec<Result<Arc<ValidatorSigner>, SignError>> = votes
            .iter()
            .map(|(pubkey, _)| self.enabled_signer(pubkey))
            .collect();
        let allowed: Vec<(BlsPubkey, &AttestationData)> = votes
            .iter()
            .zip(&signers)
            .filter(|(_, signer)| signer.is_ok())
            .map(|(vote, _)| *vote)
            .collect();

        // Phase 2: one durable write for every allowed vote.
        let cleared = match self.guard.clear_votes::<P>(&allowed) {
            Ok(cleared) => cleared,
            Err(error) => {
                let message = error.to_string();
                return votes
                    .iter()
                    .map(|_| Err(SignError::Unavailable(message.clone())))
                    .collect();
            }
        };

        // Phase 3: sign each cleared vote with its own key.
        let mut cleared = cleared.into_iter();
        let mut signatures = Vec::with_capacity(votes.len());
        for signer in signers {
            let signature = match signer {
                Err(error) => Err(error),
                Ok(signer) => match cleared.next() {
                    Some(Ok(cleared)) => signer.sign(&cleared, self.guard.context()).await,
                    Some(Err(refusal)) => Err(refusal.into()),
                    // Invariant: one clearing per allowed vote, in order.
                    None => Err(SignError::Unavailable("vote not cleared".to_owned())),
                },
            };
            signatures.push(signature);
        }
        signatures
    }

    /// The signer of a key that may sign.
    fn enabled_signer(&self, pubkey: &BlsPubkey) -> Result<Arc<ValidatorSigner>, SignError> {
        let (signer, enabled) = self
            .read()
            .get(pubkey)
            .map(|entry| (Arc::clone(&entry.signer), entry.enabled))
            .ok_or(SignError::UnknownKey(*pubkey))?;
        if !enabled {
            return Err(SignError::Disabled(*pubkey));
        }
        Ok(signer)
    }

    /// Applies a change to one validator.
    fn update(&self, pubkey: &BlsPubkey, change: impl FnOnce(&mut Entry)) -> bool {
        self.write().get_mut(pubkey).map(change).is_some()
    }

    /// The validators, for reading.
    fn read(&self) -> RwLockReadGuard<'_, BTreeMap<BlsPubkey, Entry>> {
        // A panic under the lock leaves a consistent map: every change is one insert or field write.
        self.entries.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// The validators, for writing.
    fn write(&self) -> RwLockWriteGuard<'_, BTreeMap<BlsPubkey, Entry>> {
        self.entries.write().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use axiom_bls::SecretKey;
    use axiom_types::{ChainConfig, Epoch, Minimal, Root, Slot, phase0::Checkpoint};
    use tokio::runtime::Builder;

    use super::*;
    use crate::{
        protection::SlashingDatabase,
        signing::{Bls, LocalKey, SignatureScheme, SigningContext},
    };

    /// A store on the minimal chain, with one local key of secret 5, enabled or not.
    fn store(enabled: bool) -> (ValidatorStore, BlsPubkey) {
        let context = SigningContext::new(Arc::new(ChainConfig::minimal()), Root([1; 32]));
        let protection = Arc::new(SlashingDatabase::in_memory(Root([1; 32])).unwrap());
        let store = ValidatorStore::new(
            SigningGuard::new(context, protection),
            ProposerDefaults {
                gas_limit: DEFAULT_GAS_LIMIT,
                ..ProposerDefaults::default()
            },
        );
        let mut bytes = [0; 32];
        bytes[31] = 5;
        let key = LocalKey::<Bls>::new(SecretKey::from_bytes(&bytes).unwrap()).unwrap();
        let pubkey = store.add(ValidatorSigner::Local(key), enabled).unwrap();
        (store, pubkey)
    }

    /// A vote from epoch 0 to a target epoch.
    fn vote(target: u64, root: u8) -> AttestationData {
        AttestationData {
            slot: Epoch(target).start_slot::<Minimal>(),
            target: Checkpoint {
                epoch: Epoch(target),
                root: Root([root; 32]),
            },
            ..AttestationData::default()
        }
    }

    #[test]
    fn votes_sign_once_and_conflicts_are_refused() {
        Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let (store, pubkey) = store(true);
                let first = vote(1, 1);
                let conflicting = vote(1, 2);

                // The first vote for target 1 signs and verifies; its conflict is refused.
                let signatures = store
                    .sign_votes::<Minimal>(&[(pubkey, &first), (pubkey, &conflicting)])
                    .await;
                let root = store
                    .guard()
                    .context()
                    .signing_root(&SigningRequest::<Minimal>::Attestation(&first));
                assert!(Bls::verify(
                    &pubkey,
                    None,
                    root,
                    signatures[0].as_ref().unwrap()
                ));
                assert!(matches!(signatures[1], Err(SignError::Protection(_))));
            });
    }

    #[test]
    fn a_disabled_or_unknown_key_never_signs() {
        Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                // Doppelganger detection holds the key back.
                let (store, pubkey) = store(false);
                let request = SigningRequest::<Minimal>::AggregationSlot(Slot(3));
                assert!(matches!(
                    store.sign(&pubkey, request).await,
                    Err(SignError::Disabled(key)) if key == pubkey
                ));

                // Enabled, it signs.
                store.set_enabled(&pubkey, true);
                assert!(store.sign(&pubkey, request).await.is_ok());

                // A key the store never held is unknown.
                assert!(matches!(
                    store.sign(&BlsPubkey([9; 48]), request).await,
                    Err(SignError::UnknownKey(_))
                ));
            });
    }

    #[test]
    fn overrides_replace_the_defaults() {
        let (store, pubkey) = store(true);
        assert_eq!(store.settings(&pubkey).gas_limit, DEFAULT_GAS_LIMIT);
        assert!(store.set_gas_limit(&pubkey, Some(30_000_000)));
        assert!(store.set_fee_recipient(&pubkey, Some(ExecutionAddress([7; 20]))));
        assert_eq!(
            store.settings(&pubkey),
            ProposerSettings {
                fee_recipient: ExecutionAddress([7; 20]),
                gas_limit: 30_000_000,
                graffiti: Bytes32::default(),
                builder: false,
            }
        );
        // Clearing the override restores the default.
        assert!(store.set_gas_limit(&pubkey, None));
        assert_eq!(store.settings(&pubkey).gas_limit, DEFAULT_GAS_LIMIT);
    }
}
