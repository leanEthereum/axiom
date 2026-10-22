//! The store of running validators: their signers, overrides, and registry indices.

use std::{
    collections::BTreeMap,
    future::Future,
    sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::Instant,
};

use axiom_types::{BlsPubkey, BlsSignature, Preset, ValidatorIndex, phase0::AttestationData};
use tracing::warn;

use crate::{
    metrics::ValidatorMetrics,
    signing::{SignError, SigningGuard, SigningRequest, ValidatorSigner},
    validators::{
        BuilderConfig, Graffiti, GraffitiFile, NEUTRAL_BOOST_FACTOR, ProposerDefaults,
        ProposerSettings, ResolvedBuilderConfig, ValidatorSettings,
    },
};

/// One validator this client runs.
#[derive(Debug)]
struct Entry {
    /// Its key.
    signer: Arc<ValidatorSigner>,
    /// Its registry index, once a beacon node has reported it.
    index: Option<ValidatorIndex>,
    /// Its overrides of the client's defaults.
    overrides: ValidatorSettings,
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
    defaults: ProposerDefaults,
    /// A graffiti file, which overrides every other graffiti setting.
    graffiti_file: Option<GraffitiFile>,
    /// Signature counts and latencies.
    metrics: ValidatorMetrics,
}

impl ValidatorStore {
    /// An empty store signing through a guard.
    #[must_use]
    pub fn new(guard: SigningGuard, defaults: ProposerDefaults) -> Self {
        Self {
            guard,
            entries: RwLock::new(BTreeMap::new()),
            defaults,
            graffiti_file: None,
            metrics: ValidatorMetrics::detached(),
        }
    }

    /// Reads graffiti from a file before every other setting.
    #[must_use]
    pub fn with_graffiti_file(mut self, file: GraffitiFile) -> Self {
        self.graffiti_file = Some(file);
        self
    }

    /// Records signatures in exported metrics.
    #[must_use]
    pub fn with_metrics(mut self, metrics: ValidatorMetrics) -> Self {
        self.metrics = metrics;
        self
    }

    /// The settings for validators without overrides.
    #[must_use]
    pub const fn defaults(&self) -> &ProposerDefaults {
        &self.defaults
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
            overrides: ValidatorSettings::default(),
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
        let overrides = self.overrides(pubkey).unwrap_or_default();
        ProposerSettings::resolve(&self.defaults, &overrides)
    }

    /// The graffiti of a validator's blocks.
    ///
    /// A graffiti file comes first, then the validator's override, then the default.
    /// A file that cannot be read is skipped with a warning, so a proposal never fails on it.
    #[must_use]
    pub fn graffiti(&self, pubkey: &BlsPubkey) -> Graffiti {
        let from_file = self.graffiti_file.as_ref().and_then(|file| {
            file.lookup(pubkey)
                .inspect_err(|error| warn!(%error, "graffiti file unreadable"))
                .ok()
                .flatten()
        });
        from_file
            .or_else(|| {
                self.overrides(pubkey)
                    .and_then(|overrides| overrides.graffiti)
            })
            .unwrap_or(self.defaults.graffiti)
    }

    /// The builder configuration of a validator's Gloas proposals, every value resolved.
    #[must_use]
    pub fn builder_config(&self, pubkey: &BlsPubkey) -> ResolvedBuilderConfig {
        let overrides = self.overrides(pubkey).unwrap_or_default();
        let boost_factor = ProposerSettings::resolve(&self.defaults, &overrides)
            .builder_boost_factor
            .unwrap_or(NEUTRAL_BOOST_FACTOR);
        BuilderConfig::resolve(overrides.builder_config.as_ref(), boost_factor)
    }

    /// A validator's overrides, when the store holds it.
    #[must_use]
    pub fn overrides(&self, pubkey: &BlsPubkey) -> Option<ValidatorSettings> {
        self.read().get(pubkey).map(|entry| entry.overrides.clone())
    }

    /// Changes a validator's overrides.
    ///
    /// # Returns
    ///
    /// Whether the store holds the key.
    pub fn edit_overrides(
        &self,
        pubkey: &BlsPubkey,
        change: impl FnOnce(&mut ValidatorSettings),
    ) -> bool {
        self.write()
            .get_mut(pubkey)
            .map(|entry| change(&mut entry.overrides))
            .is_some()
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
        let cleared = match self.guard.clear(pubkey, request) {
            Ok(cleared) => cleared,
            Err(error) => {
                let error = SignError::from(error);
                self.metrics.record(&request, Err(&error));
                return Err(error);
            }
        };
        self.metrics.record(&request, Ok(cleared.safety()));
        // Invariant: a key removed before this point never signs.
        // Removal then exports the key's history, which holds every record cleared before it.
        // A record cleared after the export belongs to a message this check now refuses.
        self.enabled_signer(pubkey)?;
        self.timed(&signer, signer.sign(&cleared, self.guard.context()))
            .await
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
        for (signer, (pubkey, data)) in signers.into_iter().zip(votes) {
            let request = SigningRequest::<P>::Attestation(data);
            let signature = match signer {
                Err(error) => Err(error),
                Ok(signer) => match cleared.next() {
                    // Invariant: a key removed while its vote was cleared never signs it.
                    Some(Ok(cleared)) => {
                        self.metrics.record(&request, Ok(cleared.safety()));
                        match self.enabled_signer(pubkey) {
                            Ok(_) => {
                                self.timed(&signer, signer.sign(&cleared, self.guard.context()))
                                    .await
                            }
                            Err(error) => Err(error),
                        }
                    }
                    Some(Err(refusal)) => {
                        let error = SignError::from(refusal);
                        self.metrics.record(&request, Err(&error));
                        Err(error)
                    }
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

    /// Runs one signature, recording how long the signer took.
    async fn timed(
        &self,
        signer: &ValidatorSigner,
        signing: impl Future<Output = Result<BlsSignature, SignError>>,
    ) -> Result<BlsSignature, SignError> {
        let start = Instant::now();
        let signature = signing.await;
        self.metrics
            .observe_signing(signer, start.elapsed().as_secs_f64());
        signature
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
    use std::{env, fs, process};

    use axiom_bls::{PublicKey, SecretKey, Signature};
    use axiom_types::{ChainConfig, Epoch, Minimal, Root, Slot, phase0::Checkpoint};
    use tokio::runtime::Builder;

    use super::*;
    use crate::{
        protection::SlashingDatabase,
        signing::{LocalKey, SigningContext},
        validators::DEFAULT_GAS_LIMIT,
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
        let key = LocalKey::new(SecretKey::from_bytes(&bytes).unwrap());
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
                let signature = signatures[0].as_ref().unwrap();
                let public = PublicKey::from_bytes(&pubkey.0).unwrap();
                assert!(
                    Signature::from_bytes(&signature.0)
                        .unwrap()
                        .verify(&public, &root.0)
                );
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
    fn overrides_replace_the_defaults_until_cleared() {
        let (store, pubkey) = store(true);
        assert_eq!(store.settings(&pubkey).gas_limit, DEFAULT_GAS_LIMIT);
        assert!(store.edit_overrides(&pubkey, |overrides| {
            overrides.gas_limit = Some(30_000_000);
        }));
        assert_eq!(store.settings(&pubkey).gas_limit, 30_000_000);

        // Clearing the override restores the default; an unknown key changes nothing.
        assert!(store.edit_overrides(&pubkey, |overrides| overrides.gas_limit = None));
        assert_eq!(store.settings(&pubkey).gas_limit, DEFAULT_GAS_LIMIT);
        assert!(!store.edit_overrides(&BlsPubkey([9; 48]), |_| {}));
    }

    #[test]
    fn a_graffiti_file_beats_the_override_and_the_default() {
        let (store, pubkey) = store(true);
        let own = Graffiti::parse("override").unwrap();
        store.edit_overrides(&pubkey, |overrides| overrides.graffiti = Some(own));
        assert_eq!(store.graffiti(&pubkey), own);

        // Fixture state: a graffiti file with a default line only.
        let path = env::temp_dir().join(format!("axiom-store-graffiti-{}", process::id()));
        fs::write(&path, "default: from the file\n").unwrap();
        let store = store.with_graffiti_file(GraffitiFile::new(path.clone()));
        assert_eq!(
            store.graffiti(&pubkey),
            Graffiti::parse("from the file").unwrap()
        );

        // An unreadable file falls back to the override rather than failing the proposal.
        fs::remove_file(&path).unwrap();
        assert_eq!(store.graffiti(&pubkey), own);
    }
}
