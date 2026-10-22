//! Preparing proposals ahead: fee recipients, builder registrations, and proposer preferences.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, PoisonError},
};

use axiom_beacon_json::api::ProposerPreparation;
use axiom_types::{
    BlsPubkey, Epoch, Preset,
    bellatrix::{SignedValidatorRegistrationV1, ValidatorRegistrationV1},
    gloas::{ProposerPreferences, SignedProposerPreferences},
};
use tracing::{debug, info, warn};

use crate::{beacon::ApiTopic, duties::DutyContext, signing::SigningRequest};

/// Tells beacon nodes and builders, once an epoch, how this client's validators want to be paid.
///
/// # Overview
///
/// Each epoch, three messages go out:
///
/// 1. Every indexed validator's fee recipient, so a locally built payload pays it.
/// 2. For validators that use builders, a signed registration of fee recipient and gas limit.
/// 3. From Gloas on, signed preferences for each coming proposal, which bidding builders follow.
///
/// A registration is signed again only when its settings change, so builders see a stable timestamp.
/// An operator may fix the timestamp, and registrations go out in batches of a configured size.
/// See `prepareBeaconProposer`, `registerValidator`, and `get_signed_proposer_preferences`.
#[derive(Debug)]
pub struct Preparation<P: Preset> {
    /// What the preparation reaches.
    context: DutyContext<P>,
    /// The latest signed registration of each validator.
    registrations: Mutex<BTreeMap<BlsPubkey, SignedValidatorRegistrationV1>>,
}

impl<P: Preset> Preparation<P> {
    /// Preparation over a context, with no registration signed yet.
    #[must_use]
    pub const fn new(context: DutyContext<P>) -> Self {
        Self {
            context,
            registrations: Mutex::new(BTreeMap::new()),
        }
    }

    /// Sends this epoch's preparations, registrations, and preferences.
    pub async fn run(&self, epoch: Epoch) {
        self.prepare_proposers().await;
        self.register().await;
        self.publish_preferences(epoch).await;
    }

    /// Tells every node each validator's fee recipient.
    async fn prepare_proposers(&self) {
        let store = &self.context.store;
        let preparations: Arc<[ProposerPreparation]> = store
            .indices()
            .into_iter()
            .map(|(validator_index, pubkey)| ProposerPreparation {
                validator_index,
                fee_recipient: store.settings(&pubkey).fee_recipient,
            })
            .collect();
        if preparations.is_empty() {
            return;
        }
        let prepared = self
            .context
            .nodes
            .publish(ApiTopic::Subscriptions, |client| {
                let preparations = Arc::clone(&preparations);
                async move {
                    client
                        .validator()
                        .prepare_beacon_proposer(&preparations)
                        .await
                }
            })
            .await;
        if let Err(error) = prepared {
            warn!(%error, "proposer preparation refused");
        }
    }

    /// Signs and sends builder registrations for validators that use builders.
    async fn register(&self) {
        let store = &self.context.store;
        let settings = self.context.settings;
        let timestamp = settings
            .registration_timestamp
            .unwrap_or_else(|| self.context.timer.now_ms() / 1000);
        let mut registrations = Vec::new();
        for (_, pubkey) in store.indices() {
            let settings = store.settings(&pubkey);
            if !settings.builder {
                continue;
            }
            let cached = self
                .registrations
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&pubkey)
                .cloned();
            // An unchanged registration is resent as signed, keeping its timestamp.
            if let Some(cached) = cached
                && cached.message.fee_recipient == settings.fee_recipient
                && cached.message.gas_limit == settings.gas_limit
            {
                registrations.push(cached);
                continue;
            }
            let message = ValidatorRegistrationV1 {
                fee_recipient: settings.fee_recipient,
                gas_limit: settings.gas_limit,
                timestamp,
                pubkey,
            };
            match store
                .sign::<P>(&pubkey, SigningRequest::ValidatorRegistration(&message))
                .await
            {
                Ok(signature) => {
                    let signed = SignedValidatorRegistrationV1 { message, signature };
                    self.registrations
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .insert(pubkey, signed.clone());
                    registrations.push(signed);
                }
                Err(error) => debug!(%error, "registration not signed"),
            }
        }
        // Invariant: a batch holds at least one registration, whatever the configured size.
        for batch in registrations.chunks(settings.registration_batch_size.max(1)) {
            let batch: Arc<[SignedValidatorRegistrationV1]> = batch.into();
            let registered = self
                .context
                .nodes
                .publish(ApiTopic::Subscriptions, |client| {
                    let batch = Arc::clone(&batch);
                    async move { client.validator().register_validators(&batch).await }
                })
                .await;
            if let Err(error) = registered {
                warn!(%error, count = batch.len(), "builder registrations refused");
            }
        }
    }

    /// Signs and publishes preferences for this client's coming Gloas proposals.
    ///
    /// See `get_upcoming_proposal_slots` in the Gloas validator spec.
    /// See also `get_signed_proposer_preferences` there.
    async fn publish_preferences(&self, epoch: Epoch) {
        let current = self.context.timer.current_slot();
        let mut coming = Vec::new();
        for epoch in [epoch, epoch + 1] {
            // Only proposals whose payload a builder bids for take preferences.
            if !self.context.fork_at(epoch).separates_payloads() {
                continue;
            }
            let Some(duties) = self.context.book().proposers(epoch).cloned() else {
                continue;
            };
            for duty in &duties.data {
                if duty.slot > current && self.context.store.contains(&duty.pubkey) {
                    coming.push((*duty, duties.dependent_root.unwrap_or_default()));
                }
            }
        }
        let mut signed = Vec::new();
        for (duty, dependent_root) in coming {
            if !self.context.book().mark_preferences(duty.slot) {
                continue;
            }
            let settings = self.context.store.settings(&duty.pubkey);
            let message = ProposerPreferences {
                dependent_root,
                proposal_slot: duty.slot,
                validator_index: duty.validator_index,
                fee_recipient: settings.fee_recipient,
                target_gas_limit: settings.gas_limit,
            };
            match self
                .context
                .store
                .sign::<P>(&duty.pubkey, SigningRequest::ProposerPreferences(&message))
                .await
            {
                Ok(signature) => signed.push(SignedProposerPreferences { message, signature }),
                Err(error) => debug!(slot = duty.slot.0, %error, "preferences not signed"),
            }
        }
        if signed.is_empty() {
            return;
        }
        let count = signed.len();
        let signed = Arc::new(signed);
        let published = self
            .context
            .nodes
            .publish(ApiTopic::Subscriptions, |client| {
                let signed = Arc::clone(&signed);
                async move {
                    client
                        .validator()
                        .submit_proposer_preferences(&signed)
                        .await
                }
            })
            .await;
        match published {
            Ok(()) => info!(count, "proposer preferences published"),
            Err(error) => warn!(%error, "proposer preferences refused"),
        }
    }
}
