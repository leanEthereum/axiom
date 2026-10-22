//! The voluntary exit route: a signed request to leave the validator set.
//!
//! See `apis/voluntary_exit.yaml` in the keymanager API repository.

use std::{marker::PhantomData, sync::Arc};

use axiom_beacon_json::ApiJson;
use axiom_http::{Method, Request};
use axiom_types::{
    Epoch, Preset,
    phase0::{SignedVoluntaryExit, VoluntaryExit},
};

use crate::{
    duties::SlotTimer,
    keymanager::reply::{ApiError, ApiRequest, ApiResult, Reply, Routes},
    signing::{SignError, SigningRequest},
    validators::ValidatorStore,
};

/// The route that signs voluntary exits.
#[derive(Debug)]
pub(crate) struct ExitSigner<P: Preset> {
    /// The validators, whose signatures pass the store's guard.
    store: Arc<ValidatorStore>,
    /// The wall clock, for the default epoch.
    timer: SlotTimer,
    /// The preset the chain uses, which sets the epoch length.
    preset: PhantomData<P>,
}

impl<P: Preset> ExitSigner<P> {
    /// Path of the route.
    const PATH: &'static str = "/eth/v1/validator/{pubkey}/voluntary_exit";

    /// The route over a store and a clock.
    pub(crate) const fn new(store: Arc<ValidatorStore>, timer: SlotTimer) -> Self {
        Self {
            store,
            timer,
            preset: PhantomData,
        }
    }

    /// Adds the route.
    pub(crate) fn register(self, routes: Routes) -> Routes {
        let exits = Arc::new(self);
        routes.route(
            Method::Post,
            Self::PATH,
            &exits,
            |exits, request| async move { exits.sign(&request).await },
        )
    }

    /// Signs an exit valid from an epoch, the current one unless the query names another.
    ///
    /// The signature domain follows EIP-7044: from Deneb on, it uses the Capella fork version.
    /// So a signed exit stays valid across every later fork.
    async fn sign(&self, request: &Request) -> ApiResult {
        let api = ApiRequest::new(request);
        let pubkey = api.pubkey()?;
        if !self.store.contains(&pubkey) {
            return Err(ApiError::not_found(format!(
                "validator {pubkey} is not managed by this client"
            )));
        }
        let epoch = match api.query("epoch") {
            Some(text) => text
                .parse()
                .map(Epoch)
                .map_err(|_| ApiError::bad_request(format!("invalid epoch {text:?}")))?,
            None => self.timer.current_slot().epoch::<P>(),
        };
        let validator_index = self.store.index(&pubkey).ok_or_else(|| {
            ApiError::bad_request(format!(
                "validator {pubkey} has no registry index yet: no beacon node has reported it"
            ))
        })?;
        let message = VoluntaryExit {
            epoch,
            validator_index,
        };
        let signature = self
            .store
            .sign::<P>(&pubkey, SigningRequest::VoluntaryExit(&message))
            .await
            .map_err(|error| match error {
                SignError::UnknownKey(_) => ApiError::not_found(error.to_string()),
                SignError::Disabled(_) => ApiError::bad_request(error.to_string()),
                error => ApiError::internal(format!("cannot sign exit: {error}")),
            })?;
        let signed = SignedVoluntaryExit { message, signature };
        Ok(Reply::data(signed.to_json()))
    }
}
