//! The per-validator proposal settings: fee recipient, gas limit, graffiti, and builders.
//!
//! See the keymanager API repository, in its apis folder:
//!
//! - `fee_recipient.yaml`
//! - `gas_limit.yaml`
//! - `graffiti.yaml`
//! - `builder_config.yaml`

use std::sync::Arc;

use axiom_beacon_json::{ApiJson, Fields};
use axiom_http::{Method, Request, StatusCode};
use axiom_json::Json;
use axiom_types::{BlsPubkey, ExecutionAddress};

use crate::{
    keymanager::{
        registry::KeyRegistry,
        reply::{ApiError, ApiRequest, ApiResult, Reply, Routes},
    },
    validators::{BuilderConfig, Graffiti, ValidatorSettings},
};

/// The routes over each validator's proposal settings.
#[derive(Debug)]
pub(crate) struct ProposerOverrides {
    /// The running keys and their definitions.
    registry: Arc<KeyRegistry>,
}

impl ProposerOverrides {
    /// Path of the fee recipient routes.
    const FEE_RECIPIENT: &'static str = "/eth/v1/validator/{pubkey}/feerecipient";

    /// Path of the gas limit routes.
    const GAS_LIMIT: &'static str = "/eth/v1/validator/{pubkey}/gas_limit";

    /// Path of the graffiti routes.
    const GRAFFITI: &'static str = "/eth/v1/validator/{pubkey}/graffiti";

    /// Path of the builder configuration routes.
    const BUILDER_CONFIG: &'static str = "/eth/v1/validator/{pubkey}/builder_config";

    /// The group over a registry.
    pub(crate) const fn new(registry: Arc<KeyRegistry>) -> Self {
        Self { registry }
    }

    /// Adds the group's routes.
    pub(crate) fn register(self, routes: Routes) -> Routes {
        let settings = Arc::new(self);
        routes
            .route(
                Method::Get,
                Self::FEE_RECIPIENT,
                &settings,
                |s, request| async move { s.fee_recipient(&request) },
            )
            .route(
                Method::Post,
                Self::FEE_RECIPIENT,
                &settings,
                |s, request| async move { s.set_fee_recipient(&request) },
            )
            .route(
                Method::Delete,
                Self::FEE_RECIPIENT,
                &settings,
                |s, request| async move {
                    s.clear(&request, |settings| settings.fee_recipient = None)
                },
            )
            .route(
                Method::Get,
                Self::GAS_LIMIT,
                &settings,
                |s, request| async move { s.gas_limit(&request) },
            )
            .route(
                Method::Post,
                Self::GAS_LIMIT,
                &settings,
                |s, request| async move { s.set_gas_limit(&request) },
            )
            .route(
                Method::Delete,
                Self::GAS_LIMIT,
                &settings,
                |s, request| async move { s.clear(&request, |settings| settings.gas_limit = None) },
            )
            .route(
                Method::Get,
                Self::GRAFFITI,
                &settings,
                |s, request| async move { s.graffiti(&request) },
            )
            .route(
                Method::Post,
                Self::GRAFFITI,
                &settings,
                |s, request| async move { s.set_graffiti(&request) },
            )
            .route(
                Method::Delete,
                Self::GRAFFITI,
                &settings,
                |s, request| async move { s.clear(&request, |settings| settings.graffiti = None) },
            )
            .route(
                Method::Get,
                Self::BUILDER_CONFIG,
                &settings,
                |s, request| async move { s.builder_config(&request) },
            )
            .route(
                Method::Post,
                Self::BUILDER_CONFIG,
                &settings,
                |s, request| async move { s.set_builder_config(&request) },
            )
            .route(
                Method::Delete,
                Self::BUILDER_CONFIG,
                &settings,
                |s, request| async move {
                    s.clear(&request, |settings| settings.builder_config = None)
                },
            )
    }

    /// The fee recipient a validator's proposals pay, the default unless overridden.
    fn fee_recipient(&self, request: &Request) -> ApiResult {
        let pubkey = self.known(request)?;
        let address = self.registry.store().settings(&pubkey).fee_recipient;
        Ok(Reply::data(Json::from([
            ("pubkey", pubkey.to_json()),
            ("ethaddress", address.to_json()),
        ])))
    }

    /// Overrides a validator's fee recipient.
    ///
    /// The zero address is refused, as the keymanager API requires: fees sent there are burned.
    fn set_fee_recipient(&self, request: &Request) -> ApiResult {
        let pubkey = self.known(request)?;
        let body = ApiRequest::new(request).json()?;
        let address: ExecutionAddress = Fields::of(&body)?.required("ethaddress")?;
        if address == ExecutionAddress::default() {
            return Err(ApiError::bad_request(
                "the zero address cannot be a fee recipient",
            ));
        }
        self.apply(&pubkey, |settings| settings.fee_recipient = Some(address))?;
        Ok(Reply::empty(StatusCode::ACCEPTED))
    }

    /// The gas limit a validator asks for, the default unless overridden.
    fn gas_limit(&self, request: &Request) -> ApiResult {
        let pubkey = self.known(request)?;
        let gas_limit = self.registry.store().settings(&pubkey).gas_limit;
        Ok(Reply::data(Json::from([
            ("pubkey", pubkey.to_json()),
            ("gas_limit", gas_limit.to_json()),
        ])))
    }

    /// Overrides a validator's gas limit.
    fn set_gas_limit(&self, request: &Request) -> ApiResult {
        let pubkey = self.known(request)?;
        let body = ApiRequest::new(request).json()?;
        let gas_limit: u64 = Fields::of(&body)?.required("gas_limit")?;
        self.apply(&pubkey, |settings| settings.gas_limit = Some(gas_limit))?;
        Ok(Reply::empty(StatusCode::ACCEPTED))
    }

    /// The graffiti a validator's blocks carry, the default unless overridden.
    fn graffiti(&self, request: &Request) -> ApiResult {
        let pubkey = self.known(request)?;
        let graffiti = self.registry.store().graffiti(&pubkey);
        Ok(Reply::data(Json::from([
            ("pubkey", pubkey.to_json()),
            ("graffiti", Json::from(graffiti.text())),
        ])))
    }

    /// Overrides a validator's graffiti.
    fn set_graffiti(&self, request: &Request) -> ApiResult {
        let pubkey = self.known(request)?;
        let body = ApiRequest::new(request).json()?;
        let text: String = Fields::of(&body)?.required("graffiti")?;
        let graffiti =
            Graffiti::parse(&text).map_err(|error| ApiError::bad_request(error.to_string()))?;
        self.apply(&pubkey, |settings| settings.graffiti = Some(graffiti))?;
        Ok(Reply::empty(StatusCode::ACCEPTED))
    }

    /// The builder configuration in effect, with every omitted value resolved.
    fn builder_config(&self, request: &Request) -> ApiResult {
        let pubkey = self.known(request)?;
        let resolved = self.registry.store().builder_config(&pubkey);
        Ok(Reply::data(resolved.to_json()))
    }

    /// Replaces a validator's builder configuration in full, never merging it with the stored one.
    fn set_builder_config(&self, request: &Request) -> ApiResult {
        let pubkey = self.known(request)?;
        let body = ApiRequest::new(request).json()?;
        let config = BuilderConfig::from_json(&body)
            .map_err(|error| ApiError::bad_request(format!("invalid builder config: {error}")))?;
        self.apply(&pubkey, |settings| {
            settings.builder_config = Some(config.clone());
        })?;
        Ok(Reply::empty(StatusCode::ACCEPTED))
    }

    /// Clears one override, so the default applies again.
    fn clear(&self, request: &Request, reset: impl Fn(&mut ValidatorSettings)) -> ApiResult {
        let pubkey = self.known(request)?;
        self.apply(&pubkey, reset)?;
        Ok(Reply::empty(StatusCode::NO_CONTENT))
    }

    /// The key in the path, which the store must run.
    fn known(&self, request: &Request) -> Result<BlsPubkey, ApiError> {
        let pubkey = ApiRequest::new(request).pubkey()?;
        if !self.registry.store().contains(&pubkey) {
            return Err(Self::unknown(&pubkey));
        }
        Ok(pubkey)
    }

    /// Changes a key's overrides durably, failing when a concurrent delete removed the key.
    fn apply(
        &self,
        pubkey: &BlsPubkey,
        change: impl Fn(&mut ValidatorSettings),
    ) -> Result<(), ApiError> {
        match self.registry.edit_settings(pubkey, change) {
            Ok(true) => Ok(()),
            Ok(false) => Err(Self::unknown(pubkey)),
            Err(error) => Err(ApiError::internal(format!(
                "cannot store the setting: {error}"
            ))),
        }
    }

    /// The reply for a key the store does not run.
    fn unknown(pubkey: &BlsPubkey) -> ApiError {
        ApiError::not_found(format!("validator {pubkey} is not managed by this client"))
    }
}
