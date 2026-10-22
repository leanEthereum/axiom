//! The per-validator proposal settings: fee recipient, gas limit, and graffiti.
//!
//! See the keymanager API repository, in its apis folder:
//!
//! - `fee_recipient.yaml`
//! - `gas_limit.yaml`
//! - `graffiti.yaml`

use std::sync::Arc;

use axiom_http::{Method, Request, StatusCode};
use axiom_json::Json;
use axiom_types::{BlsPubkey, Bytes32, ExecutionAddress};

use crate::{
    json::{ApiJson, Fields},
    keymanager::reply::{ApiError, ApiRequest, ApiResult, Reply, Routes},
    validators::ValidatorStore,
};

/// Graffiti as the keymanager API writes it: up to 32 bytes of UTF-8 text.
///
/// The block carries 32 bytes, so shorter text is padded with zero bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Graffiti(Bytes32);

impl Graffiti {
    /// Reads text that fits the block's 32 bytes.
    fn parse(text: &str) -> Result<Self, ApiError> {
        let mut bytes = [0; 32];
        let Some(prefix) = bytes.get_mut(..text.len()) else {
            return Err(ApiError::bad_request(format!(
                "graffiti of {} bytes exceeds the {} a block holds",
                text.len(),
                bytes.len()
            )));
        };
        prefix.copy_from_slice(text.as_bytes());
        Ok(Self(Bytes32(bytes)))
    }

    /// The text, without its zero padding.
    ///
    /// Only a configured default can hold bytes that are not UTF-8.
    /// They read as replacement characters.
    fn text(self) -> String {
        let bytes = &self.0.0;
        let end = bytes
            .iter()
            .rposition(|&byte| byte != 0)
            .map_or(0, |last| last + 1);
        String::from_utf8_lossy(&bytes[..end]).into_owned()
    }
}

/// The routes over each validator's proposal settings.
#[derive(Debug)]
pub(crate) struct ProposerOverrides {
    /// The validators and their settings.
    store: Arc<ValidatorStore>,
}

impl ProposerOverrides {
    /// Path of the fee recipient routes.
    const FEE_RECIPIENT: &'static str = "/eth/v1/validator/{pubkey}/feerecipient";

    /// Path of the gas limit routes.
    const GAS_LIMIT: &'static str = "/eth/v1/validator/{pubkey}/gas_limit";

    /// Path of the graffiti routes.
    const GRAFFITI: &'static str = "/eth/v1/validator/{pubkey}/graffiti";

    /// The group over a store.
    pub(crate) const fn new(store: Arc<ValidatorStore>) -> Self {
        Self { store }
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
                    s.clear(&request, |store, pubkey| {
                        store.set_fee_recipient(pubkey, None)
                    })
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
                |s, request| async move {
                    s.clear(&request, |store, pubkey| store.set_gas_limit(pubkey, None))
                },
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
                |s, request| async move {
                    s.clear(&request, |store, pubkey| store.set_graffiti(pubkey, None))
                },
            )
    }

    /// The fee recipient a validator's proposals pay, the default unless overridden.
    fn fee_recipient(&self, request: &Request) -> ApiResult {
        let pubkey = self.known(request)?;
        let address = self.store.settings(&pubkey).fee_recipient;
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
        let address: ExecutionAddress = Fields::of(&body)?.get("ethaddress")?;
        if address == ExecutionAddress::default() {
            return Err(ApiError::bad_request(
                "the zero address cannot be a fee recipient",
            ));
        }
        Self::applied(
            self.store.set_fee_recipient(&pubkey, Some(address)),
            &pubkey,
        )?;
        Ok(Reply::empty(StatusCode::ACCEPTED))
    }

    /// The gas limit a validator asks for, the default unless overridden.
    fn gas_limit(&self, request: &Request) -> ApiResult {
        let pubkey = self.known(request)?;
        let gas_limit = self.store.settings(&pubkey).gas_limit;
        Ok(Reply::data(Json::from([
            ("pubkey", pubkey.to_json()),
            ("gas_limit", gas_limit.to_json()),
        ])))
    }

    /// Overrides a validator's gas limit.
    fn set_gas_limit(&self, request: &Request) -> ApiResult {
        let pubkey = self.known(request)?;
        let body = ApiRequest::new(request).json()?;
        let gas_limit: u64 = Fields::of(&body)?.get("gas_limit")?;
        Self::applied(self.store.set_gas_limit(&pubkey, Some(gas_limit)), &pubkey)?;
        Ok(Reply::empty(StatusCode::ACCEPTED))
    }

    /// The graffiti a validator's blocks carry, the default unless overridden.
    fn graffiti(&self, request: &Request) -> ApiResult {
        let pubkey = self.known(request)?;
        let graffiti = Graffiti(self.store.settings(&pubkey).graffiti);
        Ok(Reply::data(Json::from([
            ("pubkey", pubkey.to_json()),
            ("graffiti", Json::from(graffiti.text())),
        ])))
    }

    /// Overrides a validator's graffiti.
    fn set_graffiti(&self, request: &Request) -> ApiResult {
        let pubkey = self.known(request)?;
        let body = ApiRequest::new(request).json()?;
        let text: String = Fields::of(&body)?.get("graffiti")?;
        let graffiti = Graffiti::parse(&text)?;
        Self::applied(self.store.set_graffiti(&pubkey, Some(graffiti.0)), &pubkey)?;
        Ok(Reply::empty(StatusCode::ACCEPTED))
    }

    /// Clears one override, so the default applies again.
    fn clear(
        &self,
        request: &Request,
        reset: impl FnOnce(&ValidatorStore, &BlsPubkey) -> bool,
    ) -> ApiResult {
        let pubkey = self.known(request)?;
        Self::applied(reset(&self.store, &pubkey), &pubkey)?;
        Ok(Reply::empty(StatusCode::NO_CONTENT))
    }

    /// The key in the path, which the store must run.
    fn known(&self, request: &Request) -> Result<BlsPubkey, ApiError> {
        let pubkey = ApiRequest::new(request).pubkey()?;
        if !self.store.contains(&pubkey) {
            return Err(Self::unknown(&pubkey));
        }
        Ok(pubkey)
    }

    /// Whether a change reached the key, which a concurrent delete may have removed.
    fn applied(changed: bool, pubkey: &BlsPubkey) -> Result<(), ApiError> {
        if changed {
            Ok(())
        } else {
            Err(Self::unknown(pubkey))
        }
    }

    /// The reply for a key the store does not run.
    fn unknown(pubkey: &BlsPubkey) -> ApiError {
        ApiError::not_found(format!("validator {pubkey} is not managed by this client"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graffiti_round_trips_through_its_zero_padding() {
        // "axiom" takes 5 bytes; the other 27 are zero.
        let graffiti = Graffiti::parse("axiom").unwrap();
        let mut bytes = [0; 32];
        bytes[..5].copy_from_slice(b"axiom");
        assert_eq!(graffiti, Graffiti(Bytes32(bytes)));
        assert_eq!(graffiti.text(), "axiom");

        // Exactly 32 bytes fit with no padding; the empty text is all padding.
        let full = "x".repeat(32);
        assert_eq!(Graffiti::parse(&full).unwrap().text(), full);
        assert_eq!(Graffiti::parse("").unwrap(), Graffiti(Bytes32::default()));
    }

    #[test]
    fn graffiti_longer_than_a_block_holds_is_refused() {
        // Eleven 3-byte characters are 33 bytes, one more than a block holds.
        let text = "\u{20ac}".repeat(11);
        assert_eq!(
            Graffiti::parse(&text),
            Err(ApiError::bad_request(
                "graffiti of 33 bytes exceeds the 32 a block holds"
            ))
        );
    }
}
