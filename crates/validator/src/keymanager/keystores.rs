//! The local key routes: list, import, and delete EIP-2335 keystores.
//!
//! See `apis/local_keystores.yaml` and `flows/README.md` in the keymanager API repository.

use std::sync::Arc;

use axiom_beacon_json::{ApiJson, Fields};
use axiom_http::{Method, Request, Response, StatusCode};
use axiom_json::{Json, Object};
use axiom_types::BlsPubkey;
use tokio::task;

use crate::{
    keymanager::{
        registry::KeyRegistry,
        reply::{ApiError, ApiRequest, ApiResult, Reply, Routes},
        sealed::SealedKey,
        status::{DeleteStatus, ImportStatus},
    },
    keys::{Keystore, Password},
    protection::Interchange,
    signing::{Bls, LocalKey, ValidatorSigner},
};

/// The routes over keys decrypted into this process.
#[derive(Debug)]
pub(crate) struct LocalKeystores {
    /// The running keys and their directory.
    registry: Arc<KeyRegistry>,
}

impl LocalKeystores {
    /// The path every route of the group serves.
    const PATH: &'static str = "/eth/v1/keystores";

    /// The group over a registry.
    pub(crate) const fn new(registry: Arc<KeyRegistry>) -> Self {
        Self { registry }
    }

    /// Adds the group's routes.
    pub(crate) fn register(self, routes: Routes) -> Routes {
        let keys = Arc::new(self);
        routes
            .route(Method::Get, Self::PATH, &keys, |keys, _| async move {
                Ok(keys.list())
            })
            .route(
                Method::Post,
                Self::PATH,
                &keys,
                |keys, request| async move { keys.import(request).await },
            )
            .route(
                Method::Delete,
                Self::PATH,
                &keys,
                |keys, request| async move { keys.delete(&request) },
            )
    }

    /// Lists the local keys, each with its derivation path when its keystore records one.
    ///
    /// A key loaded from outside the key directory is read-only: the API cannot delete it.
    fn list(&self) -> Response {
        let directory = self.registry.directory();
        let data: Vec<Json> = self
            .registry
            .store()
            .pubkeys()
            .into_iter()
            .filter(|pubkey| self.is_local(pubkey))
            .map(|pubkey| {
                let mut entry = Object::new();
                entry.insert("validating_pubkey", pubkey.to_json());
                if let Some(path) = directory.derivation_path(&pubkey) {
                    entry.insert("derivation_path", Json::from(path.to_string()));
                }
                entry.insert("readonly", Json::from(!directory.holds_keystore(&pubkey)));
                Json::from(entry)
            })
            .collect();
        Reply::data(Json::from(data))
    }

    /// Imports keystores, each with its password and its slashing protection history.
    ///
    /// A malformed request changes nothing; a bad keystore fails only its own entry.
    ///
    /// # Invariants
    ///
    /// - Only the history of keys about to run is imported, as the keymanager API flow asks.
    /// - A key's history lands before the key can sign.
    /// - A key whose import fails part way has its files removed, so it never starts on a restart.
    async fn import(&self, request: Request) -> ApiResult {
        let body = ApiRequest::new(&request).json()?;
        let fields = Fields::of(&body)?;
        let keystores: Vec<String> = fields.required("keystores")?;
        let passwords: Vec<String> = fields.required("passwords")?;
        if keystores.len() != passwords.len() {
            return Err(ApiError::bad_request(format!(
                "{} keystores but {} passwords",
                keystores.len(),
                passwords.len()
            )));
        }
        let interchange = fields
            .optional::<String>("slashing_protection")?
            .map(|text| self.interchange(&text))
            .transpose()?;

        // Phase 1: parse every keystore; a malformed one fails alone.
        let mut sealed = Vec::new();
        let parsed: Vec<Result<(), String>> = keystores
            .iter()
            .zip(&passwords)
            .map(|(text, password)| {
                let keystore =
                    Keystore::parse(text).map_err(|error| format!("invalid keystore: {error}"))?;
                sealed.push(SealedKey::new(keystore, Password::new(password)));
                Ok(())
            })
            .collect();

        // Phase 2: decrypt away from the async workers, since a production KDF holds a core.
        let (sealed, opened) = task::spawn_blocking(move || {
            let opened = SealedKey::open_all(&sealed);
            (sealed, opened)
        })
        .await
        .map_err(|error| ApiError::internal(format!("keystore decryption stopped: {error}")))?;

        // Phase 3: admit the keys one by one, in request order.
        let _edit = self.registry.edit();
        let mut opened = opened.into_iter().zip(&sealed);
        let statuses: Vec<Json> = parsed
            .into_iter()
            .zip(&passwords)
            .map(|(parsed, password)| {
                let status = match parsed.map(|()| opened.next()) {
                    Err(message) => ImportStatus::Error(message),
                    Ok(Some((Ok(key), sealed))) => {
                        self.admit(sealed.keystore(), password, key, interchange.as_ref())
                    }
                    Ok(Some((Err(error), _))) => {
                        ImportStatus::Error(format!("cannot decrypt keystore: {error}"))
                    }
                    // Invariant: one decryption per parsed keystore, in order.
                    Ok(None) => ImportStatus::Error("keystore was not decrypted".to_owned()),
                };
                status.to_json()
            })
            .collect();
        Ok(Reply::data(Json::from(statuses)))
    }

    /// Deletes keys, returning the slashing protection history of every key it reports on.
    ///
    /// # Invariants
    ///
    /// - Each key stops signing before its files go and before its history is exported.
    /// - So the exported history holds every message the key signed here.
    /// - The history stays in the database, so a repeated request returns it again.
    fn delete(&self, request: &Request) -> ApiResult {
        let body = ApiRequest::new(request).json()?;
        let pubkeys: Vec<BlsPubkey> = Fields::of(&body)?.required("pubkeys")?;

        let _edit = self.registry.edit();
        let protection = self.registry.store().guard().protection();
        let statuses: Vec<DeleteStatus> = pubkeys
            .iter()
            .map(|pubkey| match self.remove(pubkey) {
                // A key that no longer runs here still has a history to hand over.
                DeleteStatus::NotFound
                    if protection.is_registered(pubkey)
                        && self.registry.signer(pubkey).is_none() =>
                {
                    DeleteStatus::NotActive
                }
                status => status,
            })
            .collect();

        // Only keys reported deleted or not active carry their history out.
        let exported: Vec<BlsPubkey> = pubkeys
            .iter()
            .zip(&statuses)
            .filter(|(_, status)| matches!(status, DeleteStatus::Deleted | DeleteStatus::NotActive))
            .map(|(pubkey, _)| *pubkey)
            .collect();
        let interchange = protection.export(Some(&exported));

        let data: Vec<Json> = statuses.iter().map(DeleteStatus::to_json).collect();
        let body = Json::from([
            ("data", Json::from(data)),
            (
                "slashing_protection",
                Json::from(interchange.to_json().to_string()),
            ),
        ]);
        Ok(Reply::json(StatusCode::OK, &body))
    }

    /// Reads an interchange, which must be for this chain.
    fn interchange(&self, text: &str) -> Result<Interchange, ApiError> {
        let interchange = Interchange::parse(text).map_err(|error| {
            ApiError::bad_request(format!("invalid slashing protection data: {error}"))
        })?;
        let expected = self
            .registry
            .store()
            .guard()
            .protection()
            .genesis_validators_root();
        if interchange.genesis_validators_root != expected {
            return Err(ApiError::bad_request(format!(
                "slashing protection data is for genesis validators root {}, not {expected}",
                interchange.genesis_validators_root
            )));
        }
        Ok(interchange)
    }

    /// Imports one decrypted key.
    fn admit(
        &self,
        keystore: &Keystore,
        password: &str,
        key: LocalKey<Bls>,
        interchange: Option<&Interchange>,
    ) -> ImportStatus {
        let pubkey = keystore.pubkey();
        if self.registry.store().contains(&pubkey) {
            return ImportStatus::Duplicate;
        }
        // The history lands before the key can sign, so its first signature already respects it.
        if let Some(interchange) = interchange {
            let own = Interchange {
                genesis_validators_root: interchange.genesis_validators_root,
                data: interchange
                    .data
                    .iter()
                    .filter(|history| history.pubkey == pubkey)
                    .cloned()
                    .collect(),
            };
            let protection = self.registry.store().guard().protection();
            if let Err(error) = protection.import(&own) {
                return ImportStatus::Error(format!("slashing protection data refused: {error}"));
            }
        }
        if let Err(error) = self.registry.directory().save_keystore(keystore, password) {
            return self.abandon(&pubkey, format!("cannot store keystore: {error}"));
        }
        match self.registry.run(ValidatorSigner::Local(key)) {
            Ok(_) => ImportStatus::Imported,
            Err(error) => self.abandon(&pubkey, format!("cannot start key: {error}")),
        }
    }

    /// Removes the files of a key whose import failed, so it never starts on a restart.
    fn abandon(&self, pubkey: &BlsPubkey, reason: String) -> ImportStatus {
        match self.registry.directory().remove_keystore(pubkey) {
            Ok(()) => ImportStatus::Error(reason),
            Err(error) => {
                ImportStatus::Error(format!("{reason}; its files could not be removed: {error}"))
            }
        }
    }

    /// Stops one local key and removes its files.
    fn remove(&self, pubkey: &BlsPubkey) -> DeleteStatus {
        if !self.is_local(pubkey) {
            return DeleteStatus::NotFound;
        }
        let directory = self.registry.directory();
        if !directory.holds_keystore(pubkey) {
            return DeleteStatus::Error(
                "read-only key: it was not loaded from the key directory".to_owned(),
            );
        }
        // Phase 1: the key stops signing before anything else changes.
        self.registry.store().remove(pubkey);
        // Phase 2: its files go, so it does not come back on a restart.
        match directory.remove_keystore(pubkey) {
            Ok(()) => DeleteStatus::Deleted,
            Err(error) => DeleteStatus::Error(format!(
                "key stopped, but its keystore could not be removed: {error}"
            )),
        }
    }

    /// Whether the store runs a key decrypted into this process.
    fn is_local(&self, pubkey: &BlsPubkey) -> bool {
        matches!(
            self.registry.signer(pubkey).as_deref(),
            Some(ValidatorSigner::Local(_))
        )
    }
}
