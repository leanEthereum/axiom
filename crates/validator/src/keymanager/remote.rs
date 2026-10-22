//! The remote key routes: list, import, and delete keys a remote signer holds.
//!
//! See `apis/remote_keystores.yaml` in the keymanager API repository.

use std::{collections::BTreeMap, sync::Arc};

use axiom_beacon_json::{ApiJson, ApiJsonError, Fields};
use axiom_http::{Client, ClientConfig, Endpoint, Method, Request};
use axiom_json::Json;
use axiom_types::BlsPubkey;

use crate::{
    keymanager::{
        registry::KeyRegistry,
        reply::{ApiError, ApiRequest, ApiResult, Reply, Routes},
        status::{DeleteStatus, ImportStatus},
    },
    signing::{RemoteSigner, ValidatorSigner},
};

/// One key of an import request, with the signer that holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RemoteKey {
    /// The key.
    pubkey: BlsPubkey,
    /// The signer's URL, when given.
    url: Option<String>,
}

impl ApiJson for RemoteKey {
    fn to_json(&self) -> Json {
        Json::from([
            ("pubkey", self.pubkey.to_json()),
            ("url", Json::from(self.url.clone())),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            pubkey: fields.required("pubkey")?,
            url: fields.optional("url")?,
        })
    }
}

/// The routes over keys a remote signer holds.
#[derive(Debug)]
pub(crate) struct RemoteKeys {
    /// The running keys and their directory.
    registry: Arc<KeyRegistry>,
}

impl RemoteKeys {
    /// The path every route of the group serves.
    const PATH: &'static str = "/eth/v1/remotekeys";

    /// The group over a registry.
    pub(crate) const fn new(registry: Arc<KeyRegistry>) -> Self {
        Self { registry }
    }

    /// Adds the group's routes.
    pub(crate) fn register(self, routes: Routes) -> Routes {
        let keys = Arc::new(self);
        routes
            .route(Method::Get, Self::PATH, &keys, |keys, _| async move {
                keys.list()
            })
            .route(
                Method::Post,
                Self::PATH,
                &keys,
                |keys, request| async move { keys.import(&request) },
            )
            .route(
                Method::Delete,
                Self::PATH,
                &keys,
                |keys, request| async move { keys.delete(&request) },
            )
    }

    /// Lists the remote keys with their signers.
    ///
    /// A key loaded from outside the key directory is read-only: the API cannot delete it.
    fn list(&self) -> ApiResult {
        let recorded = self
            .registry
            .directory()
            .remotes()
            .map_err(|error| ApiError::internal(format!("cannot read remote keys: {error}")))?;
        let data: Vec<Json> = self
            .registry
            .store()
            .pubkeys()
            .into_iter()
            .filter_map(|pubkey| {
                let signer = self.registry.signer(&pubkey)?;
                let ValidatorSigner::Remote(remote) = signer.as_ref() else {
                    return None;
                };
                let url = recorded.get(&pubkey).cloned();
                let readonly = url.is_none();
                Some(Json::from([
                    ("pubkey", pubkey.to_json()),
                    ("url", Json::from(url.unwrap_or_else(|| remote.url()))),
                    ("readonly", Json::from(readonly)),
                ]))
            })
            .collect();
        Ok(Reply::data(Json::from(data)))
    }

    /// Imports remote keys, each signing through its signer from then on.
    fn import(&self, request: &Request) -> ApiResult {
        let body = ApiRequest::new(request).json()?;
        let keys: Vec<RemoteKey> = Fields::of(&body)?.required("remote_keys")?;

        let _edit = self.registry.edit();
        // Keys behind one signer share one client, so they share its connections.
        let mut clients: BTreeMap<String, Arc<Client>> = BTreeMap::new();
        let statuses: Vec<Json> = keys
            .iter()
            .map(|key| self.admit(key, &mut clients).to_json())
            .collect();
        Ok(Reply::data(Json::from(statuses)))
    }

    /// Deletes remote keys.
    fn delete(&self, request: &Request) -> ApiResult {
        let body = ApiRequest::new(request).json()?;
        let pubkeys: Vec<BlsPubkey> = Fields::of(&body)?.required("pubkeys")?;

        let _edit = self.registry.edit();
        let data: Vec<Json> = pubkeys
            .iter()
            .map(|pubkey| self.remove(pubkey).to_json())
            .collect();
        Ok(Reply::data(Json::from(data)))
    }

    /// Imports one remote key.
    fn admit(&self, key: &RemoteKey, clients: &mut BTreeMap<String, Arc<Client>>) -> ImportStatus {
        if self.registry.store().contains(&key.pubkey) {
            return ImportStatus::Duplicate;
        }
        let Some(url) = &key.url else {
            return ImportStatus::Error("no remote signer URL given".to_owned());
        };
        let client = match clients.get(url) {
            Some(client) => Arc::clone(client),
            None => match Endpoint::parse(url) {
                Ok(endpoint) => {
                    let client = Arc::new(Client::new(endpoint, ClientConfig::default()));
                    clients.insert(url.clone(), Arc::clone(&client));
                    client
                }
                Err(error) => {
                    return ImportStatus::Error(format!(
                        "remote signer URL {url:?} is not a plain http URL: {error}"
                    ));
                }
            },
        };
        let directory = self.registry.directory();
        if let Err(error) = directory.save_remote(key.pubkey, url) {
            return ImportStatus::Error(format!("cannot store remote key: {error}"));
        }
        let signer = ValidatorSigner::Remote(RemoteSigner::new(client, key.pubkey));
        match self.registry.run(signer) {
            Ok(_) => ImportStatus::Imported,
            // The record goes too, so the key does not start on a restart.
            Err(error) => match directory.remove_remote(&key.pubkey) {
                Ok(_) => ImportStatus::Error(format!("cannot start key: {error}")),
                Err(cleanup) => ImportStatus::Error(format!(
                    "cannot start key: {error}; its record could not be removed: {cleanup}"
                )),
            },
        }
    }

    /// Stops one remote key and forgets it.
    fn remove(&self, pubkey: &BlsPubkey) -> DeleteStatus {
        let remote = matches!(
            self.registry.signer(pubkey).as_deref(),
            Some(ValidatorSigner::Remote(_))
        );
        if !remote {
            return DeleteStatus::NotFound;
        }
        let directory = self.registry.directory();
        match directory.remotes() {
            Ok(recorded) if recorded.contains_key(pubkey) => {}
            Ok(_) => {
                return DeleteStatus::Error(
                    "read-only key: it was not loaded from the key directory".to_owned(),
                );
            }
            Err(error) => {
                return DeleteStatus::Error(format!("cannot read remote keys: {error}"));
            }
        }
        // Phase 1: the key stops signing before anything else changes.
        self.registry.store().remove(pubkey);
        // Phase 2: its record goes, so it does not come back on a restart.
        match directory.remove_remote(pubkey) {
            Ok(_) => DeleteStatus::Deleted,
            Err(error) => DeleteStatus::Error(format!(
                "key stopped, but its record could not be removed: {error}"
            )),
        }
    }
}
