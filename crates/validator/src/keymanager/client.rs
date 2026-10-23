//! A client of a validator client's keymanager API, for the commands that manage its keys.
//!
//! See the `ethereum/keymanager-APIs` repository for every route.

use axiom_beacon_json::{ApiJson, Fields};
use axiom_http::{Client, ClientConfig, Endpoint, Method, Request, StatusCode};
use axiom_json::{Json, Object};
use axiom_types::{BlsPubkey, ExecutionAddress};

use crate::keymanager::{DeleteStatus, ImportStatus, KeymanagerClientError};

/// Media type of JSON bodies.
const JSON: &str = "application/json";

/// A key a validator client lists, local or remote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedKey {
    /// The key.
    pub pubkey: BlsPubkey,
    /// The remote signer holding it, for a remote key.
    pub url: Option<String>,
    /// Whether the API may not delete it, as for a key given on the command line.
    pub readonly: bool,
}

/// The keymanager API of one validator client, behind its bearer token.
#[derive(Debug)]
pub struct KeymanagerClient {
    /// The HTTP client.
    http: Client,
    /// The bearer token.
    token: String,
}

impl KeymanagerClient {
    /// Path of the local key routes.
    const KEYSTORES: &'static str = "/eth/v1/keystores";

    /// Path of the remote key routes.
    const REMOTE_KEYS: &'static str = "/eth/v1/remotekeys";

    /// A client of the API at a URL, with its token.
    ///
    /// # Errors
    ///
    /// Fails when the URL is not an http or https URL.
    pub fn new(url: &str, token: &str) -> Result<Self, KeymanagerClientError> {
        Ok(Self {
            http: Client::new(Endpoint::parse(url)?, ClientConfig::default()),
            token: token.trim().to_owned(),
        })
    }

    /// The local keys.
    ///
    /// # Errors
    ///
    /// Fails when the client refuses or answers malformed data.
    pub async fn keystores(&self) -> Result<Vec<ListedKey>, KeymanagerClientError> {
        let json = self.send(Method::Get, Self::KEYSTORES, None).await?;
        Self::items(&json)?
            .iter()
            .map(|item| {
                let fields = Fields::of(item)?;
                Ok(ListedKey {
                    pubkey: fields.required("validating_pubkey")?,
                    url: None,
                    readonly: fields.optional("readonly")?.unwrap_or(false),
                })
            })
            .collect()
    }

    /// The remote keys, with their signers.
    ///
    /// # Errors
    ///
    /// Fails when the client refuses or answers malformed data.
    pub async fn remote_keys(&self) -> Result<Vec<ListedKey>, KeymanagerClientError> {
        let json = self.send(Method::Get, Self::REMOTE_KEYS, None).await?;
        Self::items(&json)?
            .iter()
            .map(|item| {
                let fields = Fields::of(item)?;
                Ok(ListedKey {
                    pubkey: fields.required("pubkey")?,
                    url: Some(fields.required("url")?),
                    readonly: fields.optional("readonly")?.unwrap_or(false),
                })
            })
            .collect()
    }

    /// Imports keystores with their passwords and, optionally, their slashing protection history.
    ///
    /// # Errors
    ///
    /// Fails when the client refuses the request as a whole or answers malformed data.
    pub async fn import_keystores(
        &self,
        keystores: &[String],
        passwords: &[String],
        slashing_protection: Option<&str>,
    ) -> Result<Vec<ImportStatus>, KeymanagerClientError> {
        let strings = |items: &[String]| {
            Json::from(
                items
                    .iter()
                    .map(|item| Json::from(item.as_str()))
                    .collect::<Vec<_>>(),
            )
        };
        let mut body = Object::new();
        body.insert("keystores", strings(keystores));
        body.insert("passwords", strings(passwords));
        if let Some(history) = slashing_protection {
            body.insert("slashing_protection", Json::from(history));
        }
        let json = self
            .send(Method::Post, Self::KEYSTORES, Some(&Json::from(body)))
            .await?;
        Self::statuses(&json, ImportStatus::from_json)
    }

    /// Deletes local keys, returning each outcome and their slashing protection interchange.
    ///
    /// # Errors
    ///
    /// Fails when the client refuses the request as a whole or answers malformed data.
    pub async fn delete_keystores(
        &self,
        pubkeys: &[BlsPubkey],
    ) -> Result<(Vec<DeleteStatus>, String), KeymanagerClientError> {
        let body = Json::from([("pubkeys", pubkeys.to_vec().to_json())]);
        let json = self
            .send(Method::Delete, Self::KEYSTORES, Some(&body))
            .await?;
        let statuses = Self::statuses(&json, DeleteStatus::from_json)?;
        let interchange: String = Fields::of(&json)?.required("slashing_protection")?;
        Ok((statuses, interchange))
    }

    /// Imports remote keys, each with its signer's URL.
    ///
    /// # Errors
    ///
    /// Fails when the client refuses the request as a whole or answers malformed data.
    pub async fn import_remote_keys(
        &self,
        keys: &[(BlsPubkey, String)],
    ) -> Result<Vec<ImportStatus>, KeymanagerClientError> {
        let keys: Vec<Json> = keys
            .iter()
            .map(|(pubkey, url)| {
                Json::from([
                    ("pubkey", pubkey.to_json()),
                    ("url", Json::from(url.as_str())),
                ])
            })
            .collect();
        let body = Json::from([("remote_keys", Json::from(keys))]);
        let json = self
            .send(Method::Post, Self::REMOTE_KEYS, Some(&body))
            .await?;
        Self::statuses(&json, ImportStatus::from_json)
    }

    /// Deletes remote keys.
    ///
    /// # Errors
    ///
    /// Fails when the client refuses the request as a whole or answers malformed data.
    pub async fn delete_remote_keys(
        &self,
        pubkeys: &[BlsPubkey],
    ) -> Result<Vec<DeleteStatus>, KeymanagerClientError> {
        let body = Json::from([("pubkeys", pubkeys.to_vec().to_json())]);
        let json = self
            .send(Method::Delete, Self::REMOTE_KEYS, Some(&body))
            .await?;
        Self::statuses(&json, DeleteStatus::from_json)
    }

    /// The fee recipient a validator's proposals pay.
    ///
    /// # Errors
    ///
    /// Fails when the client refuses or answers malformed data.
    pub async fn fee_recipient(
        &self,
        pubkey: &BlsPubkey,
    ) -> Result<ExecutionAddress, KeymanagerClientError> {
        let json = self
            .send(
                Method::Get,
                &format!("/eth/v1/validator/{pubkey}/feerecipient"),
                None,
            )
            .await?;
        Ok(Fields::of(Self::data(&json)?)?.required("ethaddress")?)
    }

    /// Overrides a validator's fee recipient.
    ///
    /// # Errors
    ///
    /// Fails when the client refuses the address.
    pub async fn set_fee_recipient(
        &self,
        pubkey: &BlsPubkey,
        address: ExecutionAddress,
    ) -> Result<(), KeymanagerClientError> {
        let body = Json::from([("ethaddress", address.to_json())]);
        let target = format!("/eth/v1/validator/{pubkey}/feerecipient");
        self.send(Method::Post, &target, Some(&body)).await?;
        Ok(())
    }

    /// The gas limit a validator asks for.
    ///
    /// # Errors
    ///
    /// Fails when the client refuses or answers malformed data.
    pub async fn gas_limit(&self, pubkey: &BlsPubkey) -> Result<u64, KeymanagerClientError> {
        let json = self
            .send(
                Method::Get,
                &format!("/eth/v1/validator/{pubkey}/gas_limit"),
                None,
            )
            .await?;
        Ok(Fields::of(Self::data(&json)?)?.required("gas_limit")?)
    }

    /// Overrides a validator's gas limit.
    ///
    /// # Errors
    ///
    /// Fails when the client refuses the limit.
    pub async fn set_gas_limit(
        &self,
        pubkey: &BlsPubkey,
        gas_limit: u64,
    ) -> Result<(), KeymanagerClientError> {
        let body = Json::from([("gas_limit", gas_limit.to_json())]);
        let target = format!("/eth/v1/validator/{pubkey}/gas_limit");
        self.send(Method::Post, &target, Some(&body)).await?;
        Ok(())
    }

    /// Sends a request with the token, returning the JSON body, or null for an empty one.
    async fn send(
        &self,
        method: Method,
        target: &str,
        body: Option<&Json>,
    ) -> Result<Json, KeymanagerClientError> {
        let mut request = Request::new(method, target)
            .with_header("accept", JSON)
            .with_header("authorization", format!("Bearer {}", self.token));
        if let Some(body) = body {
            request = request.with_body(JSON, body.to_string().into_bytes());
        }
        let response = self.http.send(&request).await?;
        if !response.status.is_success() {
            return Err(KeymanagerClientError::from_reply(
                response.status,
                &response.body,
            ));
        }
        if response.body.is_empty() || response.status == StatusCode::NO_CONTENT {
            return Ok(Json::Null);
        }
        Ok(Json::parse(&response.body)?)
    }

    /// The data member of an answer.
    fn data(json: &Json) -> Result<&Json, KeymanagerClientError> {
        Ok(Fields::of(json)?.raw("data")?)
    }

    /// The items of an answer's data list.
    fn items(json: &Json) -> Result<&[Json], KeymanagerClientError> {
        Self::data(json)?
            .as_array()
            .ok_or(KeymanagerClientError::Shape("data is not a list"))
    }

    /// Every status of an answer's data list.
    fn statuses<T>(
        json: &Json,
        read: impl Fn(&Json) -> Result<T, KeymanagerClientError>,
    ) -> Result<Vec<T>, KeymanagerClientError> {
        Self::items(json)?.iter().map(read).collect()
    }
}
