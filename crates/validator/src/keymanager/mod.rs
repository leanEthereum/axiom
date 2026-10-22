//! The keymanager API: key management over HTTP, behind a bearer token.
//!
//! # Overview
//!
//! An operator adds and removes keys, and tunes each validator, while the client runs.
//! See the `ethereum/keymanager-APIs` repository for every route.
//!
//! - Local keys arrive as EIP-2335 keystores with their passwords and slashing protection history.
//! - Remote keys name the remote signer that holds them.
//! - Fee recipient, gas limit, and graffiti override the client's defaults per validator.
//! - A voluntary exit is signed on request, for the operator to submit.
//!
//! - A builder configuration names the builders a Gloas proposal asks for bids.
//!
//! Every change reaches the key directory's definitions, so it survives a restart.
//!
//! # Invariants
//!
//! A deleted key stops signing before its slashing protection history is exported.
//! So the exported history covers every message the key signed here.

mod auth;
mod client;
mod client_error;
mod definitions;
mod directory;
mod error;
mod exit;
mod keystores;
mod registry;
mod remote;
mod reply;
mod sealed;
mod settings;
mod status;

use std::{io, marker::PhantomData, net::SocketAddr, sync::Arc};

use axiom_http::{Cors, Router, Server, ServerConfig};
use axiom_types::Preset;
pub use client::{KeymanagerClient, ListedKey};
pub use client_error::KeymanagerClientError;
pub use definitions::{Definitions, SignerKind, ValidatorDefinition};
pub use directory::{KeyDirectory, KeySource, LoadedKey};
pub use error::{DefinitionsError, DirectoryError};
pub use status::{DeleteStatus, ImportStatus};

use self::{
    auth::ApiToken, exit::ExitSigner, keystores::LocalKeystores, registry::KeyRegistry,
    remote::RemoteKeys, reply::Routes, settings::ProposerOverrides,
};
use crate::{duties::SlotTimer, validators::ValidatorStore};

/// The keymanager API server of one validator client.
#[derive(Debug)]
pub struct Keymanager<P: Preset> {
    /// The validators the client runs.
    store: Arc<ValidatorStore>,
    /// Where keys persist across restarts.
    directory: Arc<KeyDirectory>,
    /// The token every request must carry.
    token: ApiToken,
    /// The wall clock, through the slot schedule.
    timer: SlotTimer,
    /// Whether a new key may sign at once; doppelganger detection holds it back instead.
    signs_at_once: bool,
    /// The preset the chain uses.
    preset: PhantomData<P>,
}

impl<P: Preset> Keymanager<P> {
    /// A server over the client's validators, its key directory, and its token.
    ///
    /// With doppelganger detection on, keys added through the API start disabled.
    /// Detection then enables them once it sees no other instance of them signing.
    #[must_use]
    pub fn new(
        store: Arc<ValidatorStore>,
        directory: Arc<KeyDirectory>,
        token: &str,
        timer: SlotTimer,
        doppelganger: bool,
    ) -> Self {
        Self {
            store,
            directory,
            token: ApiToken::new(token),
            timer,
            signs_at_once: !doppelganger,
            preset: PhantomData,
        }
    }

    /// The router serving every route, each behind the token.
    #[must_use]
    pub fn router(self) -> Router {
        let Self {
            store,
            directory,
            token,
            timer,
            signs_at_once,
            preset: _,
        } = self;
        let registry = Arc::new(KeyRegistry::new(
            Arc::clone(&store),
            directory,
            signs_at_once,
        ));
        let routes = Routes::new(token);
        let routes = LocalKeystores::new(Arc::clone(&registry)).register(routes);
        let routes = RemoteKeys::new(Arc::clone(&registry)).register(routes);
        let routes = ProposerOverrides::new(registry).register(routes);
        ExitSigner::<P>::new(store, timer).register(routes).finish()
    }

    /// Binds the server to an address; port zero picks a free port.
    ///
    /// Browser pages at the policy's origin may call it, sending the token in their requests.
    /// The caller serves it until a shutdown future completes.
    ///
    /// # Errors
    ///
    /// Fails when the address cannot be bound.
    pub async fn bind(self, address: SocketAddr, cors: Cors) -> io::Result<Server> {
        let router = self.router().with_cors(cors.with_header("authorization"));
        Server::bind(address, router, ServerConfig::default()).await
    }
}
