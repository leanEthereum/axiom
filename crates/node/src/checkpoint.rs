//! Checkpoint sync: a finalized block and its post-state, downloaded from a trusted beacon API.

use std::time::Duration;

use axiom_http::{Client, ClientConfig, Endpoint, Limits, Method, Request, StatusCode};
use axiom_ssz::Ssz;
use axiom_types::{
    ChainConfig, Preset, Root,
    accessors::CoreState,
    combined::{BeaconState, SignedBeaconBlock},
};
use thiserror::Error;

/// Largest state or block the download accepts.
///
/// A mainnet state weighs a few hundred megabytes and grows with the registry.
/// Two gigabytes leaves years of growth while still bounding a hostile server.
const MAX_DOWNLOAD_BYTES: usize = 2 << 30;

/// Longest wait for one download.
///
/// A mainnet state over a slow link takes minutes, not hours.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(600);

/// A beacon API trusted to serve the finalized checkpoint.
///
/// # Overview
///
/// The server is trusted: whatever it serves becomes the node's anchor.
/// So the operator should name one they run, or cross-check its answer.
/// A weak subjectivity checkpoint, when configured, then pins the chain the server gave.
///
/// 1. Download the finalized state.
/// 2. Derive its latest block's root from the state's latest block header.
/// 3. Download that block, and check it has that root.
/// 4. If the state was carried past the block through empty slots, download the block's own post-state.
///
/// The fork choice store needs the block and exactly its post-state.
/// See `get_forkchoice_store` in the phase0 fork choice spec.
#[derive(Debug)]
pub struct CheckpointServer {
    /// The client of the server.
    client: Client,
}

impl CheckpointServer {
    /// A server at a URL, such as `http://127.0.0.1:5052`.
    ///
    /// # Errors
    ///
    /// Fails when the URL is not a plain HTTP endpoint.
    pub fn new(url: &str) -> Result<Self, CheckpointError> {
        let endpoint = Endpoint::parse(url).map_err(|source| CheckpointError::Url {
            url: url.to_owned(),
            reason: source.to_string(),
        })?;
        let config = ClientConfig {
            request_timeout: DOWNLOAD_TIMEOUT,
            limits: Limits {
                max_body_bytes: MAX_DOWNLOAD_BYTES,
                ..Limits::DEFAULT
            },
            ..ClientConfig::default()
        };
        Ok(Self {
            client: Client::new(endpoint, config),
        })
    }

    /// Downloads the finalized block and its post-state.
    ///
    /// # Errors
    ///
    /// Fails when a download fails, a body does not decode, or the block and state disagree.
    pub async fn finalized<P: Preset>(
        &self,
        config: &ChainConfig,
    ) -> Result<(BeaconState<P>, SignedBeaconBlock<P>), CheckpointError> {
        let state = self.state::<P>("finalized", config).await?;

        // A block's post-state leaves its header's state root zero until the next slot fills it.
        let mut header = state.latest_block_header().clone();
        if header.state_root == Root::ZERO {
            header.state_root = state.hash_tree_root();
        }
        let root = header.hash_tree_root();
        let bytes = self
            .download(&format!("/eth/v2/beacon/blocks/{root}"))
            .await?;
        let block = SignedBeaconBlock::<P>::decode_at(&bytes, config).map_err(|error| {
            CheckpointError::Decode {
                what: "block",
                reason: error.to_string(),
            }
        })?;
        if block.block_root() != root {
            return Err(CheckpointError::Mismatch {
                expected: root,
                actual: block.block_root(),
            });
        }

        // An epoch-boundary state may sit past its block; the store wants the block's own state.
        if state.slot() == block.slot() {
            return Ok((state, block));
        }
        let state_root = block.message().state_root();
        let state = self.state::<P>(&format!("{state_root}"), config).await?;
        Ok((state, block))
    }

    /// Downloads the genesis state, which an archive needs to rebuild the states below the anchor.
    ///
    /// # Errors
    ///
    /// Fails when the download fails or the body does not decode.
    pub async fn genesis<P: Preset>(
        &self,
        config: &ChainConfig,
    ) -> Result<BeaconState<P>, CheckpointError> {
        self.state("genesis", config).await
    }

    /// Downloads a state by identifier.
    async fn state<P: Preset>(
        &self,
        id: &str,
        config: &ChainConfig,
    ) -> Result<BeaconState<P>, CheckpointError> {
        let bytes = self
            .download(&format!("/eth/v2/debug/beacon/states/{id}"))
            .await?;
        BeaconState::<P>::decode_at(&bytes, config).map_err(|error| CheckpointError::Decode {
            what: "state",
            reason: error.to_string(),
        })
    }

    /// Fetches a path as SSZ.
    async fn download(&self, path: &str) -> Result<Vec<u8>, CheckpointError> {
        let request =
            Request::new(Method::Get, path).with_header("accept", "application/octet-stream");
        let response =
            self.client
                .send(&request)
                .await
                .map_err(|error| CheckpointError::Request {
                    path: path.to_owned(),
                    reason: error.to_string(),
                })?;
        if response.status != StatusCode::OK {
            return Err(CheckpointError::Status {
                path: path.to_owned(),
                status: response.status.as_u16(),
            });
        }
        Ok(response.body)
    }
}

/// Why a checkpoint could not be downloaded.
#[derive(Debug, Error)]
pub enum CheckpointError {
    /// The URL is not a plain HTTP endpoint.
    #[error("checkpoint sync URL {url}: {reason}")]
    Url {
        /// The URL given.
        url: String,
        /// Why it is unusable.
        reason: String,
    },
    /// A request failed on the way.
    #[error("downloading {path}: {reason}")]
    Request {
        /// The path requested.
        path: String,
        /// The client's complaint.
        reason: String,
    },
    /// The server answered with an error status.
    #[error("downloading {path}: status {status}")]
    Status {
        /// The path requested.
        path: String,
        /// The status code.
        status: u16,
    },
    /// A body does not decode in the fork its slot falls in.
    #[error("downloaded {what} does not decode: {reason}")]
    Decode {
        /// What was downloaded.
        what: &'static str,
        /// The decoder's complaint.
        reason: String,
    },
    /// The block served is not the one the state names.
    #[error("downloaded block has root {actual}, but the state names {expected}")]
    Mismatch {
        /// The root the state names.
        expected: Root,
        /// The root of the block served.
        actual: Root,
    },
}
