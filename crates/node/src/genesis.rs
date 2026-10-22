//! A network's genesis state, from a file, from the binary, or from a beacon API.

use std::{
    fmt::{self, Debug},
    fs,
    path::PathBuf,
    time::Duration,
};

use axiom_snappy::frame;
use axiom_types::{
    ChainConfig, Epoch, Hash32, Preset, accessors::CoreState, combined::BeaconState,
};
use sha2::{Digest, Sha256};
use tracing::info;

use crate::{CheckpointError, CheckpointServer, NodeError};

/// Largest genesis state the binary embeds, decompressed.
///
/// The mainnet genesis state is 5.4 MB.
/// The bound only stops a corrupt frame from exhausting memory.
const MAX_EMBEDDED_BYTES: usize = 64 << 20;

/// Epochs cut from the blob retention window before a genesis sync is refused.
///
/// A sync started just inside the window would see the oldest blobs vanish from peers mid-way.
const BLOB_AVAILABILITY_MARGIN_EPOCHS: u64 = 2;

/// Where a network's genesis state comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GenesisState {
    /// An SSZ file.
    File(PathBuf),
    /// Snappy-framed SSZ compiled into the binary.
    Embedded(EmbeddedGenesis),
    /// A beacon API serving it, checked against the digest the network published.
    Download(GenesisDownload),
}

impl From<PathBuf> for GenesisState {
    fn from(path: PathBuf) -> Self {
        Self::File(path)
    }
}

impl GenesisState {
    /// Reads, decompresses, or downloads the state, and decodes it in the fork of its slot.
    ///
    /// # Errors
    ///
    /// - The source is unreadable.
    /// - A download misses its digest.
    /// - The bytes do not decode.
    pub async fn load<P: Preset>(&self, config: &ChainConfig) -> Result<BeaconState<P>, NodeError> {
        let (bytes, origin) = match self {
            Self::File(path) => {
                let bytes = fs::read(path).map_err(|error| NodeError::File {
                    context: "reading the genesis state",
                    path: path.clone(),
                    error,
                })?;
                (bytes, path.display().to_string())
            }
            Self::Embedded(embedded) => (embedded.decompress()?, embedded.network.to_owned()),
            Self::Download(download) => (download.fetch().await?, download.url.clone()),
        };
        BeaconState::<P>::decode_at(&bytes, config)
            .map_err(|source| NodeError::GenesisState { origin, source })
    }
}

/// A genesis state compiled into the binary as a snappy frame stream.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EmbeddedGenesis {
    /// The network the state starts.
    network: &'static str,
    /// The framed bytes, whose chunk checksums guard against corruption.
    framed: &'static [u8],
}

impl EmbeddedGenesis {
    /// A network's embedded genesis state.
    #[must_use]
    pub const fn new(network: &'static str, framed: &'static [u8]) -> Self {
        Self { network, framed }
    }

    /// The network the state starts.
    #[must_use]
    pub const fn network(&self) -> &'static str {
        self.network
    }

    /// The SSZ bytes, with every chunk checksum verified.
    fn decompress(self) -> Result<Vec<u8>, NodeError> {
        frame::decompress(self.framed, MAX_EMBEDDED_BYTES).map_err(|source| {
            NodeError::EmbeddedGenesis {
                network: self.network,
                source,
            }
        })
    }
}

impl Debug for EmbeddedGenesis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Megabytes of state bytes would drown a configuration dump, so only their size shows.
        f.debug_struct("EmbeddedGenesis")
            .field("network", &self.network)
            .field("framed_bytes", &self.framed.len())
            .finish()
    }
}

/// A genesis state to download from a beacon API, checked against a published digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisDownload {
    /// The beacon API, such as `http://127.0.0.1:5052`.
    pub url: String,
    /// SHA-256 of the SSZ state the network published.
    pub checksum: Hash32,
    /// Longest wait for the download.
    pub timeout: Duration,
}

impl GenesisDownload {
    /// Downloads the state and checks its digest.
    ///
    /// The digest pins the exact bytes, so the server needs no trust.
    async fn fetch(&self) -> Result<Vec<u8>, NodeError> {
        info!(url = %self.url, "downloading the genesis state");
        let server = CheckpointServer::new(&self.url, self.timeout)?;
        let bytes = server.genesis_bytes().await?;
        let actual = Hash32(Sha256::digest(&bytes).into());
        if actual != self.checksum {
            return Err(CheckpointError::Checksum {
                url: self.url.clone(),
                expected: self.checksum,
                actual,
            }
            .into());
        }
        Ok(bytes)
    }
}

/// Whether a node may sync from genesis, given how old the chain is.
///
/// # Overview
///
/// Peers serve blobs only for a bounded window of recent epochs.
/// A node syncing from genesis past that window cannot check data availability.
/// It would import blocks whose blobs nobody can serve, so it is refused.
///
/// The check runs only when Deneb is scheduled, since earlier blocks carry no blobs.
///
/// See `MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS` in the Deneb p2p spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GenesisSync {
    /// Whether the operator accepts the risk.
    pub(crate) allow_insecure: bool,
}

impl GenesisSync {
    /// Refuses a genesis sync whose Deneb blocks have aged out of the blob window.
    ///
    /// # Errors
    ///
    /// Fails when the window closed and the operator did not accept the risk.
    pub(crate) fn check<P: Preset>(
        self,
        genesis: &BeaconState<P>,
        config: &ChainConfig,
        now_ms: u64,
    ) -> Result<(), NodeError> {
        if self.allow_insecure || config.deneb_fork_epoch == Epoch::FAR_FUTURE {
            return Ok(());
        }
        let epoch_ms = P::SLOTS_PER_EPOCH.saturating_mul(config.slot_duration_ms);
        let deneb_ms = genesis
            .genesis_time()
            .saturating_mul(1000)
            .saturating_add(config.deneb_fork_epoch.0.saturating_mul(epoch_ms));
        let window = config
            .min_epochs_for_blob_sidecars_requests
            .saturating_sub(BLOB_AVAILABILITY_MARGIN_EPOCHS);
        // Threshold: the first Deneb blobs leave the window this long after the fork.
        let closes_ms = deneb_ms.saturating_add(window.saturating_mul(epoch_ms));
        if now_ms > closes_ms {
            return Err(NodeError::InsecureGenesisSync {
                closed_ms: closes_ms,
                now_ms,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::future;

    use axiom_http::{Method, Response, Router, Server, ServerConfig, StatusCode};
    use axiom_types::{Minimal, Slot, phase0};
    use tokio::{runtime::Builder, task};

    use super::*;

    /// A minimal genesis state at a genesis time.
    fn genesis(time: u64) -> BeaconState<Minimal> {
        BeaconState::Phase0(phase0::BeaconState::<Minimal> {
            genesis_time: time,
            slot: Slot(0),
            ..phase0::BeaconState::default()
        })
    }

    #[test]
    fn genesis_sync_closes_with_the_blob_window() {
        // Fixture state: 6 second slots and 8 slot epochs, so one epoch is 48000 ms.
        // Deneb at epoch 10 and a window of 4096 - 2 = 4094 epochs.
        let config = ChainConfig {
            slot_duration_ms: 6000,
            deneb_fork_epoch: Epoch(10),
            ..ChainConfig::minimal()
        };
        let state = genesis(1000);

        //     deneb  = 1000 * 1000 + 10 * 48000   = 1480000
        //     closes = 1480000 + 4094 * 48000     = 197992000
        let strict = GenesisSync {
            allow_insecure: false,
        };
        assert!(strict.check(&state, &config, 197_992_000).is_ok());
        assert!(matches!(
            strict.check(&state, &config, 197_992_001),
            Err(NodeError::InsecureGenesisSync {
                closed_ms: 197_992_000,
                now_ms: 197_992_001,
            })
        ));

        // Accepting the risk lifts the refusal.
        let lenient = GenesisSync {
            allow_insecure: true,
        };
        assert!(lenient.check(&state, &config, u64::MAX).is_ok());
    }

    #[test]
    fn a_chain_without_deneb_has_no_blob_window() {
        // The minimal configuration never reaches Deneb.
        let strict = GenesisSync {
            allow_insecure: false,
        };
        assert!(
            strict
                .check(&genesis(0), &ChainConfig::minimal(), u64::MAX)
                .is_ok()
        );
    }

    #[test]
    fn embedded_states_decompress_or_name_their_network() {
        // A framed stream round-trips; a stream cut after its identifier fails.
        let bytes: Vec<u8> = (0..200_u8).collect();
        let framed: &'static [u8] = Vec::leak(frame::compress(&bytes));
        assert_eq!(
            EmbeddedGenesis::new("devnet", framed).decompress().unwrap(),
            bytes
        );
        let cut = &framed[..framed.len() - 1];
        assert!(matches!(
            EmbeddedGenesis::new("devnet", cut).decompress(),
            Err(NodeError::EmbeddedGenesis {
                network: "devnet",
                ..
            })
        ));
    }

    #[test]
    fn a_download_must_match_the_published_digest() {
        // Fixture state: a server answering the genesis route with a minimal phase0 state.
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let state = genesis(1_606_824_023);
        let bytes = state.encode();
        let checksum = Hash32(Sha256::digest(&bytes).into());
        let router =
            Router::new().route(
                Method::Get,
                "/eth/v2/debug/beacon/states/genesis",
                move |_| {
                    let body = bytes.clone();
                    async move {
                        Response::new(StatusCode::OK).with_body("application/octet-stream", body)
                    }
                },
            );

        runtime.block_on(async {
            let server = Server::bind("127.0.0.1:0", router, ServerConfig::default())
                .await
                .unwrap();
            let url = format!("http://{}", server.local_addr().unwrap());
            let serving = task::spawn(server.serve(future::pending()));
            let download = |checksum| {
                GenesisState::Download(GenesisDownload {
                    url: url.clone(),
                    checksum,
                    timeout: Duration::from_secs(5),
                })
            };

            // The published digest admits the state, decoded whole.
            let config = ChainConfig::minimal();
            let loaded = download(checksum).load::<Minimal>(&config).await.unwrap();
            assert_eq!(loaded, state);

            // One flipped digest bit refuses the same bytes, naming both digests.
            let mut wrong = checksum;
            wrong.0[0] ^= 1;
            let refused = download(wrong).load::<Minimal>(&config).await;
            assert!(matches!(
                refused,
                Err(NodeError::Checkpoint(CheckpointError::Checksum { expected, actual, .. }))
                    if expected == wrong && actual == checksum
            ));
            serving.abort();
        });
    }

    #[test]
    fn embedded_states_print_their_size_not_their_bytes() {
        let embedded = EmbeddedGenesis::new("devnet", &[1, 2, 3]);
        assert_eq!(
            format!("{embedded:?}"),
            "EmbeddedGenesis { network: \"devnet\", framed_bytes: 3 }"
        );
    }
}
