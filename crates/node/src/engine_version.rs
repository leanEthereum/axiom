//! The execution client's identity, asked of the engine and kept for a while.

use std::{
    sync::{Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use axiom_execution::{ClientVersion, EngineClient};
use tracing::{debug, warn};

use crate::client_version;

/// How long an answer stays fresh: about six mainnet epochs.
///
/// An execution client changes version only on restart, which is rare.
/// Block production reads the identity, so a fresh answer spares it a round trip.
const MAX_AGE: Duration = Duration::from_secs(6 * 32 * 12);

/// The last identities the engine gave, and when.
#[derive(Debug, Default)]
pub(crate) struct EngineVersions {
    /// The identities, with the moment they arrived.
    cached: Mutex<Option<(Instant, Vec<ClientVersion>)>>,
}

impl EngineVersions {
    /// The engine's identity, when exactly one execution client answers.
    ///
    /// A list of several comes from a multiplexer, which speaks for no single client.
    /// An empty list comes from an engine that does not implement the method.
    /// See `src/engine/identification.md`.
    pub(crate) async fn single(&self, engine: &EngineClient) -> Option<ClientVersion> {
        let versions = self.current(engine).await?;
        match versions.as_slice() {
            [version] => Some(version.clone()),
            [] => {
                debug!("engine does not report its client version");
                None
            }
            _ => {
                warn!(
                    count = versions.len(),
                    "engine multiplexer reports several client versions"
                );
                None
            }
        }
    }

    /// The cached identities, or fresh ones when the cache is empty or stale.
    async fn current(&self, engine: &EngineClient) -> Option<Vec<ClientVersion>> {
        if let Some(versions) = self.fresh(Instant::now()) {
            return Some(versions);
        }
        match engine.client_version(&client_version::ours()).await {
            Ok(versions) => {
                *self.cache() = Some((Instant::now(), versions.clone()));
                Some(versions)
            }
            Err(error) => {
                debug!(%error, "engine did not report its client version");
                None
            }
        }
    }

    /// The cached identities, if they arrived less than the maximum age before a moment.
    fn fresh(&self, now: Instant) -> Option<Vec<ClientVersion>> {
        self.cache()
            .as_ref()
            .filter(|(at, _)| now.saturating_duration_since(*at) < MAX_AGE)
            .map(|(_, versions)| versions.clone())
    }

    /// The cache, recovered from a panic in another holder since it holds plain data.
    fn cache(&self) -> MutexGuard<'_, Option<(Instant, Vec<ClientVersion>)>> {
        self.cached.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_versions_expire_after_six_epochs() {
        // Fixture state: one identity cached at a moment.
        let versions = EngineVersions::default();
        let at = Instant::now();
        let geth = ClientVersion {
            code: "GE".to_owned(),
            name: "go-ethereum".to_owned(),
            version: "v1.14.0".to_owned(),
            commit: [0xfa, 0x4f, 0xf9, 0x22],
        };
        *versions.cache() = Some((at, vec![geth.clone()]));

        // Just under 2304 seconds later it is fresh; at 2304 it is stale.
        assert_eq!(
            versions.fresh(at + Duration::from_secs(6 * 32 * 12 - 1)),
            Some(vec![geth])
        );
        assert_eq!(versions.fresh(at + MAX_AGE), None);
    }
}
