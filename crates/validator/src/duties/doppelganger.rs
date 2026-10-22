//! Doppelganger detection: a new key waits, watching for another instance of itself, before it signs.

use std::{
    collections::BTreeMap,
    sync::{Mutex, PoisonError},
};

use axiom_types::{BlsPubkey, Epoch, Preset, ValidatorIndex};
use tracing::{error, info, warn};

use crate::duties::DutyContext;

/// Where a watched key stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Watch {
    /// Watching since an epoch.
    Since(Epoch),
    /// Seen live elsewhere: the key never signs in this process.
    Detected,
}

/// Holds new keys back until the network shows no other instance of them.
///
/// # Overview
///
/// Two clients running one key will sign conflicting messages and be slashed.
/// Slashing protection cannot see the other client's records, so liveness is the only signal.
///
/// A new key stays disabled while it is watched.
/// Each epoch, the beacon node reports whether the key was live in the previous epoch.
/// Since this client signed nothing with it, any liveness comes from another instance.
///
/// After the configured number of full epochs without a sighting, the key may sign.
/// A sighting keeps it disabled for the life of the process, and is logged as an error.
#[derive(Debug)]
pub struct Doppelganger<P: Preset> {
    /// What the detector reaches.
    context: DutyContext<P>,
    /// Watched keys.
    watched: Mutex<BTreeMap<BlsPubkey, Watch>>,
}

impl<P: Preset> Doppelganger<P> {
    /// A detector over a context, watching nothing yet.
    #[must_use]
    pub const fn new(context: DutyContext<P>) -> Self {
        Self {
            context,
            watched: Mutex::new(BTreeMap::new()),
        }
    }

    /// Starts watching every disabled key not yet watched, from an epoch.
    pub fn watch_new(&self, epoch: Epoch) {
        let mut watched = self.watched.lock().unwrap_or_else(PoisonError::into_inner);
        for pubkey in self.context.store.disabled() {
            watched.entry(pubkey).or_insert(Watch::Since(epoch));
        }
    }

    /// Checks the previous epoch's liveness, and enables keys that waited long enough.
    pub async fn check(&self, epoch: Epoch) {
        let epochs = self.context.settings.doppelganger_epochs;
        let store = &self.context.store;
        let indices: BTreeMap<BlsPubkey, ValidatorIndex> = store
            .indices()
            .into_iter()
            .map(|(index, pubkey)| (pubkey, index))
            .collect();
        let watching: Vec<(BlsPubkey, Epoch)> = self
            .watched
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter_map(|(pubkey, watch)| match watch {
                Watch::Since(since) => Some((*pubkey, *since)),
                Watch::Detected => None,
            })
            .collect();
        if watching.is_empty() {
            return;
        }

        // Liveness of the previous epoch, for watched keys with a known index.
        let previous = Epoch(epoch.0.saturating_sub(1));
        let asked: Vec<ValidatorIndex> = watching
            .iter()
            .filter(|(_, since)| previous >= *since)
            .filter_map(|(pubkey, _)| indices.get(pubkey).copied())
            .collect();
        let live = if asked.is_empty() {
            Vec::new()
        } else {
            let asked = &asked;
            match self
                .context
                .nodes
                .first(|client| async move { client.validator().liveness(previous, asked).await })
                .await
            {
                Ok(liveness) => liveness,
                Err(error) => {
                    // No answer is no evidence: the keys stay disabled and the watch goes on.
                    warn!(epoch = previous.0, %error, "liveness unavailable");
                    return;
                }
            }
        };

        let mut watched = self.watched.lock().unwrap_or_else(PoisonError::into_inner);
        for (pubkey, since) in watching {
            let Some(index) = indices.get(&pubkey) else {
                continue;
            };
            if live
                .iter()
                .any(|entry| entry.index == *index && entry.is_live)
            {
                error!(
                    validator = index.0,
                    "doppelganger detected: another client signs with this key"
                );
                watched.insert(pubkey, Watch::Detected);
                continue;
            }
            // Enabled once the configured number of full epochs passed unseen.
            if epoch.0 > since.0 + epochs {
                info!(validator = index.0, "no doppelganger seen; signing enabled");
                store.set_enabled(&pubkey, true);
                watched.remove(&pubkey);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use axiom_beacon_json::{ApiJson, api::Liveness};
    use axiom_bls::SecretKey;
    use axiom_http::{ClientConfig, Method, Response, Router, Server, ServerConfig, StatusCode};
    use axiom_json::Json;
    use axiom_node::ManualClock;
    use axiom_types::{ChainConfig, Minimal, Root, SlotClock};
    use tokio::{runtime::Builder, sync::oneshot, task};

    use super::*;
    use crate::{
        beacon::{BeaconClient, BeaconNodes},
        duties::{ClientSettings, SlotTimer},
        protection::SlashingDatabase,
        signing::{Bls, LocalKey, SigningContext, SigningGuard, ValidatorSigner},
        validators::{ProposerDefaults, ValidatorStore},
    };

    /// A beacon node whose liveness route reports validator 1 live, and every other one silent.
    fn liveness_node() -> Router {
        Router::new().route(
            Method::Post,
            "/eth/v1/validator/liveness/{epoch}",
            |request| async move {
                let indices =
                    Vec::<ValidatorIndex>::from_json(&Json::parse(&request.body).unwrap()).unwrap();
                let liveness: Vec<Liveness> = indices
                    .into_iter()
                    .map(|index| Liveness {
                        index,
                        is_live: index == ValidatorIndex(1),
                    })
                    .collect();
                let body = Json::from([("data", liveness.to_json())]);
                Response::new(StatusCode::OK)
                    .with_body("application/json", body.to_string().into_bytes())
            },
        )
    }

    #[test]
    fn a_key_seen_elsewhere_stays_disabled_and_the_rest_wait_out_the_watch() {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                // Fixture state: validators 1 and 2, both disabled, and a node that sees 1 live.
                let server = Server::bind("127.0.0.1:0", liveness_node(), ServerConfig::default())
                    .await
                    .unwrap();
                let url = format!("http://{}", server.local_addr().unwrap());
                let (stop, stopped) = oneshot::channel::<()>();
                let serving = task::spawn(server.serve(async {
                    let _stopped = stopped.await;
                }));
                let config = ClientConfig {
                    request_timeout: Duration::from_secs(5),
                    ..ClientConfig::default()
                };
                let nodes =
                    BeaconNodes::new(vec![BeaconClient::new(&url, config).unwrap()]).unwrap();
                let context = SigningContext::new(Arc::new(ChainConfig::minimal()), Root::ZERO);
                let protection = Arc::new(SlashingDatabase::in_memory(Root::ZERO).unwrap());
                let store = ValidatorStore::new(
                    SigningGuard::new(context, protection),
                    ProposerDefaults::default(),
                );
                let mut keys = Vec::new();
                for index in [1_u64, 2] {
                    let mut bytes = [0; 32];
                    bytes[31] = index as u8 + 1;
                    let key = LocalKey::<Bls>::new(SecretKey::from_bytes(&bytes).unwrap()).unwrap();
                    let pubkey = store.add(ValidatorSigner::Local(key), false).unwrap();
                    store.set_index(&pubkey, ValidatorIndex(index));
                    keys.push(pubkey);
                }
                let duties = DutyContext::<Minimal>::new(
                    Arc::new(store),
                    Arc::new(nodes),
                    Arc::new(ChainConfig::minimal()),
                    SlotTimer::new(Arc::new(ManualClock::at(0)), SlotClock::new(0, 6_000)),
                    ClientSettings {
                        doppelganger_epochs: 2,
                        ..ClientSettings::default()
                    },
                );
                let doppelganger = Doppelganger::new(duties.clone());

                // Watched from epoch 10; epochs 10, 11, and 12 are checked at 11, 12, and 13.
                doppelganger.watch_new(Epoch(10));
                for epoch in [11, 12] {
                    doppelganger.check(Epoch(epoch)).await;
                    assert!(
                        !duties.store.is_enabled(&keys[1]),
                        "still watched at epoch {epoch}"
                    );
                }
                doppelganger.check(Epoch(13)).await;

                // Validator 2 was never seen and may now sign; validator 1 was seen and never will.
                assert!(duties.store.is_enabled(&keys[1]));
                assert!(!duties.store.is_enabled(&keys[0]));
                doppelganger.check(Epoch(14)).await;
                assert!(!duties.store.is_enabled(&keys[0]));

                let _stopping = stop.send(());
                serving.await.unwrap();
            });
    }
}
