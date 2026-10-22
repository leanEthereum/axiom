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
