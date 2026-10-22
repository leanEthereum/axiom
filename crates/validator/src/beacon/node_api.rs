//! The node namespace: whether a beacon node is fit to serve duties.

use crate::beacon::{BeaconClient, BeaconError, SyncStatus};

/// The node namespace of one beacon node.
#[derive(Clone, Copy, Debug)]
pub struct NodeEndpoints<'a> {
    /// The node.
    client: &'a BeaconClient,
}

impl<'a> NodeEndpoints<'a> {
    /// The namespace of a node.
    pub(crate) const fn new(client: &'a BeaconClient) -> Self {
        Self { client }
    }

    /// How far the node is from the chain's head.
    ///
    /// See `getSyncingStatus` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node is unreachable or answers malformed data.
    pub async fn syncing(self) -> Result<SyncStatus, BeaconError> {
        let json = self.client.get_json("/eth/v1/node/syncing").await?;
        BeaconClient::data(&json)
    }
}
