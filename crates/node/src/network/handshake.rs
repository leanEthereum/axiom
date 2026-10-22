//! Status handshakes in flight, and the version each peer speaks.

use std::collections::BTreeSet;

use axiom_p2p::{
    PeerId,
    eth::reqresp::{ResponseChunk, ResponseCode, Status, StatusVersion},
    swarm::{RequestError, RequestId},
};

/// The status requests this node sent, and the peers that refused the newest version.
///
/// # Overview
///
/// 1. A handshake proposes the newest version first.
/// 2. A peer that refuses it during negotiation gets the older version at once.
/// 3. That peer keeps the older version until it disconnects.
///
/// The Fulu p2p spec adds the second version and drops none, so a peer may serve only the first.
/// Before Fulu, a peer serving the second version answers it all the same.
#[derive(Debug, Default)]
pub(crate) struct Handshakes {
    /// Requests awaiting an answer, with the peer and the version sent.
    in_flight: Vec<(RequestId, PeerId, StatusVersion)>,
    /// Peers that refused a newer version, with the version they accepted.
    downgraded: BTreeSet<(PeerId, StatusVersion)>,
}

impl Handshakes {
    /// The version to open a handshake with a peer: the newest it has not refused.
    pub(crate) fn version_for(&self, peer: &PeerId) -> StatusVersion {
        self.downgraded
            .iter()
            .find(|(known, _)| known == peer)
            .map_or(StatusVersion::NEWEST, |(_, version)| *version)
    }

    /// Records a status request sent to a peer.
    pub(crate) fn sent(&mut self, request: RequestId, peer: PeerId, version: StatusVersion) {
        self.in_flight.push((request, peer, version));
    }

    /// Takes the answer to a status request, read in the version it was sent under.
    ///
    /// # Returns
    ///
    /// Nothing when the request was no handshake.
    /// Otherwise the peer, with its status when the answer is a success that decodes.
    pub(crate) fn answered(
        &mut self,
        request: RequestId,
        chunk: &ResponseChunk,
    ) -> Option<(PeerId, Option<Status>)> {
        let (peer, version) = self.take(request)?;
        let status = (chunk.code == ResponseCode::Success)
            .then(|| version.decode(&chunk.payload).ok())
            .flatten();
        Some((peer, status))
    }

    /// Takes a failed status request.
    ///
    /// # Returns
    ///
    /// The peer, when it refused the version and an older one remains to try.
    pub(crate) fn failed(&mut self, request: RequestId, error: &RequestError) -> Option<PeerId> {
        let (peer, version) = self.take(request)?;
        let RequestError::Unsupported { .. } = error else {
            return None;
        };
        let older = version.older()?;
        self.downgraded.retain(|(known, _)| *known != peer);
        self.downgraded.insert((peer.clone(), older));
        Some(peer)
    }

    /// Forgets a peer that disconnected, so a reconnect proposes the newest version again.
    pub(crate) fn forget(&mut self, peer: &PeerId) {
        self.in_flight.retain(|(_, known, _)| known != peer);
        self.downgraded.retain(|(known, _)| known != peer);
    }

    /// Removes a request from those in flight.
    /// Whether a request is a status handshake in flight.
    pub(crate) fn owns(&self, request: RequestId) -> bool {
        self.in_flight.iter().any(|(id, ..)| *id == request)
    }

    fn take(&mut self, request: RequestId) -> Option<(PeerId, StatusVersion)> {
        let position = self.in_flight.iter().position(|(id, ..)| *id == request)?;
        let (_, peer, version) = self.in_flight.swap_remove(position);
        Some((peer, version))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axiom_p2p::{Keypair, eth::reqresp::Protocol};
    use axiom_types::{Epoch, ForkDigest, Root, Slot};

    use super::*;

    /// The peer whose secp256k1 secret is 32 copies of a seed byte.
    fn peer(seed: u8) -> PeerId {
        let key = Keypair::from_secret_bytes(&[seed; 32]).expect("seed is a valid scalar");
        PeerId::from_public_key(key.public_key())
    }

    /// A status whose earliest available slot is 64.
    fn status() -> Status {
        Status {
            fork_digest: ForkDigest([1, 2, 3, 4]),
            finalized_root: Root::from([1; 32]),
            finalized_epoch: Epoch(3),
            head_root: Root::from([2; 32]),
            head_slot: Slot(100),
            earliest_available_slot: Slot(64),
        }
    }

    #[test]
    fn a_first_version_peer_gets_the_first_version() {
        let mut handshakes = Handshakes::default();
        let bob = peer(2);

        // Request 1 proposes version 2, and bob refuses it during negotiation.
        assert_eq!(handshakes.version_for(&bob), StatusVersion::V2);
        handshakes.sent(RequestId(1), bob.clone(), StatusVersion::V2);
        let refused = RequestError::Unsupported {
            protocol: Protocol::StatusV2,
        };
        assert_eq!(handshakes.failed(RequestId(1), &refused), Some(bob.clone()));

        // Bob now gets version 1, and request 2 carries it.
        assert_eq!(handshakes.version_for(&bob), StatusVersion::V1);
        handshakes.sent(RequestId(2), bob.clone(), StatusVersion::V1);

        // His 84-byte answer reads as a status with the earliest slot at genesis.
        let answer = ResponseChunk::success(None, StatusVersion::V1.encode(&status()));
        assert_eq!(
            handshakes.answered(RequestId(2), &answer),
            Some((
                bob.clone(),
                Some(Status {
                    earliest_available_slot: Slot::GENESIS,
                    ..status()
                })
            ))
        );

        // A refusal of version 1 has nothing older to fall back to.
        handshakes.sent(RequestId(3), bob.clone(), StatusVersion::V1);
        let refused = RequestError::Unsupported {
            protocol: Protocol::StatusV1,
        };
        assert_eq!(handshakes.failed(RequestId(3), &refused), None);

        // Once bob disconnects, a reconnect proposes version 2 again.
        handshakes.forget(&bob);
        assert_eq!(handshakes.version_for(&bob), StatusVersion::V2);
    }

    #[test]
    fn answers_and_other_failures_keep_the_newest_version() {
        let mut handshakes = Handshakes::default();
        let carol = peer(3);

        // Request 7, version 2: a 92-byte answer reads back whole.
        handshakes.sent(RequestId(7), carol.clone(), StatusVersion::V2);
        let answer = ResponseChunk::success(None, StatusVersion::V2.encode(&status()));
        assert_eq!(
            handshakes.answered(RequestId(7), &answer),
            Some((carol.clone(), Some(status())))
        );
        // The same request again is no longer in flight.
        assert_eq!(handshakes.answered(RequestId(7), &answer), None);

        // Request 8 gets an 84-byte answer under version 2: no usable status.
        handshakes.sent(RequestId(8), carol.clone(), StatusVersion::V2);
        let short = ResponseChunk::success(None, StatusVersion::V1.encode(&status()));
        assert_eq!(
            handshakes.answered(RequestId(8), &short),
            Some((carol.clone(), None))
        );

        // Request 9 times out after 10 seconds: no retry, and carol keeps version 2.
        handshakes.sent(RequestId(9), carol.clone(), StatusVersion::V2);
        let timeout = RequestError::Timeout {
            timeout: Duration::from_secs(10),
        };
        assert_eq!(handshakes.failed(RequestId(9), &timeout), None);
        assert_eq!(handshakes.version_for(&carol), StatusVersion::V2);
    }
}
