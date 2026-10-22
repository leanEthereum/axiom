//! The connection ids the peer issued for this side to address it with, per RFC 9000, section 5.1.
//!
//! This side never migrates, so it keeps using one id while that id stays active.
//! It moves on only when the peer asks for the id to be retired.

use std::{collections::BTreeMap, mem};

use crate::quic::{ConnectionId, TransportError, TransportErrorCode};

/// Peer-issued connection ids by sequence number.
#[derive(Debug)]
pub(crate) struct PeerIds {
    /// Active ids by sequence number; sequence 0 is the one from the handshake.
    active: BTreeMap<u64, ConnectionId>,
    /// The sequence number in use.
    current: u64,
    /// The most active ids this side stores, as its transport parameter announced.
    limit: u64,
    /// Ids below this sequence number are retired.
    retired_below: u64,
    /// Retirements to announce.
    retire_due: Vec<u64>,
}

impl PeerIds {
    /// The handshake id, with a storage limit.
    pub(crate) fn new(initial: ConnectionId, limit: u64) -> Self {
        Self {
            active: BTreeMap::from([(0, initial)]),
            current: 0,
            limit,
            retired_below: 0,
            retire_due: Vec::new(),
        }
    }

    /// The id to put in outgoing packets.
    pub(crate) fn current(&self) -> ConnectionId {
        self.active
            .get(&self.current)
            .copied()
            .unwrap_or(ConnectionId::EMPTY)
    }

    /// Replaces the handshake id, as the client does on the server's first packet or a Retry.
    pub(crate) fn replace_initial(&mut self, id: ConnectionId) {
        self.active.insert(0, id);
    }

    /// Takes in a NEW_CONNECTION_ID frame.
    ///
    /// # Errors
    ///
    /// Fails when the peer uses empty ids, reuses a sequence number for another id, or exceeds the limit.
    pub(crate) fn on_new_id(
        &mut self,
        sequence: u64,
        retire_prior_to: u64,
        id: ConnectionId,
    ) -> Result<(), TransportError> {
        if self.current().is_empty() {
            return Err(TransportError::protocol(
                "new connection id from a peer that uses empty ids",
            ));
        }
        if sequence < self.retired_below {
            // Already retired: retire this one at once, per RFC 9000, section 19.15.
            self.retire_due.push(sequence);
            return Ok(());
        }
        if let Some(existing) = self.active.get(&sequence)
            && *existing != id
        {
            return Err(TransportError::protocol(format!(
                "sequence {sequence} reissued with another connection id"
            )));
        }
        self.active.insert(sequence, id);
        if retire_prior_to > self.retired_below {
            let retired: Vec<u64> = self
                .active
                .range(..retire_prior_to)
                .map(|(seq, _)| *seq)
                .collect();
            for seq in retired {
                self.active.remove(&seq);
                self.retire_due.push(seq);
            }
            self.retired_below = retire_prior_to;
            if self.current < retire_prior_to
                && let Some((&next, _)) = self.active.first_key_value()
            {
                self.current = next;
            }
        }
        if self.active.len() as u64 > self.limit {
            return Err(TransportError::new(
                TransportErrorCode::CONNECTION_ID_LIMIT_ERROR,
                format!(
                    "{} active connection ids exceed the limit of {}",
                    self.active.len(),
                    self.limit
                ),
            ));
        }
        Ok(())
    }

    /// Takes the retirements to announce.
    pub(crate) fn take_retirements(&mut self) -> Vec<u64> {
        mem::take(&mut self.retire_due)
    }

    /// Schedules a lost retirement again.
    pub(crate) fn on_retirement_lost(&mut self, sequence: u64) {
        self.retire_due.push(sequence);
    }

    /// Whether retirements wait to be sent.
    pub(crate) const fn has_retirements(&self) -> bool {
        !self.retire_due.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> ConnectionId {
        ConnectionId::new(&[byte; 8]).unwrap()
    }

    #[test]
    fn retire_prior_to_moves_to_the_next_id() {
        let mut ids = PeerIds::new(id(0), 4);
        ids.on_new_id(1, 0, id(1)).unwrap();
        ids.on_new_id(2, 0, id(2)).unwrap();
        assert_eq!(ids.current(), id(0));

        // Retire everything below 2: sequences 0 and 1 go, and 2 takes over.
        ids.on_new_id(3, 2, id(3)).unwrap();
        assert_eq!(ids.current(), id(2));
        assert_eq!(ids.take_retirements(), [0, 1]);

        // A late frame for sequence 1 is retired at once.
        ids.on_new_id(1, 0, id(1)).unwrap();
        assert_eq!(ids.take_retirements(), [1]);
    }

    #[test]
    fn limits_and_conflicts() {
        let mut ids = PeerIds::new(id(0), 2);
        ids.on_new_id(1, 0, id(1)).unwrap();
        assert_eq!(
            ids.on_new_id(1, 0, id(9)).map_err(|error| error.code),
            Err(TransportErrorCode::PROTOCOL_VIOLATION)
        );
        assert_eq!(
            ids.on_new_id(2, 0, id(2)).map_err(|error| error.code),
            Err(TransportErrorCode::CONNECTION_ID_LIMIT_ERROR)
        );
        let mut empty = PeerIds::new(ConnectionId::EMPTY, 2);
        assert_eq!(
            empty.on_new_id(1, 0, id(1)).map_err(|error| error.code),
            Err(TransportErrorCode::PROTOCOL_VIOLATION)
        );
    }
}
