//! The packet layer: sessions, handshakes, and requests on the wire.
//!
//! # Overview
//!
//! The handler turns messages into datagrams and back.
//! It opens sessions on demand and keeps every request until it is answered or times out.
//!
//! ```text
//! A -> B   message packet, random content      (no session yet)
//! A <- B   WHOAREYOU, nonce of A's packet      (B stores the challenge)
//! A -> B   handshake packet carrying the request
//! A <- B   response under the new session
//! ```
//!
//! See discv5-theory.md, "Sessions".

mod challenge;
mod event;
mod in_flight;
mod received;

use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    time::Duration,
};

use axiom_crypto::secp256k1::SecretKey;
use challenge::Challenge;
pub(crate) use event::HandlerEvent;
use in_flight::{Delivery, InFlight};
use received::ReceivedHandshake;

use super::Datagram;
use crate::{
    enr::Enr,
    message::{Message, RequestId},
    node_id::NodeId,
    packet::{AuthData, Header, IdNonce, MaskingIv, Nonce, Packet},
    rng::Csprng,
    session::{ChallengeData, IdSignature, Session, SessionCache, SessionKeys},
};

/// Random bytes in the message of a packet that only opens a handshake.
///
/// Anything from a tag's 16 bytes up works; the recipient cannot open it either way.
const RANDOM_MESSAGE_LEN: usize = 32;

/// Handshakes one request may carry before it fails.
///
/// A second covers a peer that lost its session while the first was in flight.
const MAX_HANDSHAKES: u8 = 2;

/// Most challenges awaiting handshakes at once.
///
/// Each costs a few hundred bytes; past the cap, new strangers wait for old challenges to lapse.
const MAX_CHALLENGES: usize = 1024;

/// Timeouts of the packet layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HandlerConfig {
    /// How long a request waits for its response.
    pub(crate) request_timeout: Duration,
    /// How long a challenge waits for its handshake.
    pub(crate) handshake_timeout: Duration,
    /// Most sessions kept.
    pub(crate) session_capacity: usize,
}

/// Sessions, challenges, and requests in flight.
#[derive(Debug)]
pub(crate) struct Handler {
    /// The local static key.
    key: SecretKey,
    /// The local record, sent in handshakes when the peer's copy is stale.
    local_enr: Enr,
    /// The timeouts.
    config: HandlerConfig,
    /// Established sessions.
    sessions: SessionCache,
    /// Challenges sent, by peer and endpoint.
    challenges: BTreeMap<(NodeId, SocketAddr), Challenge>,
    /// Requests awaiting responses, by peer and request id.
    in_flight: BTreeMap<(NodeId, RequestId), InFlight>,
    /// Peers this node has sent a handshake-opening packet to and awaits WHOAREYOU from.
    initiating: BTreeSet<NodeId>,
}

impl Handler {
    /// A handler for a local identity.
    pub(crate) const fn new(key: SecretKey, local_enr: Enr, config: HandlerConfig) -> Self {
        // No sessions, challenges, or requests yet.
        Self {
            key,
            local_enr,
            sessions: SessionCache::new(config.session_capacity),
            config,
            challenges: BTreeMap::new(),
            in_flight: BTreeMap::new(),
            initiating: BTreeSet::new(),
        }
    }

    /// The local node's id.
    pub(crate) const fn local_id(&self) -> NodeId {
        self.local_enr.node_id()
    }

    /// The local record.
    pub(crate) const fn local_enr(&self) -> &Enr {
        &self.local_enr
    }

    /// Replaces the local record, for example after an address change.
    pub(crate) fn set_local_enr(&mut self, enr: Enr) {
        self.local_enr = enr;
    }

    /// Sends a request, opening a session first when none exists.
    ///
    /// # Returns
    ///
    /// False when the record has no UDP endpoint, so nothing was sent.
    pub(crate) fn send_request(
        &mut self,
        now: Duration,
        contact: &Enr,
        message: Message,
        rng: &mut Csprng,
        out: &mut Vec<Datagram>,
    ) -> bool {
        let Some(addr) = contact.endpoints().udp_socket() else {
            return false;
        };
        let node = contact.node_id();
        let deadline = now + self.config.request_timeout;

        // Case 1: a session exists, so seal the request at once.
        // Case 2: a handshake is under way, so wait for it.
        // Case 3: open a handshake with a packet the peer cannot read.
        let delivery = if let Some(session) = self.sessions.get_mut(node, addr) {
            let (nonce, datagram) = Self::seal(session, rng, &self.local_enr, &node, &message);
            out.push(Datagram {
                to: addr,
                bytes: datagram,
            });
            Delivery::Sent(nonce)
        } else if self.initiating.contains(&node) {
            Delivery::Queued
        } else {
            let nonce = Nonce(rng.bytes());
            let packet = Packet {
                masking_iv: MaskingIv(rng.bytes()),
                header: Header {
                    nonce,
                    auth: AuthData::Message {
                        src_id: self.local_id(),
                    },
                },
                message: rng.bytes::<RANDOM_MESSAGE_LEN>().to_vec(),
            };
            out.push(Datagram {
                to: addr,
                bytes: packet.encode(&node),
            });
            self.initiating.insert(node);
            Delivery::Sent(nonce)
        };
        // Timing: a queued request also waits out the handshake.
        let deadline = match delivery {
            Delivery::Sent(_) => deadline,
            Delivery::Queued => deadline + self.config.handshake_timeout,
        };
        self.in_flight.insert(
            (node, message.request_id()),
            InFlight {
                contact: contact.clone(),
                addr,
                message,
                delivery,
                deadline,
                handshakes: 0,
            },
        );
        true
    }

    /// Sends a response over the session the request came through.
    pub(crate) fn send_response(
        &mut self,
        node: NodeId,
        addr: SocketAddr,
        message: &Message,
        rng: &mut Csprng,
        out: &mut Vec<Datagram>,
    ) {
        // Invariant: a request only arrives through a session, so one exists unless evicted since.
        if let Some(session) = self.sessions.get_mut(node, addr) {
            let (_, datagram) = Self::seal(session, rng, &self.local_enr, &node, message);
            out.push(Datagram {
                to: addr,
                bytes: datagram,
            });
        }
    }

    /// Marks a request answered, so it no longer times out.
    pub(crate) fn complete(&mut self, node: NodeId, request_id: RequestId) {
        self.in_flight.remove(&(node, request_id));
    }

    /// Seals a message in an ordinary packet under a session.
    fn seal(
        session: &mut Session,
        rng: &mut Csprng,
        local: &Enr,
        dest: &NodeId,
        message: &Message,
    ) -> (Nonce, Vec<u8>) {
        // A fresh nonce and masking IV for every packet.
        let nonce = session.next_nonce(rng);
        let auth = AuthData::Message {
            src_id: local.node_id(),
        };
        let datagram = session.seal(MaskingIv(rng.bytes()), nonce, auth, message, dest);
        (nonce, datagram)
    }

    /// Processes one datagram.
    ///
    /// # Arguments
    ///
    /// The known-record lookup tells which record of a peer the local node holds.
    /// Challenges carry its sequence number, and handshakes without a record rely on it.
    pub(crate) fn receive(
        &mut self,
        now: Duration,
        from: SocketAddr,
        datagram: &[u8],
        known: impl Fn(&NodeId) -> Option<Enr>,
        rng: &mut Csprng,
        out: &mut Vec<Datagram>,
    ) -> Vec<HandlerEvent> {
        // Undecodable datagrams are dropped silently: UDP carries anything.
        let Ok(packet) = Packet::decode(&self.local_id(), datagram) else {
            return Vec::new();
        };
        match packet.header.auth.clone() {
            AuthData::Message { src_id } => {
                self.on_message(now, from, (src_id, &packet), &known, rng, out)
            }
            AuthData::WhoAreYou { enr_seq, .. } => {
                self.on_whoareyou(now, from, &packet, enr_seq, rng, out);
                Vec::new()
            }
            AuthData::Handshake {
                src_id,
                id_signature,
                ephemeral_key,
                record,
            } => {
                let handshake = ReceivedHandshake {
                    src_id,
                    id_signature: IdSignature(id_signature),
                    ephemeral_key,
                    record: record.map(|record| *record),
                };
                self.on_handshake(from, &packet, handshake, &known)
            }
        }
    }

    /// An ordinary packet: open it, or challenge the sender.
    fn on_message(
        &mut self,
        now: Duration,
        from: SocketAddr,
        (src_id, packet): (NodeId, &Packet),
        known: &impl Fn(&NodeId) -> Option<Enr>,
        rng: &mut Csprng,
        out: &mut Vec<Datagram>,
    ) -> Vec<HandlerEvent> {
        // A session that opens the message settles it.
        if let Some(session) = self.sessions.get_mut(src_id, from)
            && let Ok(message) = session.open(packet)
        {
            return self.classify(src_id, from, message).into_iter().collect();
        }

        // Otherwise challenge, resending a live challenge rather than minting another.
        let key = (src_id, from);
        if let Some(challenge) = self.challenges.get(&key)
            && challenge.deadline > now
        {
            out.push(Datagram {
                to: from,
                bytes: challenge.datagram.clone(),
            });
            return Vec::new();
        }
        // Threshold: packets from made-up ids must not grow the challenge store without bound.
        self.challenges
            .retain(|_, challenge| challenge.deadline > now);
        if self.challenges.len() >= MAX_CHALLENGES {
            return Vec::new();
        }
        let known = known(&src_id);
        let whoareyou = Packet {
            masking_iv: MaskingIv(rng.bytes()),
            header: Header {
                nonce: packet.header.nonce,
                auth: AuthData::WhoAreYou {
                    id_nonce: IdNonce(rng.bytes()),
                    enr_seq: known.as_ref().map_or(0, Enr::seq),
                },
            },
            message: Vec::new(),
        };
        let datagram = whoareyou.encode(&src_id);
        out.push(Datagram {
            to: from,
            bytes: datagram.clone(),
        });
        self.challenges.insert(
            key,
            Challenge {
                data: ChallengeData(whoareyou.message_ad()),
                datagram,
                known,
                deadline: now + self.config.handshake_timeout,
            },
        );
        Vec::new()
    }

    /// Sorts an opened message into a request or a response to a request in flight.
    fn classify(&self, node: NodeId, from: SocketAddr, message: Message) -> Option<HandlerEvent> {
        if message.is_request() {
            return Some(HandlerEvent::Request {
                node,
                addr: from,
                message,
            });
        }
        // A response counts only from the endpoint the request went to.
        let request = self.in_flight.get(&(node, message.request_id()))?;
        (request.addr == from).then(|| HandlerEvent::Response {
            node,
            request: request.message.clone(),
            message,
        })
    }

    /// A WHOAREYOU: answer with a handshake carrying the request it names.
    fn on_whoareyou(
        &mut self,
        now: Duration,
        from: SocketAddr,
        packet: &Packet,
        enr_seq: u64,
        rng: &mut Csprng,
        out: &mut Vec<Datagram>,
    ) {
        // Only a challenge to a packet this node sent is valid.
        let nonce = packet.header.nonce;
        let Some(key) = self
            .in_flight
            .iter()
            .find(|(_, request)| request.delivery == Delivery::Sent(nonce) && request.addr == from)
            .map(|(key, _)| *key)
        else {
            return;
        };
        let (node, _) = key;
        let Some(request) = self.in_flight.get(&key) else {
            return;
        };
        if request.handshakes >= MAX_HANDSHAKES {
            return;
        }
        let contact = request.contact.clone();
        let message = request.message.clone();

        // Phase 1: fresh ephemeral key, session keys, and the identity proof.
        let challenge = ChallengeData(packet.message_ad());
        let ephemeral = rng.secret_key();
        let ephemeral_key = ephemeral.public_key();
        let keys = SessionKeys::initiate(
            &ephemeral,
            contact.public_key(),
            &challenge,
            &self.local_id(),
            &node,
        );
        let id_signature = IdSignature::sign(&self.key, &challenge, &ephemeral_key, &node);
        let mut session = Session::initiator(&keys);
        if let Some(old) = self.sessions.get(node, from) {
            session = session.replacing(old);
        }

        // Phase 2: the record goes along when the challenger's copy is older.
        let record = (enr_seq < self.local_enr.seq()).then(|| Box::new(self.local_enr.clone()));
        let packet_nonce = session.next_nonce(rng);
        let auth = AuthData::Handshake {
            src_id: self.local_id(),
            id_signature: id_signature.0,
            ephemeral_key,
            record,
        };
        let datagram = session.seal(MaskingIv(rng.bytes()), packet_nonce, auth, &message, &node);
        out.push(Datagram {
            to: from,
            bytes: datagram,
        });
        if let Some(request) = self.in_flight.get_mut(&key) {
            request.delivery = Delivery::Sent(packet_nonce);
            request.deadline = now + self.config.request_timeout;
            request.handshakes += 1;
        }
        self.sessions.insert(node, from, session);
        self.initiating.remove(&node);

        // Phase 3: every other request to the peer goes out under the new session.
        let others: Vec<(NodeId, RequestId)> = self
            .in_flight
            .keys()
            .filter(|other| other.0 == node && **other != key)
            .copied()
            .collect();
        for other in others {
            let Some(session) = self.sessions.get_mut(node, from) else {
                return;
            };
            let Some(request) = self.in_flight.get_mut(&other) else {
                continue;
            };
            let (nonce, datagram) =
                Self::seal(session, rng, &self.local_enr, &node, &request.message);
            out.push(Datagram {
                to: from,
                bytes: datagram,
            });
            request.delivery = Delivery::Sent(nonce);
            request.deadline = now + self.config.request_timeout;
        }
    }

    /// A handshake answering this node's challenge: verify, derive, and open.
    fn on_handshake(
        &mut self,
        from: SocketAddr,
        packet: &Packet,
        handshake: ReceivedHandshake,
        known: &impl Fn(&NodeId) -> Option<Enr>,
    ) -> Vec<HandlerEvent> {
        // Phase 1: the challenge this handshake answers, used once.
        let src_id = handshake.src_id;
        let Some(challenge) = self.challenges.remove(&(src_id, from)) else {
            return Vec::new();
        };

        // Phase 2: the peer's record, sent along or already known, must match its id.
        let Some(enr) = handshake
            .record
            .or(challenge.known)
            .or_else(|| known(&src_id))
            .filter(|enr| enr.node_id() == src_id)
        else {
            return Vec::new();
        };
        if !handshake.id_signature.verify(
            enr.public_key(),
            &challenge.data,
            &handshake.ephemeral_key,
            &self.local_id(),
        ) {
            return Vec::new();
        }

        // Phase 3: derive the keys and open the message; failure leaves no session behind.
        let keys = SessionKeys::accept(
            &self.key,
            &handshake.ephemeral_key,
            &challenge.data,
            &src_id,
            &self.local_id(),
        );
        let mut session = Session::recipient(&keys);
        let Ok(message) = session.open(packet) else {
            return Vec::new();
        };
        if let Some(old) = self.sessions.get(src_id, from) {
            session = session.replacing(old);
        }
        self.sessions.insert(src_id, from, session);
        let mut events = vec![HandlerEvent::Established { enr, addr: from }];
        events.extend(self.classify(src_id, from, message));
        events
    }

    /// Drops lapsed challenges and fails lapsed requests.
    ///
    /// # Returns
    ///
    /// The requests that failed, with their peers.
    pub(crate) fn expire(&mut self, now: Duration) -> Vec<(NodeId, Message)> {
        self.challenges
            .retain(|_, challenge| challenge.deadline > now);
        let lapsed: Vec<(NodeId, RequestId)> = self
            .in_flight
            .iter()
            .filter(|(_, request)| request.deadline <= now)
            .map(|(key, _)| *key)
            .collect();
        let mut failed = Vec::with_capacity(lapsed.len());
        for key in lapsed {
            let Some(request) = self.in_flight.remove(&key) else {
                continue;
            };
            // A lapsed opening packet ends the handshake attempt, and the requests queued behind it.
            let (node, _) = key;
            if request.handshakes == 0
                && !self.sessions.contains(node, request.addr)
                && self.initiating.remove(&node)
            {
                let queued: Vec<(NodeId, RequestId)> = self
                    .in_flight
                    .iter()
                    .filter(|(other, queued)| {
                        other.0 == node && queued.delivery == Delivery::Queued
                    })
                    .map(|(other, _)| *other)
                    .collect();
                for other in queued {
                    if let Some(queued) = self.in_flight.remove(&other) {
                        failed.push((node, queued.message));
                    }
                }
            }
            failed.push((node, request.message));
        }
        failed
    }

    /// The earliest deadline of a request or challenge.
    pub(crate) fn next_deadline(&self) -> Option<Duration> {
        let requests = self.in_flight.values().map(|request| request.deadline);
        let challenges = self.challenges.values().map(|challenge| challenge.deadline);
        requests.chain(challenges).min()
    }

    /// Sessions currently held.
    pub(crate) fn session_count(&self) -> usize {
        self.sessions.len()
    }
}
