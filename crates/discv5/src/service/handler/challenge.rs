//! A WHOAREYOU this node sent and awaits an answer to.

use std::time::Duration;

use crate::{enr::Enr, session::ChallengeData};

/// The state kept between sending WHOAREYOU and receiving the handshake.
///
/// See discv5-theory.md, "Handshake Steps", step 2.
#[derive(Clone, Debug)]
pub(crate) struct Challenge {
    /// The unmasked challenge, salt of the key derivation.
    pub(crate) data: ChallengeData,
    /// The WHOAREYOU datagram, resent unchanged if the peer sends again first.
    pub(crate) datagram: Vec<u8>,
    /// The peer's record as known when challenging, absent when unknown.
    pub(crate) known: Option<Enr>,
    /// When the challenge lapses.
    pub(crate) deadline: Duration,
}
