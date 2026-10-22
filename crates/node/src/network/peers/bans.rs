//! Banned peers and addresses, with bans that grow for repeat offenders and expire.
//!
//! # Overview
//!
//! A ban lasts a base time, doubled for each earlier ban of the same peer:
//!
//! ```text
//! duration = 30 min * 2^(offences - 1), capped at 24 h
//! ```
//!
//! Offences are forgotten a day after the last ban ends, so a reformed peer starts clean.
//!
//! Adversary: an attacker spins up fresh identities, which are free.
//! Its addresses are not free, so an address that produced several banned identities is banned too.
//! The threshold leaves room for honest nodes behind one NAT.

use std::{collections::HashMap, net::IpAddr, time::Duration};

use axiom_p2p::PeerId;

/// The first ban's length.
const BASE_BAN: Duration = Duration::from_mins(30);

/// The longest ban.
const MAX_BAN: Duration = Duration::from_hours(24);

/// How long a peer's offences are remembered after its last ban ends.
const MEMORY: Duration = Duration::from_hours(24);

/// Banned identities from one address before the address itself is banned.
///
/// Threshold: a few honest nodes may share a NAT, but five banned identities do not happen by chance.
const BANNED_PEERS_PER_IP: usize = 5;

/// The ban record of one peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PeerBan {
    /// When the current or last ban ends.
    until: Duration,
    /// Bans so far.
    offences: u32,
    /// The address the peer was banned from, if known.
    ip: Option<IpAddr>,
}

/// Bans by peer and by address.
#[derive(Debug, Default)]
pub(crate) struct BanList {
    /// Peers banned now or recently.
    peers: HashMap<PeerId, PeerBan>,
    /// Banned addresses and when their bans end.
    ips: HashMap<IpAddr, Duration>,
}

impl BanList {
    /// Bans a peer, escalating for repeat offences, and its address when it is a repeat source.
    ///
    /// # Returns
    ///
    /// When the ban ends.
    pub(crate) fn ban(&mut self, peer: &PeerId, ip: Option<IpAddr>, now: Duration) -> Duration {
        let record = self.peers.entry(peer.clone()).or_insert(PeerBan {
            until: now,
            offences: 0,
            ip,
        });
        record.offences += 1;
        record.ip = ip.or(record.ip);
        let doubling = 2_u32.saturating_pow(record.offences - 1);
        let duration = BASE_BAN.saturating_mul(doubling).min(MAX_BAN);
        record.until = now + duration;
        let until = record.until;
        if let Some(ip) = ip {
            let banned_here = self
                .peers
                .values()
                .filter(|ban| ban.ip == Some(ip) && ban.until > now)
                .count();
            if banned_here >= BANNED_PEERS_PER_IP {
                self.ips.insert(ip, now + MAX_BAN);
            }
        }
        until
    }

    /// Whether a peer is banned now.
    pub(crate) fn is_banned(&self, peer: &PeerId, now: Duration) -> bool {
        self.peers.get(peer).is_some_and(|ban| ban.until > now)
    }

    /// Whether an address is banned now.
    pub(crate) fn is_ip_banned(&self, ip: &IpAddr, now: Duration) -> bool {
        self.ips.get(ip).is_some_and(|until| *until > now)
    }

    /// Peers banned now.
    pub(crate) fn active(&self, now: Duration) -> usize {
        self.peers.values().filter(|ban| ban.until > now).count()
    }

    /// Forgets expired address bans and offences past their memory.
    pub(crate) fn prune(&mut self, now: Duration) {
        self.ips.retain(|_, until| *until > now);
        self.peers.retain(|_, ban| ban.until + MEMORY > now);
    }
}

#[cfg(test)]
mod tests {
    use axiom_p2p::{Keypair, PeerId};

    use super::*;

    const MINUTE: Duration = Duration::from_secs(60);

    fn peer(seed: u8) -> PeerId {
        Keypair::from_secret_bytes(&[seed; 32]).unwrap().peer_id()
    }

    #[test]
    fn repeat_offences_double_the_ban() {
        let mut bans = BanList::default();
        let alice = peer(1);
        // First ban: 30 minutes.
        assert_eq!(bans.ban(&alice, None, Duration::ZERO), 30 * MINUTE);
        assert!(bans.is_banned(&alice, 29 * MINUTE));
        assert!(!bans.is_banned(&alice, 30 * MINUTE));
        // Second: an hour; the seventh would be 32 hours and is capped at 24.
        assert_eq!(bans.ban(&alice, None, 40 * MINUTE), 100 * MINUTE);
        for _ in 0..4 {
            bans.ban(&alice, None, 40 * MINUTE);
        }
        assert_eq!(bans.ban(&alice, None, 40 * MINUTE), 40 * MINUTE + MAX_BAN);
    }

    #[test]
    fn offences_are_forgotten_a_day_after_the_ban() {
        let mut bans = BanList::default();
        let alice = peer(1);
        bans.ban(&alice, None, Duration::ZERO);
        // A day after the ban ended the record goes, so the next ban starts at 30 minutes again.
        bans.prune(30 * MINUTE + MEMORY);
        assert_eq!(bans.active(Duration::ZERO), 0);
        let later = 30 * MINUTE + MEMORY;
        assert_eq!(bans.ban(&alice, None, later), later + 30 * MINUTE);
    }

    #[test]
    fn an_address_of_five_banned_peers_is_banned() {
        let mut bans = BanList::default();
        let ip: IpAddr = [203, 0, 113, 9].into();
        for seed in 1..5 {
            bans.ban(&peer(seed), Some(ip), Duration::ZERO);
        }
        // Four banned identities: the address is still welcome.
        assert!(!bans.is_ip_banned(&ip, MINUTE));
        bans.ban(&peer(5), Some(ip), Duration::ZERO);
        assert!(bans.is_ip_banned(&ip, MINUTE));
        assert_eq!(bans.active(MINUTE), 5);
        // Address bans end too.
        bans.prune(MAX_BAN);
        assert!(!bans.is_ip_banned(&ip, MAX_BAN));
    }
}
