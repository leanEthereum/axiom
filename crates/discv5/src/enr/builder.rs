//! Assembles and signs node records.

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr},
};

use axiom_crypto::secp256k1::SecretKey;
use axiom_rlp::Encoder;
use axiom_ssz::Ssz;
use axiom_types::ForkDigest;

use super::{
    Attnets, Enr, EnrError, EnrForkId, Syncnets,
    endpoint::{KEY_IP, KEY_IP6, KEY_QUIC, KEY_QUIC6, KEY_TCP, KEY_TCP6, KEY_UDP, KEY_UDP6},
    eth2::{KEY_ATTNETS, KEY_CGC, KEY_ETH2, KEY_NFD, KEY_SYNCNETS},
    record::{KEY_ID, KEY_SECP256K1, SCHEME_V4},
};

/// Collects the entries of a record, then signs it under the "v4" scheme.
///
/// The scheme name and the public key are written at signing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrBuilder {
    /// The sequence number to sign.
    seq: u64,
    /// Raw RLP values by key.
    pairs: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Default for EnrBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EnrBuilder {
    /// An empty builder at sequence number 1.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            seq: 1,
            pairs: BTreeMap::new(),
        }
    }

    /// Sets the sequence number.
    #[must_use]
    pub const fn seq(mut self, seq: u64) -> Self {
        self.seq = seq;
        self
    }

    /// Sets a raw RLP value, replacing any earlier one under the key.
    #[must_use]
    pub fn raw(mut self, key: &[u8], value: &[u8]) -> Self {
        self.pairs.insert(key.to_vec(), value.to_vec());
        self
    }

    /// Sets a byte-string value.
    #[must_use]
    pub fn bytes(self, key: &[u8], value: &[u8]) -> Self {
        let mut encoder = Encoder::new();
        encoder.bytes(value);
        self.raw(key, &encoder.finish())
    }

    /// Sets an integer value.
    #[must_use]
    pub fn uint(self, key: &[u8], value: u64) -> Self {
        let mut encoder = Encoder::new();
        encoder.uint(value);
        self.raw(key, &encoder.finish())
    }

    /// Sets the IPv4 address.
    #[must_use]
    pub fn ip4(self, ip: Ipv4Addr) -> Self {
        self.bytes(KEY_IP, &ip.octets())
    }

    /// Sets the IPv6 address.
    #[must_use]
    pub fn ip6(self, ip: Ipv6Addr) -> Self {
        self.bytes(KEY_IP6, &ip.octets())
    }

    /// Sets the UDP port.
    #[must_use]
    pub fn udp4(self, port: u16) -> Self {
        self.uint(KEY_UDP, u64::from(port))
    }

    /// Sets the IPv6-specific UDP port.
    #[must_use]
    pub fn udp6(self, port: u16) -> Self {
        self.uint(KEY_UDP6, u64::from(port))
    }

    /// Sets the TCP port.
    #[must_use]
    pub fn tcp4(self, port: u16) -> Self {
        self.uint(KEY_TCP, u64::from(port))
    }

    /// Sets the IPv6-specific TCP port.
    #[must_use]
    pub fn tcp6(self, port: u16) -> Self {
        self.uint(KEY_TCP6, u64::from(port))
    }

    /// Sets the libp2p QUIC port.
    #[must_use]
    pub fn quic4(self, port: u16) -> Self {
        self.uint(KEY_QUIC, u64::from(port))
    }

    /// Sets the IPv6-specific libp2p QUIC port.
    #[must_use]
    pub fn quic6(self, port: u16) -> Self {
        self.uint(KEY_QUIC6, u64::from(port))
    }

    /// Sets the fork identifier.
    #[must_use]
    pub fn fork_id(self, fork_id: &EnrForkId) -> Self {
        self.bytes(KEY_ETH2, &fork_id.encode())
    }

    /// Sets the attestation subnet bitfield.
    #[must_use]
    pub fn attnets(self, attnets: &Attnets) -> Self {
        self.bytes(KEY_ATTNETS, attnets.as_bytes())
    }

    /// Sets the sync committee subnet bitfield.
    #[must_use]
    pub fn syncnets(self, syncnets: &Syncnets) -> Self {
        self.bytes(KEY_SYNCNETS, syncnets.as_bytes())
    }

    /// Sets the custody group count, Fulu.
    #[must_use]
    pub fn custody_group_count(self, count: u64) -> Self {
        self.uint(KEY_CGC, count)
    }

    /// Sets the next fork digest, Fulu.
    #[must_use]
    pub fn next_fork_digest(self, digest: ForkDigest) -> Self {
        self.bytes(KEY_NFD, &digest.0)
    }

    /// Signs the record.
    ///
    /// # Errors
    ///
    /// Fails when the record would exceed 300 bytes.
    pub fn build(self, key: &SecretKey) -> Result<Enr, EnrError> {
        // Phase 1: the scheme entries name the signer.
        let public_key = key.public_key();
        let builder = self
            .bytes(KEY_ID, SCHEME_V4)
            .bytes(KEY_SECP256K1, &public_key.to_compressed());

        // Phase 2: sign the content hash, low-s, with an RFC 6979 nonce.
        let hash = Enr::content_hash(builder.seq, &builder.pairs);
        let signature = key.sign(&hash).to_bytes();

        // Phase 3: encode the record, then decode it so every check runs once more.
        let mut encoder = Encoder::new();
        encoder.list(|list| {
            list.bytes(&signature).uint(builder.seq);
            for (key, value) in &builder.pairs {
                list.bytes(key).raw(value);
            }
        });
        Enr::decode(&encoder.finish())
    }
}
