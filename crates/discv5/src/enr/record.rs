//! A signed, verified node record.

use std::{
    collections::BTreeMap,
    fmt,
    hash::{Hash, Hasher},
    str::FromStr,
};

use axiom_crypto::{
    keccak::Keccak256,
    secp256k1::{PublicKey, Signature},
};
use axiom_rlp::{Decoder, Encoder};

use super::{Endpoints, EnrBuilder, EnrError, Eth2Fields};
use crate::{base64::Base64Url, node_id::NodeId};

/// Largest encoded record, per EIP-778.
pub const MAX_RECORD_LEN: usize = 300;

/// Key naming the identity scheme.
pub(crate) const KEY_ID: &[u8] = b"id";

/// Key of the compressed secp256k1 public key.
pub(crate) const KEY_SECP256K1: &[u8] = b"secp256k1";

/// The only identity scheme defined, "v4".
pub(crate) const SCHEME_V4: &[u8] = b"v4";

/// Prefix of the text form.
const TEXT_PREFIX: &str = "enr:";

/// An Ethereum node record whose signature has been checked.
///
/// # Overview
///
/// ```text
/// content   = [seq, k1, v1, k2, v2, ...]       keys sorted, unique
/// signature = sign(keccak256(rlp(content)))    "v4" scheme, 64 bytes r || s
/// record    = [signature, seq, k1, v1, ...]    at most 300 bytes
/// ```
///
/// Every value is kept as its raw RLP item, so a record re-encodes to its exact bytes.
/// Known keys are parsed once, at decoding.
///
/// See EIP-778.
#[derive(Clone)]
pub struct Enr {
    /// The sequence number.
    seq: u64,
    /// Raw RLP values by key, in key order.
    pairs: BTreeMap<Vec<u8>, Vec<u8>>,
    /// The signer's key, from the secp256k1 entry.
    public_key: PublicKey,
    /// The identifier derived from the key.
    node_id: NodeId,
    /// The parsed endpoint entries.
    endpoints: Endpoints,
    /// The parsed consensus entries.
    eth2: Eth2Fields,
    /// The canonical encoding.
    encoded: Vec<u8>,
}

impl Enr {
    /// A builder for a fresh record.
    #[must_use]
    pub const fn builder() -> EnrBuilder {
        EnrBuilder::new()
    }

    /// A builder holding this record's entries, for a re-signed update.
    ///
    /// The builder's sequence number is one above this record's.
    #[must_use]
    pub fn to_builder(&self) -> EnrBuilder {
        // The scheme entries are rewritten at signing, so drop them here.
        let mut builder = EnrBuilder::new().seq(self.seq.saturating_add(1));
        for (key, value) in &self.pairs {
            if key != KEY_ID && key != KEY_SECP256K1 {
                builder = builder.raw(key, value);
            }
        }
        builder
    }

    /// Decodes and verifies a record.
    ///
    /// # Errors
    ///
    /// Fails past 300 bytes, on non-canonical RLP, on unsorted or repeated keys,
    /// on a scheme other than "v4", and on a signature that does not verify.
    pub fn decode(bytes: &[u8]) -> Result<Self, EnrError> {
        // Threshold: EIP-778 caps records at 300 bytes.
        if bytes.len() > MAX_RECORD_LEN {
            return Err(EnrError::TooLarge { len: bytes.len() });
        }
        // Phase 1: signature, sequence number, then key-value pairs in strict key order.
        let mut outer = Decoder::new(bytes);
        let mut list = outer.list()?;
        outer.finish()?;
        let signature = list.bytes()?;
        let seq = list.uint()?;
        let mut pairs: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        while !list.is_empty() {
            let key = list.bytes()?;
            let value = list.raw()?;
            // Invariant: a key above the current last one keeps the map in wire order.
            if pairs
                .last_key_value()
                .is_some_and(|(last, _)| last.as_slice() >= key)
            {
                return Err(EnrError::UnsortedKeys {
                    position: pairs.len(),
                });
            }
            pairs.insert(key.to_vec(), value.to_vec());
        }

        // Phase 2: the "v4" scheme names the key and checks the signature.
        let scheme = pairs.get(KEY_ID).ok_or(EnrError::MissingScheme)?;
        if Decoder::new(scheme).bytes()? != SCHEME_V4 {
            return Err(EnrError::UnsupportedScheme);
        }
        let mut decoder = Decoder::new(pairs.get(KEY_SECP256K1).ok_or(EnrError::MissingPublicKey)?);
        let compressed = decoder.array::<33>()?;
        decoder.finish()?;
        let public_key =
            PublicKey::from_compressed(&compressed).map_err(EnrError::InvalidPublicKey)?;
        let signature: &[u8; 64] = signature
            .try_into()
            .map_err(|_| EnrError::SignatureLength {
                len: signature.len(),
            })?;
        let signature = Signature::from_bytes(signature).map_err(EnrError::InvalidSignature)?;
        public_key
            .verify(&Self::content_hash(seq, &pairs), &signature)
            .map_err(EnrError::InvalidSignature)?;

        // Phase 3: parse the well-known entries once.
        let lookup = |key: &[u8]| pairs.get(key).map(Vec::as_slice);
        let endpoints = Endpoints::read(lookup);
        let eth2 = Eth2Fields::read(lookup);
        Ok(Self {
            seq,
            node_id: NodeId::from_public_key(&public_key),
            public_key,
            endpoints,
            eth2,
            pairs,
            encoded: bytes.to_vec(),
        })
    }

    /// The keccak256 hash of the signed content, rlp([seq, k, v, ...]).
    pub(crate) fn content_hash(seq: u64, pairs: &BTreeMap<Vec<u8>, Vec<u8>>) -> [u8; 32] {
        // Values are already canonical items, so they append raw.
        let mut encoder = Encoder::new();
        encoder.list(|list| {
            list.uint(seq);
            for (key, value) in pairs {
                list.bytes(key).raw(value);
            }
        });
        Keccak256::digest(&encoder.finish())
    }

    /// The sequence number.
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    /// The node identifier.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// The signer's public key.
    #[must_use]
    pub const fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// The endpoint entries.
    #[must_use]
    pub const fn endpoints(&self) -> &Endpoints {
        &self.endpoints
    }

    /// The consensus entries.
    #[must_use]
    pub const fn eth2(&self) -> &Eth2Fields {
        &self.eth2
    }

    /// The raw RLP value under a key.
    #[must_use]
    pub fn get_raw(&self, key: &[u8]) -> Option<&[u8]> {
        self.pairs.get(key).map(Vec::as_slice)
    }

    /// The canonical encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }
}

impl PartialEq for Enr {
    fn eq(&self, other: &Self) -> bool {
        // The encoding is canonical, so equal bytes mean equal records.
        self.encoded == other.encoded
    }
}

impl Eq for Enr {}

impl Hash for Enr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Consistent with equality: hash the encoding.
        self.encoded.hash(state);
    }
}

impl fmt::Debug for Enr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Identity, version, and where to reach the node.
        f.debug_struct("Enr")
            .field("node_id", &self.node_id)
            .field("seq", &self.seq)
            .field("udp", &self.endpoints.udp_socket())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for Enr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The text form: prefix, then unpadded URL-safe base64 of the encoding.
        write!(f, "{TEXT_PREFIX}{}", Base64Url::encode(&self.encoded))
    }
}

impl FromStr for Enr {
    type Err = EnrError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        // Strip the prefix, decode the base64, then verify the record.
        let body = text
            .strip_prefix(TEXT_PREFIX)
            .ok_or(EnrError::MissingPrefix)?;
        Self::decode(&Base64Url::decode(body)?)
    }
}
