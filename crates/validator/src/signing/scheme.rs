//! Signature schemes a validator key can sign under, and BLS, the scheme of today's chain.

use std::{fmt, hash::Hash};

use axiom_bls::{PublicKey, SecretKey, Signature};
use axiom_types::{BlsPubkey, BlsSignature, Root};
use thiserror::Error;

/// How a scheme's keys spend state as they sign.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyState {
    /// A key signs any number of messages and keeps no state, as BLS does.
    Stateless,
    /// Each signature spends one leaf of a fixed supply, and a leaf signs once.
    ///
    /// Signing two messages with one leaf leaks enough of the key to forge.
    /// Hash-based schemes such as XMSS and its synchronized variants work this way.
    OneTime {
        /// Leaves a key holds over its lifetime.
        leaves: u64,
    },
}

/// The position of a one-time key pair within a stateful key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Leaf(pub u64);

/// A signature scheme validator keys can sign under.
///
/// # Overview
///
/// The scheme only turns a signing root into a signature.
/// The domain, the root, and the slashing checks happen before it, the same for every scheme.
///
/// The trait admits the two families Ethereum is weighing.
///
/// - BLS: stateless keys, 48-byte keys, 96-byte signatures, and aggregation.
/// - Hash-based: one-time leaves, kilobyte signatures, and no native aggregation.
///
/// Sizes live in the associated types, so no container assumes 96 bytes.
pub trait SignatureScheme {
    /// A key that signs.
    type SecretKey: Send + Sync;

    /// The key that verifies, as the validator registry records it.
    type PublicKey: AsRef<[u8]> + Clone + Eq + Hash + fmt::Debug + Send + Sync;

    /// A signature over one signing root.
    type Signature: Clone + Eq + fmt::Debug + Send + Sync;

    /// Name of the scheme, for logs and key files.
    const NAME: &'static str;

    /// Whether signing spends state.
    const KEY_STATE: KeyState;

    /// The public key of a secret key.
    fn public_key(secret: &Self::SecretKey) -> Self::PublicKey;

    /// Signs a root, with the leaf a stateful key spends.
    ///
    /// A stateless scheme ignores the leaf.
    ///
    /// # Errors
    ///
    /// Fails when a stateful scheme gets no leaf, or a leaf outside its key's supply.
    fn sign(
        secret: &Self::SecretKey,
        leaf: Option<Leaf>,
        root: Root,
    ) -> Result<Self::Signature, SchemeError>;

    /// Whether a signature over a root verifies under a public key.
    fn verify(
        public: &Self::PublicKey,
        leaf: Option<Leaf>,
        root: Root,
        signature: &Self::Signature,
    ) -> bool;

    /// One signature standing for all of them, when the scheme aggregates.
    ///
    /// Returns nothing for an empty set, or when the scheme has no aggregation.
    fn aggregate(signatures: &[Self::Signature]) -> Option<Self::Signature>;
}

/// Why a scheme refused to sign.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum SchemeError {
    /// A stateful scheme was asked to sign without a leaf.
    #[error("the {scheme} scheme signs only with a one-time leaf")]
    MissingLeaf {
        /// Name of the scheme.
        scheme: &'static str,
    },
    /// The leaf lies outside the key's supply.
    #[error("leaf {leaf} is outside the key's {leaves} leaves")]
    LeafOutOfRange {
        /// The leaf asked for.
        leaf: u64,
        /// Leaves the key holds.
        leaves: u64,
    },
}

/// BLS12-381 with proof of possession, the scheme of every fork so far.
///
/// See the phase0 beacon chain spec and draft-irtf-cfrg-bls-signature-05.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bls;

impl SignatureScheme for Bls {
    type SecretKey = SecretKey;
    type PublicKey = BlsPubkey;
    type Signature = BlsSignature;

    const NAME: &'static str = "bls12-381";
    const KEY_STATE: KeyState = KeyState::Stateless;

    fn public_key(secret: &SecretKey) -> BlsPubkey {
        BlsPubkey(secret.public_key().to_bytes())
    }

    fn sign(
        secret: &SecretKey,
        _leaf: Option<Leaf>,
        root: Root,
    ) -> Result<BlsSignature, SchemeError> {
        Ok(BlsSignature(secret.sign(&root.0).to_bytes()))
    }

    fn verify(
        public: &BlsPubkey,
        _leaf: Option<Leaf>,
        root: Root,
        signature: &BlsSignature,
    ) -> bool {
        // Decompression checks the curve and the subgroup, so a malformed input is rejected.
        let Ok(key) = PublicKey::from_bytes(&public.0) else {
            return false;
        };
        let Ok(signature) = Signature::from_bytes(&signature.0) else {
            return false;
        };
        signature.verify(&key, &root.0)
    }

    fn aggregate(signatures: &[BlsSignature]) -> Option<BlsSignature> {
        let points = signatures
            .iter()
            .map(|signature| Signature::from_bytes(&signature.0).ok())
            .collect::<Option<Vec<_>>>()?;
        let aggregate = Signature::aggregate(&points).ok()?;
        Some(BlsSignature(aggregate.to_bytes()))
    }
}
