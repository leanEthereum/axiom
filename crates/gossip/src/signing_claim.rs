//! A signature claimed over an object, checked against one key or many.

use axiom_bls::{PublicKey, Signature};
use axiom_ssz::Ssz;
use axiom_types::{BlsPubkey, BlsSignature, Domain, SigningData};

/// An object, the domain it is signed in, and the signature a message claims over it.
///
/// Gossip rules check such claims one at a time, never batched.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SigningClaim<'a, T> {
    /// The signed object.
    object: &'a T,
    /// The signing domain.
    domain: Domain,
    /// The claimed signature.
    signature: &'a BlsSignature,
}

impl<'a, T: Ssz> SigningClaim<'a, T> {
    /// A claim that a signature covers an object in a domain.
    pub(crate) const fn new(object: &'a T, domain: Domain, signature: &'a BlsSignature) -> Self {
        Self {
            object,
            domain,
            signature,
        }
    }

    /// Whether one key made the signature.
    pub(crate) fn is_signed_by(&self, pubkey: &BlsPubkey) -> bool {
        let (Ok(key), Ok(signature)) = (
            PublicKey::from_bytes(&pubkey.0),
            Signature::from_bytes(&self.signature.0),
        ) else {
            return false;
        };
        signature.verify(&key, &self.signing_root())
    }

    /// Whether keys made the signature together, with an empty set and the empty signature accepted.
    ///
    /// See `eth_fast_aggregate_verify` in the Altair BLS extensions.
    pub(crate) fn is_signed_by_all(&self, pubkeys: &[BlsPubkey]) -> bool {
        let Ok(signature) = Signature::from_bytes(&self.signature.0) else {
            return false;
        };
        if pubkeys.is_empty() {
            return signature.is_infinity();
        }
        let Ok(keys) = pubkeys
            .iter()
            .map(|pubkey| PublicKey::from_bytes(&pubkey.0))
            .collect::<Result<Vec<_>, _>>()
        else {
            return false;
        };
        let refs: Vec<&PublicKey> = keys.iter().collect();
        signature.fast_aggregate_verify(&refs, &self.signing_root())
    }

    /// The message the signature covers.
    fn signing_root(&self) -> [u8; 32] {
        SigningData::signing_root(self.object, self.domain).0
    }
}
