//! The post-quantum key registry: registered keys, registrations, and owner authorizations.
//!
//! See EIP-8450.

use axiom_ssz::{
    Container, DecodeError, FieldDecoder, FieldVisitor, PersistentProgressiveList, ProgressiveList,
    Ssz,
};

use crate::{
    BlsPubkey, BlsSignature, Epoch, ExecutionAddress, Root, ValidatorIndex, XmssPublicKey,
    constants::PQ_KEYS_VERSION_UNSET, hstar::XmssSignature,
};

/// Registered post-quantum keys, one entry per validator, by validator index.
pub type ValidatorPqPublicKeys = PersistentProgressiveList<PqPublicKeys>;

/// Key authorizations made by withdrawal addresses and not yet used.
pub type PendingPqKeyAuthorizations = PersistentProgressiveList<PendingPqKeyAuthorization>;

/// Post-quantum key registrations included in a block.
pub type PqKeyRegistrations = ProgressiveList<SignedPqKeyRegistration>;

/// Key authorization requests of an execution payload.
pub type PqKeyAuthorizationRequests = ProgressiveList<PqKeyAuthorizationRequest>;

/// The post-quantum key of one validator, as the registry stores it.
///
/// See `PQPublicKeys` in EIP-8450.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PqPublicKeys {
    /// Parameter set of the key, or the unset version when no key is registered.
    pub version: u8,

    /// Root of the top tree followed by the public parameter.
    pub xmss_public_key: XmssPublicKey,
}

impl PqPublicKeys {
    /// Whether the entry holds a registered key.
    ///
    /// A validator without keys holds the all-zero entry, of the unset version.
    /// See `is_pq_registered` in EIP-8450.
    #[must_use]
    pub const fn is_registered(&self) -> bool {
        self.version != PQ_KEYS_VERSION_UNSET
    }
}

impl Container for PqPublicKeys {
    const FIELDS: &'static [Option<usize>] = &[u8::FIXED_SIZE, XmssPublicKey::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.version);
        visitor.field(&self.xmss_public_key);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            version: fields.field()?,
            xmss_public_key: fields.field()?,
        })
    }
}

/// The message of a registration: which validator, and which key.
///
/// See `PQKeyRegistration` in EIP-8450.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PqKeyRegistration {
    /// Validator the key is registered for.
    ///
    /// The proof of possession signs it, which ties the key to this validator.
    pub validator_index: ValidatorIndex,

    /// Key being registered.
    pub public_keys: PqPublicKeys,
}

impl Container for PqKeyRegistration {
    const FIELDS: &'static [Option<usize>] =
        &[ValidatorIndex::FIXED_SIZE, PqPublicKeys::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.validator_index);
        visitor.field(&self.public_keys);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            validator_index: fields.field()?,
            public_keys: fields.field()?,
        })
    }
}

/// A registration as a block carries it: the key, a proof of possession, and the authorization.
///
/// See `SignedPQKeyRegistration` in EIP-8450.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignedPqKeyRegistration {
    /// Validator and key being registered.
    pub message: PqKeyRegistration,

    /// Signature of the registration by the registered key, at the reserved leaf index.
    ///
    /// It proves that the registrant holds the secret key.
    pub possession: XmssSignature,

    /// Who authorized the registration.
    ///
    /// - The validator's BLS signature of the registration, on the operator path.
    /// - The BLS point at infinity, on the owner path.
    pub signature: BlsSignature,
}

impl Container for SignedPqKeyRegistration {
    const FIELDS: &'static [Option<usize>] = &[
        PqKeyRegistration::FIXED_SIZE,
        XmssSignature::FIXED_SIZE,
        BlsSignature::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.message);
        visitor.field(&self.possession);
        visitor.field(&self.signature);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            message: fields.field()?,
            possession: fields.field()?,
            signature: fields.field()?,
        })
    }
}

/// A key authorization made by a withdrawal address on the execution layer.
///
/// See `PQKeyAuthorizationRequest` in EIP-8450.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PqKeyAuthorizationRequest {
    /// Address that called the request contract.
    pub source_address: ExecutionAddress,

    /// Validator the authorization is for, named by its BLS public key.
    pub validator_pubkey: BlsPubkey,

    /// Hash tree root of the authorized keys.
    pub public_keys_root: Root,
}

impl Container for PqKeyAuthorizationRequest {
    const FIELDS: &'static [Option<usize>] = &[
        ExecutionAddress::FIXED_SIZE,
        BlsPubkey::FIXED_SIZE,
        Root::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.source_address);
        visitor.field(&self.validator_pubkey);
        visitor.field(&self.public_keys_root);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            source_address: fields.field()?,
            validator_pubkey: fields.field()?,
            public_keys_root: fields.field()?,
        })
    }
}

/// A key authorization waiting in the state for a matching registration.
///
/// See `PendingPQKeyAuthorization` in EIP-8450.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PendingPqKeyAuthorization {
    /// Validator the authorization is for.
    pub validator_index: ValidatorIndex,

    /// Withdrawal address that authorized the keys.
    pub source_address: ExecutionAddress,

    /// Hash tree root of the authorized keys, which a registration must match.
    pub public_keys_root: Root,

    /// Last epoch at which a registration can use this authorization.
    pub expiry_epoch: Epoch,
}

impl Container for PendingPqKeyAuthorization {
    const FIELDS: &'static [Option<usize>] = &[
        ValidatorIndex::FIXED_SIZE,
        ExecutionAddress::FIXED_SIZE,
        Root::FIXED_SIZE,
        Epoch::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.validator_index);
        visitor.field(&self.source_address);
        visitor.field(&self.public_keys_root);
        visitor.field(&self.expiry_epoch);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            validator_index: fields.field()?,
            source_address: fields.field()?,
            public_keys_root: fields.field()?,
            expiry_epoch: fields.field()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::PQ_KEYS_VERSION_1;

    #[test]
    fn sizes_match_the_eip() {
        // A registry entry: version 1 + key 32 = 33 bytes, about 33 MB per million validators.
        assert_eq!(PqPublicKeys::FIXED_SIZE, Some(33));

        // A registration: index 8 + entry 33 + proof 2404 + BLS signature 96 = 2541 bytes.
        assert_eq!(SignedPqKeyRegistration::FIXED_SIZE, Some(2541));

        // A contract record: address 20 + BLS key 48 + root 32 = 100 bytes.
        assert_eq!(PqKeyAuthorizationRequest::FIXED_SIZE, Some(100));
    }

    #[test]
    fn only_the_unset_version_is_unregistered() {
        // The all-zero entry a new validator receives has no key.
        assert!(!PqPublicKeys::default().is_registered());

        // Version 1 with the all-zero key still counts: the version alone decides.
        let registered = PqPublicKeys {
            version: PQ_KEYS_VERSION_1,
            xmss_public_key: XmssPublicKey::ZERO,
        };
        assert!(registered.is_registered());
    }
}
