//! Builder preferences: what a proposer tells one builder ahead of a slot, out of protocol.
//!
//! See the Gloas builder and validator specs of the builder API.

use axiom_ssz::{ByteList, Const, Container, DecodeError, FieldDecoder, FieldVisitor, List, Ssz};

use crate::{BlsPubkey, BlsSignature, Gwei, Slot};

/// Most bytes of a builder's authentication data: MAX_BUILDER_AUTH_DATA_SIZE.
///
/// See the constants of the Gloas builder spec of the builder API.
pub type MaxBuilderAuthDataSize = Const<4096>;

/// Most bytes of a builder URL: MAX_BUILDER_URL_SIZE.
///
/// See `BuilderPreferencesEntry` in the Gloas types of beacon-APIs.
pub type MaxBuilderUrlSize = Const<2048>;

/// Most entries one submission of builder preferences holds.
///
/// It is MAX_BUILDER_ENTRIES * (MIN_SEED_LOOKAHEAD + 1) * SLOTS_PER_EPOCH, fixed at 4096.
/// See the builder preferences route of beacon-APIs.
pub type MaxBuilderPreferencesEntries = Const<4096>;

/// Opaque bytes a builder and a proposer agreed on, for one proposal slot.
///
/// See `BuilderRequestAuth` in the Gloas validator spec of the builder API.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuilderRequestAuth {
    /// The agreed bytes; empty is invalid.
    pub data: ByteList<MaxBuilderAuthDataSize>,

    /// The proposal slot the request is for.
    pub slot: Slot,
}

impl Container for BuilderRequestAuth {
    const FIELDS: &'static [Option<usize>] = &[None, Slot::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.data);
        visitor.field(&self.slot);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            data: fields.field()?,
            slot: fields.field()?,
        })
    }
}

/// A builder request authentication with its proposer's signature.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignedBuilderRequestAuth {
    /// The authentication.
    pub message: BuilderRequestAuth,

    /// Proposer's signature under the builder request domain.
    pub signature: BlsSignature,
}

impl Container for SignedBuilderRequestAuth {
    const FIELDS: &'static [Option<usize>] = &[None, BlsSignature::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.message);
        visitor.field(&self.signature);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            message: fields.field()?,
            signature: fields.field()?,
        })
    }
}

/// What a proposer accepts from one builder.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BuilderPreferences {
    /// Largest execution-layer payment the proposer accepts from the builder.
    pub max_execution_payment: Gwei,
}

impl Container for BuilderPreferences {
    const FIELDS: &'static [Option<usize>] = &[Gwei::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.max_execution_payment);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            max_execution_payment: fields.field()?,
        })
    }
}

/// A proposer's preferences for one builder, with the authentication the builder checks.
///
/// See `submitBuilderPreferences` in the builder API.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuilderPreferencesRequest {
    /// The preferences.
    pub preferences: BuilderPreferences,

    /// The proposer's signed authentication.
    pub auth: SignedBuilderRequestAuth,
}

impl Container for BuilderPreferencesRequest {
    const FIELDS: &'static [Option<usize>] = &[BuilderPreferences::FIXED_SIZE, None];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.preferences);
        visitor.field(&self.auth);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            preferences: fields.field()?,
            auth: fields.field()?,
        })
    }
}

/// One proposer's preferences for one builder, as a validator client hands them to its node.
///
/// See `BuilderPreferencesEntry` in the Gloas types of beacon-APIs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuilderPreferencesEntry {
    /// The proposer the preferences belong to.
    pub proposer_pubkey: BlsPubkey,

    /// The builder's URL, as UTF-8 bytes; empty is invalid.
    pub url: ByteList<MaxBuilderUrlSize>,

    /// The proposer's signed authentication, forwarded unchanged.
    pub auth: SignedBuilderRequestAuth,

    /// Largest execution-layer payment the proposer accepts from the builder.
    pub max_execution_payment: Gwei,
}

impl BuilderPreferencesEntry {
    /// The request the builder receives for this entry.
    #[must_use]
    pub fn request(&self) -> BuilderPreferencesRequest {
        BuilderPreferencesRequest {
            preferences: BuilderPreferences {
                max_execution_payment: self.max_execution_payment,
            },
            auth: self.auth.clone(),
        }
    }
}

impl Container for BuilderPreferencesEntry {
    const FIELDS: &'static [Option<usize>] = &[BlsPubkey::FIXED_SIZE, None, None, Gwei::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.proposer_pubkey);
        visitor.field(&self.url);
        visitor.field(&self.auth);
        visitor.field(&self.max_execution_payment);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            proposer_pubkey: fields.field()?,
            url: fields.field()?,
            auth: fields.field()?,
            max_execution_payment: fields.field()?,
        })
    }
}

/// One submission of builder preferences, as its SSZ body lists them.
pub type BuilderPreferencesEntries = List<BuilderPreferencesEntry, MaxBuilderPreferencesEntries>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_survives_its_encoding() {
        // Fixture state: a 32-byte URL and 3 bytes of auth data, for slot 9.
        let entry = BuilderPreferencesEntry {
            proposer_pubkey: BlsPubkey([7; 48]),
            url: ByteList::try_from(b"http://builder.example:18550/api".as_slice()).unwrap(),
            auth: SignedBuilderRequestAuth {
                message: BuilderRequestAuth {
                    data: ByteList::try_from(vec![1, 2, 3]).unwrap(),
                    slot: Slot(9),
                },
                signature: BlsSignature([5; 96]),
            },
            max_execution_payment: Gwei(1_000_000_000),
        };
        let bytes = entry.encode();

        // The URL and the auth are variable, so each takes a 4-byte offset.
        //
        //     fixed part:  48 key + 4 offset + 4 offset + 8 payment       = 64
        //     url:         32 bytes                                       = 32
        //     auth:        4 offset + 96 signature + 4 offset + 8 slot + 3 = 115
        assert_eq!(bytes.len(), 211);
        assert_eq!(BuilderPreferencesEntry::decode(&bytes), Ok(entry.clone()));

        // The request keeps the auth as signed, and the payment.
        assert_eq!(
            entry.request(),
            BuilderPreferencesRequest {
                preferences: BuilderPreferences {
                    max_execution_payment: Gwei(1_000_000_000),
                },
                auth: entry.auth,
            }
        );
    }
}
