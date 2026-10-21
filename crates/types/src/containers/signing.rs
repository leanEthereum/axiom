//! The envelope every signed message is hashed into.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Ssz};

use crate::{Domain, Root};

/// A message root bound to the domain it is signed in.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SigningData {
    /// Root of the message being signed.
    pub object_root: Root,

    /// Domain that separates message kinds, forks, and chains.
    pub domain: Domain,
}

impl Container for SigningData {
    const FIELDS: &'static [Option<usize>] = &[Root::FIXED_SIZE, Domain::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.object_root);
        visitor.field(&self.domain);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            object_root: fields.field()?,
            domain: fields.field()?,
        })
    }
}
