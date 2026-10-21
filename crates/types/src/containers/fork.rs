//! Fork versions and the data signatures commit to.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Ssz};

use crate::{Epoch, Root, Version};

/// The fork the state is on, and the one it came from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fork {
    /// Version before the latest fork.
    pub previous_version: Version,

    /// Version from the latest fork on.
    pub current_version: Version,

    /// Epoch the latest fork activated.
    pub epoch: Epoch,
}

impl Container for Fork {
    const FIELDS: &'static [Option<usize>] =
        &[Version::FIXED_SIZE, Version::FIXED_SIZE, Epoch::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.previous_version);
        visitor.field(&self.current_version);
        visitor.field(&self.epoch);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            previous_version: fields.field()?,
            current_version: fields.field()?,
            epoch: fields.field()?,
        })
    }
}

/// The fork version and chain identity a signature domain commits to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ForkData {
    /// Fork version the message is signed under.
    pub current_version: Version,

    /// Root of the genesis validator set, which identifies the chain.
    pub genesis_validators_root: Root,
}

impl Container for ForkData {
    const FIELDS: &'static [Option<usize>] = &[Version::FIXED_SIZE, Root::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.current_version);
        visitor.field(&self.genesis_validators_root);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            current_version: fields.field()?,
            genesis_validators_root: fields.field()?,
        })
    }
}

impl ForkData {
    /// Root of a fork version bound to a chain.
    ///
    /// See `compute_fork_data_root` in the phase0 beacon chain spec.
    #[must_use]
    pub fn root(current_version: Version, genesis_validators_root: Root) -> Root {
        Self {
            current_version,
            genesis_validators_root,
        }
        .hash_tree_root()
    }
}

impl Fork {
    /// Version that signs messages of an epoch, which may predate the latest fork.
    #[must_use]
    pub fn version_at(&self, epoch: Epoch) -> Version {
        if epoch < self.epoch {
            self.previous_version
        } else {
            self.current_version
        }
    }
}
