//! The public key: the Merkle root over every active epoch's one-time key, and the hash parameter.

use crate::{
    codec::Writer,
    words::{Digest, PublicParameter},
};

/// A public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PublicKey {
    /// The Merkle root.
    pub(crate) root: Digest,
    /// The public parameter of the tweakable hash.
    pub(crate) parameter: PublicParameter,
}

impl PublicKey {
    /// The Merkle root.
    #[must_use]
    pub const fn root(&self) -> &Digest {
        &self.root
    }

    /// The public parameter.
    #[must_use]
    pub const fn parameter(&self) -> &PublicParameter {
        &self.parameter
    }

    /// The encoding: the root's elements, then the parameter's.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::default();
        writer.elements(self.root.elements());
        writer.elements(&self.parameter.0);
        writer.finish()
    }
}
