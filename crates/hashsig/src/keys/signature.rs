//! A signature: the epoch's authentication path, the encoding randomness, and one value per chain.

use crate::{
    codec::{ELEMENT_BYTES, OFFSET_BYTES, Writer},
    words::{Digest, Randomness},
};

/// A signature for one message at one epoch.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Signature {
    /// Siblings from the epoch's leaf up to the root, lowest first.
    pub(crate) path: Vec<Digest>,
    /// The randomness under which the message encodes.
    pub(crate) randomness: Randomness,
    /// Chain i's value at the codeword's position x_i.
    pub(crate) chain_values: Vec<Digest>,
}

impl Signature {
    /// Siblings from the leaf up to the root.
    #[must_use]
    pub fn path(&self) -> &[Digest] {
        &self.path
    }

    /// The encoding randomness.
    #[must_use]
    pub const fn randomness(&self) -> &Randomness {
        &self.randomness
    }

    /// One value per chain.
    #[must_use]
    pub fn chain_values(&self) -> &[Digest] {
        &self.chain_values
    }

    /// The encoding, an SSZ container of the path, the randomness, and the chain values.
    ///
    /// ```text
    /// offset to path | randomness | offset to chain values | path (offset, siblings) | chain values
    /// ```
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let randomness_len = self.randomness.elements().len() * ELEMENT_BYTES;
        let path_len: usize = self
            .path
            .iter()
            .map(|sibling| sibling.elements().len() * ELEMENT_BYTES)
            .sum();
        let path_offset = 2 * OFFSET_BYTES + randomness_len;
        let chains_offset = path_offset + OFFSET_BYTES + path_len;

        let mut writer = Writer::with_capacity(chains_offset + self.chain_values.len() * 32);
        writer.offset(path_offset);
        writer.elements(self.randomness.elements());
        writer.offset(chains_offset);
        // The path is itself a container with one variable field.
        writer.offset(OFFSET_BYTES);
        writer.words(&self.path);
        writer.words(&self.chain_values);
        writer.finish()
    }
}
