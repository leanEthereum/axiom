//! Compatible unions: a selector byte naming one of several options of one tree shape.
//!
//! # Overview
//!
//! A union is written once by hand, as an enum with one variant per option.
//! The implementor declares the selectors, names the held option, shows its value, and decodes one.
//! Every SSZ operation then follows from that description.
//!
//! See EIP-8016, and the consensus specs' generic SSZ vectors that pin it.

mod visitors;

use visitors::{OptionEncoder, OptionLength, OptionProver, OptionRoot};

use crate::{DecodeError, GeneralizedIndex, MerkleProof, Root, Ssz};

/// Smallest selector an option may take.
///
/// Zero is reserved, so an all-zero encoding never names an option.
const MIN_SELECTOR: u8 = 1;

/// Largest selector an option may take.
///
/// The high bit is reserved for future extensions of the encoding.
const MAX_SELECTOR: u8 = 127;

/// Generalized index of the held option's root, the left child of the union's root.
const DATA_INDEX: GeneralizedIndex = GeneralizedIndex::new(2);

/// The options a compatible union can hold, each under its own selector.
///
/// # Invariants
///
/// The selectors lie between 1 and 127, ascend strictly, and number at least one.
/// The compiler checks that for every union used.
///
/// The selector of a value, the option shown, and the option decoded agree.
/// The options merkleize into compatible tree shapes, as EIP-8016 requires.
/// That is what lets one proof verify against every option declaring the proven field.
pub trait UnionOptions: Sized {
    /// Selector of every option, in ascending order.
    const SELECTORS: &'static [u8];

    /// Selector of the held option.
    fn selector(&self) -> u8;

    /// Shows the held option's value to the visitor.
    fn visit_option<V: OptionVisitor>(&self, visitor: &mut V);

    /// Decodes the option a declared selector names from the bytes that follow it.
    ///
    /// # Errors
    ///
    /// Fails when the bytes are not the encoding of that option.
    fn decode_option(selector: u8, bytes: &[u8]) -> Result<Self, DecodeError>;
}

/// A look at the value a union holds.
///
/// Encoding, length counting, merkleization, and proving are each one visitor.
/// The trait is sealed, because a union only ever meets the visitors of this crate.
pub trait OptionVisitor: visitors::Sealed {
    /// Visits the held option's value.
    fn option<T: Ssz>(&mut self, value: &T);
}

/// A value of one option among several, the spec's `CompatibleUnion`.
///
/// It encodes as the selector byte followed by the option's encoding.
/// Its root mixes the selector into the option's root, see EIP-8016.
///
/// A wrapper rather than a blanket implementation, since containers already claim one.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CompatibleUnion<O>(O);

impl<O: UnionOptions> CompatibleUnion<O> {
    /// Rejects at compile time a union whose selectors break the invariants.
    const SELECTORS_ARE_VALID: () = {
        let selectors = O::SELECTORS;
        assert!(!selectors.is_empty(), "a compatible union has an option");
        let mut index = 0;
        while index < selectors.len() {
            assert!(
                selectors[index] >= MIN_SELECTOR && selectors[index] <= MAX_SELECTOR,
                "a selector lies between 1 and 127"
            );
            assert!(
                index == 0 || selectors[index - 1] < selectors[index],
                "selectors ascend strictly"
            );
            index += 1;
        }
    };

    /// A union holding the given option.
    #[must_use]
    pub const fn new(option: O) -> Self {
        let () = Self::SELECTORS_ARE_VALID;
        Self(option)
    }

    /// The held option.
    #[must_use]
    pub const fn get(&self) -> &O {
        &self.0
    }

    /// The held option, by value.
    #[must_use]
    pub fn into_inner(self) -> O {
        self.0
    }

    /// Selector of the held option.
    #[must_use]
    pub fn selector(&self) -> u8 {
        self.0.selector()
    }

    /// Root of the held option, before the selector is mixed in.
    fn data_root(&self) -> Root {
        let mut root = OptionRoot::new();
        self.0.visit_option(&mut root);
        root.into_root()
    }
}

impl<O: UnionOptions> From<O> for CompatibleUnion<O> {
    fn from(option: O) -> Self {
        Self::new(option)
    }
}

impl<O: UnionOptions> Ssz for CompatibleUnion<O> {
    // The selector is read per value, so no union is fixed-size, even over fixed-size options.
    const FIXED_SIZE: Option<usize> = None;

    fn encoded_len(&self) -> usize {
        let mut length = OptionLength::new();
        self.0.visit_option(&mut length);
        1 + length.total()
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        debug_assert!(
            O::SELECTORS.contains(&self.selector()),
            "selector {} is not declared",
            self.selector()
        );
        out.push(self.selector());
        self.0.visit_option(&mut OptionEncoder::new(out));
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (&selector, data) = bytes.split_first().ok_or(DecodeError::TooShort {
            minimum: 1,
            actual: bytes.len(),
        })?;

        // Invariant: only a declared selector reaches the option decoder.
        // Reserved selectors are never declared, so this check rejects them too.
        if !O::SELECTORS.contains(&selector) {
            return Err(DecodeError::UnknownSelector { selector });
        }
        O::decode_option(selector, data).map(Self::new)
    }

    fn hash_tree_root(&self) -> Root {
        self.data_root().mix_in_selector(self.selector())
    }

    /// Proves a node of the union's tree, descending into the held option below its root.
    ///
    /// The option's root is node 2 and the selector chunk node 3.
    /// The option's own proof comes first, then the selector chunk as the last sibling.
    fn prove(&self, index: GeneralizedIndex) -> Option<(Root, MerkleProof)> {
        if index == GeneralizedIndex::ROOT {
            return Some((self.hash_tree_root(), MerkleProof::default()));
        }
        let inner = index.relative_to(DATA_INDEX)?;
        let mut prover = OptionProver::new(inner);
        self.0.visit_option(&mut prover);
        let (node, mut proof) = prover.into_result()?;
        proof.branch.push(Root::from_partial(&[self.selector()]));
        Some((node, proof))
    }
}

#[cfg(test)]
mod tests;
