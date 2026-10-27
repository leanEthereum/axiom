//! leanXMSS signatures as SSZ containers.
//!
//! A two-layer leanXMSS signature serializes to exactly the bytes leanXMSS defines for it.
//! See EIP-8450.

use axiom_ssz::{Const, Container, DecodeError, FieldDecoder, FieldVisitor, Ssz, Vector};

use crate::{
    Hash16, XmssLeafIndex,
    constants::{XMSS_CHAINS, XMSS_TREE_HEIGHT},
};

/// The chain values a one-time signature reveals, one per hash chain.
pub type XmssChainValues = Vector<Hash16, Const<XMSS_CHAINS>>;

/// The siblings from a leaf up to the root of its tree.
pub type XmssMerklePath = Vector<Hash16, Const<XMSS_TREE_HEIGHT>>;

/// One layer of a leanXMSS signature: a one-time signature and its authentication path.
///
/// Serializes to 16 * (1 + 58 + 16) = 1200 bytes.
/// See `XMSSLayerSignature` in EIP-8450.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct XmssLayerSignature {
    /// Randomizer that makes the message digest a codeword.
    pub randomness: Hash16,

    /// One value per chain, at the position its digit names.
    pub chain_values: XmssChainValues,

    /// Siblings from the leaf up to the root of its tree.
    pub merkle_path: XmssMerklePath,
}

impl Container for XmssLayerSignature {
    const FIELDS: &'static [Option<usize>] = &[
        Hash16::FIXED_SIZE,
        XmssChainValues::FIXED_SIZE,
        XmssMerklePath::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.randomness);
        visitor.field(&self.chain_values);
        visitor.field(&self.merkle_path);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            randomness: fields.field()?,
            chain_values: fields.field()?,
            merkle_path: fields.field()?,
        })
    }
}

/// A two-layer leanXMSS signature.
///
/// The bottom layer signs the message, and the top layer certifies the bottom tree's root.
/// Serializes to 4 + 1200 + 1200 = 2404 bytes.
/// See `XMSSSignature` in EIP-8450.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct XmssSignature {
    /// Leaf index the signature uses.
    pub leaf_index: XmssLeafIndex,

    /// One-time signature of the message, with its path in the bottom tree.
    pub bottom: XmssLayerSignature,

    /// One-time signature of the bottom tree's root, with its path in the top tree.
    pub top: XmssLayerSignature,
}

impl Container for XmssSignature {
    const FIELDS: &'static [Option<usize>] = &[
        XmssLeafIndex::FIXED_SIZE,
        XmssLayerSignature::FIXED_SIZE,
        XmssLayerSignature::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.leaf_index);
        visitor.field(&self.bottom);
        visitor.field(&self.top);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            leaf_index: fields.field()?,
            bottom: fields.field()?,
            top: fields.field()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts_match_the_lean_xmss_byte_sizes() {
        // One layer: randomizer 16 + 58 chain values * 16 + 16 path nodes * 16 = 1200 bytes.
        assert_eq!(XmssLayerSignature::FIXED_SIZE, Some(1200));

        // The whole signature: leaf index 4 + two layers of 1200 = 2404 bytes.
        assert_eq!(XmssSignature::FIXED_SIZE, Some(2404));
    }

    #[test]
    fn encoding_lays_the_leaf_index_then_bottom_then_top() {
        // Fixture state: leaf index 0x01020304, bottom randomizer all 0xaa, top path all 0xbb.
        let signature = XmssSignature {
            leaf_index: XmssLeafIndex(0x0102_0304),
            bottom: XmssLayerSignature {
                randomness: Hash16([0xaa; 16]),
                ..XmssLayerSignature::default()
            },
            top: XmssLayerSignature {
                merkle_path: Vector::repeat(Hash16([0xbb; 16])),
                ..XmssLayerSignature::default()
            },
        };

        let bytes = signature.encode();

        // The layout, with byte offsets:
        //
        //     0..4        leaf index, little-endian
        //     4..20       bottom randomizer
        //     1204..2148  top randomizer and chain values, all zero here
        //     2148..2404  top path
        assert_eq!(bytes[..4], [0x04, 0x03, 0x02, 0x01]);
        assert_eq!(bytes[4..20], [0xaa; 16]);
        assert!(bytes[20..2148].iter().all(|byte| *byte == 0));
        assert!(bytes[2148..].iter().all(|byte| *byte == 0xbb));

        // Decoding gives the same signature back.
        assert_eq!(XmssSignature::decode(&bytes).unwrap(), signature);
    }
}
