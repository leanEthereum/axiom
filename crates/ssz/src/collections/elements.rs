//! Encoding, decoding, and merkleization shared by vectors and lists.

use std::{borrow::Borrow, marker::PhantomData};

use crate::{
    BYTES_PER_CHUNK, BYTES_PER_LENGTH_OFFSET, DecodeError, GeneralizedIndex, MerkleProof,
    Merkleizer, ProgressiveMerkleizer, Root, Ssz, ZeroHashes, offset::Offset,
};

/// The rules for a run of same-typed elements, which vectors and lists share.
///
/// A vector and a list encode their elements identically.
/// They differ only in how the length is checked and whether it is mixed into the root.
pub(crate) struct Elements<T>(PhantomData<T>);

impl<T: Ssz> Elements<T> {
    /// Encoded length of a run of elements.
    pub(crate) fn encoded_len(items: &[T]) -> usize {
        match T::FIXED_SIZE {
            Some(size) => size * items.len(),
            // Each variable-size element costs its offset plus its own bytes.
            None => items
                .iter()
                .map(|item| BYTES_PER_LENGTH_OFFSET + item.encoded_len())
                .sum(),
        }
    }

    /// Appends the encoding of a run of elements.
    ///
    /// Variable-size elements are laid out as a table of offsets, then the bodies.
    ///
    /// ```text
    /// [offset 0][offset 1][offset 2][body 0][body 1][body 2]
    ///  each offset counts bytes from the start of the run
    /// ```
    pub(crate) fn encode_to(items: &[T], out: &mut Vec<u8>) {
        if T::FIXED_SIZE.is_some() {
            for item in items {
                item.encode_to(out);
            }
            return;
        }

        // Phase 1: write the offset table, each offset counting bodies before it.
        let mut offset = BYTES_PER_LENGTH_OFFSET * items.len();
        for item in items {
            out.extend_from_slice(&Offset::encode(offset));
            offset += item.encoded_len();
        }

        // Phase 2: write the bodies in order.
        for item in items {
            item.encode_to(out);
        }
    }

    /// Decodes a run of elements spanning exactly the given bytes.
    ///
    /// The limit is checked before any element is decoded, so a hostile length costs nothing.
    pub(crate) fn decode(bytes: &[u8], limit: usize) -> Result<Vec<T>, DecodeError> {
        match T::FIXED_SIZE {
            Some(size) => Self::decode_fixed(bytes, size, limit),
            None => Self::decode_variable(bytes, limit),
        }
    }

    /// Depth of the tree of a run of elements, sized for the limit.
    ///
    /// Basic elements pack into chunks, while composite elements take one leaf each.
    pub(crate) const fn depth(limit: usize) -> usize {
        match T::PACKED_SIZE {
            Some(size) => Merkleizer::depth_for((limit * size).div_ceil(BYTES_PER_CHUNK)),
            None => Merkleizer::depth_for(limit),
        }
    }

    /// Number of leaves a run of this many elements fills.
    pub(crate) const fn leaf_count(length: usize) -> usize {
        match T::PACKED_SIZE {
            Some(size) => (length * size).div_ceil(BYTES_PER_CHUNK),
            None => length,
        }
    }

    /// Root of a run of elements, in a tree sized for the limit.
    pub(crate) fn root(items: &[T], limit: usize) -> Root {
        Self::subtree_root(items, Self::depth(limit))
    }

    /// Root of a run of elements, in a tree of the given depth.
    ///
    /// Basic elements pack into chunks, while composite elements contribute one root each.
    /// The run starts on a leaf boundary, and leaves past its end are zero.
    pub(crate) fn subtree_root(items: &[T], depth: usize) -> Root {
        let mut merkleizer = Merkleizer::with_depth(depth);
        match T::PACKED_SIZE {
            Some(size) => {
                // Packed values are their own encoding, laid end to end.
                let mut packed = Vec::with_capacity(size * items.len());
                for item in items {
                    item.encode_to(&mut packed);
                }
                merkleizer.push_bytes(&packed);
            }
            None => {
                for item in items {
                    merkleizer.push(item.hash_tree_root());
                }
            }
        }
        merkleizer.finish()
    }

    /// Proves a node of the tree of a run of elements, sized for the limit.
    ///
    /// The tree's leaves are chunks of packed basic elements, or one root per composite element.
    /// A node below a composite element's leaf is proven inside the element first.
    /// Returns nothing for a node in the zero padding past the last element.
    pub(crate) fn prove<R: Borrow<T>>(
        items: &[R],
        limit: usize,
        index: GeneralizedIndex,
    ) -> Option<(Root, MerkleProof)> {
        let (leaves, depth) = match T::PACKED_SIZE {
            Some(size) => {
                let mut packed = Vec::with_capacity(size * items.len());
                for item in items {
                    item.borrow().encode_to(&mut packed);
                }
                let chunks = packed
                    .chunks(BYTES_PER_CHUNK)
                    .map(Root::from_partial)
                    .collect::<Vec<_>>();
                let depth = Merkleizer::depth_for((limit * size).div_ceil(BYTES_PER_CHUNK));
                (chunks, depth)
            }
            None => (
                items
                    .iter()
                    .map(|item| item.borrow().hash_tree_root())
                    .collect(),
                Merkleizer::depth_for(limit),
            ),
        };
        if index.depth() as usize <= depth {
            // A node of the tree itself: the root of the leaves below it.
            let height = depth - index.depth() as usize;
            let first = (index.position() as usize) << height;
            let node = match leaves.get(first..) {
                Some(below) if !below.is_empty() => {
                    let mut merkleizer = Merkleizer::with_depth(height);
                    for leaf in below.iter().take(1 << height) {
                        merkleizer.push(*leaf);
                    }
                    merkleizer.finish()
                }
                // Past the last element the tree holds zero subtrees.
                _ => ZeroHashes::at(height),
            };
            // Its proof is the upper part of the proof of the first leaf below it.
            let mut proof = MerkleProof::generate(&leaves, depth, first);
            proof.branch.drain(..height);
            return Some((node, proof));
        }

        // A node inside one element's own tree.
        let (position, inner) = (0..leaves.len()).find_map(|position| {
            index
                .relative_to(GeneralizedIndex::at(depth, position as u64))
                .map(|inner| (position, inner))
        })?;
        if T::PACKED_SIZE.is_some() {
            return None;
        }
        let (leaf, mut proof) = items.get(position)?.borrow().prove(inner)?;
        proof
            .branch
            .extend(MerkleProof::generate(&leaves, depth, position).branch);
        Some((leaf, proof))
    }

    /// Root of a run of elements, in a progressive tree that grows with the length.
    ///
    /// Basic elements pack into chunks, while composite elements contribute one root each.
    /// See EIP-7916.
    pub(crate) fn progressive_root(items: &[T]) -> Root {
        let mut merkleizer = ProgressiveMerkleizer::new();
        match T::PACKED_SIZE {
            Some(_) => {
                // Packed values are their own encoding, laid end to end.
                let mut packed = Vec::with_capacity(Self::encoded_len(items));
                Self::encode_to(items, &mut packed);
                merkleizer.push_bytes(&packed);
            }
            None => {
                for item in items {
                    merkleizer.push(item.hash_tree_root());
                }
            }
        }
        merkleizer.finish()
    }

    /// Decodes a run of fixed-size elements.
    fn decode_fixed(bytes: &[u8], size: usize, limit: usize) -> Result<Vec<T>, DecodeError> {
        // A zero-size element cannot occur in SSZ, so the division is safe.
        if !bytes.len().is_multiple_of(size) {
            return Err(DecodeError::TrailingBytes {
                element_size: size,
                length: bytes.len(),
            });
        }

        let count = bytes.len() / size;
        if count > limit {
            return Err(DecodeError::TooManyElements {
                limit,
                actual: count,
            });
        }

        bytes.chunks_exact(size).map(T::decode).collect()
    }

    /// Decodes a run of variable-size elements behind an offset table.
    fn decode_variable(bytes: &[u8], limit: usize) -> Result<Vec<T>, DecodeError> {
        if bytes.is_empty() {
            return Ok(Vec::new());
        }

        // The first offset marks the end of the table, so it fixes the element count.
        let first = Offset::read(bytes, 0)?;
        if !first.is_multiple_of(BYTES_PER_LENGTH_OFFSET) || first == 0 {
            return Err(DecodeError::MisalignedOffsetTable(first));
        }
        if first > bytes.len() {
            return Err(DecodeError::OffsetOutOfBounds {
                offset: first,
                length: bytes.len(),
            });
        }

        let count = first / BYTES_PER_LENGTH_OFFSET;
        if count > limit {
            return Err(DecodeError::TooManyElements {
                limit,
                actual: count,
            });
        }

        // Each body runs from its offset to the next one, the last to the end of input.
        let mut items = Vec::with_capacity(count);
        let mut start = first;
        for index in 1..=count {
            let end = if index == count {
                bytes.len()
            } else {
                Offset::read(bytes, index * BYTES_PER_LENGTH_OFFSET)?
            };
            if end < start {
                return Err(DecodeError::OffsetsNotIncreasing {
                    previous: start,
                    next: end,
                });
            }
            if end > bytes.len() {
                return Err(DecodeError::OffsetOutOfBounds {
                    offset: end,
                    length: bytes.len(),
                });
            }
            items.push(T::decode(&bytes[start..end])?);
            start = end;
        }
        Ok(items)
    }
}
