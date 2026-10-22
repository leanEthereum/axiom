//! Sparse Merkle trees over one-time public keys, split into one top tree and many bottom trees.
//!
//! # Overview
//!
//! A key of lifetime L = 2^h has one leaf per epoch, under a tree of depth h.
//! Storing all of it is out of reach at h = 32, so the tree splits at depth h / 2.
//!
//! - The top tree holds levels h / 2 to h: one node per bottom tree, up to the root.
//! - Bottom tree i holds levels 0 to h / 2 over epochs [i * 2^(h/2), (i + 1) * 2^(h/2)).
//!
//! A key keeps the top tree and two consecutive bottom trees, so it signs inside a sliding window.
//!
//! A tree may be sparse: only a contiguous run of nodes exists on each level.
//! Each stored level starts at an even index and ends at an odd one, padded with random nodes.
//! Then every parent has both children, and a padding node never needs a preimage.
//!
//! eprint 2025/055, section 5, uses this top-bottom split for the synchronized scheme.

use crate::{
    codec::{ELEMENT_BYTES, OFFSET_BYTES, Reader, Writer},
    error::DecodeError,
    tweak_hash::TweakHash,
    words::Digest,
};

/// One stored level of a tree: a contiguous run of nodes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Layer {
    /// Index of the first node within its level.
    start: u64,
    /// The nodes, in index order.
    nodes: Vec<Digest>,
}

impl Layer {
    /// A run of nodes padded to start at an even index and end at an odd one.
    ///
    /// The padding draws a node before the run when it starts odd, then after it when it ends even.
    fn padded(start: u64, nodes: Vec<Digest>, mut pad: impl FnMut() -> Digest) -> Self {
        let front = start % 2 == 1;
        let back = (start + nodes.len() as u64 - 1).is_multiple_of(2);
        let mut padded = Vec::with_capacity(nodes.len() + 2);
        if front {
            padded.push(pad());
        }
        padded.extend(nodes);
        if back {
            padded.push(pad());
        }
        Self {
            start: start - u64::from(front),
            nodes: padded,
        }
    }

    /// The parents of a padded run, one per pair of siblings, at the next level.
    fn parents(&self, hash: &TweakHash, parent_level: u8) -> Vec<Digest> {
        let first_parent = self.start / 2;
        let (pairs, _) = self.nodes.as_chunks::<2>();
        pairs
            .iter()
            .enumerate()
            .map(|(i, [left, right])| {
                // Invariant: levels hold at most 2^32 nodes, so positions fit 32 bits.
                hash.node(parent_level, (first_parent + i as u64) as u32, left, right)
            })
            .collect()
    }

    /// The node at an index of the level, if stored.
    fn node(&self, index: u64) -> Option<&Digest> {
        let offset = index.checked_sub(self.start)?;
        self.nodes.get(usize::try_from(offset).ok()?)
    }

    /// Bytes of the encoding: start, offset, then the nodes.
    const fn encoded_len(&self, hash_len: usize) -> usize {
        8 + OFFSET_BYTES + self.nodes.len() * hash_len * ELEMENT_BYTES
    }

    /// Appends the encoding.
    fn encode(&self, writer: &mut Writer) {
        writer.u64(self.start);
        writer.offset(8 + OFFSET_BYTES);
        writer.words(&self.nodes);
    }

    /// Decodes a layer that spans all of its bytes.
    fn decode(bytes: &[u8], hash_len: usize) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes);
        let start = reader.u64()?;
        reader.offset(8 + OFFSET_BYTES)?;
        let nodes = reader.words_to_end(hash_len)?;
        Ok(Self { start, nodes })
    }
}

/// The upper levels of a tree, from a lowest stored level to the root.
///
/// # Invariants
///
/// Every layer below the last starts at an even index and holds an even number of nodes.
/// The last layer holds the subtree's root first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Subtree {
    /// Depth h of the full tree.
    depth: u64,
    /// The full tree's level of the first stored layer.
    lowest: u64,
    /// Stored levels, lowest first.
    layers: Vec<Layer>,
}

impl Subtree {
    /// The top tree over a run of bottom-tree roots, padded with nodes drawn from a source.
    pub(crate) fn top(
        hash: &TweakHash,
        depth: u32,
        first_root: u64,
        roots: Vec<Digest>,
        mut pad: impl FnMut() -> Digest,
    ) -> Self {
        let lowest = depth / 2;
        let mut layers = vec![Layer::padded(first_root, roots, &mut pad)];
        for level in lowest..depth {
            let below = layers.last().expect("the lowest layer is pushed first");
            let parents = below.parents(hash, (level + 1) as u8);
            layers.push(Layer::padded(below.start / 2, parents, &mut pad));
        }
        Self {
            depth: u64::from(depth),
            lowest: u64::from(lowest),
            layers,
        }
    }

    /// Bottom tree number index over its 2^(h/2) leaves, with its root alone on top.
    ///
    /// A full, aligned run of leaves needs no padding below the root.
    pub(crate) fn bottom(hash: &TweakHash, depth: u32, index: u64, leaves: Vec<Digest>) -> Self {
        let half = depth / 2;
        debug_assert_eq!(leaves.len() as u64, 1 << half);
        let mut layers = vec![Layer {
            start: index << half,
            nodes: leaves,
        }];
        for level in 0..half {
            let below = layers.last().expect("the leaves are pushed first");
            let parents = below.parents(hash, (level + 1) as u8);
            layers.push(Layer {
                start: below.start / 2,
                nodes: parents,
            });
        }
        Self {
            depth: u64::from(depth),
            lowest: 0,
            layers,
        }
    }

    /// The root: the first node of the highest layer.
    pub(crate) fn root(&self) -> Digest {
        self.layers
            .last()
            .expect("a subtree has a root layer")
            .nodes[0]
    }

    /// The bottom tree's index, the position of its root.
    pub(crate) fn index(&self) -> u64 {
        self.layers
            .last()
            .expect("a subtree has a root layer")
            .start
    }

    /// Appends the siblings on the path from a node of the lowest level up to the subtree's root.
    pub(crate) fn path(&self, position: u64, siblings: &mut Vec<Digest>) {
        let mut position = position;
        for layer in &self.layers[..self.layers.len() - 1] {
            // Invariant: a validated subtree stores both siblings of every stored node.
            let sibling = layer
                .node(position ^ 1)
                .expect("padded layers hold every sibling");
            siblings.push(*sibling);
            position /= 2;
        }
    }

    /// Bytes of the encoding.
    pub(crate) fn encoded_len(&self, hash_len: usize) -> usize {
        8 + 8
            + OFFSET_BYTES
            + self
                .layers
                .iter()
                .map(|layer| OFFSET_BYTES + layer.encoded_len(hash_len))
                .sum::<usize>()
    }

    /// Appends the encoding: depth, lowest level, then the list of layers.
    pub(crate) fn encode(&self, writer: &mut Writer, hash_len: usize) {
        writer.u64(self.depth);
        writer.u64(self.lowest);
        writer.offset(8 + 8 + OFFSET_BYTES);

        // A list of variable-size items: one offset per item, from the list's start, then the items.
        let mut offset = OFFSET_BYTES * self.layers.len();
        for layer in &self.layers {
            writer.offset(offset);
            offset += layer.encoded_len(hash_len);
        }
        for layer in &self.layers {
            layer.encode(writer);
        }
    }

    /// Decodes a subtree and checks it has exactly the shape the caller expects.
    pub(crate) fn decode(
        bytes: &[u8],
        hash_len: usize,
        expected: &Self,
    ) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes);
        let depth = reader.u64()?;
        let lowest = reader.u64()?;
        reader.offset(8 + 8 + OFFSET_BYTES)?;
        let list = reader.take(reader.remaining())?;
        let subtree = Self {
            depth,
            lowest,
            layers: decode_list(list, hash_len)?,
        };
        subtree.check_shape(expected)?;
        Ok(subtree)
    }

    /// Checks that every layer covers the same indices as the expected tree's.
    ///
    /// The shape alone is checked: the nodes themselves are the stored key's secret work.
    fn check_shape(&self, expected: &Self) -> Result<(), DecodeError> {
        if (self.depth, self.lowest, self.layers.len())
            != (expected.depth, expected.lowest, expected.layers.len())
        {
            return Err(DecodeError::Count {
                list: "tree layers",
                expected: expected.layers.len(),
                actual: self.layers.len(),
            });
        }
        for (index, (layer, wanted)) in self.layers.iter().zip(&expected.layers).enumerate() {
            if (layer.start, layer.nodes.len()) != (wanted.start, wanted.nodes.len()) {
                return Err(DecodeError::Layer {
                    layer: index,
                    start: layer.start,
                    len: layer.nodes.len(),
                });
            }
        }
        Ok(())
    }

    /// A subtree of the given shape with zero nodes, to check a decoded one against.
    pub(crate) fn shape_of_top(depth: u32, first_root: u64, roots: usize) -> Self {
        let zero = Digest::default();
        let mut layers = vec![Layer::padded(first_root, vec![zero; roots], || zero)];
        for _ in depth / 2..depth {
            let below = layers.last().expect("the lowest layer is pushed first");
            let parents = vec![zero; below.nodes.len() / 2];
            layers.push(Layer::padded(below.start / 2, parents, || zero));
        }
        Self {
            depth: u64::from(depth),
            lowest: u64::from(depth / 2),
            layers,
        }
    }

    /// A bottom tree of the given shape with zero nodes.
    pub(crate) fn shape_of_bottom(depth: u32, index: u64) -> Self {
        let half = depth / 2;
        let layers = (0..=half)
            .map(|level| Layer {
                start: (index << half) >> level,
                nodes: vec![Digest::default(); 1 << (half - level)],
            })
            .collect();
        Self {
            depth: u64::from(depth),
            lowest: 0,
            layers,
        }
    }
}

/// Decodes an SSZ list of variable-size layers.
fn decode_list(bytes: &[u8], hash_len: usize) -> Result<Vec<Layer>, DecodeError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    // The first offset counts the offsets: it points just past them.
    let mut reader = Reader::new(bytes);
    let first = reader.u32()? as usize;
    if first == 0 || !first.is_multiple_of(OFFSET_BYTES) || first > bytes.len() {
        return Err(DecodeError::Offset {
            expected: OFFSET_BYTES,
            actual: first,
        });
    }
    let mut offsets = vec![first];
    for _ in 1..first / OFFSET_BYTES {
        offsets.push(reader.u32()? as usize);
    }
    offsets.push(bytes.len());
    offsets
        .windows(2)
        .map(|pair| {
            if pair[0] > pair[1] {
                return Err(DecodeError::Offset {
                    expected: pair[0],
                    actual: pair[1],
                });
            }
            Layer::decode(&bytes[pair[0]..pair[1]], hash_len)
        })
        .collect()
}

/// Recomputes the root from a leaf digest and its authentication path, siblings lowest first.
pub(crate) fn root_from_path(
    hash: &TweakHash,
    position: u64,
    leaf: Digest,
    siblings: &[Digest],
) -> Digest {
    let mut node = leaf;
    let mut position = position;
    for (level, sibling) in siblings.iter().enumerate() {
        // An even position is a left child, an odd one a right child.
        let (left, right) = if position.is_multiple_of(2) {
            (&node, sibling)
        } else {
            (sibling, &node)
        };
        position /= 2;
        // Invariant: paths hold at most 32 siblings and positions stay below 2^32.
        node = hash.node((level + 1) as u8, position as u32, left, right);
    }
    node
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        entropy::SeedStream,
        words::{PublicParameter, Words},
    };

    /// A hash and distinct leaves from a stream.
    fn fixture(leaves: usize) -> (TweakHash, Vec<Digest>, SeedStream) {
        let mut stream = SeedStream::new(b"merkle");
        let hash = TweakHash::new(PublicParameter::sample(&mut stream), 7, 4);
        let leaves = (0..leaves).map(|_| Words::sample(7, &mut stream)).collect();
        (hash, leaves, stream)
    }

    #[test]
    fn padding_aligns_a_run_to_whole_sibling_pairs() {
        // Fixture state: runs [3, 4], [2, 3], and [5] at one level.
        let pad = Digest::default();
        let node = Words::from_slice(&[crate::field::KoalaBear::ONE]);

        // Starts odd and ends even: one pad on each side, from index 2 to 5.
        let layer = Layer::padded(3, vec![node, node], || pad);
        assert_eq!((layer.start, layer.nodes), (2, vec![pad, node, node, pad]));

        // Already aligned: no padding.
        let layer = Layer::padded(2, vec![node, node], || pad);
        assert_eq!((layer.start, layer.nodes), (2, vec![node, node]));

        // A lone odd node gets its left sibling.
        let layer = Layer::padded(5, vec![node], || pad);
        assert_eq!((layer.start, layer.nodes), (4, vec![pad, node]));
    }

    #[test]
    fn every_path_of_a_split_tree_leads_to_the_root() {
        // Fixture state: depth 4, so 4 bottom trees of 4 leaves; bottom trees 1 and 2 exist.
        let (hash, leaves, mut stream) = fixture(8);
        let bottoms: Vec<Subtree> = (1..3)
            .map(|index| {
                let run = leaves[(index as usize - 1) * 4..index as usize * 4].to_vec();
                Subtree::bottom(&hash, 4, index, run)
            })
            .collect();
        let roots = bottoms.iter().map(Subtree::root).collect();
        let top = Subtree::top(&hash, 4, 1, roots, || Words::sample(7, &mut stream));

        // Every leaf of epochs 4 to 11 climbs to the root through its bottom tree, then the top tree.
        for (offset, leaf) in leaves.iter().enumerate() {
            let epoch = 4 + offset as u64;
            let bottom = &bottoms[offset / 4];
            let mut siblings = Vec::new();
            bottom.path(epoch, &mut siblings);
            top.path(bottom.index(), &mut siblings);
            assert_eq!(siblings.len(), 4);
            assert_eq!(root_from_path(&hash, epoch, *leaf, &siblings), top.root());

            // The same path does not authenticate the leaf at the neighbouring position.
            assert_ne!(
                root_from_path(&hash, epoch ^ 1, *leaf, &siblings),
                top.root()
            );
        }
    }

    #[test]
    fn subtrees_round_trip_through_bytes_and_shapes_are_checked() {
        let (hash, leaves, mut stream) = fixture(4);
        let bottom = Subtree::bottom(&hash, 4, 3, leaves);
        let top = Subtree::top(&hash, 4, 3, vec![bottom.root()], || {
            Words::sample(7, &mut stream)
        });

        for (tree, shape) in [
            (&bottom, Subtree::shape_of_bottom(4, 3)),
            (&top, Subtree::shape_of_top(4, 3, 1)),
        ] {
            let mut writer = Writer::default();
            tree.encode(&mut writer, 7);
            let bytes = writer.finish();
            assert_eq!(bytes.len(), tree.encoded_len(7));
            assert_eq!(Subtree::decode(&bytes, 7, &shape).as_ref(), Ok(tree));
        }

        // The bottom tree's bytes do not have the shape of bottom tree 2.
        let mut writer = Writer::default();
        bottom.encode(&mut writer, 7);
        assert_eq!(
            Subtree::decode(&writer.finish(), 7, &Subtree::shape_of_bottom(4, 2)),
            Err(DecodeError::Layer {
                layer: 0,
                start: 12,
                len: 4
            })
        );
    }
}
