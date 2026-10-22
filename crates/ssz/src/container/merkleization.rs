//! The two tree shapes a container's field roots can take.

use crate::{
    BYTES_PER_CHUNK, GeneralizedIndex, MerkleProof, Merkleizer, ProgressiveMerkleizer, Root,
};

/// Most positions a progressive container can declare, one bit each in a chunk.
const MAX_PROGRESSIVE_POSITIONS: usize = BYTES_PER_CHUNK * 8;

/// How a container's field roots form its hash tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Merkleization {
    /// A binary tree with one leaf per field, padded to a power of two.
    Binary,

    /// A progressive tree over declared positions, mixed with the bitmap of active ones.
    ///
    /// Each entry says whether a position holds a field, in declaration order.
    /// An inactive position hashes as a zero chunk, so later fields keep their place.
    /// The last entry is set, and there are at most 256 entries.
    /// See EIP-7495.
    Progressive(&'static [bool]),
}

impl Merkleization {
    /// Whether the shape fits a container with the given number of fields.
    #[must_use]
    pub const fn fits(self, field_count: usize) -> bool {
        match self {
            Self::Binary => true,
            Self::Progressive(active) => {
                let mut set = 0;
                let mut index = 0;
                while index < active.len() {
                    if active[index] {
                        set += 1;
                    }
                    index += 1;
                }
                let ends_active = match active.last() {
                    Some(last) => *last,
                    None => false,
                };
                set == field_count && ends_active && active.len() <= MAX_PROGRESSIVE_POSITIONS
            }
        }
    }

    /// Generalized index of a field in a container with the given number of fields.
    ///
    /// # Panics
    ///
    /// Panics when the container has no field at that index.
    #[must_use]
    pub fn field_index(self, field_count: usize, field: usize) -> GeneralizedIndex {
        assert!(field < field_count, "field {field} does not exist");
        match self {
            Self::Binary => GeneralizedIndex::at(Merkleizer::depth_for(field_count), field as u64),
            // The progressive tree is the left child, the bitmap chunk the right one.
            Self::Progressive(active) => {
                GeneralizedIndex::new(2)
                    .concat(ProgressiveMerkleizer::leaf_index(
                        Self::position(active, field) as u64,
                    ))
            }
        }
    }

    /// Proof that a field's root sits at its leaf, given every field root in order.
    ///
    /// # Panics
    ///
    /// Panics when the container has no field at that index.
    #[must_use]
    pub fn field_proof(self, field_roots: &[Root], field: usize) -> MerkleProof {
        assert!(field < field_roots.len(), "field {field} does not exist");
        match self {
            Self::Binary => {
                MerkleProof::generate(field_roots, Merkleizer::depth_for(field_roots.len()), field)
            }
            Self::Progressive(active) => {
                let mut leaves = Vec::with_capacity(active.len());
                let mut roots = field_roots.iter();
                for is_active in active {
                    leaves.push(match is_active {
                        true => roots.next().copied().unwrap_or(Root::ZERO),
                        false => Root::ZERO,
                    });
                }
                let mut proof =
                    ProgressiveMerkleizer::proof(&leaves, Self::position(active, field));
                proof.branch.push(Self::active_fields_chunk(active));
                proof
            }
        }
    }

    /// Position of a field among the declared positions.
    ///
    /// The field is the n-th active position, counting from zero.
    fn position(active: &[bool], field: usize) -> usize {
        active
            .iter()
            .enumerate()
            .filter(|(_, is_active)| **is_active)
            .nth(field)
            .map_or(active.len(), |(position, _)| position)
    }

    /// The bitmap of active positions, packed into one chunk, low bit first.
    fn active_fields_chunk(active: &[bool]) -> Root {
        let mut chunk = [0; BYTES_PER_CHUNK];
        for (position, _) in active.iter().enumerate().filter(|(_, bit)| **bit) {
            chunk[position / 8] |= 1 << (position % 8);
        }
        Root(chunk)
    }
}

/// A container's hash tree, fed one field root at a time.
#[derive(Clone, Debug)]
pub(super) enum FieldTree {
    /// A binary tree with one leaf per field.
    Binary(Merkleizer),

    /// A progressive tree over declared positions.
    Progressive {
        /// The tree over every position, active or not.
        merkleizer: ProgressiveMerkleizer,
        /// Which positions hold a field.
        active: &'static [bool],
        /// Next position to fill.
        position: usize,
    },
}

impl FieldTree {
    /// An empty tree for a container of the given shape and number of fields.
    pub(super) fn new(merkleization: Merkleization, field_count: usize) -> Self {
        debug_assert!(
            merkleization.fits(field_count),
            "progressive positions do not match the fields"
        );
        match merkleization {
            Merkleization::Binary => Self::Binary(Merkleizer::with_limit(field_count)),
            Merkleization::Progressive(active) => Self::Progressive {
                merkleizer: ProgressiveMerkleizer::new(),
                active,
                position: 0,
            },
        }
    }

    /// Adds the root of the next field.
    pub(super) fn push(&mut self, field_root: Root) {
        match self {
            Self::Binary(merkleizer) => merkleizer.push(field_root),
            Self::Progressive {
                merkleizer,
                active,
                position,
            } => {
                // Inactive positions before this field hash as zero chunks.
                while *position < active.len() && !active[*position] {
                    merkleizer.push(Root::ZERO);
                    *position += 1;
                }
                merkleizer.push(field_root);
                *position += 1;
            }
        }
    }

    /// Root of the container.
    pub(super) fn finish(self) -> Root {
        match self {
            Self::Binary(merkleizer) => merkleizer.finish(),
            Self::Progressive {
                merkleizer, active, ..
            } => Root::hash_pair(
                &merkleizer.finish(),
                &Merkleization::active_fields_chunk(active),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progressive_shape_must_match_the_fields() {
        // Three positions with two active fields, ending on an active one.
        assert!(Merkleization::Progressive(&[true, false, true]).fits(2));
        // Mutation: the last position is inactive.
        assert!(!Merkleization::Progressive(&[true, true, false]).fits(2));
        // Mutation: one active position too few.
        assert!(!Merkleization::Progressive(&[false, true]).fits(2));
    }

    #[test]
    fn bitmap_chunk_packs_low_bit_first() {
        // Positions 0, 2, and 9 set: byte 0 is 0b101, byte 1 is 0b10.
        let mut active = [false; 10];
        active[0] = true;
        active[2] = true;
        active[9] = true;

        let chunk = Merkleization::active_fields_chunk(&active);

        let mut expected = [0; 32];
        expected[0] = 0b101;
        expected[1] = 0b10;
        assert_eq!(chunk, Root(expected));
    }

    #[test]
    fn inactive_positions_shift_field_indices() {
        // Fields sit at positions 0 and 2, which are nodes 2 and 25 of the progressive tree.
        // That tree hangs under node 2, so its path bits follow the bits of 2.
        //
        //     node 2 = 0b10, node 25 = 0b1_1001  ->  0b10_1001 = 41
        let shape = Merkleization::Progressive(&[true, false, true]);

        assert_eq!(shape.field_index(2, 0).get(), 4);
        assert_eq!(shape.field_index(2, 1).get(), 41);
    }
}
