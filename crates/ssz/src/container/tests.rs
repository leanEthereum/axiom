use proptest::prelude::*;

use super::*;
use crate::{Const, List};

/// Two fixed fields, the shape of a checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Fixed {
    a: u64,
    b: Root,
}

impl Container for Fixed {
    const FIELDS: &'static [Option<usize>] = &[u64::FIXED_SIZE, Root::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.a);
        visitor.field(&self.b);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            a: fields.field()?,
            b: fields.field()?,
        })
    }
}

/// Fixed and variable fields interleaved, with a nested container.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Mixed {
    x: u16,
    list: List<u8, Const<8>>,
    nested: Fixed,
    tail: List<u32, Const<4>>,
}

impl Container for Mixed {
    const FIELDS: &'static [Option<usize>] = &[
        u16::FIXED_SIZE,
        <List<u8, Const<8>>>::FIXED_SIZE,
        Fixed::FIXED_SIZE,
        <List<u32, Const<4>>>::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.x);
        visitor.field(&self.list);
        visitor.field(&self.nested);
        visitor.field(&self.tail);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            x: fields.field()?,
            list: fields.field()?,
            nested: fields.field()?,
            tail: fields.field()?,
        })
    }
}

fn mixed() -> Mixed {
    Mixed {
        x: 0x0201,
        list: List::try_from(vec![7, 8, 9]).unwrap(),
        nested: Fixed {
            a: 5,
            b: Root([1; 32]),
        },
        tail: List::try_from(vec![0x0a0b_0c0d]).unwrap(),
    }
}

#[test]
fn fixed_container_has_a_fixed_size() {
    // 8 bytes of u64 plus a 32-byte root.
    assert_eq!(Fixed::FIXED_SIZE, Some(40));
    assert_eq!(Mixed::FIXED_SIZE, None);
}

#[test]
fn mixed_container_lays_out_offsets_then_bodies() {
    // Fixed part: x (2) + offset (4) + nested (40) + offset (4) = 50 bytes.
    //
    //     [x][off=50][nested......][off=53][7 8 9][0d 0c 0b 0a]
    let bytes = mixed().encode();

    let mut expected = vec![0x01, 0x02, 50, 0, 0, 0];
    expected.extend_from_slice(&5_u64.to_le_bytes());
    expected.extend_from_slice(&[1; 32]);
    expected.extend_from_slice(&[53, 0, 0, 0, 7, 8, 9, 0x0d, 0x0c, 0x0b, 0x0a]);

    assert_eq!(bytes, expected);
    assert_eq!(mixed().encoded_len(), expected.len());
}

#[test]
fn root_is_the_tree_over_field_roots() {
    // Four fields fill a depth-2 tree exactly.
    let value = mixed();
    let roots = value.field_roots();

    let expected = Root::hash_pair(
        &Root::hash_pair(&roots[0], &roots[1]),
        &Root::hash_pair(&roots[2], &roots[3]),
    );
    assert_eq!(value.hash_tree_root(), expected);
}

#[test]
fn field_proof_verifies_against_the_root() {
    let value = mixed();
    let proof = value.field_proof(2);

    assert!(proof.verify(
        value.nested.hash_tree_root(),
        Mixed::field_index(2),
        value.hash_tree_root()
    ));
}

#[test]
fn nested_field_proof_descends_into_the_inner_container() {
    // Fixture state: field 2 of a 4-field container is node 6.
    // Its field 1 in a 2-field container adds one more step.
    //
    //     node 6 = 0b110, then field 1 -> 0b1101 = 13
    let value = mixed();
    let index = GeneralizedIndex::new(13);

    let (leaf, proof) = value.prove(index).unwrap();

    assert_eq!(leaf, value.nested.b.hash_tree_root());
    assert_eq!(proof.branch.len(), 3);
    assert!(proof.verify(leaf, index, value.hash_tree_root()));
}

#[test]
fn index_above_the_field_level_is_not_proven() {
    // Node 2 is an inner node of the field tree, not a field, so this container declines it.
    assert_eq!(mixed().prove(GeneralizedIndex::new(2)), None);
}

#[test]
fn first_offset_must_end_the_fixed_part() {
    // Mutation: the first offset claims 51 while the fixed part is 50 bytes.
    let mut bytes = mixed().encode();
    bytes[2] = 51;

    assert_eq!(
        Mixed::decode(&bytes),
        Err(DecodeError::FirstOffsetMismatch {
            expected: 50,
            actual: 51
        })
    );
}

#[test]
fn later_offset_before_earlier_is_rejected() {
    // Mutation: the second offset 49 points inside the fixed part, before the first body.
    let mut bytes = mixed().encode();
    bytes[46] = 49;

    assert_eq!(
        Mixed::decode(&bytes),
        Err(DecodeError::OffsetsNotIncreasing {
            previous: 50,
            next: 49
        })
    );
}

#[test]
fn input_shorter_than_the_fixed_part_is_rejected() {
    assert_eq!(
        Mixed::decode(&[0; 20]),
        Err(DecodeError::TooShort {
            minimum: 50,
            actual: 20
        })
    );
}

#[test]
fn fixed_container_rejects_extra_bytes() {
    assert_eq!(
        Fixed::decode(&[0; 41]),
        Err(DecodeError::InvalidLength {
            expected: 40,
            actual: 41
        })
    );
}

proptest! {
    #[test]
    fn mixed_round_trips(
        x: u16,
        list in proptest::collection::vec(any::<u8>(), 0..=8),
        a: u64,
        tail in proptest::collection::vec(any::<u32>(), 0..=4),
    ) {
        let value = Mixed {
            x,
            list: List::try_from(list).unwrap(),
            nested: Fixed { a, b: Root([3; 32]) },
            tail: List::try_from(tail).unwrap(),
        };

        prop_assert_eq!(Mixed::decode(&value.encode()), Ok(value));
    }

    #[test]
    fn accepted_bytes_re_encode_identically(bytes in proptest::collection::vec(any::<u8>(), 50..80)) {
        if let Ok(value) = Mixed::decode(&bytes) {
            prop_assert_eq!(value.encode(), bytes);
        }
    }
}
