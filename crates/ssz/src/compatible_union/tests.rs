use proptest::prelude::*;

use super::*;
use crate::{Container, FieldDecoder, FieldVisitor, Merkleization};

/// A square: its side at position 0 and its color at position 2.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Square {
    side: u16,
    color: u8,
}

impl Container for Square {
    const FIELDS: &'static [Option<usize>] = &[u16::FIXED_SIZE, u8::FIXED_SIZE];
    const MERKLEIZATION: Merkleization = Merkleization::Progressive(&[true, false, true]);

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.side);
        visitor.field(&self.color);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            side: fields.field()?,
            color: fields.field()?,
        })
    }
}

/// A circle: its radius at position 1 and its color at position 2, where the square has it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Circle {
    radius: u16,
    color: u8,
}

impl Container for Circle {
    const FIELDS: &'static [Option<usize>] = &[u16::FIXED_SIZE, u8::FIXED_SIZE];
    const MERKLEIZATION: Merkleization = Merkleization::Progressive(&[false, true, true]);

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.radius);
        visitor.field(&self.color);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            radius: fields.field()?,
            color: fields.field()?,
        })
    }
}

/// A square under selector 1, or a circle under selector 2.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Shape {
    Square(Square),
    Circle(Circle),
}

impl UnionOptions for Shape {
    const SELECTORS: &'static [u8] = &[1, 2];

    fn selector(&self) -> u8 {
        match self {
            Self::Square(_) => 1,
            Self::Circle(_) => 2,
        }
    }

    fn visit_option<V: OptionVisitor>(&self, visitor: &mut V) {
        match self {
            Self::Square(square) => visitor.option(square),
            Self::Circle(circle) => visitor.option(circle),
        }
    }

    fn decode_option(selector: u8, bytes: &[u8]) -> Result<Self, DecodeError> {
        match selector {
            1 => Square::decode(bytes).map(Self::Square),
            2 => Circle::decode(bytes).map(Self::Circle),
            _ => Err(DecodeError::UnknownSelector { selector }),
        }
    }
}

fn circle() -> CompatibleUnion<Shape> {
    CompatibleUnion::new(Shape::Circle(Circle {
        radius: 0x0102,
        color: 0x42,
    }))
}

#[test]
fn encoding_is_the_selector_then_the_option() {
    // Selector 2, then the radius little-endian, then the color.
    let union = circle();

    assert_eq!(union.encode(), [2, 0x02, 0x01, 0x42]);
    assert_eq!(union.encoded_len(), 4);
}

#[test]
fn root_mixes_the_selector_into_the_option_root() {
    // The selector chunk is the byte 2 followed by 31 zero bytes.
    let union = circle();
    let option_root = Circle {
        radius: 0x0102,
        color: 0x42,
    }
    .hash_tree_root();

    let mut selector_chunk = [0; 32];
    selector_chunk[0] = 2;
    let expected = Root::hash_pair(&option_root, &Root(selector_chunk));

    assert_eq!(union.hash_tree_root(), expected);
}

#[test]
fn decoding_reads_the_option_the_selector_names() {
    // Selector 1 names the square: side 0x0304, color 7.
    let decoded = CompatibleUnion::<Shape>::decode(&[1, 0x04, 0x03, 7]);

    assert_eq!(
        decoded,
        Ok(CompatibleUnion::new(Shape::Square(Square {
            side: 0x0304,
            color: 7,
        })))
    );
}

#[test]
fn empty_input_lacks_a_selector() {
    assert_eq!(
        CompatibleUnion::<Shape>::decode(&[]),
        Err(DecodeError::TooShort {
            minimum: 1,
            actual: 0
        })
    );
}

#[test]
fn undeclared_and_reserved_selectors_are_rejected() {
    // Selector 3 is free but undeclared, 0 and 128 are reserved by the encoding.
    for selector in [3, 0, 128] {
        assert_eq!(
            CompatibleUnion::<Shape>::decode(&[selector, 0x02, 0x01, 0x42]),
            Err(DecodeError::UnknownSelector { selector })
        );
    }
}

#[test]
fn option_bytes_must_fit_the_option_exactly() {
    // Mutation: one byte past the three a circle takes.
    assert_eq!(
        CompatibleUnion::<Shape>::decode(&[2, 0x02, 0x01, 0x42, 0]),
        Err(DecodeError::InvalidLength {
            expected: 3,
            actual: 4
        })
    );
}

#[test]
fn proof_descends_into_the_held_option() {
    // Fixture state: the circle's color sits at position 2, node 41 of the circle's tree.
    // The circle's root is node 2 of the union, so its path bits follow the bits of 2.
    //
    //     node 2 = 0b10
    //     node 41 = 0b1_01001
    //     joined = 0b10_01001 = 73
    let union = circle();
    let color_in_option = Circle::field_index(1);
    let index = DATA_INDEX.concat(color_in_option);

    let (leaf, proof) = union.prove(index).unwrap();

    assert_eq!(color_in_option.get(), 41);
    assert_eq!(index.get(), 73);
    assert_eq!(leaf, 0x42_u8.hash_tree_root());
    assert!(proof.verify(leaf, index, union.hash_tree_root()));
}

#[test]
fn shared_field_sits_at_one_index_in_every_option() {
    // Both options place the color at position 2, so one index proves it in either.
    assert_eq!(Square::field_index(1), Circle::field_index(1));
}

#[test]
fn selector_node_is_not_proven() {
    // Node 3 is the selector chunk, outside the held option.
    assert_eq!(circle().prove(GeneralizedIndex::new(3)), None);
}

fn shapes() -> impl Strategy<Value = CompatibleUnion<Shape>> {
    prop_oneof![
        (any::<u16>(), any::<u8>()).prop_map(|(side, color)| Shape::Square(Square { side, color })),
        (any::<u16>(), any::<u8>())
            .prop_map(|(radius, color)| Shape::Circle(Circle { radius, color })),
    ]
    .prop_map(CompatibleUnion::new)
}

proptest! {
    #[test]
    fn round_trips(union in shapes()) {
        let bytes = union.encode();

        prop_assert_eq!(bytes.len(), union.encoded_len());
        prop_assert_eq!(CompatibleUnion::decode(&bytes), Ok(union));
    }

    #[test]
    fn root_equals_the_reference_formula(union in shapes()) {
        // The reference: the held option's own root, then the selector mixed in.
        let option_root = match union.get() {
            Shape::Square(square) => square.hash_tree_root(),
            Shape::Circle(circle) => circle.hash_tree_root(),
        };

        prop_assert_eq!(
            union.hash_tree_root(),
            option_root.mix_in_selector(union.selector())
        );
    }

    #[test]
    fn options_with_equal_numbers_have_distinct_roots(side in any::<u16>(), color in any::<u8>()) {
        // A square and a circle with the same numbers differ in tree position and selector.
        let square = CompatibleUnion::new(Shape::Square(Square { side, color }));
        let circle = CompatibleUnion::new(Shape::Circle(Circle { radius: side, color }));

        prop_assert_ne!(square.hash_tree_root(), circle.hash_tree_root());
    }
}
