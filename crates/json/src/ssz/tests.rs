use axiom_ssz::{
    BitList, BitVector, ByteList, Const, Container, DecodeError, Field, FieldDecoder, FieldVisitor,
    List, Root, U256, Vector,
};
use proptest::prelude::*;

use super::*;
use crate::HexError;

/// A container with one field of each kind, two of them variable-size.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Sample {
    flag: bool,
    small: u8,
    big: U256,
    root: Root,
    bits: BitVector<Const<10>>,
    votes: BitList<Const<16>>,
    extra: ByteList<Const<4>>,
    pair: Vector<u64, Const<2>>,
    nested: List<Inner, Const<3>>,
}

/// A variable-size container, so a list of them needs an offset table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Inner {
    index: u64,
    data: ByteList<Const<8>>,
}

impl Container for Inner {
    const FIELDS: &'static [Field] = &[
        Field::new::<u64>("index"),
        Field::new::<ByteList<Const<8>>>("data"),
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.index);
        visitor.field(&self.data);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            index: fields.field()?,
            data: fields.field()?,
        })
    }
}

impl Container for Sample {
    const FIELDS: &'static [Field] = &[
        Field::new::<bool>("flag"),
        Field::new::<u8>("small"),
        Field::new::<U256>("big"),
        Field::new::<Root>("root"),
        Field::new::<BitVector<Const<10>>>("bits"),
        Field::new::<BitList<Const<16>>>("votes"),
        Field::new::<ByteList<Const<4>>>("extra"),
        Field::new::<Vector<u64, Const<2>>>("pair"),
        Field::new::<List<Inner, Const<3>>>("nested"),
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.flag);
        visitor.field(&self.small);
        visitor.field(&self.big);
        visitor.field(&self.root);
        visitor.field(&self.bits);
        visitor.field(&self.votes);
        visitor.field(&self.extra);
        visitor.field(&self.pair);
        visitor.field(&self.nested);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            flag: fields.field()?,
            small: fields.field()?,
            big: fields.field()?,
            root: fields.field()?,
            bits: fields.field()?,
            votes: fields.field()?,
            extra: fields.field()?,
            pair: fields.field()?,
            nested: fields.field()?,
        })
    }
}

/// The JSON of a sample, as the beacon API writes it.
const SAMPLE: &str = concat!(
    r#"{"flag":true,"small":"7","big":"300","#,
    r#""root":"0xab00000000000000000000000000000000000000000000000000000000000001","#,
    r#""bits":"0x0102","votes":"0x0b","extra":"0xc0ffee","pair":["1","18446744073709551615"],"#,
    r#""nested":[{"index":"5","data":"0x"},{"index":"6","data":"0x0102"}]}"#,
);

fn sample() -> Sample {
    Sample::from_json(&Json::parse(SAMPLE).unwrap()).unwrap()
}

#[test]
fn every_kind_reads_and_writes_its_beacon_api_form() {
    // The decoded sample holds the values the text spells out.
    let value = sample();
    let mut root = [0; 32];
    root[0] = 0xab;
    root[31] = 0x01;
    assert_eq!(value.root, Root(root));
    assert_eq!(value.big, U256::from_u64(300));
    assert_eq!(value.small, 7);
    assert_eq!(value.pair.as_slice(), &[1, u64::MAX]);
    assert_eq!(value.nested.len(), 2);

    // Writing it back gives the same text, member for member.
    assert_eq!(value.to_json().to_string(), SAMPLE);
}

#[test]
fn integers_may_be_json_numbers_on_input() {
    // The spec's vectors write small integers as bare numbers.
    let json = Json::parse(r#"{"index":5,"data":"0x"}"#).unwrap();
    assert_eq!(
        Inner::from_json(&json),
        Ok(Inner {
            index: 5,
            data: ByteList::default()
        })
    );
}

#[test]
fn each_stray_names_its_place() {
    // Mutation: one field at a time, against a valid inner container.
    let cases = [
        (
            r#"{"index":"5"}"#,
            SszJsonError::MissingField {
                path: "$".to_owned(),
                field: "data",
            },
        ),
        (
            r#"{"index":"5","data":"0x","extra":"1"}"#,
            SszJsonError::UnknownField {
                path: "$".to_owned(),
                field: "extra".to_owned(),
            },
        ),
        (
            r#"{"index":true,"data":"0x"}"#,
            SszJsonError::WrongKind {
                path: "$.index".to_owned(),
                expected: "a decimal string",
                found: "boolean",
            },
        ),
        (
            r#"{"index":"18446744073709551616","data":"0x"}"#,
            SszJsonError::InvalidUint {
                path: "$.index".to_owned(),
                text: "18446744073709551616".to_owned(),
                bits: 64,
            },
        ),
        (
            r#"{"index":"5","data":"0x123"}"#,
            SszJsonError::InvalidHex {
                path: "$.data".to_owned(),
                source: HexError::OddLength { digits: 3 },
            },
        ),
        (
            r#"{"index":"5","data":"0x000102030405060708"}"#,
            SszJsonError::TooLong {
                path: "$.data".to_owned(),
                limit: 8,
                actual: 9,
            },
        ),
    ];
    for (text, error) in cases {
        assert_eq!(
            Inner::from_json(&Json::parse(text).unwrap()),
            Err(error),
            "{text}"
        );
    }
}

#[test]
fn nested_strays_carry_the_whole_path() {
    // The second nested element has a malformed index.
    let text = SAMPLE.replace(r#""index":"6""#, r#""index":"six""#);
    assert_eq!(
        Sample::from_json(&Json::parse(text).unwrap()),
        Err(SszJsonError::InvalidUint {
            path: "$.nested[1].index".to_owned(),
            text: "six".to_owned(),
            bits: 64,
        })
    );

    // A vector of two given three items.
    let text = SAMPLE.replace(r#"["1","18446744073709551615"]"#, r#"["1","2","3"]"#);
    assert_eq!(
        Sample::from_json(&Json::parse(text).unwrap()),
        Err(SszJsonError::WrongLength {
            path: "$.pair".to_owned(),
            expected: 2,
            actual: 3,
        })
    );
}

#[test]
fn type_invariants_are_checked_after_the_shape() {
    // A bitlist without its delimiter bit has the right shape but no valid encoding.
    let text = SAMPLE.replace(r#""votes":"0x0b""#, r#""votes":"0x00""#);
    assert_eq!(
        Sample::from_json(&Json::parse(text).unwrap()),
        Err(SszJsonError::Decode(DecodeError::MissingSentinel {
            length: 1
        }))
    );
}

proptest! {
    #[test]
    fn json_round_trips(
        flag: bool,
        small: u8,
        index in any::<u64>(),
        data in proptest::collection::vec(any::<u8>(), 0..=8),
        count in 0_usize..=3,
    ) {
        // Any value written as JSON reads back equal.
        let inner = Inner { index, data: ByteList::try_from(data).unwrap() };
        let mut value = sample();
        value.flag = flag;
        value.small = small;
        value.nested = List::try_from(vec![inner; count]).unwrap();
        prop_assert_eq!(Sample::from_json(&value.to_json()), Ok(value));
    }
}
