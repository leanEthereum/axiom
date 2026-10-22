//! Cases from JSONTestSuite, the RFC 8259 conformance corpus, written inline.
//!
//! Names follow the corpus.
//! A y_ case must parse, an n_ case must fail, an i_ case is the implementation's choice.

use axiom_json::{ErrorKind, Json, Limits};

/// Inputs every conforming parser must accept.
const ACCEPT: &[(&str, &[u8])] = &[
    ("y_array_arraysWithSpaces", b"[[]   ]"),
    ("y_array_empty", b"[]"),
    ("y_array_empty-string", b"[\"\"]"),
    ("y_array_false", b"[false]"),
    ("y_array_heterogeneous", b"[null, 1, \"1\", {}]"),
    ("y_array_null", b"[null]"),
    ("y_array_with_1_and_newline", b"[1\n]"),
    ("y_array_with_leading_space", b" [1]"),
    ("y_array_with_several_null", b"[1,null,null,null,2]"),
    ("y_array_with_trailing_space", b"[2] "),
    ("y_number", b"[123e65]"),
    ("y_number_0e+1", b"[0e+1]"),
    ("y_number_0e1", b"[0e1]"),
    ("y_number_after_space", b"[ 4]"),
    ("y_number_double_close_to_zero", b"[-0.000000000000000000000000000000000000000000000000000000000000000000000000000001]"),
    ("y_number_int_with_exp", b"[20e1]"),
    ("y_number_minus_zero", b"[-0]"),
    ("y_number_negative_int", b"[-123]"),
    ("y_number_negative_one", b"[-1]"),
    ("y_number_real_capital_e", b"[1E22]"),
    ("y_number_real_capital_e_neg_exp", b"[1E-2]"),
    ("y_number_real_capital_e_pos_exp", b"[1E+2]"),
    ("y_number_real_exponent", b"[123e45]"),
    ("y_number_real_fraction_exponent", b"[123.456e78]"),
    ("y_number_simple_int", b"[123]"),
    ("y_number_simple_real", b"[123.456789]"),
    ("y_object_basic", b"{\"asd\":\"sdf\"}"),
    ("y_object_empty", b"{}"),
    ("y_object_empty_key", b"{\"\":0}"),
    ("y_object_escaped_null_in_key", b"{\"foo\\u0000bar\": 42}"),
    ("y_object_extreme_numbers", b"{ \"min\": -1.0e+28, \"max\": 1.0e+28 }"),
    ("y_object_long_strings", b"{\"x\":[{\"id\": \"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"}], \"id\": \"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"}"),
    ("y_object_simple", b"{\"a\":[]}"),
    ("y_object_string_unicode", b"{\"title\":\"\\u041f\\u043e\\u043b\\u0442\\u043e\\u0440\\u0430 \\u0417\\u0435\\u043c\\u043b\\u0435\\u043a\\u043e\\u043f\\u0430\" }"),
    ("y_object_with_newlines", b"{\n\"a\": \"b\"\n}"),
    ("y_string_1_2_3_bytes_UTF-8_sequences", b"[\"\\u0060\\u012a\\u12AB\"]"),
    ("y_string_accepted_surrogate_pair", b"[\"\\uD801\\udc37\"]"),
    ("y_string_allowed_escapes", b"[\"\\\"\\\\\\/\\b\\f\\n\\r\\t\"]"),
    ("y_string_backslash_and_u_escaped_zero", b"[\"\\\\u0000\"]"),
    ("y_string_comments", b"[\"a/*b*/c/*d//e\"]"),
    ("y_string_escaped_control_character", b"[\"\\u0012\"]"),
    ("y_string_in_array_with_leading_space", b"[ \"asd\"]"),
    ("y_string_nonCharacterInUTF-8_U+FFFF", b"[\"\xef\xbf\xbf\"]"),
    ("y_string_null_escape", b"[\"\\u0000\"]"),
    ("y_string_pi", b"[\"\xcf\x80\"]"),
    ("y_string_simple_ascii", b"[\"asd \"]"),
    ("y_string_space", b"\" \""),
    ("y_string_utf8", b"[\"\xe2\x82\xac\xf0\x9d\x84\x9e\"]"),
    ("y_string_with_del_character", b"[\"a\x7fa\"]"),
    ("y_structure_lonely_false", b"false"),
    ("y_structure_lonely_int", b"42"),
    ("y_structure_lonely_negative_real", b"-0.1"),
    ("y_structure_lonely_null", b"null"),
    ("y_structure_lonely_string", b"\"asd\""),
    ("y_structure_lonely_true", b"true"),
    ("y_structure_string_empty", b"\"\""),
    ("y_structure_trailing_newline", b"[\"a\"]\n"),
    ("y_structure_true_in_array", b"[true]"),
    ("y_structure_whitespace_array", b" [] "),
];

/// Inputs every conforming parser must reject.
const REJECT: &[(&str, &[u8])] = &[
    ("n_array_1_true_without_comma", b"[1 true]"),
    ("n_array_colon_instead_of_comma", b"[\"\": 1]"),
    ("n_array_comma_after_close", b"[\"\"],"),
    ("n_array_comma_and_number", b"[,1]"),
    ("n_array_double_comma", b"[1,,2]"),
    ("n_array_extra_close", b"[\"x\"]]"),
    ("n_array_extra_comma", b"[\"\",]"),
    ("n_array_incomplete", b"[\"x\""),
    ("n_array_just_comma", b"[,]"),
    ("n_array_just_minus", b"[-]"),
    ("n_array_missing_value", b"[   , \"\"]"),
    ("n_array_unclosed", b"[\"\""),
    ("n_array_unclosed_with_new_lines", b"[1,\n1\n,1"),
    ("n_incomplete_false", b"[fals]"),
    ("n_incomplete_null", b"[nul]"),
    ("n_incomplete_true", b"[tru]"),
    ("n_number_++", b"[++1234]"),
    ("n_number_+1", b"[+1]"),
    ("n_number_-01", b"[-01]"),
    ("n_number_-1.0.", b"[-1.0.]"),
    ("n_number_.-1", b"[.-1]"),
    ("n_number_0.e1", b"[0.e1]"),
    ("n_number_0_capital_E", b"[0E]"),
    ("n_number_1.0e+", b"[1.0e+]"),
    ("n_number_2.e3", b"[2.e3]"),
    ("n_number_Inf", b"[Inf]"),
    ("n_number_NaN", b"[NaN]"),
    ("n_number_hex_1_digit", b"[0x1]"),
    ("n_number_minus_space_1", b"[- 1]"),
    ("n_number_neg_int_starting_with_zero", b"[-012]"),
    ("n_number_with_leading_zero", b"[012]"),
    ("n_object_bad_value", b"[\"x\", truth]"),
    ("n_object_comma_instead_of_colon", b"{\"x\", null}"),
    ("n_object_double_colon", b"{\"x\"::\"b\"}"),
    ("n_object_missing_colon", b"{\"a\" b}"),
    ("n_object_missing_key", b"{:\"b\"}"),
    ("n_object_missing_value", b"{\"a\":"),
    ("n_object_non_string_key", b"{1:1}"),
    ("n_object_single_quote", b"{'a':0}"),
    ("n_object_trailing_comma", b"{\"id\":0,}"),
    ("n_object_trailing_comment", b"{\"a\":\"b\"}/**/"),
    ("n_object_unquoted_key", b"{a: \"b\"}"),
    ("n_single_space", b" "),
    ("n_string_1_surrogate_then_escape", b"[\"\\uD800\\\"]"),
    ("n_string_escape_x", b"[\"\\x00\"]"),
    ("n_string_escaped_emoji", b"[\"\\\xf0\x9f\x8c\x80\"]"),
    ("n_string_incomplete_escape", b"[\"\\\"]"),
    (
        "n_string_incomplete_surrogate_escape_invalid",
        b"[\"\\uD800\\uD800\\x\"]",
    ),
    ("n_string_invalid_unicode_escape", b"[\"\\uqqqq\"]"),
    ("n_string_invalid_utf8_after_escape", b"[\"\\\xe5\"]"),
    ("n_string_no_quotes_with_bad_escape", b"[\\n]"),
    ("n_string_single_quote", b"['single quote']"),
    ("n_string_unescaped_newline", b"[\"new\nline\"]"),
    ("n_string_unescaped_tab", b"[\"\t\"]"),
    ("n_structure_UTF8_BOM_no_data", b"\xef\xbb\xbf"),
    ("n_structure_angle_bracket_null", b"[<null>]"),
    ("n_structure_array_with_unclosed_string", b"[\"asd]"),
    ("n_structure_capitalized_True", b"[True]"),
    ("n_structure_close_unopened_array", b"1]"),
    ("n_structure_double_array", b"[][]"),
    ("n_structure_end_array", b"]"),
    ("n_structure_no_data", b""),
    ("n_structure_null-byte-outside-string", b"[\x00]"),
    ("n_structure_object_followed_by_closing_object", b"{}}"),
    ("n_structure_open_object", b"{"),
    ("n_structure_unclosed_array", b"[1"),
    ("n_structure_unclosed_object", b"{\"asd\":\"asd\""),
    ("n_structure_whitespace_formfeed", b"[\x0c]"),
];

#[test]
fn accepts_every_y_case() {
    // Each y_ input must parse, and its compact form must parse back to the same value.
    for (name, input) in ACCEPT {
        let value = Json::parse(input).unwrap_or_else(|error| panic!("{name}: {error}"));
        let compact = value.to_string();
        assert_eq!(Json::parse(&compact).as_ref(), Ok(&value), "{name}");
    }
}

#[test]
fn rejects_every_n_case() {
    // Each n_ input must fail, with an offset inside or at the end of the input.
    for (name, input) in REJECT {
        let error = Json::parse(input).expect_err(name);
        assert!(
            error.offset() <= input.len(),
            "{name}: offset {}",
            error.offset()
        );
    }
}

#[test]
fn implementation_defined_choices() {
    // i_string_1st_surrogate_but_2nd_missing: a lone high surrogate.
    // A Rust string cannot hold it, so the parser rejects at the escape's backslash.
    //
    //     ["\uDADA"]
    //      ^ offset 2
    let error = Json::parse(b"[\"\\uDADA\"]").unwrap_err();
    assert_eq!(
        (error.offset(), error.kind()),
        (2, &ErrorKind::LoneSurrogate(0xdada))
    );

    // i_string_UTF-8_invalid_sequence: raw bytes that are not UTF-8.
    //
    //     ["日ш\xfa"]   the stray 0xfa sits at offset 7
    let error = Json::parse(b"[\"\xe6\x97\xa5\xd1\x88\xfa\"]").unwrap_err();
    assert_eq!((error.offset(), error.kind()), (7, &ErrorKind::InvalidUtf8));

    // i_structure_UTF-8_BOM_empty_object: RFC 8259 lets a parser ignore a BOM.
    // This one rejects it, since no JSON-RPC peer sends one.
    let error = Json::parse(b"\xef\xbb\xbf{}").unwrap_err();
    assert_eq!(
        (error.offset(), error.kind()),
        (0, &ErrorKind::UnexpectedByte(0xef))
    );

    // i_number_huge_exp: the number parses with its text kept.
    // Its value overflows a double, so the float view declines it.
    let text = "0.4e00669999999999999999999999999999999999999999999999";
    let value = Json::parse(format!("[{text}]")).unwrap();
    let number = value.as_array().unwrap()[0].as_number().unwrap();
    assert_eq!((number.as_str(), number.as_f64()), (text, None));
}

#[test]
fn duplicate_names_are_rejected() {
    // y_object_duplicated_key is valid RFC 8259, which only says names SHOULD be unique.
    // Rejecting it removes any doubt over which value a reader would pick.
    //
    //     {"a":"b","a":"c"}
    //              ^ second "a" at offset 9
    let error = Json::parse(b"{\"a\":\"b\",\"a\":\"c\"}").unwrap_err();
    assert_eq!(
        (error.offset(), error.kind()),
        (9, &ErrorKind::DuplicateKey("a".to_owned()))
    );
}

#[test]
fn error_offsets_point_at_the_fault() {
    // Each case names the byte the parser stops at.
    //
    //     [1,,2]      second comma at offset 3
    //     [012]       the 1 after a lone zero at offset 2
    //     ["a\nb"]    raw line feed at offset 3
    //     [tru]       closing bracket where e belongs, offset 4
    //     [1          end of input at offset 2
    //     {"a" 1}     the 1 where a colon belongs, offset 5
    //     [] x        trailing x at offset 3
    let cases: [(&[u8], usize, ErrorKind); 7] = [
        (b"[1,,2]", 3, ErrorKind::UnexpectedByte(b',')),
        (b"[012]", 2, ErrorKind::InvalidNumber),
        (b"[\"a\nb\"]", 3, ErrorKind::ControlCharacter(b'\n')),
        (b"[tru]", 4, ErrorKind::UnexpectedByte(b']')),
        (b"[1", 2, ErrorKind::UnexpectedEnd),
        (b"{\"a\" 1}", 5, ErrorKind::UnexpectedByte(b'1')),
        (b"[] x", 3, ErrorKind::TrailingCharacters),
    ];
    for (input, offset, kind) in cases {
        let error = Json::parse(input).unwrap_err();
        assert_eq!((error.offset(), error.kind()), (offset, &kind));
    }
}

#[test]
fn limits_bound_depth_and_size() {
    // Depth 3 admits three nested arrays and refuses the fourth bracket at offset 3.
    let limits = Limits {
        max_depth: 3,
        max_bytes: 100,
    };
    assert!(Json::parse_with(b"[[[]]]", limits).is_ok());
    let error = Json::parse_with(b"[[[[]]]]", limits).unwrap_err();
    assert_eq!(
        (error.offset(), error.kind()),
        (3, &ErrorKind::TooDeep { limit: 3 })
    );

    // A 101-byte text breaks a 100-byte limit, reported at the limit.
    let long = format!("\"{}\"", "a".repeat(99));
    let error = Json::parse_with(&long, limits).unwrap_err();
    assert_eq!(
        (error.offset(), error.kind()),
        (
            100,
            &ErrorKind::TooLarge {
                length: 101,
                limit: 100
            }
        )
    );

    // A million nested brackets under a generous limit still return an error, not a crash.
    // The parser's own stack holds the open arrays, so the thread stack never grows.
    let deep = "[".repeat(1_000_000);
    let unbounded = Limits {
        max_depth: usize::MAX,
        max_bytes: usize::MAX,
    };
    let error = Json::parse_with(&deep, unbounded).unwrap_err();
    assert_eq!(
        (error.offset(), error.kind()),
        (1_000_000, &ErrorKind::UnexpectedEnd)
    );
}
