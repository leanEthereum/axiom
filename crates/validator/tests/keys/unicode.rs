//! The Unicode 16.0.0 normalization conformance file, NormalizationTest.txt, for NFKD.
//!
//! Each data line has five columns: source, NFC, NFD, NFKC, and NFKD.
//! For NFKD, conformance requires, per the file's header:
//!
//! ```text
//! c5 == NFKD(c1) == NFKD(c2) == NFKD(c3) == NFKD(c4) == NFKD(c5)
//! ```
//!
//! Every code point not listed as a source in part 1 must also map to itself.

use std::{collections::HashSet, fs};

use axiom_validator::keys::nfkd;

use crate::vector_file;

/// Data lines in each part of the pinned file, parts 0 to 5.
const LINES_PER_PART: [usize; 6] = [45, 17_085, 1_868, 194, 735, 38];

/// The text of a column: code points in hex, separated by spaces.
fn column(text: &str) -> String {
    text.split_whitespace()
        .map(|hex| {
            let value = u32::from_str_radix(hex, 16).expect("a hex code point");
            char::from_u32(value).expect("a Unicode scalar value")
        })
        .collect()
}

#[test]
fn normalization_test_nfkd() {
    let Some(file) = vector_file("unicode/NormalizationTest.txt") else {
        return;
    };
    let text = fs::read_to_string(file).expect("the file is UTF-8");

    let mut lines = [0; 6];
    let mut part: Option<usize> = None;
    let mut part_one = HashSet::new();
    for line in text.lines() {
        // Comments run from a hash to the end of the line.
        let data = line.split('#').next().unwrap_or_default().trim();
        if data.is_empty() {
            continue;
        }
        if let Some(name) = data.strip_prefix("@Part") {
            part = Some(name.parse().expect("a part number"));
            continue;
        }
        let part = part.expect("data follows a part header");
        lines[part] += 1;

        let columns: Vec<String> = data.split(';').take(5).map(column).collect();
        let expected = &columns[4];
        for (index, source) in columns.iter().enumerate() {
            assert_eq!(
                &nfkd(source),
                expected,
                "line {line:?}, column c{}",
                index + 1
            );
        }
        if part == 1 {
            part_one.insert(columns[0].clone());
        }
    }
    assert_eq!(lines, LINES_PER_PART);

    // Part 1 lists every code point that normalization changes; all others are fixed points.
    // Surrogates are no scalar values, so the walk skips them.
    let mut fixed = 0;
    for c in (0..=0x0010_ffff).filter_map(char::from_u32) {
        let single = c.to_string();
        if !part_one.contains(&single) {
            assert_eq!(nfkd(&single), single, "U+{:04X}", u32::from(c));
            fixed += 1;
        }
    }
    // 1114112 code points, minus 2048 surrogates, minus the 17085 of part 1.
    assert_eq!(fixed, 1_094_979);
}
