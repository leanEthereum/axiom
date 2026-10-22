//! Helpers shared by the unit tests.

/// Decodes a hex string written in a test.
pub(crate) fn hex(text: &str) -> Vec<u8> {
    // Two characters per byte, most significant nibble first.
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
