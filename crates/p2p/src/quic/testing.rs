//! Helpers shared by the QUIC unit tests.

/// Decodes a hex string, two characters per byte.
pub(crate) fn hex(text: &str) -> Vec<u8> {
    assert!(text.len() % 2 == 0, "odd hex length {}", text.len());
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("valid hex"))
        .collect()
}
