//! Keystore passwords, processed as EIP-2335 requires.

use std::fmt;

use crate::keys::{nfkd, wipe::Wipe};

/// The bytes a keystore password feeds to its key derivation function.
///
/// The bytes are overwritten with zero on drop, and debug output hides them.
///
/// # Overview
///
/// Per EIP-2335, section "Password requirements":
///
/// 1. Normalize the text to NFKD.
/// 2. Strip the C0 controls 0x00 to 0x1F, the C1 controls 0x80 to 0x9F, and DELETE 0x7F.
/// 3. Encode the rest as UTF-8.
///
/// Space, 0x20, is kept.
/// So two spellings of one password, or one with a trailing newline, unlock the same keystore.
pub struct Password {
    /// The processed UTF-8 bytes.
    bytes: Vec<u8>,
}

impl Password {
    /// Processes a password typed or read as text.
    #[must_use]
    pub fn new(text: &str) -> Self {
        let mut normalized = nfkd(text);
        let mut bytes = Vec::with_capacity(normalized.len());
        let mut utf8 = [0; 4];
        for c in normalized.chars().filter(|&c| !Self::is_stripped(c)) {
            bytes.extend_from_slice(c.encode_utf8(&mut utf8).as_bytes());
        }
        utf8.wipe();
        normalized.wipe();
        Self { bytes }
    }

    /// The processed bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Whether EIP-2335 strips a code point: the C0 and C1 control codes, and DELETE.
    const fn is_stripped(c: char) -> bool {
        matches!(c, '\u{00}'..='\u{1F}' | '\u{7F}' | '\u{80}'..='\u{9F}')
    }
}

impl From<&str> for Password {
    fn from(text: &str) -> Self {
        Self::new(text)
    }
}

impl Drop for Password {
    fn drop(&mut self) {
        self.bytes.wipe();
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_eip_password_normalizes_to_its_encoding() {
        // EIP-2335 test vectors: fraktur letters and a key emoji.
        // Encoded password: 0x7465737470617373776f7264f09f9491.
        let password = Password::new(
            "\u{1D531}\u{1D522}\u{1D530}\u{1D531}\u{1D52D}\u{1D51E}\u{1D530}\u{1D530}\u{1D534}\u{1D52C}\u{1D52F}\u{1D521}\u{1F511}",
        );
        assert_eq!(password.as_bytes(), b"testpassword\xf0\x9f\x94\x91");
    }

    #[test]
    fn control_codes_are_stripped_and_space_kept() {
        // One code point at each edge of the stripped ranges, around a kept space.
        //
        //     0x00 0x1F  stripped (C0)
        //     0x20       kept (space)
        //     0x7E       kept (tilde)
        //     0x7F       stripped (DELETE)
        //     0x80 0x9F  stripped (C1)
        //     0xA0       kept by the strip, then NFKD maps it to a space
        let password = Password::new("a\u{00}\u{1F} ~\u{7F}\u{80}\u{9F}\u{A0}b\n");
        assert_eq!(password.as_bytes(), b"a ~ b");
    }

    #[test]
    fn debug_output_hides_the_bytes() {
        assert_eq!(
            format!("{:?}", Password::new("hunter2")),
            "Password(<redacted>)"
        );
    }
}
