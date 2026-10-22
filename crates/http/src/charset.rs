//! The byte classes of the message grammar.

/// A set of bytes the HTTP grammar allows in one kind of element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Charset {
    /// Bytes of a token, such as a field name or a method.
    ///
    /// RFC 9110 section 5.6.2: any visible ASCII except the delimiters.
    Token,

    /// Bytes of a field value or a reason phrase.
    ///
    /// RFC 9110 section 5.5: visible ASCII, space, tab, and bytes from 0x80 up.
    /// Carriage return, line feed, and NUL are excluded, which blocks header injection.
    FieldValue,
}

impl Charset {
    /// Whether one byte belongs to the set.
    pub(crate) const fn contains(self, byte: u8) -> bool {
        match self {
            Self::Token => matches!(
                byte,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
                    | b'0'..=b'9'
                    | b'a'..=b'z'
                    | b'A'..=b'Z'
            ),
            Self::FieldValue => matches!(byte, b'\t' | b' '..=b'~' | 0x80..=0xff),
        }
    }

    /// Whether every byte belongs to the set; the empty string passes.
    pub(crate) fn admits(self, bytes: &[u8]) -> bool {
        bytes.iter().all(|&byte| self.contains(byte))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delimiters_and_controls_split_the_sets() {
        // A colon delimits a field name, so it is no token byte, yet a value may hold it.
        assert!(!Charset::Token.contains(b':'));
        assert!(Charset::FieldValue.contains(b':'));

        // A space separates tokens; values keep inner spaces.
        assert!(!Charset::Token.admits(b"a b"));
        assert!(Charset::FieldValue.admits(b"a b"));

        // A line feed would end the field line early, so neither set has it.
        assert!(!Charset::FieldValue.admits(b"a\nb"));

        // Bytes from 0x80 up appear in values only.
        assert!(Charset::FieldValue.contains(0xc3));
        assert!(!Charset::Token.contains(0xc3));
    }
}
