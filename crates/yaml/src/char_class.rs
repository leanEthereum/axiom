//! The structural classes of a byte, as the YAML grammar names them.

/// The role a byte plays in the YAML grammar.
///
/// The classes follow the productions of YAML 1.2, chapter 5.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CharClass {
    /// A line break, `b-char` in the grammar.
    Break,
    /// A space or a tab, `s-white` in the grammar.
    White,
    /// A delimiter of flow collections, `c-flow-indicator` in the grammar.
    FlowIndicator,
    /// Any other byte.
    Other,
}

impl CharClass {
    /// The class of a byte.
    pub(crate) const fn of(byte: u8) -> Self {
        match byte {
            b'\n' | b'\r' => Self::Break,
            b' ' | b'\t' => Self::White,
            b',' | b'[' | b']' | b'{' | b'}' => Self::FlowIndicator,
            _ => Self::Other,
        }
    }

    /// Whether the byte ends a line.
    pub(crate) const fn is_break(self) -> bool {
        matches!(self, Self::Break)
    }

    /// Whether the byte separates tokens within a line.
    pub(crate) const fn is_white(self) -> bool {
        matches!(self, Self::White)
    }

    /// Whether the byte is whitespace or a line break.
    pub(crate) const fn is_space(self) -> bool {
        matches!(self, Self::Break | Self::White)
    }

    /// Whether the byte delimits entries of a flow collection.
    pub(crate) const fn is_flow_indicator(self) -> bool {
        matches!(self, Self::FlowIndicator)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_of_structural_bytes() {
        // Both break bytes, both white bytes, and the five flow indicators.
        for byte in *b"\n\r" {
            assert_eq!(CharClass::of(byte), CharClass::Break);
        }
        for byte in *b" \t" {
            assert_eq!(CharClass::of(byte), CharClass::White);
        }
        for byte in *b",[]{}" {
            assert_eq!(CharClass::of(byte), CharClass::FlowIndicator);
        }

        // A colon and a hash are indicators, but not of these classes.
        assert_eq!(CharClass::of(b':'), CharClass::Other);
        assert_eq!(CharClass::of(b'#'), CharClass::Other);
    }
}
