//! The compact serializer.
//!
//! Output has no whitespace between tokens.
//! Member order and number text are kept, so parsing then writing gives back compact input.

use std::fmt::{self, Formatter, Write};

use crate::Json;

/// Writes values as compact text to a formatter.
pub(crate) struct Writer<'a, 'f> {
    /// The destination.
    f: &'a mut Formatter<'f>,
}

impl<'a, 'f> Writer<'a, 'f> {
    /// A writer to the given formatter.
    pub(crate) const fn new(f: &'a mut Formatter<'f>) -> Self {
        Self { f }
    }

    /// Writes the compact text of a value.
    pub(crate) fn value(&mut self, value: &Json) -> fmt::Result {
        match value {
            Json::Null => self.f.write_str("null"),
            Json::Bool(true) => self.f.write_str("true"),
            Json::Bool(false) => self.f.write_str("false"),
            // Numbers are stored as validated text, written back unchanged.
            Json::Number(number) => self.f.write_str(number.as_str()),
            Json::String(text) => self.string(text),
            Json::Array(items) => {
                // [item,item,...]
                self.f.write_char('[')?;
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        self.f.write_char(',')?;
                    }
                    self.value(item)?;
                }
                self.f.write_char(']')
            }
            Json::Object(object) => {
                // {"name":value,...} in member order.
                self.f.write_char('{')?;
                for (index, (name, value)) in object.iter().enumerate() {
                    if index > 0 {
                        self.f.write_char(',')?;
                    }
                    self.string(name)?;
                    self.f.write_char(':')?;
                    self.value(value)?;
                }
                self.f.write_char('}')
            }
        }
    }

    /// Writes a string literal, escaping only what RFC 8259 section 7 requires.
    ///
    /// ```text
    ///     "      -> \"        \      -> \\
    ///     U+000A -> \n        U+0001 -> \u0001
    ///     é      -> é         (non-ASCII stays raw UTF-8)
    /// ```
    fn string(&mut self, text: &str) -> fmt::Result {
        self.f.write_char('"')?;

        // Write unescaped runs whole; split only at bytes that need an escape.
        // Every byte that needs one is ASCII, so each split lands on a character boundary.
        let mut run_start = 0;
        for (index, byte) in text.bytes().enumerate() {
            let escape = match byte {
                b'"' => "\\\"",
                b'\\' => "\\\\",
                b'\n' => "\\n",
                b'\r' => "\\r",
                b'\t' => "\\t",
                0x08 => "\\b",
                0x0c => "\\f",
                // Other control characters have no short form.
                0x00..=0x1f => "",
                _ => continue,
            };
            self.f.write_str(&text[run_start..index])?;
            if escape.is_empty() {
                write!(self.f, "\\u{byte:04x}")?;
            } else {
                self.f.write_str(escape)?;
            }
            run_start = index + 1;
        }

        // The tail after the last escaped byte.
        self.f.write_str(&text[run_start..])?;
        self.f.write_char('"')
    }
}

#[cfg(test)]
mod tests {
    use crate::{Json, Number, Object};

    #[test]
    fn nested_value_is_compact() {
        // {"a":[1,true,null],"b":{"c":"d"}} built member by member.
        let mut inner = Object::new();
        inner.insert("c", Json::from("d"));
        let mut outer = Object::new();
        outer.insert(
            "a",
            Json::Array(vec![Json::from(1_u64), Json::Bool(true), Json::Null]),
        );
        outer.insert("b", Json::Object(inner));

        assert_eq!(
            Json::Object(outer).to_string(),
            r#"{"a":[1,true,null],"b":{"c":"d"}}"#
        );
    }

    #[test]
    fn strings_escape_only_what_must_be_escaped() {
        // Quote, backslash, the short controls, a long control, and raw non-ASCII.
        let text = "q\"b\\n\nt\tc\u{1}e\u{e9}/";
        assert_eq!(Json::from(text).to_string(), r#""q\"b\\n\nt\tc\u0001eé/""#);
    }

    #[test]
    fn number_text_is_kept() {
        // 1.50e+3 keeps its trailing zero and its explicit plus sign.
        let number: Number = "1.50e+3".parse().unwrap();
        assert_eq!(Json::Number(number).to_string(), "1.50e+3");
    }
}
