//! Graffiti: the 32 bytes a proposer writes into its block, and the file that sets them per key.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use axiom_json::Data;
use axiom_types::{BlsPubkey, Bytes32};

use crate::validators::{GraffitiError, GraffitiFileError};

/// Graffiti as an operator writes it: up to 32 bytes of UTF-8 text.
///
/// The block carries 32 bytes, so shorter text is padded with zero bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Graffiti(pub Bytes32);

impl Graffiti {
    /// Bytes a block's graffiti field holds.
    pub const MAX_LEN: usize = 32;

    /// Reads text that fits the block's 32 bytes.
    ///
    /// # Errors
    ///
    /// Fails when the text is longer than 32 bytes.
    pub fn parse(text: &str) -> Result<Self, GraffitiError> {
        let mut bytes = [0; Self::MAX_LEN];
        let Some(prefix) = bytes.get_mut(..text.len()) else {
            return Err(GraffitiError::TooLong {
                len: text.len(),
                max: Self::MAX_LEN,
            });
        };
        prefix.copy_from_slice(text.as_bytes());
        Ok(Self(Bytes32(bytes)))
    }

    /// The text, without its zero padding.
    ///
    /// Bytes that are not UTF-8 read as replacement characters.
    #[must_use]
    pub fn text(self) -> String {
        let bytes = &self.0.0;
        let end = bytes
            .iter()
            .rposition(|&byte| byte != 0)
            .map_or(0, |last| last + 1);
        String::from_utf8_lossy(&bytes[..end]).into_owned()
    }
}

/// A file of graffiti per key, read again before every proposal so edits apply at once.
///
/// # Overview
///
/// Each line is a key, a colon, and the graffiti, which is trimmed:
///
/// ```text
/// default: a fallback for every key
/// 0x8000...06aa: one key's own text
/// ```
///
/// Blank lines are skipped.
/// A later line for the same key replaces an earlier one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraffitiFile {
    /// The file.
    path: PathBuf,
}

impl GraffitiFile {
    /// The key that names the fallback line.
    const DEFAULT: &'static str = "default";

    /// A graffiti file at a path, read on each lookup.
    #[must_use]
    pub const fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// The file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The graffiti the file gives a key: its own line, else the default line, else none.
    ///
    /// # Errors
    ///
    /// Fails when the file cannot be read or a line is malformed.
    pub fn lookup(&self, pubkey: &BlsPubkey) -> Result<Option<Graffiti>, GraffitiFileError> {
        let text = fs::read_to_string(&self.path).map_err(|source| GraffitiFileError::Io {
            path: self.path.clone(),
            source,
        })?;
        let (default, keys) = self.parse(&text)?;
        Ok(keys.get(pubkey).copied().or(default))
    }

    /// The default graffiti and each key's graffiti in a file's text.
    fn parse(
        &self,
        text: &str,
    ) -> Result<(Option<Graffiti>, BTreeMap<BlsPubkey, Graffiti>), GraffitiFileError> {
        let mut default = None;
        let mut keys = BTreeMap::new();
        for (index, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            // Lines count from one, as an editor shows them.
            let line_number = index + 1;
            let malformed = |reason: String| GraffitiFileError::Line {
                path: self.path.clone(),
                line: line_number,
                reason,
            };
            let (key, value) = line
                .split_once(':')
                .ok_or_else(|| malformed("no colon after the key".to_owned()))?;
            let graffiti =
                Graffiti::parse(value.trim()).map_err(|error| malformed(error.to_string()))?;
            let key = key.trim();
            if key == Self::DEFAULT {
                default = Some(graffiti);
            } else {
                let bytes = <[u8; 48]>::from_data(key)
                    .map_err(|error| malformed(format!("invalid public key {key:?}: {error}")))?;
                keys.insert(BlsPubkey(bytes), graffiti);
            }
        }
        Ok((default, keys))
    }
}

#[cfg(test)]
mod tests {
    use std::{env, process};

    use super::*;

    /// A graffiti file with some text, unique to one test.
    fn file(name: &str, text: &str) -> GraffitiFile {
        let path = env::temp_dir().join(format!("axiom-graffiti-{name}-{}", process::id()));
        fs::write(&path, text).unwrap();
        GraffitiFile::new(path)
    }

    #[test]
    fn graffiti_round_trips_through_its_zero_padding() {
        // "axiom" takes 5 bytes; the other 27 are zero.
        let graffiti = Graffiti::parse("axiom").unwrap();
        let mut bytes = [0; 32];
        bytes[..5].copy_from_slice(b"axiom");
        assert_eq!(graffiti, Graffiti(Bytes32(bytes)));
        assert_eq!(graffiti.text(), "axiom");

        // Exactly 32 bytes fit with no padding; the empty text is all padding.
        let full = "x".repeat(32);
        assert_eq!(Graffiti::parse(&full).unwrap().text(), full);
        assert_eq!(Graffiti::parse("").unwrap(), Graffiti::default());
    }

    #[test]
    fn graffiti_longer_than_a_block_holds_is_refused() {
        // Eleven 3-byte characters are 33 bytes, one more than a block holds.
        assert_eq!(
            Graffiti::parse(&"\u{20ac}".repeat(11)),
            Err(GraffitiError::TooLong { len: 33, max: 32 })
        );
    }

    #[test]
    fn a_key_line_beats_the_default_line() {
        let own = BlsPubkey([0x80; 48]);
        let other = BlsPubkey([0x90; 48]);
        // Fixture state: a default line, a blank line, and one line for the own key.
        let file = file(
            "lookup",
            &format!("default: everyone\n\n{}:  mine  \n", own.0.to_data()),
        );
        assert_eq!(
            file.lookup(&own).unwrap(),
            Some(Graffiti::parse("mine").unwrap())
        );
        assert_eq!(
            file.lookup(&other).unwrap(),
            Some(Graffiti::parse("everyone").unwrap())
        );
        fs::remove_file(file.path()).unwrap();
    }

    #[test]
    fn a_malformed_line_names_its_number() {
        // Line 2 has no colon.
        let file = file("malformed", "default: x\nnot a line\n");
        let error = file.lookup(&BlsPubkey([0x80; 48])).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("{} line 2: no colon after the key", file.path().display())
        );
        fs::remove_file(file.path()).unwrap();
    }
}
