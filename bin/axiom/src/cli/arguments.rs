//! The words of a command line, read one flag and its value at a time.

use std::{path::PathBuf, str::FromStr};

use crate::cli::CliError;

/// A cursor over the words after a command, handing out flags and their values.
#[derive(Debug)]
pub(crate) struct Arguments<I: Iterator<Item = String>> {
    /// The words not read yet.
    words: I,
}

impl<I: Iterator<Item = String>> Arguments<I> {
    /// A cursor at the first word.
    pub(crate) const fn new(words: I) -> Self {
        Self { words }
    }

    /// The next flag, or none at the end.
    pub(crate) fn next_flag(&mut self) -> Option<String> {
        self.words.next()
    }

    /// The value a flag needs, the next word.
    pub(crate) fn value(&mut self, flag: &'static str) -> Result<String, CliError> {
        self.words.next().ok_or(CliError::MissingValue(flag))
    }

    /// A value that parses from text, such as a number or an address.
    pub(crate) fn parsed<T: FromStr>(&mut self, flag: &'static str) -> Result<T, CliError> {
        let value = self.value(flag)?;
        value
            .parse()
            .map_err(|_| CliError::InvalidValue { flag, value })
    }

    /// A path value.
    pub(crate) fn path(&mut self, flag: &'static str) -> Result<PathBuf, CliError> {
        self.value(flag).map(PathBuf::from)
    }

    /// A value of true or false, as flags that default to on take.
    pub(crate) fn boolean(&mut self, flag: &'static str) -> Result<bool, CliError> {
        let value = self.value(flag)?;
        Self::truth(&value).ok_or(CliError::InvalidValue { flag, value })
    }

    /// The truth a word spells, if it spells one.
    fn truth(word: &str) -> Option<bool> {
        match word {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(words: &[&str]) -> Arguments<impl Iterator<Item = String>> {
        Arguments::new(
            words
                .iter()
                .map(|word| (*word).to_owned())
                .collect::<Vec<_>>()
                .into_iter(),
        )
    }

    #[test]
    fn values_follow_their_flag() {
        let mut words = arguments(&["--port", "9000", "--dir", "/data"]);
        assert_eq!(words.next_flag().as_deref(), Some("--port"));
        assert_eq!(words.parsed::<u16>("--port").unwrap(), 9000);
        assert_eq!(words.next_flag().as_deref(), Some("--dir"));
        assert_eq!(words.path("--dir").unwrap(), PathBuf::from("/data"));
        assert_eq!(words.next_flag(), None);
    }

    #[test]
    fn missing_and_malformed_values_name_the_flag() {
        // 70000 is past the largest port.
        let mut words = arguments(&["70000"]);
        assert!(matches!(
            words.parsed::<u16>("--port"),
            Err(CliError::InvalidValue { flag: "--port", value }) if value == "70000"
        ));
        assert!(matches!(
            words.value("--port"),
            Err(CliError::MissingValue("--port"))
        ));
    }

    #[test]
    fn booleans_are_spelled_out() {
        let mut words = arguments(&["false", "yes"]);
        assert!(!words.boolean("--prune-blobs").unwrap());
        assert!(matches!(
            words.boolean("--prune-blobs"),
            Err(CliError::InvalidValue { flag: "--prune-blobs", value }) if value == "yes"
        ));
    }
}
