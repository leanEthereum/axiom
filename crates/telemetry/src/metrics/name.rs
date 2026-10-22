//! Validated metric and label names.

use std::fmt;

use crate::metrics::RegistryError;

/// A metric name that matches the Prometheus grammar.
///
/// The grammar is `[a-zA-Z_:][a-zA-Z0-9_:]*`, per the Prometheus data model.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct MetricName(String);

impl MetricName {
    /// Checks a name against the metric grammar.
    pub(crate) fn parse(name: &str) -> Result<Self, RegistryError> {
        // Colons are legal anywhere, digits everywhere but the first byte.
        if is_identifier(name, |byte| byte == b':') {
            Ok(Self(name.to_owned()))
        } else {
            Err(RegistryError::InvalidMetricName(name.to_owned()))
        }
    }

    /// The name as text.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MetricName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A label name that matches the Prometheus grammar and is not reserved.
///
/// The grammar is `[a-zA-Z_][a-zA-Z0-9_]*`.
/// Names starting with two underscores belong to Prometheus itself.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct LabelName(String);

impl LabelName {
    /// Checks a name against the label grammar and the reserved prefix.
    pub(crate) fn parse(name: &str) -> Result<Self, RegistryError> {
        // Labels allow no colon, and the double underscore prefix is reserved.
        if is_identifier(name, |_| false) && !name.starts_with("__") {
            Ok(Self(name.to_owned()))
        } else {
            Err(RegistryError::InvalidLabelName(name.to_owned()))
        }
    }

    /// Checks a list of names, refusing a repeat or a name the metric kind reserves.
    ///
    /// Histograms reserve their bucket bound label.
    pub(crate) fn parse_all(
        names: &[&str],
        reserved: &[&str],
    ) -> Result<Box<[Self]>, RegistryError> {
        let mut parsed: Vec<Self> = Vec::with_capacity(names.len());
        for name in names {
            // A label the exposition adds itself would collide on every sample.
            if reserved.contains(name) {
                return Err(RegistryError::InvalidLabelName((*name).to_owned()));
            }
            let label = Self::parse(name)?;
            // Two labels with one name would make every series ambiguous.
            if parsed.contains(&label) {
                return Err(RegistryError::DuplicateLabelName(label.0));
            }
            parsed.push(label);
        }
        Ok(parsed.into_boxed_slice())
    }

    /// The name as text.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether a name is an identifier, with extra bytes allowed by a predicate.
///
/// ```text
///     first byte   letter, underscore, or extra
///     later bytes  letter, digit, underscore, or extra
/// ```
fn is_identifier(name: &str, extra: impl Fn(u8) -> bool) -> bool {
    // An empty name names nothing.
    let Some((&first, rest)) = name.as_bytes().split_first() else {
        return false;
    };
    // The first byte may not be a digit, so a name never reads as a number.
    let head = first.is_ascii_alphabetic() || first == b'_' || extra(first);
    // Every later byte is a word byte or an extra one.
    let tail = rest
        .iter()
        .all(|&byte| byte.is_ascii_alphanumeric() || byte == b'_' || extra(byte));
    head && tail
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_names() {
        // Letters, later digits, underscores, and colons are legal.
        for good in ["a_b:c9", ":x", "_"] {
            assert_eq!(MetricName::parse(good), Ok(MetricName(good.to_owned())));
        }

        // A leading digit, a dash, a dot, and the empty name are not.
        for bad in ["9a", "a-b", "a.b", ""] {
            assert_eq!(
                MetricName::parse(bad),
                Err(RegistryError::InvalidMetricName(bad.to_owned()))
            );
        }
    }

    #[test]
    fn label_names() {
        // A colon is legal in metric names only.
        assert_eq!(
            LabelName::parse("a:b"),
            Err(RegistryError::InvalidLabelName("a:b".to_owned()))
        );

        // Two leading underscores are reserved, while one is fine.
        assert_eq!(
            LabelName::parse("__name"),
            Err(RegistryError::InvalidLabelName("__name".to_owned()))
        );
        assert_eq!(LabelName::parse("_x"), Ok(LabelName("_x".to_owned())));

        // A repeated name is refused by name.
        assert_eq!(
            LabelName::parse_all(&["a", "a"], &[]),
            Err(RegistryError::DuplicateLabelName("a".to_owned()))
        );

        // A name the kind reserves is refused even though its grammar is fine.
        assert_eq!(
            LabelName::parse_all(&["le"], &["le"]),
            Err(RegistryError::InvalidLabelName("le".to_owned()))
        );
    }
}
