//! The Prometheus text exposition format, version 0.0.4.
//!
//! Source: the Prometheus "Exposition formats" reference, text format section.

use std::fmt::{self, Display, Write};

use crate::metrics::{HistogramSnapshot, name::MetricName};

/// The media type of the text format, as a scraper expects it.
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// The kind a metric declares on its type line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A monotonic count.
    Counter,

    /// A value that moves both ways.
    Gauge,

    /// Bucketed observations with their sum and count.
    Histogram,
}

impl Kind {
    /// The keyword on the type line.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::Histogram => "histogram",
        }
    }
}

/// A float written the way Prometheus reads it.
///
/// ```text
///     infinity  -> +Inf
///     -infinity -> -Inf
///     NaN       -> NaN
///     2.5       -> 2.5
///     1.0       -> 1
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Float(pub(crate) f64);

impl Display for Float {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The three special values have fixed spellings in the format.
        if self.0.is_nan() {
            f.write_str("NaN")
        } else if self.0 == f64::INFINITY {
            f.write_str("+Inf")
        } else if self.0 == f64::NEG_INFINITY {
            f.write_str("-Inf")
        } else {
            // The shortest text that reads back as the same float.
            write!(f, "{}", self.0)
        }
    }
}

/// A writer of exposition lines into any text sink.
#[derive(Debug)]
pub(crate) struct Exposition<'a, W> {
    /// The sink.
    out: &'a mut W,
}

impl<'a, W: Write> Exposition<'a, W> {
    /// A writer appending to a sink.
    pub(crate) const fn new(out: &'a mut W) -> Self {
        Self { out }
    }

    /// Writes the help and type lines that open a metric.
    ///
    /// ```text
    ///     # HELP beacon_head_slot Slot of the head block.
    ///     # TYPE beacon_head_slot gauge
    /// ```
    pub(crate) fn header(&mut self, name: &MetricName, help: &str, kind: Kind) -> fmt::Result {
        write!(self.out, "# HELP {name} ")?;
        // Help text escapes only backslash and newline; quotes stay literal.
        self.escaped(help, false)?;
        writeln!(self.out, "\n# TYPE {name} {}", kind.as_str())
    }

    /// Writes one sample line.
    ///
    /// ```text
    ///     name suffix { label="value",... } space value newline
    ///     gossip_messages_total{topic="beacon_block",outcome="accept"} 7
    /// ```
    pub(crate) fn sample(
        &mut self,
        name: &MetricName,
        suffix: &str,
        labels: &[(&str, &str)],
        value: &dyn Display,
    ) -> fmt::Result {
        write!(self.out, "{name}{suffix}")?;
        // An unlabelled sample has no braces at all.
        if !labels.is_empty() {
            self.out.write_char('{')?;
            for (index, (label, text)) in labels.iter().enumerate() {
                // Commas separate pairs; no trailing comma.
                if index > 0 {
                    self.out.write_char(',')?;
                }
                write!(self.out, "{label}=\"")?;
                // Label values escape the quote as well, since they sit inside quotes.
                self.escaped(text, true)?;
                self.out.write_char('"')?;
            }
            self.out.write_char('}')?;
        }
        writeln!(self.out, " {value}")
    }

    /// Writes the bucket, sum, and count lines of one histogram series.
    ///
    /// ```text
    ///     name_bucket{le="0.5"} 2      cumulative count at or below 0.5
    ///     name_bucket{le="+Inf"} 3     always equal to the count
    ///     name_sum 4.75
    ///     name_count 3
    /// ```
    pub(crate) fn histogram(
        &mut self,
        name: &MetricName,
        labels: &[(&str, &str)],
        snapshot: &HistogramSnapshot,
    ) -> fmt::Result {
        for (bound, count) in &snapshot.buckets {
            // The bound label goes after the series labels, so each bucket line extends them.
            let le = Float(*bound).to_string();
            let mut bucket_labels = labels.to_vec();
            bucket_labels.push(("le", &le));
            self.sample(name, "_bucket", &bucket_labels, count)?;
        }
        self.sample(name, "_sum", labels, &Float(snapshot.sum))?;
        self.sample(name, "_count", labels, &snapshot.count)
    }

    /// Writes text with backslash and newline escaped, and the double quote when asked.
    fn escaped(&mut self, text: &str, quote: bool) -> fmt::Result {
        for c in text.chars() {
            // Only these three characters are special in the text format.
            match c {
                '\\' => self.out.write_str("\\\\")?,
                '\n' => self.out.write_str("\\n")?,
                '"' if quote => self.out.write_str("\\\"")?,
                _ => self.out.write_char(c)?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floats() {
        // Each special value and two ordinary ones.
        let cases = [
            (f64::INFINITY, "+Inf"),
            (f64::NEG_INFINITY, "-Inf"),
            (f64::NAN, "NaN"),
            (1.0, "1"),
            (0.005, "0.005"),
        ];
        for (value, text) in cases {
            assert_eq!(Float(value).to_string(), text);
        }
    }

    #[test]
    fn escaping() {
        let name = MetricName::parse("m").expect("valid name");
        let mut out = String::new();
        let mut exposition = Exposition::new(&mut out);

        // Help: backslash and newline escaped, quote kept.
        exposition
            .header(&name, "a\\b\n\"c\"", Kind::Gauge)
            .expect("string sink");

        // Label value: backslash, newline, and quote all escaped.
        exposition
            .sample(&name, "", &[("l", "a\\b\n\"c\"")], &1)
            .expect("string sink");

        assert_eq!(
            out,
            "# HELP m a\\\\b\\n\"c\"\n# TYPE m gauge\nm{l=\"a\\\\b\\n\\\"c\\\"\"} 1\n"
        );
    }
}
