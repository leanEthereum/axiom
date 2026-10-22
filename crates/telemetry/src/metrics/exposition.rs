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
    use proptest::prelude::*;

    use super::*;
    use crate::metrics::{Buckets, Registry};

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

    #[test]
    fn every_kind_renders_exactly() {
        let registry = Registry::new();

        // An unlabelled counter at 7.
        let counter = registry.counter("a_total", "Counter.").unwrap();
        counter.inc_by(7);

        // An unlabelled gauge below zero.
        let gauge = registry.gauge("b", "Gauge.").unwrap();
        gauge.set(-3);

        // A histogram with bounds 0.5 and 1, observing 0.25, 0.75, and 3.
        //
        //     slots       0.5:1  1:1  +Inf:1
        //     cumulative  1      2    3       sum 4, count 3
        let buckets = Buckets::new(&[0.5, 1.0]).unwrap();
        let histogram = registry
            .histogram("c_seconds", "Histogram.", buckets)
            .unwrap();
        for value in [0.25, 0.75, 3.0] {
            histogram.observe(value);
        }

        // Two labels; children render sorted by value tuple, not by creation order.
        let gauges = registry
            .gauge_vec("d", "Gauge family.", ["x", "y"])
            .unwrap();
        gauges.with_label_values(["2", "a"]).set(20);
        gauges.with_label_values(["1", "b"]).set(10);

        // One label over a single bound; "put" exists but has seen nothing.
        let buckets = Buckets::new(&[1.0]).unwrap();
        let requests = registry
            .histogram_vec("e_seconds", "Histogram family.", ["method"], buckets)
            .unwrap();
        requests.with_label_values(["get"]).observe(2.0);
        let _ = requests.with_label_values(["put"]);

        // A family with no children shows only its help and type lines.
        let _empty = registry.counter_vec("f_total", "Empty.", ["x"]).unwrap();

        let expected = concat!(
            "# HELP a_total Counter.\n",
            "# TYPE a_total counter\n",
            "a_total 7\n",
            "# HELP b Gauge.\n",
            "# TYPE b gauge\n",
            "b -3\n",
            "# HELP c_seconds Histogram.\n",
            "# TYPE c_seconds histogram\n",
            "c_seconds_bucket{le=\"0.5\"} 1\n",
            "c_seconds_bucket{le=\"1\"} 2\n",
            "c_seconds_bucket{le=\"+Inf\"} 3\n",
            "c_seconds_sum 4\n",
            "c_seconds_count 3\n",
            "# HELP d Gauge family.\n",
            "# TYPE d gauge\n",
            "d{x=\"1\",y=\"b\"} 10\n",
            "d{x=\"2\",y=\"a\"} 20\n",
            "# HELP e_seconds Histogram family.\n",
            "# TYPE e_seconds histogram\n",
            "e_seconds_bucket{method=\"get\",le=\"1\"} 0\n",
            "e_seconds_bucket{method=\"get\",le=\"+Inf\"} 1\n",
            "e_seconds_sum{method=\"get\"} 2\n",
            "e_seconds_count{method=\"get\"} 1\n",
            "e_seconds_bucket{method=\"put\",le=\"1\"} 0\n",
            "e_seconds_bucket{method=\"put\",le=\"+Inf\"} 0\n",
            "e_seconds_sum{method=\"put\"} 0\n",
            "e_seconds_count{method=\"put\"} 0\n",
            "# HELP f_total Empty.\n",
            "# TYPE f_total counter\n",
        );
        assert_eq!(registry.render(), expected);
    }

    #[test]
    fn label_values_and_help_are_escaped() {
        let registry = Registry::new();

        // Help escapes backslash and newline but keeps the quote.
        let paths = registry
            .counter_vec("p_total", "Say \"hi\"\\\nbye.", ["path"])
            .unwrap();

        // Label values escape backslash, quote, and newline.
        //
        //     a\b   -> a\\b
        //     "q"   -> \"q\"
        //     x<LF>y -> x\ny
        paths.with_label_values(["a\\b"]).inc();
        paths.with_label_values(["\"q\""]).inc();
        paths.with_label_values(["x\ny"]).inc();

        // Children sort by raw value: '"' (0x22) < 'a' (0x61) < 'x' (0x78).
        let expected = concat!(
            "# HELP p_total Say \"hi\"\\\\\\nbye.\n",
            "# TYPE p_total counter\n",
            "p_total{path=\"\\\"q\\\"\"} 1\n",
            "p_total{path=\"a\\\\b\"} 1\n",
            "p_total{path=\"x\\ny\"} 1\n",
        );
        assert_eq!(registry.render(), expected);
    }

    #[test]
    fn special_floats_in_sums() {
        let registry = Registry::new();

        // No finite bounds: every observation lands in the infinite bucket.
        let none = Buckets::new(&[]).unwrap();

        // Minus infinity sums to minus infinity.
        let low = registry.histogram("h_low", "Low.", none.clone()).unwrap();
        low.observe(f64::NEG_INFINITY);

        // NaN sums to NaN.
        let nan = registry.histogram("h_nan", "NaN.", none.clone()).unwrap();
        nan.observe(f64::NAN);

        // Plus infinity sums to plus infinity.
        let high = registry.histogram("h_up", "High.", none).unwrap();
        high.observe(f64::INFINITY);

        let expected = concat!(
            "# HELP h_low Low.\n",
            "# TYPE h_low histogram\n",
            "h_low_bucket{le=\"+Inf\"} 1\n",
            "h_low_sum -Inf\n",
            "h_low_count 1\n",
            "# HELP h_nan NaN.\n",
            "# TYPE h_nan histogram\n",
            "h_nan_bucket{le=\"+Inf\"} 1\n",
            "h_nan_sum NaN\n",
            "h_nan_count 1\n",
            "# HELP h_up High.\n",
            "# TYPE h_up histogram\n",
            "h_up_bucket{le=\"+Inf\"} 1\n",
            "h_up_sum +Inf\n",
            "h_up_count 1\n",
        );
        assert_eq!(registry.render(), expected);
    }

    /// Reads one exposition sample line with a single label back into its parts.
    ///
    /// ```text
    ///     name{label="escaped value"} sample
    /// ```
    ///
    /// Returns the name, the label, the unescaped value, and the sample text.
    fn parse_line(line: &str) -> Option<(String, String, String, String)> {
        let (name, rest) = line.split_once('{')?;
        let (label, rest) = rest.split_once("=\"")?;
        let mut value = String::new();
        let mut chars = rest.chars();
        // Walk the quoted value, undoing each of the three escapes.
        loop {
            match chars.next()? {
                '"' => break,
                '\\' => match chars.next()? {
                    '\\' => value.push('\\'),
                    '"' => value.push('"'),
                    'n' => value.push('\n'),
                    _ => return None,
                },
                c => value.push(c),
            }
        }
        // After the closing quote: a brace, a space, then the sample.
        let sample = chars.as_str().strip_prefix("} ")?;
        Some((name.to_owned(), label.to_owned(), value, sample.to_owned()))
    }

    proptest! {
        #[test]
        fn label_values_round_trip(value in any::<String>()) {
            let registry = Registry::new();
            let family = registry.counter_vec("m_total", "Help.", ["v"]).unwrap();
            family.with_label_values([value.as_str()]).inc_by(5);

            // The only sample line is the third: after the help and type lines.
            let text = registry.render();
            let line = text.lines().nth(2).unwrap();

            // Escaping removed every raw newline, so the sample sits on one line.
            prop_assert_eq!(text.lines().count(), 3);

            // Parsing the line recovers the exact value.
            let parsed = parse_line(line);
            prop_assert_eq!(
                parsed,
                Some(("m_total".to_owned(), "v".to_owned(), value, "5".to_owned()))
            );
        }
    }
}
