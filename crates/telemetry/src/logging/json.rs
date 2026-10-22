//! One JSON object per log event, written without a serialization library.

use std::{
    error::Error,
    fmt::{self, Debug, Display, Write},
};

use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{
    fmt::{
        FmtContext, FormatEvent, FormatFields, FormattedFields,
        format::Writer,
        time::{FormatTime, SystemTime},
    },
    registry::LookupSpan,
};

/// Lays out each event as one line of JSON.
///
/// ```text
///     {"timestamp":"2026-10-22T09:00:00.000000Z","level":"INFO","target":"axiom",
///      "fields":{"message":"imported","slot":7},
///      "spans":[{"name":"import","fields":"root=0xab"}]}
/// ```
///
/// Span fields keep their text form, since spans record them before this layout runs.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct JsonFormat;

impl<S, N> FormatEvent<S, N> for JsonFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let metadata = event.metadata();

        // Phase 1: when, how severe, and where from.
        // The RFC 3339 timestamp contains no character that needs escaping.
        writer.write_str("{\"timestamp\":\"")?;
        SystemTime.format_time(&mut writer)?;
        write!(
            writer,
            "\",\"level\":\"{}\",\"target\":{}",
            metadata.level(),
            JsonString(metadata.target())
        )?;

        // Phase 2: the event's own fields, typed where JSON has a matching type.
        writer.write_str(",\"fields\":{")?;
        let mut visitor = FieldVisitor {
            out: &mut writer,
            first: true,
            result: Ok(()),
        };
        event.record(&mut visitor);
        visitor.result?;
        writer.write_char('}')?;

        // Phase 3: the enclosing spans, outermost first.
        if let Some(scope) = ctx.event_scope() {
            writer.write_str(",\"spans\":[")?;
            for (index, span) in scope.from_root().enumerate() {
                if index > 0 {
                    writer.write_char(',')?;
                }
                write!(writer, "{{\"name\":{}", JsonString(span.name()))?;
                // The formatting layer stored each span's fields as text when the span opened.
                let extensions = span.extensions();
                if let Some(fields) = extensions.get::<FormattedFields<N>>()
                    && !fields.fields.is_empty()
                {
                    write!(writer, ",\"fields\":{}", JsonString(&fields.fields))?;
                }
                // Release the span's extension lock before the next span takes its own.
                drop(extensions);
                writer.write_char('}')?;
            }
            writer.write_char(']')?;
        }

        // One object per line, so a collector can split the stream on newlines.
        writer.write_str("}\n")
    }
}

/// Writes each field of an event as a JSON member.
struct FieldVisitor<'a, W> {
    /// The sink.
    out: &'a mut W,

    /// Whether no member has been written yet, so no comma is due.
    first: bool,

    /// The first write error, since the visiting methods cannot return one.
    result: fmt::Result,
}

impl<W: Write> FieldVisitor<'_, W> {
    /// Writes a member whose value is a JSON literal, such as a number.
    fn literal(&mut self, field: &Field, value: &dyn Display) {
        // After a failure, skip the rest; the error surfaces once visiting ends.
        if self.result.is_ok() {
            self.result = self.key(field).and_then(|()| write!(self.out, "{value}"));
        }
    }

    /// Writes a member whose value is a JSON string.
    fn string(&mut self, field: &Field, value: &dyn Display) {
        // After a failure, skip the rest; the error surfaces once visiting ends.
        if self.result.is_ok() {
            // Escape the text as it streams, so no temporary string is built.
            self.result = self
                .key(field)
                .and_then(|()| write!(self.out, "{}", JsonString(value)));
        }
    }

    /// Writes the separator and the quoted field name.
    fn key(&mut self, field: &Field) -> fmt::Result {
        // A comma goes between members, never before the first.
        if !self.first {
            self.out.write_char(',')?;
        }
        self.first = false;
        write!(self.out, "{}:", JsonString(field.name()))
    }
}

impl<W: Write> Visit for FieldVisitor<'_, W> {
    fn record_f64(&mut self, field: &Field, value: f64) {
        // JSON has no spelling for NaN or infinity, so those become strings.
        if value.is_finite() {
            self.literal(field, &value);
        } else {
            self.string(field, &value);
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        // Integers print as JSON numbers.
        self.literal(field, &value);
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        // Integers print as JSON numbers.
        self.literal(field, &value);
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        // Integers print as JSON numbers, whatever their width.
        self.literal(field, &value);
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        // Integers print as JSON numbers, whatever their width.
        self.literal(field, &value);
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        // Booleans print as JSON true or false.
        self.literal(field, &value);
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        // Text is quoted and escaped.
        self.string(field, &value);
    }

    fn record_error(&mut self, field: &Field, value: &(dyn Error + 'static)) {
        // An error prints its message, as a reader expects.
        self.string(field, &format_args!("{value}"));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        // Everything else, the message included, prints its debug form as a string.
        self.string(field, &format_args!("{value:?}"));
    }
}

/// A sink adapter that escapes text for the inside of a JSON string.
///
/// Source: RFC 8259 section 7, which requires escaping quotes, backslashes, and control bytes.
struct Escaped<'a, W>(&'a mut W);

impl<W: Write> Write for Escaped<'_, W> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        for c in text.chars() {
            match c {
                // The two characters that end or start an escape.
                '"' => self.0.write_str("\\\"")?,
                '\\' => self.0.write_str("\\\\")?,
                // Common control characters have short escapes.
                '\n' => self.0.write_str("\\n")?,
                '\r' => self.0.write_str("\\r")?,
                '\t' => self.0.write_str("\\t")?,
                // Other control characters use the four-digit form.
                c if u32::from(c) < 0x20 => write!(self.0, "\\u{:04x}", u32::from(c))?,
                c => self.0.write_char(c)?,
            }
        }
        Ok(())
    }
}

/// A display adapter that writes a value as a quoted, escaped JSON string.
///
/// The value's text streams through the escaper, so no temporary string is built.
struct JsonString<T>(T);

impl<T: Display> Display for JsonString<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_char('"')?;
        // Every character between the quotes goes through the escaper.
        write!(Escaped(&mut *f), "{}", self.0)?;
        f.write_char('"')
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        sync::{Arc, Mutex, PoisonError},
    };

    use tracing::{info, info_span, subscriber};
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;
    use crate::logging::{LogConfig, LogFormat};

    /// A sink collecting every written byte.
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            // Append under the lock; a test never poisons it.
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            // Nothing is buffered.
            Ok(())
        }
    }

    impl MakeWriter<'_> for Capture {
        type Writer = Self;

        fn make_writer(&self) -> Self::Writer {
            // Every writer appends to the same buffer.
            self.clone()
        }
    }

    #[test]
    fn events_become_single_json_lines() {
        let capture = Capture::default();
        let config = LogConfig {
            filter: "info".to_owned(),
            format: LogFormat::Json,
        };
        let built = config.subscriber(capture.clone()).expect("valid filter");

        // One event inside one span, with a quote and a newline to escape.
        subscriber::with_default(built, || {
            let span = info_span!("import", slot = 7);
            let _entered = span.enter();
            info!(peers = 3_u64, ok = true, "got \"block\"\nnext");
        });

        let text =
            String::from_utf8(capture.0.lock().expect("unpoisoned").clone()).expect("utf-8 output");

        // The timestamp varies, so check its frame and drop it.
        //
        //     {"timestamp":"2026-...Z","level":...
        let rest = text
            .strip_prefix("{\"timestamp\":\"")
            .expect("timestamp first");
        let (stamp, rest) = rest.split_once('"').expect("closing quote");
        assert!(stamp.ends_with('Z'), "{stamp}");

        // The rest is exact: typed fields, escaped message, span with text fields.
        assert_eq!(
            rest,
            concat!(
                ",\"level\":\"INFO\",\"target\":\"axiom_telemetry::logging::json::tests\",",
                "\"fields\":{\"message\":\"got \\\"block\\\"\\nnext\",\"peers\":3,\"ok\":true},",
                "\"spans\":[{\"name\":\"import\",\"fields\":\"slot=7\"}]}\n"
            )
        );
    }

    #[test]
    fn control_characters_use_the_long_escape() {
        // Bell is 0x07 and has no short escape; tab does.
        let out = JsonString("a\u{7}\tb").to_string();
        assert_eq!(out, "\"a\\u0007\\tb\"");
    }
}
