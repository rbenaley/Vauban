//! One log event, one line.
//!
//! Services log text that another process or the network supplied: an
//! error string from a proxy, a path from a request, a server banner.
//! With the plain text formatter a line feed in such a value starts a new
//! line, and whoever chose the value writes the rest of it: a forged
//! `WARN` or `INFO` entry that looks like the service's own.
//!
//! The formatter writes each event with a single `write_all`. This
//! writer sits under it and escapes every carriage return and line feed
//! of the event except the terminator. It covers every call site of
//! every service at once, whatever sigil (`%`, `?`) or format string the
//! call uses. The JSON formatter already escapes them; the writer is then
//! a no-op.
//!
//! # Invariant
//!
//! An event written through [`SingleLine`] contains exactly one line
//! feed, its last byte.

use std::borrow::Cow;
use std::io;
use tracing_subscriber::fmt::MakeWriter;

/// Escape the carriage returns and line feeds of one event, keeping the
/// final line feed.
pub fn escape_event(event: &[u8]) -> Cow<'_, [u8]> {
    let (body, terminator) = match event.split_last() {
        Some((b'\n', body)) => (body, &b"\n"[..]),
        _ => (event, &b""[..]),
    };
    if !body.iter().any(|b| matches!(b, b'\n' | b'\r')) {
        return Cow::Borrowed(event);
    }
    let mut escaped = Vec::with_capacity(event.len() + 8);
    for byte in body {
        match byte {
            b'\n' => escaped.extend_from_slice(b"\\n"),
            b'\r' => escaped.extend_from_slice(b"\\r"),
            other => escaped.push(*other),
        }
    }
    escaped.extend_from_slice(terminator);
    Cow::Owned(escaped)
}

/// A writer that passes each `write` through [`escape_event`].
#[derive(Debug)]
pub struct SingleLineWriter<W>(W);

impl<W> SingleLineWriter<W> {
    pub fn new(inner: W) -> Self {
        Self(inner)
    }

    pub fn into_inner(self) -> W {
        self.0
    }
}

impl<W: io::Write> io::Write for SingleLineWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // All of it or an error: a partial write would split the event
        // and the next call would treat its tail as a new event.
        self.0.write_all(&escape_event(buf))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// `MakeWriter` for `tracing_subscriber::fmt`: standard output, one line
/// per event.
///
/// ```ignore
/// tracing_subscriber::fmt()
///     .with_writer(shared::log_line::SingleLine)
///     .init();
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct SingleLine;

impl<'a> MakeWriter<'a> for SingleLine {
    type Writer = SingleLineWriter<io::Stdout>;

    fn make_writer(&'a self) -> Self::Writer {
        SingleLineWriter(io::stdout())
    }
}

/// As [`SingleLine`], on standard error. For a service whose standard
/// output carries a protocol (the stdio MCP bridge).
#[derive(Debug, Clone, Copy, Default)]
pub struct SingleLineStderr;

impl<'a> MakeWriter<'a> for SingleLineStderr {
    type Writer = SingleLineWriter<io::Stderr>;

    fn make_writer(&'a self) -> Self::Writer {
        SingleLineWriter(io::stderr())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_plain_event_is_untouched() {
        let event = b"2026-11-17 INFO started\n";
        assert!(matches!(escape_event(event), Cow::Borrowed(_)));
        assert_eq!(&*escape_event(event), event);
    }

    #[test]
    fn attack_line_feed_in_a_value_does_not_start_a_line() {
        let event = b"WARN refused error=bad\n2026-11-17 INFO login ok user=admin\n";
        let escaped = escape_event(event);
        assert_eq!(
            &*escaped,
            &b"WARN refused error=bad\\n2026-11-17 INFO login ok user=admin\n"[..]
        );
    }

    #[test]
    fn attack_carriage_return_does_not_overwrite_the_line() {
        assert_eq!(
            &*escape_event(b"WARN x=a\rINFO forged\r\n"),
            &b"WARN x=a\\rINFO forged\\r\n"[..]
        );
    }

    #[test]
    fn test_event_without_terminator_is_escaped_whole() {
        assert_eq!(&*escape_event(b"a\nb"), &b"a\\nb"[..]);
        assert_eq!(&*escape_event(b""), &b""[..]);
        assert_eq!(&*escape_event(b"\n"), &b"\n"[..]);
    }

    /// Shared sink for the end-to-end tests.
    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Sink {
        type Writer = SingleLineWriter<Sink>;
        fn make_writer(&'a self) -> Self::Writer {
            SingleLineWriter(self.clone())
        }
    }

    /// Through the real formatter, with every sigil a call site uses.
    #[test]
    fn attack_forged_line_through_the_formatter_is_one_line() {
        let sink = Sink::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(sink.clone())
            .finish();
        let hostile = "boom\n2026-11-17T00:00:00Z  INFO vauban_web: login ok user=admin";
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(error = %hostile, "proxy refused");
            tracing::warn!(error = ?hostile, "proxy refused");
            tracing::warn!("proxy refused: {hostile}");
            tracing::warn!(error = hostile, "proxy refused\r\nINFO forged");
        });
        let out = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 4, "four events, four lines: {out:?}");
        for line in lines {
            assert!(line.contains("WARN"), "{line:?}");
            assert!(!line.trim_start().starts_with("2026-11-17T00:00:00Z"));
        }
        assert!(!out.contains('\r'));
    }

    proptest! {
        /// The invariant, for any bytes: at most one line feed, and only
        /// as the last byte; no carriage return at all.
        #[test]
        fn prop_escaped_event_is_one_line(event in proptest::collection::vec(any::<u8>(), 0..256)) {
            let escaped = escape_event(&event);
            let feeds = escaped.iter().filter(|b| **b == b'\n').count();
            prop_assert!(feeds <= 1);
            if feeds == 1 {
                prop_assert_eq!(escaped.last(), Some(&b'\n'));
                prop_assert_eq!(event.last(), Some(&b'\n'));
            }
            prop_assert!(!escaped.contains(&b'\r'));
        }

        /// Nothing else is changed.
        #[test]
        fn prop_event_without_cr_or_lf_is_unchanged(event in "[ -~\t]{0,128}") {
            let mut bytes = event.into_bytes();
            bytes.push(b'\n');
            let escaped = escape_event(&bytes);
            prop_assert_eq!(&*escaped, &bytes[..]);
        }
    }
}
