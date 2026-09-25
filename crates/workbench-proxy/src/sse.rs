//! Server-Sent Events framing: reads a `text/event-stream` body into events,
//! incrementally, following the WHATWG event-stream interpretation rules.
//!
//! Lines end with CRLF, LF, or CR (a CR at the end of one chunk may pair with
//! an LF at the start of the next). A line starting with `:` is a comment. A
//! `field: value` line sets `event`, appends to `data`, or sets `id`/`retry`;
//! one leading space of the value is dropped. A blank line dispatches the
//! pending event when it has data. An event cut off by the end of the stream
//! (no closing blank line) is not dispatched, as a browser would not.

/// Largest data retained per event; larger events keep their full size and a
/// truncated payload.
pub const MAX_SSE_EVENT_BYTES: usize = 1024 * 1024;

/// Room for a field name and separator beyond the retained value.
const LINE_SLACK: usize = 64;

/// One dispatched event.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SseEvent {
    /// The `event:` type; `None` means the default `message` type.
    pub event: Option<String>,
    /// The `data:` lines, joined by line feeds (possibly truncated).
    pub data: String,
    /// Full data size, larger than `data.len()` when truncated.
    pub data_bytes: usize,
    /// The `id:` this event set, if any.
    pub id: Option<String>,
    /// The `retry:` reconnection time this event set, if any.
    pub retry_ms: Option<u64>,
}

/// Incremental event-stream parser; feed it body chunks as they arrive.
#[derive(Clone, Debug, Default)]
pub struct SseParser {
    line: Vec<u8>,
    line_bytes: usize,
    after_cr: bool,
    seen_line: bool,
    has_data: bool,
    pending: SseEvent,
}

impl SseParser {
    /// Parses one body chunk, returning the events it completes.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<SseEvent> {
        let mut events = Vec::new();
        for &byte in bytes {
            match byte {
                b'\n' if self.after_cr => self.after_cr = false,
                b'\n' | b'\r' => {
                    self.after_cr = byte == b'\r';
                    self.end_line(&mut events);
                }
                _ => {
                    self.after_cr = false;
                    if self.line.len() < MAX_SSE_EVENT_BYTES + LINE_SLACK {
                        self.line.push(byte);
                    }
                    self.line_bytes += 1;
                }
            }
        }
        events
    }

    fn end_line(&mut self, events: &mut Vec<SseEvent>) {
        let mut line = std::mem::take(&mut self.line);
        let mut full = std::mem::take(&mut self.line_bytes);
        if !self.seen_line {
            self.seen_line = true;
            if line.starts_with(&[0xEF, 0xBB, 0xBF]) {
                line.drain(..3);
                full -= 3;
            }
        }
        if line.is_empty() {
            self.dispatch(events);
            return;
        }
        if line[0] == b':' {
            return;
        }
        let (field, mut value) = match line.iter().position(|&byte| byte == b':') {
            Some(colon) => (&line[..colon], &line[colon + 1..]),
            None => (&line[..], &[][..]),
        };
        if value.first() == Some(&b' ') {
            value = &value[1..];
        }
        let value_bytes = full - (line.len() - value.len());
        let text = String::from_utf8_lossy(value);
        match field {
            b"event" => self.pending.event = Some(text.into_owned()),
            b"data" => {
                if self.has_data {
                    self.pending.data_bytes += 1;
                    push_capped(&mut self.pending.data, "\n");
                }
                self.has_data = true;
                self.pending.data_bytes += value_bytes;
                push_capped(&mut self.pending.data, &text);
            }
            b"id" if !value.contains(&0) => self.pending.id = Some(text.into_owned()),
            b"retry" if !value.is_empty() && value.iter().all(u8::is_ascii_digit) => {
                self.pending.retry_ms = text.parse().ok();
            }
            _ => {}
        }
    }

    fn dispatch(&mut self, events: &mut Vec<SseEvent>) {
        let pending = std::mem::take(&mut self.pending);
        if std::mem::take(&mut self.has_data) {
            events.push(pending);
        }
    }
}

/// Appends `text`, stopping at [`MAX_SSE_EVENT_BYTES`] on a char boundary.
fn push_capped(data: &mut String, text: &str) {
    let room = MAX_SSE_EVENT_BYTES.saturating_sub(data.len());
    if text.len() <= room {
        data.push_str(text);
        return;
    }
    let mut end = room;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    data.push_str(&text[..end]);
}

/// Whether a `Content-Type` value is an event stream.
#[must_use]
pub fn is_event_stream(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("text/event-stream"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(chunks: &[&[u8]]) -> Vec<SseEvent> {
        let mut parser = SseParser::default();
        chunks.iter().flat_map(|chunk| parser.feed(chunk)).collect()
    }

    fn data(event: &SseEvent) -> &str {
        &event.data
    }

    #[test]
    fn multi_line_data_joins_with_line_feeds_and_types_and_ids_are_per_event() {
        let events = parse(&[b"event: price\nid: 7\ndata: {\"a\":\ndata:  1}\n\ndata: next\n\n"]);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event.as_deref(), Some("price"));
        assert_eq!(events[0].id.as_deref(), Some("7"));
        // One leading space is dropped; the second is data.
        assert_eq!(data(&events[0]), "{\"a\":\n 1}");
        assert_eq!(events[0].data_bytes, events[0].data.len());
        assert_eq!(events[1].event, None, "the type does not carry over");
        assert_eq!(events[1].id, None);
        assert_eq!(data(&events[1]), "next");
    }

    #[test]
    fn comments_are_skipped_and_blocks_without_data_do_not_dispatch() {
        let events = parse(&[b": keep-alive\n\nid: 3\n\n:another\ndata: x\n\n"]);
        assert_eq!(events.len(), 1);
        assert_eq!(data(&events[0]), "x");
        assert_eq!(events[0].id, None, "the id-only block did not dispatch");
    }

    #[test]
    fn every_line_ending_and_chunk_split_parses_the_same() {
        let expected = vec!["one", "two", "three"];
        for stream in [
            &b"data: one\n\ndata: two\n\ndata: three\n\n"[..],
            b"data: one\r\n\r\ndata: two\r\n\r\ndata: three\r\n\r\n",
            b"data: one\r\rdata: two\r\rdata: three\r\r",
        ] {
            let whole = parse(&[stream]);
            assert_eq!(whole.iter().map(data).collect::<Vec<_>>(), expected);
            // Split after every byte: a CR|LF pair straddles chunks.
            let bytes = stream.iter().map(std::slice::from_ref).collect::<Vec<_>>();
            let split = parse(&bytes);
            assert_eq!(split, whole);
        }
    }

    #[test]
    fn empty_data_fields_retry_bom_and_unknown_fields() {
        let events = parse(&[
            b"\xEF\xBB\xBFdata\ndata\n\n",
            b"retry: 3000\nbogus: 1\ndata: r\n\n",
            b"retry: 12x\ndata: bad-retry\n\n",
        ]);
        assert_eq!(data(&events[0]), "\n", "two empty data lines");
        assert_eq!(events[1].retry_ms, Some(3000));
        assert_eq!(data(&events[1]), "r");
        assert_eq!(events[2].retry_ms, None);
    }

    #[test]
    fn an_event_cut_off_by_the_end_of_the_stream_is_not_dispatched() {
        assert!(parse(&[b"data: partial\n"]).is_empty());
    }

    #[test]
    fn oversized_data_is_truncated_but_its_full_size_is_kept() {
        let big = "x".repeat(MAX_SSE_EVENT_BYTES + 10);
        let stream = format!("data: {big}\n\n");
        let events = parse(&[stream.as_bytes()]);
        assert_eq!(events[0].data.len(), MAX_SSE_EVENT_BYTES);
        assert_eq!(events[0].data_bytes, MAX_SSE_EVENT_BYTES + 10);
    }

    #[test]
    fn event_stream_content_types_are_recognized() {
        assert!(is_event_stream("text/event-stream"));
        assert!(is_event_stream("Text/Event-Stream; charset=utf-8"));
        assert!(!is_event_stream("text/plain"));
        assert!(!is_event_stream("application/json"));
    }
}
