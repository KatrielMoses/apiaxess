//! Payload generation and processing engine for the Fuzzer.
//!
//! This module turns a [`PayloadSet`] — a source plus an ordered processing
//! pipeline plus an optional final URL-encode step — into a *lazy* stream of
//! final payload strings. Laziness is architectural: sources such as
//! [`PayloadSource::Numbers`], [`PayloadSource::BruteForcer`], and
//! [`PayloadSource::Dates`] can be astronomically large, so nothing here ever
//! collects a full source into a `Vec`; every generator is an iterator that
//! produces one value at a time, and the attack expansion in `fuzzer.rs` stops
//! pulling once it reaches `max_results`.
//!
//! Payloads are UTF-8 [`String`]s throughout (the request-substitution path
//! inserts them into UTF-8 fields). Sources that describe non-UTF-8 bytes
//! (illegal Unicode, bit flips, ECB block shuffles) emit the standard textual
//! representation used to deliver those bytes over HTTP — percent-encoding, or
//! ASCII-hex where the source is itself hex — never a fabricated "raw byte"
//! capability the transport cannot honor.

// This module is numeric- and encoding-heavy: number formatting, RNG mixing,
// cardinality saturation, and byte<->char conversions unavoidably cast between
// integer widths and float. These casts are intentional and bounded; allow the
// pedantic cast lints module-wide rather than dusting every line with attributes.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]

use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use apiaxess_workbench_store::{
    BitFlipFormat, CaseMode, DecodeScheme, EncodeScheme, HashAlgorithm, HashOutput, IteratorSlot,
    NullCount, NumberOrder, NumberRadix, PayloadProcessor, PayloadSet, PayloadSource,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use regex::Regex;
use std::io::BufRead as _;

/// The number of values a source will produce, without generating them.
///
/// `Exact` is a precise count; `AtLeast` is a saturated lower bound used when
/// the true count overflows `u64` (huge brute-force / cluster spaces) or is
/// otherwise unknown ahead of time (a continuous null source). The count
/// preview renders `AtLeast` honestly ("≈ N — will stop at `max_results`").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cardinality {
    /// A precise value count.
    Exact(u64),
    /// A saturated lower bound; the true count is at least this.
    AtLeast(u64),
}

impl Cardinality {
    /// The numeric bound, whether exact or saturated.
    pub(crate) fn bound(self) -> u64 {
        match self {
            Cardinality::Exact(n) | Cardinality::AtLeast(n) => n,
        }
    }

    /// Whether this is a precise count.
    pub(crate) fn is_exact(self) -> bool {
        matches!(self, Cardinality::Exact(_))
    }

    /// Saturating product, staying `Exact` only when both inputs are exact and
    /// the multiplication does not overflow.
    pub(crate) fn saturating_mul(self, other: Cardinality) -> Cardinality {
        match self.bound().checked_mul(other.bound()) {
            Some(product) if self.is_exact() && other.is_exact() => Cardinality::Exact(product),
            Some(product) => Cardinality::AtLeast(product),
            None => Cardinality::AtLeast(u64::MAX),
        }
    }

    /// Saturating sum, staying `Exact` only when both inputs are exact and the
    /// addition does not overflow.
    pub(crate) fn saturating_add(self, other: Cardinality) -> Cardinality {
        match self.bound().checked_add(other.bound()) {
            Some(sum) if self.is_exact() && other.is_exact() => Cardinality::Exact(sum),
            Some(sum) => Cardinality::AtLeast(sum),
            None => Cardinality::AtLeast(u64::MAX),
        }
    }

    /// The smaller of two cardinalities (Pitchfork length). Exact only when both
    /// are exact, since a saturated lower bound cannot pin the true minimum.
    pub(crate) fn min_with(self, other: Cardinality) -> Cardinality {
        let bound = self.bound().min(other.bound());
        if self.is_exact() && other.is_exact() {
            Cardinality::Exact(bound)
        } else {
            Cardinality::AtLeast(bound)
        }
    }
}

/// How a source produces its raw values and how many there are.
pub(crate) trait PayloadGeneration {
    /// A lazy iterator over the raw (pre-processing) values.
    fn generate(&self) -> Box<dyn Iterator<Item = String> + Send>;
    /// The value count without generating; see [`Cardinality`].
    fn cardinality(&self) -> Cardinality;
}

/// One stateless processing step applied to a single payload value. Returning
/// `None` drops the payload (it is not sent).
///
/// [`PayloadProcessor::AddRawPayload`] is intentionally an identity here: it
/// needs the pre-processing raw value, which only [`PayloadPipeline`] holds, so
/// the pipeline applies it — `apply` alone cannot.
pub(crate) trait PayloadProcessing {
    /// Apply this step, or drop the payload with `None`.
    fn apply(&self, value: &str) -> Option<String>;
}

// ---------------------------------------------------------------------------
// Source generation
// ---------------------------------------------------------------------------

impl PayloadGeneration for PayloadSource {
    #[allow(clippy::too_many_lines)]
    fn generate(&self) -> Box<dyn Iterator<Item = String> + Send> {
        match self {
            PayloadSource::SimpleList { values } => Box::new(values.clone().into_iter()),
            PayloadSource::RuntimeFile { path } => Box::new(RuntimeFileIter::open(path)),
            PayloadSource::CustomIterator { slots } => Box::new(CustomIteratorIter::new(slots)),
            PayloadSource::CharacterSubstitution { base, rules } => {
                let rules = rules.clone();
                Box::new(base.clone().into_iter().map(move |value| {
                    let mut out = value;
                    for rule in &rules {
                        out = out.replace(rule.from, &rule.to.to_string());
                    }
                    out
                }))
            }
            PayloadSource::CaseModification { base, modes } => {
                let modes = modes.clone();
                Box::new(base.clone().into_iter().flat_map(move |value| {
                    modes
                        .clone()
                        .into_iter()
                        .map(move |mode| apply_case(&value, mode))
                }))
            }
            // Until Grep-Extract (WS3) is wired, this only ever emits its seed;
            // the fuzzer validate step rejects a run so it never silently no-ops.
            PayloadSource::RecursiveGrep { seed } => Box::new(seed.clone().into_iter()),
            PayloadSource::IllegalUnicode { base, target } => {
                let encodings = overlong_encodings(*target);
                let target = *target;
                Box::new(base.clone().into_iter().flat_map(move |value| {
                    let value = value.clone();
                    encodings
                        .clone()
                        .into_iter()
                        .map(move |encoded| splice_first(&value, target, &encoded))
                }))
            }
            PayloadSource::CharacterBlocks {
                item,
                min,
                max,
                step,
            } => Box::new(CharacterBlocksIter::new(item.clone(), *min, *max, *step)),
            PayloadSource::Numbers {
                from,
                to,
                step,
                order,
                radix,
                min_integer_digits,
                max_fraction_digits,
            } => {
                let format = NumberFormat {
                    radix: *radix,
                    min_integer_digits: *min_integer_digits,
                    max_fraction_digits: *max_fraction_digits,
                };
                match order {
                    NumberOrder::Sequential => {
                        Box::new(NumbersSeqIter::new(*from, *to, *step, format))
                    }
                    NumberOrder::Random => {
                        Box::new(NumbersRandomIter::new(*from, *to, *step, format))
                    }
                }
            }
            PayloadSource::Dates {
                from,
                to,
                step_days,
                format,
            } => Box::new(DatesIter::new(*from, *to, *step_days, format.clone())),
            PayloadSource::BruteForcer {
                charset,
                min_len,
                max_len,
            } => Box::new(BruteForceIter::new(charset, *min_len, *max_len)),
            PayloadSource::NullPayloads { count } => match count {
                NullCount::Fixed(n) => Box::new(std::iter::repeat_n(
                    String::new(),
                    usize::try_from(*n).unwrap_or(usize::MAX),
                )),
                NullCount::Continuous => Box::new(std::iter::repeat(String::new())),
            },
            PayloadSource::CharacterFrobber { base } => Box::new(
                base.clone()
                    .into_iter()
                    .flat_map(|value| frob_positions(&value)),
            ),
            PayloadSource::BitFlipper { base, format } => {
                let format = *format;
                Box::new(
                    base.clone()
                        .into_iter()
                        .flat_map(move |value| bit_flips(&value, format)),
                )
            }
            PayloadSource::UsernameGenerator { names } => Box::new(
                names
                    .clone()
                    .into_iter()
                    .flat_map(|name| username_schemes(&name)),
            ),
            PayloadSource::EcbBlockShuffler { base, block_size } => {
                let block_size = (*block_size).max(1);
                Box::new(
                    base.clone()
                        .into_iter()
                        .flat_map(move |value| ecb_shuffles(&value, block_size)),
                )
            }
            // Slaved to another position; produces nothing on its own. The
            // fuzzer resolves its value from the referenced position at each step.
            PayloadSource::CopyOtherPayload { .. } => Box::new(std::iter::empty()),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn cardinality(&self) -> Cardinality {
        match self {
            PayloadSource::SimpleList { values } => Cardinality::Exact(values.len() as u64),
            PayloadSource::RuntimeFile { path } => match count_lines(path) {
                Some(n) => Cardinality::Exact(n),
                None => Cardinality::AtLeast(0),
            },
            PayloadSource::CustomIterator { slots } => {
                let mut card = Cardinality::Exact(1);
                for slot in slots {
                    card = card.saturating_mul(Cardinality::Exact(slot.items.len() as u64));
                }
                card
            }
            PayloadSource::CharacterSubstitution { base, .. } => {
                Cardinality::Exact(base.len() as u64)
            }
            // Recursion runs until the extract yields nothing; the seed count is
            // only a lower bound, so the preview renders it as "at least".
            PayloadSource::RecursiveGrep { seed } => Cardinality::AtLeast(seed.len() as u64),
            PayloadSource::CaseModification { base, modes } => {
                Cardinality::Exact((base.len() as u64).saturating_mul(modes.len() as u64))
            }
            PayloadSource::IllegalUnicode { base, target } => Cardinality::Exact(
                (base.len() as u64).saturating_mul(overlong_encodings(*target).len() as u64),
            ),
            PayloadSource::CharacterBlocks { min, max, step, .. } => {
                Cardinality::Exact(block_count(*min, *max, *step))
            }
            PayloadSource::Numbers { from, to, step, .. } => {
                Cardinality::Exact(numbers_count(*from, *to, *step))
            }
            PayloadSource::Dates {
                from,
                to,
                step_days,
                ..
            } => Cardinality::Exact(dates_count(*from, *to, *step_days)),
            PayloadSource::BruteForcer {
                charset,
                min_len,
                max_len,
            } => brute_cardinality(charset.chars().count() as u64, *min_len, *max_len),
            PayloadSource::NullPayloads { count } => match count {
                NullCount::Fixed(n) => Cardinality::Exact(*n),
                NullCount::Continuous => Cardinality::AtLeast(u64::MAX),
            },
            PayloadSource::CharacterFrobber { base } => {
                Cardinality::Exact(base.iter().map(|value| value.chars().count() as u64).sum())
            }
            PayloadSource::BitFlipper { base, format } => {
                let bits: u64 = base
                    .iter()
                    .map(|value| bit_flip_byte_len(value, *format) as u64 * 8)
                    .sum();
                Cardinality::Exact(bits)
            }
            PayloadSource::UsernameGenerator { names } => Cardinality::Exact(
                names
                    .iter()
                    .map(|name| username_schemes(name).len() as u64)
                    .sum(),
            ),
            PayloadSource::EcbBlockShuffler { base, block_size } => {
                let block_size = (*block_size).max(1);
                let mut total = Cardinality::Exact(0);
                for value in base {
                    let blocks = value.len().div_ceil(block_size);
                    total = total.saturating_add(saturating_factorial(blocks as u64));
                }
                total
            }
            // Slaved; contributes no independent axis to any preview math.
            PayloadSource::CopyOtherPayload { .. } => Cardinality::Exact(0),
        }
    }
}

// ---------------------------------------------------------------------------
// Processing pipeline
// ---------------------------------------------------------------------------

impl PayloadProcessing for PayloadProcessor {
    fn apply(&self, value: &str) -> Option<String> {
        match self {
            PayloadProcessor::AddPrefix { text } => Some(format!("{text}{value}")),
            PayloadProcessor::AddSuffix { text } => Some(format!("{value}{text}")),
            PayloadProcessor::MatchReplace {
                pattern,
                replacement,
            } => Regex::new(pattern)
                .ok()
                .map(|regex| regex.replace_all(value, replacement.as_str()).into_owned()),
            PayloadProcessor::Substring { from, length } => Some(substring(value, *from, *length)),
            PayloadProcessor::ReverseSubstring { from, length } => {
                Some(reverse_substring(value, *from, *length))
            }
            PayloadProcessor::ModifyCase { mode } => Some(apply_case(value, *mode)),
            PayloadProcessor::Encode { scheme } => Some(encode(value, *scheme)),
            PayloadProcessor::Decode { scheme } => decode(value, *scheme),
            PayloadProcessor::Hash { algorithm, output } => Some(hash(value, *algorithm, *output)),
            // Raw-append needs the pre-processing value; the pipeline supplies it.
            PayloadProcessor::AddRawPayload => Some(value.to_owned()),
            PayloadProcessor::SkipIfMatchesRegex { pattern } => match Regex::new(pattern) {
                Ok(regex) if regex.is_match(value) => None,
                _ => Some(value.to_owned()),
            },
        }
    }
}

/// A prepared, per-value processing pipeline: regexes compiled once, applied in
/// order, with the final `url_encode_chars` step last.
pub(crate) struct PayloadPipeline {
    processors: Vec<Prepared>,
    url_encode_chars: Option<String>,
}

/// A processor prepared for repeated application; regex steps are compiled once.
enum Prepared {
    MatchReplace { regex: Regex, replacement: String },
    Skip { regex: Regex },
    AddRawPayload,
    Stateless(PayloadProcessor),
}

impl PayloadPipeline {
    /// Compiles a set's processing pipeline, validating every regex up front.
    ///
    /// # Errors
    ///
    /// Returns a configuration diagnostic when a `MatchReplace` or
    /// `SkipIfMatchesRegex` pattern fails to compile.
    pub(crate) fn prepare(set: &PayloadSet) -> Result<Self, Diagnostic> {
        let mut processors = Vec::with_capacity(set.processors.len());
        for processor in &set.processors {
            let prepared = match processor {
                PayloadProcessor::MatchReplace {
                    pattern,
                    replacement,
                } => Prepared::MatchReplace {
                    regex: compile(pattern)?,
                    replacement: replacement.clone(),
                },
                PayloadProcessor::SkipIfMatchesRegex { pattern } => Prepared::Skip {
                    regex: compile(pattern)?,
                },
                PayloadProcessor::AddRawPayload => Prepared::AddRawPayload,
                other => Prepared::Stateless(other.clone()),
            };
            processors.push(prepared);
        }
        Ok(Self {
            processors,
            url_encode_chars: set.url_encode_chars.clone(),
        })
    }

    /// Runs one raw value through the pipeline, returning the final payload or
    /// `None` when a processor drops it.
    pub(crate) fn process(&self, raw: &str) -> Option<String> {
        let mut current = raw.to_owned();
        for processor in &self.processors {
            match processor {
                Prepared::MatchReplace { regex, replacement } => {
                    current = regex
                        .replace_all(&current, replacement.as_str())
                        .into_owned();
                }
                Prepared::Skip { regex } => {
                    if regex.is_match(&current) {
                        return None;
                    }
                }
                // Burp semantics: append the ORIGINAL, unprocessed payload.
                Prepared::AddRawPayload => current.push_str(raw),
                Prepared::Stateless(processor) => current = processor.apply(&current)?,
            }
        }
        if let Some(chars) = &self.url_encode_chars {
            current = percent_encode_chars(&current, chars);
        }
        Some(current)
    }
}

/// A lazy stream of a set's final, fully-processed payload values.
///
/// # Errors
///
/// Returns a configuration diagnostic when the set's processing pipeline has an
/// invalid regex.
pub(crate) fn generate_processed(
    set: &PayloadSet,
) -> Result<Box<dyn Iterator<Item = String> + Send>, Diagnostic> {
    let pipeline = PayloadPipeline::prepare(set)?;
    Ok(Box::new(
        set.source
            .generate()
            .filter_map(move |raw| pipeline.process(&raw)),
    ))
}

/// The pre-skip value count of a set — the source cardinality. Processors do
/// not change the count except `SkipIfMatchesRegex`, which cannot be counted
/// ahead of time; the preview shows the pre-skip count (as Burp does) and the
/// run reports the actual sent count.
pub(crate) fn set_cardinality(set: &PayloadSet) -> Cardinality {
    set.source.cardinality()
}

/// Validates a set can be generated and processed: its pipeline regexes
/// compile, and generated sources with a hard prerequisite (a usable date
/// format, a non-empty brute-force alphabet) are usable.
///
/// # Errors
///
/// Returns a configuration diagnostic describing the first problem found.
pub(crate) fn validate_set(set: &PayloadSet) -> Result<(), Diagnostic> {
    PayloadPipeline::prepare(set)?;
    match &set.source {
        PayloadSource::Dates { format, .. } => {
            if !date_format_is_valid(format) {
                return Err(config_diagnostic(
                    "payload.dates",
                    "the date format string is not a valid chrono format",
                ));
            }
        }
        PayloadSource::BruteForcer {
            charset, max_len, ..
        } => {
            if *max_len > 0 && charset.is_empty() {
                return Err(config_diagnostic(
                    "payload.bruteforce",
                    "brute forcer needs a non-empty character set",
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Lazy source iterators
// ---------------------------------------------------------------------------

/// Streams a file line-by-line; never materializes the whole file.
struct RuntimeFileIter {
    lines: Option<std::io::Lines<std::io::BufReader<std::fs::File>>>,
}

impl RuntimeFileIter {
    fn open(path: &std::path::Path) -> Self {
        let lines = std::fs::File::open(path)
            .ok()
            .map(|file| std::io::BufReader::new(file).lines());
        Self { lines }
    }
}

impl Iterator for RuntimeFileIter {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        // Stop cleanly on end-of-file or a read error rather than looping on it.
        if let Some(Ok(line)) = self.lines.as_mut()?.next() {
            Some(line)
        } else {
            self.lines = None;
            None
        }
    }
}

fn count_lines(path: &std::path::Path) -> Option<u64> {
    let file = std::fs::File::open(path).ok()?;
    let count = std::io::BufReader::new(file)
        .lines()
        .take_while(Result::is_ok)
        .count();
    Some(count as u64)
}

/// Odometer over the custom-iterator slots, joining each slot's separator and
/// current item into one value.
struct CustomIteratorIter {
    slots: Vec<IteratorSlot>,
    index: Vec<usize>,
    done: bool,
}

impl CustomIteratorIter {
    fn new(slots: &[IteratorSlot]) -> Self {
        let done = slots.iter().any(|slot| slot.items.is_empty());
        Self {
            slots: slots.to_vec(),
            index: vec![0; slots.len()],
            done,
        }
    }
}

impl Iterator for CustomIteratorIter {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        if self.done {
            return None;
        }
        let mut out = String::new();
        for (slot, &position) in self.slots.iter().zip(&self.index) {
            out.push_str(&slot.separator);
            out.push_str(&slot.items[position]);
        }
        // Advance the odometer, last slot fastest.
        let mut i = self.slots.len();
        loop {
            if i == 0 {
                self.done = true;
                break;
            }
            i -= 1;
            self.index[i] += 1;
            if self.index[i] < self.slots[i].items.len() {
                break;
            }
            self.index[i] = 0;
        }
        Some(out)
    }
}

/// Repeats a unit in growing blocks from `min` to `max` by `step`.
struct CharacterBlocksIter {
    item: String,
    current: usize,
    max: usize,
    step: usize,
}

impl CharacterBlocksIter {
    fn new(item: String, min: usize, max: usize, step: usize) -> Self {
        Self {
            item,
            current: min,
            max,
            step: step.max(1),
        }
    }
}

impl Iterator for CharacterBlocksIter {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        if self.current > self.max {
            return None;
        }
        let out = self.item.repeat(self.current);
        self.current += self.step;
        Some(out)
    }
}

/// Formatting parameters shared by the sequential and random number sources.
#[derive(Clone, Copy)]
struct NumberFormat {
    radix: NumberRadix,
    min_integer_digits: usize,
    max_fraction_digits: usize,
}

/// A deterministic stepped numeric sequence; iterates by index to avoid float
/// drift accumulating over a long range.
struct NumbersSeqIter {
    from: f64,
    step: f64,
    count: u64,
    emitted: u64,
    format: NumberFormat,
}

impl NumbersSeqIter {
    fn new(from: f64, to: f64, step: f64, format: NumberFormat) -> Self {
        Self {
            from,
            step,
            count: numbers_count(from, to, step),
            emitted: 0,
            format,
        }
    }
}

impl Iterator for NumbersSeqIter {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        if self.emitted >= self.count {
            return None;
        }
        let value = self.from + (self.emitted as f64) * self.step;
        self.emitted += 1;
        Some(format_number(value, self.format))
    }
}

/// Uniformly random numeric draws within `[from, to]` (with replacement); the
/// count matches the equivalent sequential range so the preview stays exact.
struct NumbersRandomIter {
    from: f64,
    span: f64,
    count: u64,
    emitted: u64,
    state: u64,
    format: NumberFormat,
}

impl NumbersRandomIter {
    fn new(from: f64, to: f64, step: f64, format: NumberFormat) -> Self {
        Self {
            from,
            span: to - from,
            count: numbers_count(from, to, step),
            emitted: 0,
            state: seed_rng(),
            format,
        }
    }
}

impl Iterator for NumbersRandomIter {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        if self.emitted >= self.count {
            return None;
        }
        self.emitted += 1;
        // 53-bit mantissa fraction in [0, 1).
        let fraction = (xorshift(&mut self.state) >> 11) as f64 / (1u64 << 53) as f64;
        Some(format_number(self.from + fraction * self.span, self.format))
    }
}

/// A stepped date range formatted with a `chrono` format string.
struct DatesIter {
    current: Option<chrono::NaiveDate>,
    to: chrono::NaiveDate,
    step_days: i64,
    ascending: bool,
    format: String,
}

impl DatesIter {
    fn new(from: chrono::NaiveDate, to: chrono::NaiveDate, step_days: i64, format: String) -> Self {
        Self {
            current: Some(from),
            to,
            step_days: if step_days == 0 { 1 } else { step_days },
            ascending: step_days >= 0,
            format,
        }
    }
}

impl Iterator for DatesIter {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        let date = self.current?;
        let past_end = if self.ascending {
            date > self.to
        } else {
            date < self.to
        };
        if past_end {
            self.current = None;
            return None;
        }
        let out = date.format(&self.format).to_string();
        self.current = date.checked_add_signed(chrono::Duration::days(self.step_days));
        Some(out)
    }
}

/// Every string over an alphabet, lengths `min_len..=max_len`, generated as an
/// odometer so an enormous space never materializes.
struct BruteForceIter {
    chars: Vec<char>,
    len: usize,
    max_len: usize,
    index: Vec<usize>,
    done: bool,
}

impl BruteForceIter {
    fn new(charset: &str, min_len: usize, max_len: usize) -> Self {
        let chars: Vec<char> = charset.chars().collect();
        let mut iter = Self {
            chars,
            len: min_len,
            max_len,
            index: vec![0; min_len],
            done: false,
        };
        iter.skip_impossible_lengths();
        iter
    }

    /// Advance past lengths that cannot be generated (any length >= 1 with an
    /// empty alphabet), stopping at a generable length or marking done.
    fn skip_impossible_lengths(&mut self) {
        loop {
            if self.len > self.max_len {
                self.done = true;
                return;
            }
            if self.len == 0 || !self.chars.is_empty() {
                return;
            }
            self.len += 1;
            self.index = vec![0; self.len];
        }
    }
}

impl Iterator for BruteForceIter {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        if self.done {
            return None;
        }
        let out: String = self.index.iter().map(|&i| self.chars[i]).collect();
        // Advance the odometer over the current length.
        let mut i = self.index.len();
        let mut carried = true;
        while i > 0 {
            i -= 1;
            self.index[i] += 1;
            if self.index[i] < self.chars.len() {
                carried = false;
                break;
            }
            self.index[i] = 0;
        }
        // A length-0 pass (single empty string) always carries to the next length.
        if carried || self.index.is_empty() {
            self.len += 1;
            self.index = vec![0; self.len];
            self.skip_impossible_lengths();
        }
        Some(out)
    }
}

// ---------------------------------------------------------------------------
// Eager-but-bounded generators (fan-out is bounded by the base list length)
// ---------------------------------------------------------------------------

/// Percent-encoded overlong / illegal UTF-8 encodings of a character: the
/// classic 2-, 3-, and 4-byte overlong forms, as delivered over HTTP.
fn overlong_encodings(target: char) -> Vec<String> {
    let code = target as u32;
    let mut out = Vec::new();
    // 2-byte overlong: 110xxxxx 10xxxxxx
    if code <= 0x7FF {
        out.push(percent_bytes(&[
            0xC0 | ((code >> 6) as u8 & 0x1F),
            0x80 | (code as u8 & 0x3F),
        ]));
    }
    // 3-byte overlong: 1110xxxx 10xxxxxx 10xxxxxx
    if code <= 0xFFFF {
        out.push(percent_bytes(&[
            0xE0 | ((code >> 12) as u8 & 0x0F),
            0x80 | ((code >> 6) as u8 & 0x3F),
            0x80 | (code as u8 & 0x3F),
        ]));
    }
    // 4-byte overlong.
    out.push(percent_bytes(&[
        0xF0 | ((code >> 18) as u8 & 0x07),
        0x80 | ((code >> 12) as u8 & 0x3F),
        0x80 | ((code >> 6) as u8 & 0x3F),
        0x80 | (code as u8 & 0x3F),
    ]));
    out
}

/// Replace the first occurrence of `target` with `replacement`, or append it
/// when the target is absent.
fn splice_first(value: &str, target: char, replacement: &str) -> String {
    if let Some(position) = value.find(target) {
        let mut out = String::with_capacity(value.len() + replacement.len());
        out.push_str(&value[..position]);
        out.push_str(replacement);
        out.push_str(&value[position + target.len_utf8()..]);
        out
    } else {
        format!("{value}{replacement}")
    }
}

/// One variant per character position with that character incremented by one
/// code point; a resulting control/non-ASCII character is percent-encoded.
fn frob_positions(value: &str) -> Vec<String> {
    let chars: Vec<char> = value.chars().collect();
    (0..chars.len())
        .map(|position| {
            let mut out = String::new();
            for (i, &c) in chars.iter().enumerate() {
                if i == position {
                    let next = char::from_u32(c as u32 + 1).unwrap_or(c);
                    out.push_str(&char_to_payload(next));
                } else {
                    out.push(c);
                }
            }
            out
        })
        .collect()
}

/// One variant per bit of the base value with that single bit flipped.
fn bit_flips(value: &str, format: BitFlipFormat) -> Vec<String> {
    let bytes = match format {
        BitFlipFormat::Literal => value.as_bytes().to_vec(),
        BitFlipFormat::AsciiHex => ascii_hex_decode(value).unwrap_or_default(),
    };
    let mut out = Vec::with_capacity(bytes.len() * 8);
    for byte_index in 0..bytes.len() {
        for bit in 0..8u8 {
            let mut flipped = bytes.clone();
            flipped[byte_index] ^= 1 << bit;
            out.push(match format {
                BitFlipFormat::Literal => bytes_to_payload(&flipped),
                BitFlipFormat::AsciiHex => ascii_hex_encode(&flipped),
            });
        }
    }
    out
}

/// The byte length a bit-flipper operates over, for cardinality.
fn bit_flip_byte_len(value: &str, format: BitFlipFormat) -> usize {
    match format {
        BitFlipFormat::Literal => value.len(),
        BitFlipFormat::AsciiHex => ascii_hex_decode(value).map_or(0, |bytes| bytes.len()),
    }
}

/// Common username schemes from a full name or email; de-duplicated, order
/// stable so cardinality matches generation exactly.
fn username_schemes(name: &str) -> Vec<String> {
    // An email address contributes its local part.
    let local = name.split('@').next().unwrap_or(name).trim();
    let parts: Vec<String> = local
        .split(|c: char| c.is_whitespace() || c == '.' || c == '_')
        .filter(|part| !part.is_empty())
        .map(str::to_lowercase)
        .collect();
    let mut schemes = Vec::new();
    let mut push = |candidate: String| {
        if !candidate.is_empty() && !schemes.contains(&candidate) {
            schemes.push(candidate);
        }
    };
    match parts.as_slice() {
        [] => {}
        [single] => push(single.clone()),
        [first, rest @ ..] => {
            let last = rest.last().cloned().unwrap_or_default();
            let fi = first
                .chars()
                .next()
                .map(|c| c.to_string())
                .unwrap_or_default();
            let li = last
                .chars()
                .next()
                .map(|c| c.to_string())
                .unwrap_or_default();
            push(first.clone());
            push(last.clone());
            push(format!("{first}{last}"));
            push(format!("{first}.{last}"));
            push(format!("{first}_{last}"));
            push(format!("{fi}{last}"));
            push(format!("{fi}.{last}"));
            push(format!("{first}{li}"));
            push(format!("{last}{first}"));
            push(format!("{last}.{first}"));
        }
    }
    schemes
}

/// Every block-ordering of the value split into `block_size`-byte blocks; the
/// reassembled bytes are percent-encoded when not valid UTF-8.
fn ecb_shuffles(value: &str, block_size: usize) -> Vec<String> {
    let blocks: Vec<&[u8]> = value.as_bytes().chunks(block_size).collect();
    PermutationIter::new(blocks.len())
        .map(|order| {
            let mut bytes = Vec::with_capacity(value.len());
            for index in order {
                bytes.extend_from_slice(blocks[index]);
            }
            bytes_to_payload(&bytes)
        })
        .collect()
}

/// Lazily yields index permutations in lexicographic order (n! total).
struct PermutationIter {
    perm: Vec<usize>,
    first: bool,
    done: bool,
}

impl PermutationIter {
    fn new(n: usize) -> Self {
        Self {
            perm: (0..n).collect(),
            first: true,
            done: false,
        }
    }
}

impl Iterator for PermutationIter {
    type Item = Vec<usize>;

    fn next(&mut self) -> Option<Vec<usize>> {
        if self.done {
            return None;
        }
        if self.first {
            self.first = false;
            return Some(self.perm.clone());
        }
        if next_permutation(&mut self.perm) {
            Some(self.perm.clone())
        } else {
            self.done = true;
            None
        }
    }
}

/// Standard in-place lexicographic next-permutation; returns false at the last.
fn next_permutation(perm: &mut [usize]) -> bool {
    if perm.len() < 2 {
        return false;
    }
    let mut i = perm.len() - 1;
    while i > 0 && perm[i - 1] >= perm[i] {
        i -= 1;
    }
    if i == 0 {
        return false;
    }
    let mut j = perm.len() - 1;
    while perm[j] <= perm[i - 1] {
        j -= 1;
    }
    perm.swap(i - 1, j);
    perm[i..].reverse();
    true
}

// ---------------------------------------------------------------------------
// Counting helpers
// ---------------------------------------------------------------------------

fn block_count(min: usize, max: usize, step: usize) -> u64 {
    let step = step.max(1);
    if min > max {
        return 0;
    }
    ((max - min) / step) as u64 + 1
}

fn numbers_count(from: f64, to: f64, step: f64) -> u64 {
    if step == 0.0 {
        return 1;
    }
    let span = to - from;
    let steps = span / step;
    if steps < 0.0 {
        return 0;
    }
    steps.floor() as u64 + 1
}

fn dates_count(from: chrono::NaiveDate, to: chrono::NaiveDate, step_days: i64) -> u64 {
    let step = if step_days == 0 { 1 } else { step_days };
    let span = (to - from).num_days();
    if span.signum() != step.signum() && span != 0 {
        return 0;
    }
    (span / step) as u64 + 1
}

fn brute_cardinality(alphabet: u64, min_len: usize, max_len: usize) -> Cardinality {
    let mut total = Cardinality::Exact(0);
    for n in min_len..=max_len {
        let term = if n == 0 {
            Cardinality::Exact(1)
        } else {
            saturating_pow(alphabet, n)
        };
        total = total.saturating_add(term);
    }
    total
}

fn saturating_pow(base: u64, exp: usize) -> Cardinality {
    let mut acc: u64 = 1;
    for _ in 0..exp {
        match acc.checked_mul(base) {
            Some(value) => acc = value,
            None => return Cardinality::AtLeast(u64::MAX),
        }
    }
    Cardinality::Exact(acc)
}

fn saturating_factorial(n: u64) -> Cardinality {
    let mut acc: u64 = 1;
    for k in 2..=n {
        match acc.checked_mul(k) {
            Some(value) => acc = value,
            None => return Cardinality::AtLeast(u64::MAX),
        }
    }
    Cardinality::Exact(acc)
}

// ---------------------------------------------------------------------------
// Encoding / formatting primitives
// ---------------------------------------------------------------------------

fn apply_case(value: &str, mode: CaseMode) -> String {
    match mode {
        CaseMode::Lower => value.to_lowercase(),
        CaseMode::Upper => value.to_uppercase(),
        CaseMode::Toggle => value
            .chars()
            .flat_map(|c| {
                if c.is_uppercase() {
                    c.to_lowercase().collect::<Vec<_>>()
                } else {
                    c.to_uppercase().collect::<Vec<_>>()
                }
            })
            .collect(),
        CaseMode::Propercase => value
            .split_inclusive(char::is_whitespace)
            .map(|word| {
                let mut chars = word.chars();
                match chars.next() {
                    Some(first) => {
                        first.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase()
                    }
                    None => String::new(),
                }
            })
            .collect(),
    }
}

fn substring(value: &str, from: usize, length: Option<usize>) -> String {
    let chars: Vec<char> = value.chars().collect();
    let start = from.min(chars.len());
    let end = match length {
        Some(len) => (start + len).min(chars.len()),
        None => chars.len(),
    };
    chars[start..end].iter().collect()
}

fn reverse_substring(value: &str, from: usize, length: Option<usize>) -> String {
    let chars: Vec<char> = value.chars().collect();
    let total = chars.len();
    let end = total.saturating_sub(from);
    let start = match length {
        Some(len) => end.saturating_sub(len),
        None => 0,
    };
    chars[start..end].iter().collect()
}

fn encode(value: &str, scheme: EncodeScheme) -> String {
    match scheme {
        EncodeScheme::Url => percent_encode_url(value),
        EncodeScheme::UrlAll => percent_encode_all(value),
        EncodeScheme::Html => html_encode(value),
        EncodeScheme::Base64 => BASE64.encode(value.as_bytes()),
        EncodeScheme::AsciiHex => ascii_hex_encode(value.as_bytes()),
    }
}

fn decode(value: &str, scheme: DecodeScheme) -> Option<String> {
    match scheme {
        // Lenient: unparseable escapes are left literal rather than dropped.
        DecodeScheme::Url => Some(percent_decode(value)),
        DecodeScheme::Html => Some(html_decode(value)),
        DecodeScheme::Base64 => BASE64
            .decode(value.as_bytes())
            .ok()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
        DecodeScheme::AsciiHex => {
            ascii_hex_decode(value).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        }
    }
}

fn hash(value: &str, algorithm: HashAlgorithm, output: HashOutput) -> String {
    use md5::Md5;
    use sha1::Sha1;
    use sha2::{Digest as _, Sha256, Sha512};
    let digest: Vec<u8> = match algorithm {
        HashAlgorithm::Md5 => Md5::digest(value.as_bytes()).to_vec(),
        HashAlgorithm::Sha1 => Sha1::digest(value.as_bytes()).to_vec(),
        HashAlgorithm::Sha256 => Sha256::digest(value.as_bytes()).to_vec(),
        HashAlgorithm::Sha512 => Sha512::digest(value.as_bytes()).to_vec(),
    };
    match output {
        HashOutput::Hex => ascii_hex_encode(&digest),
        HashOutput::Base64 => BASE64.encode(&digest),
    }
}

fn char_to_payload(c: char) -> String {
    if c.is_ascii_graphic() || c == ' ' {
        c.to_string()
    } else {
        let mut buffer = [0u8; 4];
        percent_bytes(c.encode_utf8(&mut buffer).as_bytes())
    }
}

fn bytes_to_payload(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &byte in bytes {
        if (0x20..=0x7E).contains(&byte) && byte != b'%' {
            out.push(byte as char);
        } else {
            percent_encode_byte(byte, &mut out);
        }
    }
    out
}

fn percent_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for &byte in bytes {
        percent_encode_byte(byte, &mut out);
    }
    out
}

fn percent_encode_byte(byte: u8, out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    out.push('%');
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0x0F) as usize] as char);
}

fn percent_encode_all(value: &str) -> String {
    percent_bytes(value.as_bytes())
}

fn percent_encode_url(value: &str) -> String {
    let mut out = String::new();
    for &byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            percent_encode_byte(byte, &mut out);
        }
    }
    out
}

fn percent_encode_chars(value: &str, chars: &str) -> String {
    let set: std::collections::HashSet<char> = chars.chars().collect();
    let mut out = String::new();
    for c in value.chars() {
        if set.contains(&c) {
            let mut buffer = [0u8; 4];
            out.push_str(&percent_bytes(c.encode_utf8(&mut buffer).as_bytes()));
        } else {
            out.push(c);
        }
    }
    out
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let high = (bytes[i + 1] as char).to_digit(16);
            let low = (bytes[i + 2] as char).to_digit(16);
            if let (Some(high), Some(low)) = (high, low) {
                out.push((high * 16 + low) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn html_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

fn html_decode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let tail = &rest[amp..];
        if let Some(semi) = tail.find(';') {
            let entity = &tail[1..semi];
            let decoded = match entity {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "#39" | "apos" => Some('\''),
                numeric if numeric.starts_with("#x") || numeric.starts_with("#X") => {
                    u32::from_str_radix(&numeric[2..], 16)
                        .ok()
                        .and_then(char::from_u32)
                }
                numeric if numeric.starts_with('#') => {
                    numeric[1..].parse::<u32>().ok().and_then(char::from_u32)
                }
                _ => None,
            };
            if let Some(c) = decoded {
                out.push(c);
                rest = &tail[semi + 1..];
                continue;
            }
        }
        out.push('&');
        rest = &tail[1..];
    }
    out.push_str(rest);
    out
}

fn ascii_hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

fn ascii_hex_decode(value: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = value
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_digit(16).map(|d| d as u8))
        .collect::<Option<Vec<_>>>()?;
    if digits.len() % 2 != 0 {
        return None;
    }
    Some(
        digits
            .chunks(2)
            .map(|pair| (pair[0] << 4) | pair[1])
            .collect(),
    )
}

fn date_format_is_valid(format: &str) -> bool {
    // chrono's Display panics on an invalid specifier only when written; probe
    // it against a fixed date inside catch_unwind so a bad format is a clean
    // validation error, not a runtime panic during a run.
    let probe = chrono::NaiveDate::from_ymd_opt(2000, 1, 1).unwrap_or_default();
    let format = format.to_owned();
    std::panic::catch_unwind(move || probe.format(&format).to_string()).is_ok()
}

fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn seed_rng() -> u64 {
    let mut buffer = [0u8; 8];
    let seed = if getrandom::fill(&mut buffer).is_ok() {
        u64::from_le_bytes(buffer)
    } else {
        0
    };
    // xorshift must never be seeded with zero.
    if seed == 0 {
        0x9E37_79B9_7F4A_7C15
    } else {
        seed
    }
}

fn format_number(value: f64, format: NumberFormat) -> String {
    match format.radix {
        NumberRadix::Dec => {
            let rendered = format!("{value:.*}", format.max_fraction_digits);
            pad_integer_part(&rendered, format.min_integer_digits)
        }
        NumberRadix::Hex => {
            let integer = value.trunc() as i64;
            let hex = format!(
                "{:0width$x}",
                integer.unsigned_abs(),
                width = format.min_integer_digits
            );
            if integer < 0 { format!("-{hex}") } else { hex }
        }
    }
}

/// Left-pad the integer part of a decimal rendering to `min_digits`, preserving
/// a leading sign and any fractional part.
fn pad_integer_part(rendered: &str, min_digits: usize) -> String {
    let (sign, body) = rendered
        .strip_prefix('-')
        .map_or(("", rendered), |rest| ("-", rest));
    let (integer, fraction) = body
        .split_once('.')
        .map_or((body, None), |(int, frac)| (int, Some(frac)));
    let padded = if integer.len() < min_digits {
        format!("{}{integer}", "0".repeat(min_digits - integer.len()))
    } else {
        integer.to_owned()
    };
    match fraction {
        Some(fraction) => format!("{sign}{padded}.{fraction}"),
        None => format!("{sign}{padded}"),
    }
}

fn compile(pattern: &str) -> Result<Regex, Diagnostic> {
    Regex::new(pattern).map_err(|error| config_diagnostic("payload.regex", &error.to_string()))
}

fn config_diagnostic(operation: &str, detail: &str) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "operation".to_owned(),
        DiagnosticValue::String(operation.to_owned()),
    );
    context.insert(
        "error".to_owned(),
        DiagnosticValue::String(detail.to_owned()),
    );
    catalogue::PROXY_FUZZER_CONFIG_INVALID.instantiate(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use apiaxess_workbench_store::CharacterRule;

    fn simple(values: &[&str]) -> PayloadSet {
        PayloadSet {
            name: "t".to_owned(),
            source: PayloadSource::SimpleList {
                values: values.iter().map(|v| (*v).to_owned()).collect(),
            },
            processors: Vec::new(),
            url_encode_chars: None,
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    fn generated(source: PayloadSource) -> Vec<String> {
        source.generate().collect()
    }

    // ---- per-source generation + cardinality ----

    #[test]
    fn simple_list_generates_and_counts() {
        let source = PayloadSource::SimpleList {
            values: vec!["a".to_owned(), "b".to_owned()],
        };
        assert_eq!(generated(source.clone()), vec!["a", "b"]);
        assert_eq!(source.cardinality(), Cardinality::Exact(2));
    }

    #[test]
    fn custom_iterator_emits_cross_product_with_separators() {
        let source = PayloadSource::CustomIterator {
            slots: vec![
                IteratorSlot {
                    items: vec!["a".to_owned(), "b".to_owned()],
                    separator: String::new(),
                },
                IteratorSlot {
                    items: vec!["1".to_owned(), "2".to_owned()],
                    separator: "-".to_owned(),
                },
            ],
        };
        assert_eq!(generated(source.clone()), vec!["a-1", "a-2", "b-1", "b-2"]);
        assert_eq!(source.cardinality(), Cardinality::Exact(4));
    }

    #[test]
    fn character_substitution_applies_all_rules() {
        let source = PayloadSource::CharacterSubstitution {
            base: vec!["leet".to_owned()],
            rules: vec![
                CharacterRule { from: 'e', to: '3' },
                CharacterRule { from: 't', to: '7' },
            ],
        };
        // "leet" -> e→3 -> "l33t" -> t→7 -> "l337".
        assert_eq!(generated(source), vec!["l337".to_owned()]);
    }

    #[test]
    fn case_modification_emits_each_mode() {
        let source = PayloadSource::CaseModification {
            base: vec!["Ab".to_owned()],
            modes: vec![CaseMode::Lower, CaseMode::Upper, CaseMode::Toggle],
        };
        assert_eq!(generated(source.clone()), vec!["ab", "AB", "aB"]);
        assert_eq!(source.cardinality(), Cardinality::Exact(3));
    }

    #[test]
    fn character_blocks_repeat_the_unit() {
        let source = PayloadSource::CharacterBlocks {
            item: "A".to_owned(),
            min: 1,
            max: 4,
            step: 1,
        };
        assert_eq!(generated(source.clone()), vec!["A", "AA", "AAA", "AAAA"]);
        assert_eq!(source.cardinality(), Cardinality::Exact(4));
    }

    #[test]
    fn numbers_sequential_formats_with_padding() {
        let source = PayloadSource::Numbers {
            from: 1.0,
            to: 3.0,
            step: 1.0,
            order: NumberOrder::Sequential,
            radix: NumberRadix::Dec,
            min_integer_digits: 3,
            max_fraction_digits: 0,
        };
        assert_eq!(generated(source.clone()), vec!["001", "002", "003"]);
        assert_eq!(source.cardinality(), Cardinality::Exact(3));
    }

    #[test]
    fn numbers_hex_radix() {
        let source = PayloadSource::Numbers {
            from: 10.0,
            to: 12.0,
            step: 1.0,
            order: NumberOrder::Sequential,
            radix: NumberRadix::Hex,
            min_integer_digits: 2,
            max_fraction_digits: 0,
        };
        assert_eq!(generated(source), vec!["0a", "0b", "0c"]);
    }

    #[test]
    fn dates_step_and_format() {
        let source = PayloadSource::Dates {
            from: chrono::NaiveDate::from_ymd_opt(2020, 1, 1).unwrap(),
            to: chrono::NaiveDate::from_ymd_opt(2020, 1, 3).unwrap(),
            step_days: 1,
            format: "%Y-%m-%d".to_owned(),
        };
        assert_eq!(
            generated(source.clone()),
            vec!["2020-01-01", "2020-01-02", "2020-01-03"]
        );
        assert_eq!(source.cardinality(), Cardinality::Exact(3));
    }

    #[test]
    fn brute_forcer_enumerates_lengths() {
        let source = PayloadSource::BruteForcer {
            charset: "ab".to_owned(),
            min_len: 1,
            max_len: 2,
        };
        assert_eq!(
            generated(source.clone()),
            vec!["a", "b", "aa", "ab", "ba", "bb"]
        );
        assert_eq!(source.cardinality(), Cardinality::Exact(6));
    }

    #[test]
    fn null_payloads_fixed_and_continuous() {
        let fixed = PayloadSource::NullPayloads {
            count: NullCount::Fixed(3),
        };
        assert_eq!(generated(fixed.clone()), vec!["", "", ""]);
        assert_eq!(fixed.cardinality(), Cardinality::Exact(3));

        let continuous = PayloadSource::NullPayloads {
            count: NullCount::Continuous,
        };
        assert_eq!(
            continuous.generate().take(5).collect::<Vec<_>>(),
            vec!["", "", "", "", ""]
        );
        assert_eq!(continuous.cardinality(), Cardinality::AtLeast(u64::MAX));
    }

    #[test]
    fn character_frobber_one_variant_per_position() {
        let source = PayloadSource::CharacterFrobber {
            base: vec!["abc".to_owned()],
        };
        assert_eq!(generated(source.clone()), vec!["bbc", "acc", "abd"]);
        assert_eq!(source.cardinality(), Cardinality::Exact(3));
    }

    #[test]
    fn bit_flipper_literal_flips_each_bit() {
        let source = PayloadSource::BitFlipper {
            base: vec!["A".to_owned()],
            format: BitFlipFormat::Literal,
        };
        let flips = generated(source.clone());
        assert_eq!(flips.len(), 8);
        assert_eq!(source.cardinality(), Cardinality::Exact(8));
        // 'A' = 0x41; flipping bit 0 -> 0x40 '@' (printable, literal).
        assert!(flips.contains(&"@".to_owned()));
        // Flipping bit 7 -> 0xC1, non-ASCII -> percent-encoded.
        assert!(flips.contains(&"%C1".to_owned()));
    }

    #[test]
    fn bit_flipper_ascii_hex_roundtrips_hex() {
        let source = PayloadSource::BitFlipper {
            base: vec!["41".to_owned()],
            format: BitFlipFormat::AsciiHex,
        };
        let flips = generated(source);
        assert_eq!(flips.len(), 8);
        assert!(flips.contains(&"40".to_owned()));
        assert!(flips.contains(&"c1".to_owned()));
    }

    #[test]
    fn username_generator_schemes() {
        let source = PayloadSource::UsernameGenerator {
            names: vec!["John Smith".to_owned()],
        };
        let names = generated(source.clone());
        assert!(names.contains(&"john".to_owned()));
        assert!(names.contains(&"smith".to_owned()));
        assert!(names.contains(&"jsmith".to_owned()));
        assert!(names.contains(&"john.smith".to_owned()));
        assert_eq!(source.cardinality(), Cardinality::Exact(names.len() as u64));
    }

    #[test]
    fn ecb_block_shuffler_permutes_blocks() {
        let source = PayloadSource::EcbBlockShuffler {
            base: vec!["AABB".to_owned()],
            block_size: 2,
        };
        let shuffles = generated(source.clone());
        // Two blocks -> 2! = 2 orderings.
        assert_eq!(shuffles, vec!["AABB", "BBAA"]);
        assert_eq!(source.cardinality(), Cardinality::Exact(2));
    }

    #[test]
    fn illegal_unicode_emits_percent_encoded_overlongs() {
        let source = PayloadSource::IllegalUnicode {
            base: vec![".".to_owned()],
            target: '.',
        };
        let variants = generated(source);
        // '.' has 2-, 3-, and 4-byte overlong forms.
        assert_eq!(variants, vec!["%C0%AE", "%E0%80%AE", "%F0%80%80%AE"]);
    }

    #[test]
    fn copy_other_payload_generates_nothing_on_its_own() {
        let source = PayloadSource::CopyOtherPayload { source_position: 0 };
        assert!(generated(source.clone()).is_empty());
        assert_eq!(source.cardinality(), Cardinality::Exact(0));
    }

    // ---- laziness / bounded memory ----

    #[test]
    fn enormous_brute_force_is_lazy() {
        // 95^12 vastly overflows u64; taking a handful must be instant and O(1).
        let source = PayloadSource::BruteForcer {
            charset: (' '..='~').collect(),
            min_len: 1,
            max_len: 12,
        };
        let head: Vec<String> = source.generate().take(4).collect();
        assert_eq!(head, vec![" ", "!", "\"", "#"]);
        assert_eq!(source.cardinality(), Cardinality::AtLeast(u64::MAX));
    }

    #[test]
    fn enormous_number_range_is_lazy() {
        let source = PayloadSource::Numbers {
            from: 0.0,
            to: 1_000_000_000.0,
            step: 1.0,
            order: NumberOrder::Sequential,
            radix: NumberRadix::Dec,
            min_integer_digits: 1,
            max_fraction_digits: 0,
        };
        let head: Vec<String> = source.generate().take(3).collect();
        assert_eq!(head, vec!["0", "1", "2"]);
        assert_eq!(source.cardinality(), Cardinality::Exact(1_000_000_001));
    }

    // ---- processors ----

    #[test]
    fn each_processor_applies() {
        assert_eq!(
            PayloadProcessor::AddPrefix { text: "a".into() }.apply("x"),
            Some("ax".to_owned())
        );
        assert_eq!(
            PayloadProcessor::AddSuffix { text: "z".into() }.apply("x"),
            Some("xz".to_owned())
        );
        assert_eq!(
            PayloadProcessor::MatchReplace {
                pattern: "[0-9]+".into(),
                replacement: "N".into(),
            }
            .apply("a12b3"),
            Some("aNbN".to_owned())
        );
        assert_eq!(
            PayloadProcessor::Substring {
                from: 1,
                length: Some(2),
            }
            .apply("abcd"),
            Some("bc".to_owned())
        );
        assert_eq!(
            PayloadProcessor::ReverseSubstring {
                from: 1,
                length: Some(2),
            }
            .apply("abcd"),
            Some("bc".to_owned())
        );
        assert_eq!(
            PayloadProcessor::ModifyCase {
                mode: CaseMode::Upper,
            }
            .apply("abc"),
            Some("ABC".to_owned())
        );
        assert_eq!(
            PayloadProcessor::Encode {
                scheme: EncodeScheme::Base64,
            }
            .apply("hi"),
            Some("aGk=".to_owned())
        );
        assert_eq!(
            PayloadProcessor::Encode {
                scheme: EncodeScheme::Url,
            }
            .apply("a b&c"),
            Some("a%20b%26c".to_owned())
        );
        assert_eq!(
            PayloadProcessor::Decode {
                scheme: DecodeScheme::Base64,
            }
            .apply("aGk="),
            Some("hi".to_owned())
        );
        assert_eq!(
            PayloadProcessor::Hash {
                algorithm: HashAlgorithm::Sha256,
                output: HashOutput::Hex,
            }
            .apply("abc"),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_owned())
        );
        assert_eq!(
            PayloadProcessor::SkipIfMatchesRegex {
                pattern: "skip".into(),
            }
            .apply("skip-me"),
            None
        );
    }

    #[test]
    fn pipeline_applies_in_order_with_url_encode_last() {
        let set = PayloadSet {
            name: "t".to_owned(),
            source: PayloadSource::SimpleList {
                values: vec!["a".to_owned()],
            },
            processors: vec![
                PayloadProcessor::AddSuffix { text: "&".into() },
                PayloadProcessor::AddPrefix { text: "x=".into() },
            ],
            url_encode_chars: Some("&".to_owned()),
        };
        let out: Vec<String> = generate_processed(&set).unwrap().collect();
        // AddSuffix then AddPrefix -> "x=a&", then url-encode of '&' only.
        assert_eq!(out, vec!["x=a%26".to_owned()]);
    }

    #[test]
    fn pipeline_add_raw_appends_original_value() {
        let set = PayloadSet {
            name: "t".to_owned(),
            source: PayloadSource::SimpleList {
                values: vec!["ab".to_owned()],
            },
            processors: vec![
                PayloadProcessor::ModifyCase {
                    mode: CaseMode::Upper,
                },
                PayloadProcessor::AddRawPayload,
            ],
            url_encode_chars: None,
        };
        let out: Vec<String> = generate_processed(&set).unwrap().collect();
        // Uppercased "AB" then the raw "ab" appended.
        assert_eq!(out, vec!["ABab".to_owned()]);
    }

    #[test]
    fn pipeline_skip_drops_matching_payloads() {
        let set = PayloadSet {
            name: "t".to_owned(),
            source: PayloadSource::SimpleList {
                values: vec!["keep".to_owned(), "drop-me".to_owned(), "also".to_owned()],
            },
            processors: vec![PayloadProcessor::SkipIfMatchesRegex {
                pattern: "drop".into(),
            }],
            url_encode_chars: None,
        };
        let out: Vec<String> = generate_processed(&set).unwrap().collect();
        assert_eq!(out, vec!["keep".to_owned(), "also".to_owned()]);
    }

    #[test]
    fn invalid_regex_is_rejected_at_prepare() {
        let mut set = simple(&["a"]);
        set.processors = vec![PayloadProcessor::MatchReplace {
            pattern: "(".into(),
            replacement: String::new(),
        }];
        assert!(generate_processed(&set).is_err());
        assert!(validate_set(&set).is_err());
    }

    #[test]
    fn cardinality_saturates_and_combines() {
        assert_eq!(
            Cardinality::Exact(3).saturating_mul(Cardinality::Exact(4)),
            Cardinality::Exact(12)
        );
        assert_eq!(
            Cardinality::Exact(u64::MAX).saturating_mul(Cardinality::Exact(2)),
            Cardinality::AtLeast(u64::MAX)
        );
        assert_eq!(
            Cardinality::AtLeast(2).saturating_mul(Cardinality::Exact(3)),
            Cardinality::AtLeast(6)
        );
        assert_eq!(
            Cardinality::Exact(5).min_with(Cardinality::Exact(3)),
            Cardinality::Exact(3)
        );
    }
}
