#![forbid(unsafe_code)]

use std::fmt::{self, Write as _};
use std::io;

/// Severity level for a diagnostic emitted by `svol`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
    Info,
    Hint,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "info",
            Severity::Hint => "hint",
        }
    }

    pub const fn lsp_code(self) -> u8 {
        match self {
            Severity::Error => 1,
            Severity::Warning => 2,
            Severity::Info => 3,
            Severity::Hint => 4,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Specific category of XML 1.0 / Namespaces in XML 1.0 / Resource limit error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmlErrorKind {
    InputTooLarge,
    OutputTooLarge,
    MaxDepthExceeded,
    UnsupportedEncoding,
    InvalidUtf8,
    MalformedXmlDecl,
    MisplacedXmlDecl,
    ReservedPiTarget,
    DisallowedDoctype,
    MalformedDoctype,
    ExternalEntityDisallowed,
    CustomEntityDisallowed,
    UnexpectedEof,
    UnexpectedChar,
    InvalidName,
    InvalidQName,
    InvalidChar,
    InvalidCharRef,
    InvalidEntityRef,
    InvalidComment,
    InvalidPi,
    InvalidCdata,
    CdataEndInText,
    DuplicateAttribute,
    DuplicateExpandedAttribute,
    UndeclaredPrefix,
    InvalidNamespaceDeclaration,
    MismatchedClosingTag,
    UnclosedElement,
    MissingRootElement,
    MultipleRootElements,
    ContentOutsideRoot,
    UnescapedLtInAttribute,
    InvalidXmlSpace,
    IoError,
}

impl XmlErrorKind {
    pub const fn code(self) -> &'static str {
        match self {
            XmlErrorKind::InputTooLarge => "E001_INPUT_TOO_LARGE",
            XmlErrorKind::OutputTooLarge => "E002_OUTPUT_TOO_LARGE",
            XmlErrorKind::MaxDepthExceeded => "E003_MAX_DEPTH_EXCEEDED",
            XmlErrorKind::UnsupportedEncoding => "E004_UNSUPPORTED_ENCODING",
            XmlErrorKind::InvalidUtf8 => "E005_INVALID_UTF8",
            XmlErrorKind::MalformedXmlDecl => "E006_MALFORMED_XML_DECL",
            XmlErrorKind::MisplacedXmlDecl => "E007_MISPLACED_XML_DECL",
            XmlErrorKind::ReservedPiTarget => "E008_RESERVED_PI_TARGET",
            XmlErrorKind::DisallowedDoctype => "E009_DISALLOWED_DOCTYPE",
            XmlErrorKind::MalformedDoctype => "E010_MALFORMED_DOCTYPE",
            XmlErrorKind::ExternalEntityDisallowed => "E011_EXTERNAL_ENTITY_DISALLOWED",
            XmlErrorKind::CustomEntityDisallowed => "E012_CUSTOM_ENTITY_DISALLOWED",
            XmlErrorKind::UnexpectedEof => "E013_UNEXPECTED_EOF",
            XmlErrorKind::UnexpectedChar => "E014_UNEXPECTED_CHAR",
            XmlErrorKind::InvalidName => "E015_INVALID_NAME",
            XmlErrorKind::InvalidQName => "E016_INVALID_QNAME",
            XmlErrorKind::InvalidChar => "E017_INVALID_CHAR",
            XmlErrorKind::InvalidCharRef => "E018_INVALID_CHAR_REF",
            XmlErrorKind::InvalidEntityRef => "E019_INVALID_ENTITY_REF",
            XmlErrorKind::InvalidComment => "E020_INVALID_COMMENT",
            XmlErrorKind::InvalidPi => "E021_INVALID_PI",
            XmlErrorKind::InvalidCdata => "E022_INVALID_CDATA",
            XmlErrorKind::CdataEndInText => "E023_CDATA_END_IN_TEXT",
            XmlErrorKind::DuplicateAttribute => "E024_DUPLICATE_ATTRIBUTE",
            XmlErrorKind::DuplicateExpandedAttribute => "E025_DUPLICATE_EXPANDED_ATTRIBUTE",
            XmlErrorKind::UndeclaredPrefix => "E026_UNDECLARED_PREFIX",
            XmlErrorKind::InvalidNamespaceDeclaration => "E027_INVALID_NAMESPACE_DECL",
            XmlErrorKind::MismatchedClosingTag => "E028_MISMATCHED_CLOSING_TAG",
            XmlErrorKind::UnclosedElement => "E029_UNCLOSED_ELEMENT",
            XmlErrorKind::MissingRootElement => "E030_MISSING_ROOT_ELEMENT",
            XmlErrorKind::MultipleRootElements => "E031_MULTIPLE_ROOT_ELEMENTS",
            XmlErrorKind::ContentOutsideRoot => "E032_CONTENT_OUTSIDE_ROOT",
            XmlErrorKind::UnescapedLtInAttribute => "E033_UNESCAPED_LT_IN_ATTRIBUTE",
            XmlErrorKind::InvalidXmlSpace => "E034_INVALID_XML_SPACE",
            XmlErrorKind::IoError => "E035_IO_ERROR",
        }
    }
}

/// A structured XML diagnostic / error with 1-based line and column coordinates and byte span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlError {
    pub kind: XmlErrorKind,
    pub severity: Severity,
    pub message: String,
    pub byte_offset: usize,
    pub end_offset: usize,
    pub line: usize,
    pub column: usize,
}

impl XmlError {
    pub fn new(
        kind: XmlErrorKind,
        message: impl Into<String>,
        byte_offset: usize,
        line: usize,
        column: usize,
    ) -> Self {
        let end_offset = byte_offset.saturating_add(1);
        let raw_msg = message.into();
        Self {
            kind,
            severity: Severity::Error,
            message: sanitize_for_terminal(&raw_msg),
            byte_offset,
            end_offset,
            line: line.max(1),
            column: column.max(1),
        }
    }

    pub fn with_span(
        kind: XmlErrorKind,
        message: impl Into<String>,
        byte_offset: usize,
        end_offset: usize,
        line: usize,
        column: usize,
    ) -> Self {
        let raw_msg = message.into();
        Self {
            kind,
            severity: Severity::Error,
            message: sanitize_for_terminal(&raw_msg),
            byte_offset,
            end_offset: end_offset.max(byte_offset.saturating_add(1)),
            line: line.max(1),
            column: column.max(1),
        }
    }

    pub fn io(err: &io::Error) -> Self {
        Self {
            kind: XmlErrorKind::IoError,
            severity: Severity::Error,
            message: sanitize_for_terminal(&err.to_string()),
            byte_offset: 0,
            end_offset: 0,
            line: 1,
            column: 1,
        }
    }

    pub const fn code(&self) -> &'static str {
        self.kind.code()
    }

    /// Formats this diagnostic as a single-line JSON object without external dependencies.
    pub fn to_json(&self, file_path: Option<&str>) -> String {
        let mut out = String::with_capacity(192);
        out.push('{');
        if let Some(path) = file_path {
            out.push_str("\"file\":\"");
            push_json_escaped(&mut out, path);
            out.push_str("\",");
        }
        let _ = write!(
            out,
            "\"code\":\"{}\",\"severity\":\"{}\",\"line\":{},\"column\":{},\"byte_offset\":{},\"end_offset\":{},\"message\":\"",
            self.code(),
            self.severity.as_str(),
            self.line,
            self.column,
            self.byte_offset,
            self.end_offset
        );
        push_json_escaped(&mut out, &self.message);
        out.push_str("\"}");
        out
    }
}

impl fmt::Display for XmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}: {} [{}]: ",
            self.line,
            self.column,
            self.severity,
            self.code()
        )?;
        if !self.message.chars().any(is_unsafe_terminal_char) {
            f.write_str(&self.message)
        } else {
            for ch in self.message.chars() {
                if is_unsafe_terminal_char(ch) {
                    f.write_str("\u{FFFD}")?;
                } else {
                    f.write_char(ch)?;
                }
            }
            Ok(())
        }
    }
}

impl std::error::Error for XmlError {}

/// Returns `true` if `ch` is an unsafe terminal control, C1 control, BiDi override/isolate/mark,
/// or zero-width spoofing character (CWE-150 / CWE-451, Ruling 2).
#[inline]
pub const fn is_unsafe_terminal_char(ch: char) -> bool {
    let cp = ch as u32;
    cp <= 0x1F
        || cp == 0x7F
        || (cp >= 0x80 && cp <= 0x9F)
        || cp == 0x061C
        || (cp >= 0x200B && cp <= 0x200F)
        || (cp >= 0x202A && cp <= 0x202E)
        || (cp >= 0x2066 && cp <= 0x2069)
        || cp == 0xFEFF
}

/// Replaces terminal escape sequences, ASCII/C1 control characters, BiDi overrides,
/// and zero-width characters 1-for-1 with `'\u{FFFD}'` (`U+FFFD`) to prevent terminal
/// escape injection (CWE-150) and Trojan Source BiDi spoofing (CWE-451) while preserving
/// 1:1 character alignment.
pub fn sanitize_for_terminal(s: &str) -> String {
    if !s.chars().any(is_unsafe_terminal_char) {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if is_unsafe_terminal_char(ch) {
            out.push('\u{FFFD}');
        } else {
            out.push(ch);
        }
    }
    out
}

/// Escapes a string according to RFC 8259 JSON rules (plus C1, DEL, BiDi, and zero-width characters)
/// and appends it to `out`.
pub fn push_json_escaped(out: &mut String, s: &str) {
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x08' => out.push_str("\\b"),
            '\x0C' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || is_unsafe_terminal_char(c) => {
                let code = c as u32;
                let hex = [
                    b'\\',
                    b'u',
                    HEX_DIGITS[((code >> 12) & 0xF) as usize],
                    HEX_DIGITS[((code >> 8) & 0xF) as usize],
                    HEX_DIGITS[((code >> 4) & 0xF) as usize],
                    HEX_DIGITS[(code & 0xF) as usize],
                ];
                if let Ok(esc) = std::str::from_utf8(&hex) {
                    out.push_str(esc);
                }
            }
            c => out.push(c),
        }
    }
}

const HEX_DIGITS: [u8; 16] = *b"0123456789abcdef";

/// Stateful, zero-allocation cursor that tracks line starts monotonically across `input`
/// to avoid O(D * N) full-buffer rescans from byte 0 when computing 1-based `(line, col)`
/// or 0-based LSP `(line, utf16_col)` coordinates.
#[derive(Debug, Clone, Copy, Default)]
pub struct LineColCursor {
    scan_pos: usize,
    line_start: usize,
    line_zero_based: usize,
}

impl LineColCursor {
    /// Creates a new cursor positioned at byte 0, line 0.
    #[inline]
    pub const fn new() -> Self {
        Self {
            scan_pos: 0,
            line_start: 0,
            line_zero_based: 0,
        }
    }

    /// Resets the cursor back to byte 0, line 0.
    #[inline]
    pub fn reset(&mut self) {
        self.scan_pos = 0;
        self.line_start = 0;
        self.line_zero_based = 0;
    }

    fn advance_to(&mut self, input: &[u8], clamped: usize) {
        if clamped < self.line_start || self.scan_pos > input.len() {
            self.reset();
        }
        if clamped < self.scan_pos {
            return;
        }
        let mut i = self.scan_pos;
        while i < clamped {
            if input[i] == b'\n' {
                self.line_zero_based += 1;
                self.line_start = i + 1;
            } else if input[i] == b'\r' {
                if i + 1 < input.len() && input[i + 1] == b'\n' {
                    if i + 1 < clamped {
                        i += 1;
                        self.line_zero_based += 1;
                        self.line_start = i + 1;
                    } else {
                        break;
                    }
                } else {
                    self.line_zero_based += 1;
                    self.line_start = i + 1;
                }
            }
            i += 1;
        }
        self.scan_pos = i;
    }

    /// Computes 1-based `(line, column)` (in Unicode scalar values) at `byte_offset` in `input`.
    pub fn line_col_at(&mut self, input: &[u8], byte_offset: usize) -> (usize, usize) {
        let clamped = byte_offset.min(input.len());
        self.advance_to(input, clamped);
        let slice = &input[self.line_start..clamped];
        let col = match std::str::from_utf8(slice) {
            Ok(s) => s.chars().count() + 1,
            Err(_) => (clamped - self.line_start) + 1,
        };
        (self.line_zero_based + 1, col)
    }

    /// Converts a byte offset in `input` to 0-based `(line, utf16_col)` per the LSP specification
    /// (Ruling 3, CWE-125). Each Unicode scalar on the target line contributes `ch.len_utf16()`.
    pub fn byte_offset_to_utf16_line_col(
        &mut self,
        input: &[u8],
        byte_offset: usize,
    ) -> (usize, usize) {
        let clamped = byte_offset.min(input.len());
        self.advance_to(input, clamped);
        let slice = &input[self.line_start..clamped];
        let utf16_col = match std::str::from_utf8(slice) {
            Ok(s) => s.chars().map(|ch| ch.len_utf16()).sum(),
            Err(_) => clamped - self.line_start,
        };
        (self.line_zero_based, utf16_col)
    }
}

/// Computes 1-based `(line, column)` (in Unicode scalar values) at `byte_offset` in `input`.
pub fn line_col_at(input: &[u8], byte_offset: usize) -> (usize, usize) {
    LineColCursor::new().line_col_at(input, byte_offset)
}

/// Converts a byte offset in `input` to 0-based `(line, utf16_col)` per the LSP specification
/// (Ruling 3, CWE-125). Each Unicode scalar on the target line contributes `ch.len_utf16()`.
pub fn byte_offset_to_utf16_line_col(input: &[u8], byte_offset: usize) -> (usize, usize) {
    LineColCursor::new().byte_offset_to_utf16_line_col(input, byte_offset)
}

fn advance_to_line(
    bytes: &[u8],
    cur_line: &mut usize,
    line_start: &mut usize,
    i: &mut usize,
    target_line: usize,
) -> Option<()> {
    let len = bytes.len();
    while *cur_line < target_line {
        if *i >= len {
            return None;
        }
        if bytes[*i] == b'\n' {
            *cur_line += 1;
            *line_start = *i + 1;
        } else if bytes[*i] == b'\r' {
            if *i + 1 < len && bytes[*i + 1] == b'\n' {
                *i += 1;
            }
            *cur_line += 1;
            *line_start = *i + 1;
        }
        *i += 1;
    }
    Some(())
}

fn find_line_end(bytes: &[u8], line_start: usize) -> usize {
    let len = bytes.len();
    let mut line_end = line_start;
    while line_end < len && bytes[line_end] != b'\n' && bytes[line_end] != b'\r' {
        line_end += 1;
    }
    line_end
}

fn resolve_utf16_col_on_slice(
    slice: &str,
    base_offset: usize,
    init_col: usize,
    target_col: usize,
) -> Option<usize> {
    if target_col == init_col {
        return Some(base_offset);
    }
    if target_col < init_col {
        return None;
    }
    let mut utf16_col = init_col;
    for (rel_byte, ch) in slice.char_indices() {
        if utf16_col == target_col {
            return Some(base_offset + rel_byte);
        }
        if utf16_col > target_col {
            // Landed inside a surrogate pair!
            return None;
        }
        utf16_col += ch.len_utf16();
    }
    if utf16_col == target_col {
        Some(base_offset + slice.len())
    } else {
        None
    }
}

/// Converts a 0-based LSP `(line, character_utf16)` coordinate into a validated byte offset in `doc`.
/// Returns `None` if `line` or `character_utf16` is out of bounds, or if `character_utf16` splits
/// a 2-unit UTF-16 surrogate pair (e.g. landing on the trailing surrogate half of a 4-byte UTF-8 scalar).
pub fn utf16_position_to_byte_offset(
    doc: &str,
    line: usize,
    character_utf16: usize,
) -> Option<usize> {
    let bytes = doc.as_bytes();
    let mut cur_line = 0usize;
    let mut line_start = 0usize;
    let mut i = 0usize;

    advance_to_line(bytes, &mut cur_line, &mut line_start, &mut i, line)?;
    let line_end = find_line_end(bytes, line_start);
    resolve_utf16_col_on_slice(&doc[line_start..line_end], line_start, 0, character_utf16)
}

/// Resolves a 0-based LSP UTF-16 range `(start, end)` into validated byte offsets `(start_byte, end_byte)`
/// in a single forward scan of `doc` when `start <= end`. Returns `None` if either position is out of
/// bounds, splits a UTF-16 surrogate pair, or if `start_byte > end_byte`.
pub fn utf16_range_to_byte_offsets(
    doc: &str,
    start: (usize, usize),
    end: (usize, usize),
) -> Option<(usize, usize)> {
    if end.0 < start.0 || (end.0 == start.0 && end.1 < start.1) {
        return None;
    }

    let bytes = doc.as_bytes();
    let mut cur_line = 0usize;
    let mut line_start = 0usize;
    let mut i = 0usize;

    advance_to_line(bytes, &mut cur_line, &mut line_start, &mut i, start.0)?;
    let line_end = find_line_end(bytes, line_start);
    let start_byte =
        resolve_utf16_col_on_slice(&doc[line_start..line_end], line_start, 0, start.1)?;

    if end.0 == start.0 {
        let end_byte =
            resolve_utf16_col_on_slice(&doc[start_byte..line_end], start_byte, start.1, end.1)?;
        return if start_byte > end_byte {
            None
        } else {
            Some((start_byte, end_byte))
        };
    }

    i = line_end;
    advance_to_line(bytes, &mut cur_line, &mut line_start, &mut i, end.0)?;
    let end_line_end = find_line_end(bytes, line_start);
    let end_byte =
        resolve_utf16_col_on_slice(&doc[line_start..end_line_end], line_start, 0, end.1)?;

    if start_byte > end_byte {
        None
    } else {
        Some((start_byte, end_byte))
    }
}
