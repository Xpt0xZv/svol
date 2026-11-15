#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{self, BufRead, BufReader, Read, Write};

use crate::error::{
    byte_offset_to_utf16_line_col, push_json_escaped, utf16_range_to_byte_offsets, LineColCursor,
    XmlError, XmlErrorKind,
};
use crate::{format_xml, lint_xml, Config, DEFAULT_MAX_INPUT_BYTES};

/// Maximum LSP JSON-RPC payload size (64 MiB) to prevent memory exhaustion on malformed headers.
pub const MAX_LSP_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

/// Maximum number of HTTP-style headers allowed in a single LSP frame.
pub const MAX_LSP_HEADERS: usize = 16;

/// Maximum byte length of a single LSP header line (including CRLF).
pub const MAX_LSP_HEADER_LINE_BYTES: usize = 1024;

/// Maximum number of open documents tracked simultaneously in `LspServer`.
pub const MAX_OPEN_DOCUMENTS: usize = 1024;

/// Runs the synchronous, pure-std Language Server Protocol (LSP) loop over stdio.
pub fn run_lsp_server(config: &Config) -> io::Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = stdout.lock();
    let mut server = LspServer::new(config.clone());
    server.serve(&mut reader, &mut writer)
}

/// Representation of a single `textDocument/didChange` content change event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentChangeEvent {
    /// Optional `((start_line, start_utf16_col), (end_line, end_utf16_col))` for incremental sync.
    pub range: Option<((usize, usize), (usize, usize))>,
    pub text: String,
}

/// Pure-std LSP server state holding open document buffers (bounded).
pub struct LspServer {
    config: Config,
    documents: HashMap<String, String>,
    shutdown_requested: bool,
}

impl LspServer {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            documents: HashMap::new(),
            shutdown_requested: false,
        }
    }

    /// Returns `true` if `uri` is currently stored in the server's open document map.
    pub fn has_document(&self, uri: &str) -> bool {
        self.documents.contains_key(uri)
    }

    /// Returns a reference to the current in-memory text for `uri`, if present.
    pub fn get_document(&self, uri: &str) -> Option<&str> {
        self.documents.get(uri).map(|s| s.as_str())
    }

    pub fn serve<R: BufRead, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> io::Result<()> {
        while let Some(payload) = read_lsp_frame(reader)? {
            if let Some(true) = self.handle_message(&payload, writer)? {
                break;
            }
        }
        Ok(())
    }

    /// Processes a single JSON-RPC 2.0 message payload and writes any responses/notifications.
    /// Returns `Ok(Some(true))` when `exit` notification is received.
    pub fn handle_message<W: Write>(
        &mut self,
        payload: &str,
        writer: &mut W,
    ) -> io::Result<Option<bool>> {
        let method = extract_top_level_string_field(payload, "method");
        let id_raw = extract_top_level_id_field(payload);

        match method.as_deref() {
            Some("initialize") => {
                let id = id_raw.unwrap_or_else(|| "null".to_string());
                let resp = format!(
                    "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{{\"capabilities\":{{\"textDocumentSync\":2,\"documentFormattingProvider\":true}},\"serverInfo\":{{\"name\":\"svol\",\"version\":\"{}\"}}}}}}",
                    id,
                    env!("CARGO_PKG_VERSION")
                );
                write_lsp_message(writer, &resp)?;
            }
            Some("initialized") => {}
            Some("shutdown") => {
                self.shutdown_requested = true;
                let id = id_raw.unwrap_or_else(|| "null".to_string());
                let resp = format!("{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":null}}", id);
                write_lsp_message(writer, &resp)?;
            }
            Some("exit") => {
                return Ok(Some(true));
            }
            Some("textDocument/didOpen") => {
                if let Some((uri, text)) = extract_did_open_params(payload) {
                    let max_in = self.config.max_input_bytes.min(DEFAULT_MAX_INPUT_BYTES);
                    if text.len() > max_in {
                        self.documents.remove(&uri);
                        self.publish_oversized_diagnostic(&uri, text.len(), max_in, writer)?;
                    } else {
                        if self.documents.len() >= MAX_OPEN_DOCUMENTS
                            && !self.documents.contains_key(&uri)
                        {
                            if let Some(first_key) = self.documents.keys().next().cloned() {
                                self.documents.remove(&first_key);
                            }
                        }
                        self.publish_diagnostics(&uri, text.as_bytes(), writer)?;
                        if !self
                            .documents
                            .get(&uri)
                            .is_some_and(|existing| existing == &text)
                        {
                            self.documents.insert(uri, text);
                        }
                    }
                }
            }
            Some("textDocument/didChange") => {
                if let Some((uri, changes)) = extract_did_change_params(payload) {
                    if changes.is_empty() {
                        return Ok(Some(false));
                    }
                    let max_in = self.config.max_input_bytes.min(DEFAULT_MAX_INPUT_BYTES);
                    if changes.len() == 1 {
                        let change = changes.into_iter().next().unwrap();
                        if let Some(((sl, sc), (el, ec))) = change.range {
                            let Some(existing) = self.documents.get(&uri) else {
                                return Ok(Some(false));
                            };
                            let Some((start_byte, end_byte)) =
                                utf16_range_to_byte_offsets(existing, (sl, sc), (el, ec))
                            else {
                                return Ok(Some(false));
                            };
                            let removed_len = end_byte - start_byte;
                            let new_len =
                                (existing.len() - removed_len).saturating_add(change.text.len());
                            if new_len > max_in {
                                self.documents.remove(&uri);
                                self.publish_oversized_diagnostic(&uri, new_len, max_in, writer)?;
                                return Ok(Some(false));
                            }
                            if &existing[start_byte..end_byte] == change.text.as_str() {
                                return Ok(Some(false));
                            }
                            let doc = self.documents.get_mut(&uri).expect("checked above");
                            doc.replace_range(start_byte..end_byte, &change.text);
                            publish_diagnostics_with_config(
                                &self.config,
                                &uri,
                                doc.as_bytes(),
                                writer,
                            )?;
                        } else {
                            if change.text.len() > max_in {
                                self.documents.remove(&uri);
                                self.publish_oversized_diagnostic(
                                    &uri,
                                    change.text.len(),
                                    max_in,
                                    writer,
                                )?;
                                return Ok(Some(false));
                            }
                            if self
                                .documents
                                .get(&uri)
                                .is_some_and(|existing| existing == &change.text)
                            {
                                return Ok(Some(false));
                            }
                            if self.documents.len() >= MAX_OPEN_DOCUMENTS
                                && !self.documents.contains_key(&uri)
                            {
                                if let Some(first_key) = self.documents.keys().next().cloned() {
                                    self.documents.remove(&first_key);
                                }
                            }
                            self.publish_diagnostics(&uri, change.text.as_bytes(), writer)?;
                            self.documents.insert(uri, change.text);
                        }
                    } else {
                        let mut has_base = self.documents.contains_key(&uri);
                        let mut doc = self.documents.get(&uri).cloned().unwrap_or_default();
                        let mut evicted = false;
                        let mut invalid_range = false;
                        let mut changed = false;

                        for change in changes {
                            if let Some(((sl, sc), (el, ec))) = change.range {
                                if !has_base {
                                    invalid_range = true;
                                    break;
                                }
                                let Some((start_byte, end_byte)) =
                                    utf16_range_to_byte_offsets(&doc, (sl, sc), (el, ec))
                                else {
                                    invalid_range = true;
                                    break;
                                };
                                let removed_len = end_byte - start_byte;
                                let new_len =
                                    (doc.len() - removed_len).saturating_add(change.text.len());
                                if new_len > max_in {
                                    self.documents.remove(&uri);
                                    self.publish_oversized_diagnostic(
                                        &uri, new_len, max_in, writer,
                                    )?;
                                    evicted = true;
                                    break;
                                }
                                if &doc[start_byte..end_byte] != change.text.as_str() {
                                    changed = true;
                                    doc.replace_range(start_byte..end_byte, &change.text);
                                }
                            } else {
                                if change.text.len() > max_in {
                                    self.documents.remove(&uri);
                                    self.publish_oversized_diagnostic(
                                        &uri,
                                        change.text.len(),
                                        max_in,
                                        writer,
                                    )?;
                                    evicted = true;
                                    break;
                                }
                                if !has_base || doc != change.text {
                                    changed = true;
                                }
                                doc = change.text;
                                has_base = true;
                            }
                        }

                        if !evicted && !invalid_range && has_base && changed {
                            if self.documents.len() >= MAX_OPEN_DOCUMENTS
                                && !self.documents.contains_key(&uri)
                            {
                                if let Some(first_key) = self.documents.keys().next().cloned() {
                                    self.documents.remove(&first_key);
                                }
                            }
                            self.publish_diagnostics(&uri, doc.as_bytes(), writer)?;
                            self.documents.insert(uri, doc);
                        }
                    }
                }
            }
            Some("textDocument/didSave") => {
                if let Some(params_slice) = find_json_object_field_value(payload, "params") {
                    if let Some(uri) = extract_nested_uri(params_slice) {
                        let max_in = self.config.max_input_bytes.min(DEFAULT_MAX_INPUT_BYTES);
                        if let Some(text) = extract_top_level_string_field(params_slice, "text") {
                            if text.len() > max_in {
                                self.documents.remove(&uri);
                                self.publish_oversized_diagnostic(
                                    &uri,
                                    text.len(),
                                    max_in,
                                    writer,
                                )?;
                            } else if !self
                                .documents
                                .get(&uri)
                                .is_some_and(|existing| existing == &text)
                            {
                                if self.documents.len() >= MAX_OPEN_DOCUMENTS
                                    && !self.documents.contains_key(&uri)
                                {
                                    if let Some(first_key) = self.documents.keys().next().cloned() {
                                        self.documents.remove(&first_key);
                                    }
                                }
                                self.publish_diagnostics(&uri, text.as_bytes(), writer)?;
                                self.documents.insert(uri, text);
                            }
                        } else if let Some(existing_len) = self.documents.get(&uri).map(String::len)
                        {
                            if existing_len > max_in {
                                self.documents.remove(&uri);
                                self.publish_oversized_diagnostic(
                                    &uri,
                                    existing_len,
                                    max_in,
                                    writer,
                                )?;
                            }
                        }
                    }
                }
            }
            Some("textDocument/didClose") => {
                if let Some(params_slice) = find_json_object_field_value(payload, "params") {
                    if let Some(uri) = extract_nested_uri(params_slice) {
                        self.documents.remove(&uri);
                        let notif = format!(
                            "{{\"jsonrpc\":\"2.0\",\"method\":\"textDocument/publishDiagnostics\",\"params\":{{\"uri\":\"{}\",\"diagnostics\":[]}}}}",
                            escape_json_str(&uri)
                        );
                        write_lsp_message(writer, &notif)?;
                    }
                }
            }
            Some("textDocument/formatting") => {
                let id = id_raw.unwrap_or_else(|| "null".to_string());
                let mut config = self.config.clone();
                if let Some(params_slice) = find_json_object_field_value(payload, "params") {
                    if let Some(options_slice) =
                        find_json_object_field_value(params_slice, "options")
                    {
                        if let Some(tab_size) =
                            extract_top_level_usize_field(options_slice, "tabSize")
                        {
                            if (1..=16).contains(&tab_size) {
                                config.indent_width = tab_size;
                            }
                        }
                        if let Some(insert_spaces) =
                            extract_top_level_bool_field(options_slice, "insertSpaces")
                        {
                            config.use_tabs = !insert_spaces;
                        }
                    }

                    if let Some(uri) = extract_nested_uri(params_slice) {
                        if let Some(doc) = self.documents.get(&uri) {
                            match format_xml(doc.as_bytes(), &config) {
                                Ok(formatted) => {
                                    if formatted == doc.as_bytes() {
                                        let resp = format!(
                                            "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":[]}}",
                                            id
                                        );
                                        write_lsp_message(writer, &resp)?;
                                    } else {
                                        let formatted_str = String::from_utf8_lossy(&formatted);
                                        let (end_line, end_utf16_col) =
                                            byte_offset_to_utf16_line_col(
                                                doc.as_bytes(),
                                                doc.len(),
                                            );
                                        let mut resp = String::with_capacity(formatted.len() + 128);
                                        let _ = write!(
                                            resp,
                                            "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":[{{\"range\":{{\"start\":{{\"line\":0,\"character\":0}},\"end\":{{\"line\":{},\"character\":{}}}}},\"newText\":\"",
                                            id, end_line, end_utf16_col
                                        );
                                        push_json_escaped(&mut resp, &formatted_str);
                                        resp.push_str("\"}]}");
                                        write_lsp_message(writer, &resp)?;
                                    }
                                }
                                Err(_) => {
                                    let resp = format!(
                                        "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":[]}}",
                                        id
                                    );
                                    write_lsp_message(writer, &resp)?;
                                }
                            }
                        } else {
                            let resp =
                                format!("{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":null}}", id);
                            write_lsp_message(writer, &resp)?;
                        }
                    } else {
                        let resp = format!("{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":null}}", id);
                        write_lsp_message(writer, &resp)?;
                    }
                } else {
                    let resp = format!("{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":null}}", id);
                    write_lsp_message(writer, &resp)?;
                }
            }
            _ => {
                if let Some(id) = id_raw {
                    let resp = format!(
                        "{{\"jsonrpc\":\"2.0\",\"id\":{},\"error\":{{\"code\":-32601,\"message\":\"Method not found\"}}}}",
                        id
                    );
                    write_lsp_message(writer, &resp)?;
                }
            }
        }
        Ok(Some(false))
    }

    fn publish_oversized_diagnostic<W: Write>(
        &self,
        uri: &str,
        actual_len: usize,
        max_in: usize,
        writer: &mut W,
    ) -> io::Result<()> {
        let err = XmlError::new(
            XmlErrorKind::InputTooLarge,
            format!(
                "document size ({} bytes) exceeds maximum limit of {} bytes",
                actual_len, max_in
            ),
            0,
            1,
            1,
        );
        let mut cursor = LineColCursor::new();
        let mut notif = String::with_capacity(256);
        notif.push_str(
            "{\"jsonrpc\":\"2.0\",\"method\":\"textDocument/publishDiagnostics\",\"params\":{\"uri\":\"",
        );
        push_json_escaped(&mut notif, uri);
        notif.push_str("\",\"diagnostics\":[");
        push_lsp_diagnostic(&mut notif, b"", &err, &mut cursor);
        notif.push_str("]}}");
        write_lsp_message(writer, &notif)
    }

    fn publish_diagnostics<W: Write>(
        &self,
        uri: &str,
        content: &[u8],
        writer: &mut W,
    ) -> io::Result<()> {
        publish_diagnostics_with_config(&self.config, uri, content, writer)
    }
}

fn publish_diagnostics_with_config<W: Write>(
    config: &Config,
    uri: &str,
    content: &[u8],
    writer: &mut W,
) -> io::Result<()> {
    let errors = lint_xml(content, config);
    let mut cursor = LineColCursor::new();
    let mut notif = String::with_capacity(128 + errors.len() * 192);
    notif.push_str(
        "{\"jsonrpc\":\"2.0\",\"method\":\"textDocument/publishDiagnostics\",\"params\":{\"uri\":\"",
    );
    push_json_escaped(&mut notif, uri);
    notif.push_str("\",\"diagnostics\":[");
    for (idx, err) in errors.iter().enumerate() {
        if idx > 0 {
            notif.push(',');
        }
        push_lsp_diagnostic(&mut notif, content, err, &mut cursor);
    }
    notif.push_str("]}}");
    write_lsp_message(writer, &notif)
}

fn push_lsp_diagnostic(out: &mut String, input: &[u8], err: &XmlError, cursor: &mut LineColCursor) {
    let (start_line, start_char) = cursor.byte_offset_to_utf16_line_col(input, err.byte_offset);
    let (end_l, end_c) = cursor.byte_offset_to_utf16_line_col(input, err.end_offset);
    let end_line = end_l.max(start_line);
    let end_char = if end_line == start_line {
        end_c.max(start_char + 1)
    } else {
        end_c
    };

    let _ = write!(
        out,
        "{{\"range\":{{\"start\":{{\"line\":{},\"character\":{}}},\"end\":{{\"line\":{},\"character\":{}}}}},\"severity\":{},\"code\":\"{}\",\"source\":\"svol\",\"message\":\"",
        start_line,
        start_char,
        end_line,
        end_char,
        err.severity.lsp_code(),
        err.code()
    );
    push_json_escaped(out, &err.message);
    out.push_str("\"}");
}

/// Hardened `Content-Length` framed LSP reader (CWE-444 / CWE-400):
/// - Caps header count at `MAX_LSP_HEADERS` (16) and single header line length at `MAX_LSP_HEADER_LINE_BYTES` (1024).
/// - Rejects duplicate `Content-Length` headers and any `Transfer-Encoding` header.
/// - Caps initial payload allocation at 64 KiB and streams in bounded chunks so a forged
///   `Content-Length: 50000000` followed by EOF never OOM-allocates 50 MiB upfront.
pub fn read_lsp_frame<R: BufRead>(reader: &mut R) -> io::Result<Option<String>> {
    let mut content_length: Option<usize> = None;
    let mut header_count = 0usize;
    let mut line_buf = Vec::with_capacity(128);

    loop {
        line_buf.clear();
        let n = reader
            .take((MAX_LSP_HEADER_LINE_BYTES as u64) + 1)
            .read_until(b'\n', &mut line_buf)?;
        if n == 0 {
            if header_count == 0 && content_length.is_none() {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF while reading LSP headers",
            ));
        }
        if line_buf.len() > MAX_LSP_HEADER_LINE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LSP header line exceeds maximum allowed byte length",
            ));
        }
        let line_str = std::str::from_utf8(&line_buf).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "LSP header is not valid ASCII/UTF-8",
            )
        })?;
        let trimmed = line_str.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        header_count += 1;
        if header_count > MAX_LSP_HEADERS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "too many headers in LSP message frame",
            ));
        }
        let Some((name, value)) = trimmed.split_once(':') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed LSP header line (missing ':')",
            ));
        };
        let name_trimmed = name.trim();
        if name_trimmed.eq_ignore_ascii_case("Transfer-Encoding") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Transfer-Encoding header is disallowed in LSP framing",
            ));
        }
        if name_trimmed.eq_ignore_ascii_case("Content-Length") {
            if content_length.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate Content-Length header in LSP message",
                ));
            }
            let val_trimmed = value.trim();
            if val_trimmed.is_empty() || !val_trimmed.bytes().all(|b| b.is_ascii_digit()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid Content-Length header value",
                ));
            }
            let len = val_trimmed.parse::<usize>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid Content-Length header")
            })?;
            if len > MAX_LSP_MESSAGE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "LSP message exceeds maximum allowed byte size",
                ));
            }
            content_length = Some(len);
        }
    }

    let Some(len) = content_length else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing Content-Length header in LSP message",
        ));
    };

    // Cap initial allocation at 64 KiB and read directly from BufRead buffer to avoid double-copy
    let mut buf = Vec::with_capacity(len.min(64 * 1024));
    let mut remaining = len;
    while remaining > 0 {
        let available = match reader.fill_buf() {
            Ok(avail) => avail,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if available.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF while reading LSP message body",
            ));
        }
        let to_take = available.len().min(remaining);
        buf.extend_from_slice(&available[..to_take]);
        reader.consume(to_take);
        remaining -= to_take;
    }

    String::from_utf8(buf)
        .map(Some)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "LSP payload is not valid UTF-8"))
}

/// Alias for `read_lsp_frame`.
#[inline]
pub fn read_lsp_message<R: BufRead>(reader: &mut R) -> io::Result<Option<String>> {
    read_lsp_frame(reader)
}

/// Writes a single `Content-Length` framed LSP message to `writer`.
pub fn write_lsp_message<W: Write>(writer: &mut W, payload: &str) -> io::Result<()> {
    write!(
        writer,
        "Content-Length: {}\r\n\r\n{}",
        payload.len(),
        payload
    )?;
    writer.flush()
}

fn escape_json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    push_json_escaped(&mut out, s);
    out
}

fn extract_did_open_params(payload: &str) -> Option<(String, String)> {
    let params_slice = find_json_object_field_value(payload, "params")?;
    let td_slice = find_json_object_field_value(params_slice, "textDocument")?;
    let uri = extract_top_level_string_field(td_slice, "uri")?;
    let text = extract_top_level_string_field(td_slice, "text")?;
    Some((uri, text))
}

fn extract_did_change_params(payload: &str) -> Option<(String, Vec<ContentChangeEvent>)> {
    let params_slice = find_json_object_field_value(payload, "params")?;
    let uri = extract_nested_uri(params_slice)?;
    let cc_array = find_json_object_field_value(params_slice, "contentChanges")?;
    let changes = parse_content_changes_array(cc_array)?;
    Some((uri, changes))
}

fn parse_content_changes_array(arr_json: &str) -> Option<Vec<ContentChangeEvent>> {
    let trimmed = arr_json.trim();
    if !trimmed.starts_with('[') {
        return None;
    }
    let bytes = trimmed.as_bytes();
    let mut i = 1;
    let mut events = Vec::new();

    while i < bytes.len() {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b',') {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] == b']' {
            break;
        }
        if bytes[i] != b'{' {
            return None;
        }
        let end_obj = skip_json_value(trimmed, i)?;
        let obj_slice = &trimmed[i..end_obj];
        let text = extract_top_level_string_field(obj_slice, "text")?;
        let range = if let Some(range_slice) = find_json_object_field_value(obj_slice, "range") {
            let start_slice = find_json_object_field_value(range_slice, "start")?;
            let end_slice = find_json_object_field_value(range_slice, "end")?;
            let sl = extract_top_level_usize_field(start_slice, "line")?;
            let sc = extract_top_level_usize_field(start_slice, "character")?;
            let el = extract_top_level_usize_field(end_slice, "line")?;
            let ec = extract_top_level_usize_field(end_slice, "character")?;
            Some(((sl, sc), (el, ec)))
        } else {
            None
        };
        events.push(ContentChangeEvent { range, text });
        i = end_obj;
    }
    Some(events)
}

fn extract_nested_uri(params_or_obj: &str) -> Option<String> {
    if let Some(td_slice) = find_json_object_field_value(params_or_obj, "textDocument") {
        if let Some(uri) = extract_top_level_string_field(td_slice, "uri") {
            return Some(uri);
        }
    }
    extract_top_level_string_field(params_or_obj, "uri")
}

/// Finds a direct key-value pair at depth 1 of the JSON object `json_obj` (skipping string literals
/// and nested `{...}` / `[...]` values so nested content can never spoof outer fields)
/// and returns the raw slice of the value.
pub fn find_json_object_field_value<'a>(json_obj: &'a str, target_key: &str) -> Option<&'a str> {
    let trimmed = json_obj.trim();
    let bytes = trimmed.as_bytes();
    if bytes.first().copied() != Some(b'{') {
        return None;
    }
    let mut i = 1;
    let len = bytes.len();

    while i < len {
        while i < len && (bytes[i].is_ascii_whitespace() || bytes[i] == b',') {
            i += 1;
        }
        if i >= len || bytes[i] == b'}' {
            break;
        }
        if bytes[i] != b'"' {
            return None;
        }
        let key_end = skip_json_string(trimmed, i)?;
        let raw_key_inner = &trimmed[i + 1..key_end - 1];
        let key_matches = if !raw_key_inner.as_bytes().contains(&b'\\') {
            raw_key_inner == target_key
        } else {
            parse_json_string_literal(&trimmed[i..key_end])? == target_key
        };
        i = key_end;

        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len || bytes[i] != b':' {
            return None;
        }
        i += 1;
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len {
            return None;
        }

        let val_start = i;
        let val_end = skip_json_value(trimmed, val_start)?;
        if key_matches {
            return Some(&trimmed[val_start..val_end]);
        }
        i = val_end;
    }
    None
}

/// Skips a JSON string literal starting at `bytes[start] == b'"'`, returning the byte index
/// immediately after the closing `"` (or `None` if unterminated).
fn skip_json_string(s: &str, start: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    if bytes.get(start).copied() != Some(b'"') {
        return None;
    }
    let mut i = start + 1;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' {
            i += 2;
            continue;
        }
        if b == b'"' {
            return Some(i + 1);
        }
        i += 1;
    }
    None
}

/// Skips any JSON value (string, object, array, number, boolean, null) starting at `start`,
/// returning the byte index immediately after the value.
fn skip_json_value(s: &str, start: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    if start >= bytes.len() {
        return None;
    }
    match bytes[start] {
        b'"' => skip_json_string(s, start),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut i = start;
            while i < bytes.len() {
                match bytes[i] {
                    b'"' => {
                        i = skip_json_string(s, i)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth = depth.checked_sub(1)?;
                        if depth == 0 {
                            return Some(i + 1);
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            None
        }
        _ => {
            let mut i = start;
            while i < bytes.len() {
                let b = bytes[i];
                if b == b',' || b == b'}' || b == b']' || b.is_ascii_whitespace() {
                    break;
                }
                i += 1;
            }
            if i > start {
                Some(i)
            } else {
                None
            }
        }
    }
}

/// Extracts a string field from the top level of `json_obj` (depth 1).
pub fn extract_top_level_string_field(json_obj: &str, key: &str) -> Option<String> {
    let raw_val = find_json_object_field_value(json_obj, key)?;
    parse_json_string_literal(raw_val)
}

/// Alias for `extract_top_level_string_field`.
pub fn extract_json_string_field(json_obj: &str, key: &str) -> Option<String> {
    extract_top_level_string_field(json_obj, key)
}

/// Extracts and validates the JSON-RPC `"id"` field at depth 1 of `json_obj`
/// (must be a valid JSON integer, string, or `null`).
fn extract_top_level_id_field(json_obj: &str) -> Option<String> {
    let raw_val = find_json_object_field_value(json_obj, "id")?.trim();
    if raw_val == "null" {
        return Some("null".to_string());
    }
    if raw_val.starts_with('"') {
        let s = parse_json_string_literal(raw_val)?;
        return Some(format!("\"{}\"", escape_json_str(&s)));
    }
    // Validate JSON integer token
    let digits = raw_val.strip_prefix('-').unwrap_or(raw_val);
    if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
        return Some(raw_val.to_string());
    }
    None
}

fn extract_top_level_usize_field(json_obj: &str, key: &str) -> Option<usize> {
    let raw_val = find_json_object_field_value(json_obj, key)?.trim();
    raw_val.parse::<usize>().ok()
}

fn extract_top_level_bool_field(json_obj: &str, key: &str) -> Option<bool> {
    let raw_val = find_json_object_field_value(json_obj, key)?.trim();
    match raw_val {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// Decodes a JSON string literal (`"..."`), properly combining UTF-16 surrogate pairs
/// (`\uD800`..`\uDBFF` followed by `\uDC00`..`\uDFFF`) into astral Unicode scalar values
/// and rejecting unpaired surrogates (`None`).
pub fn parse_json_string_literal(s: &str) -> Option<String> {
    let trimmed = s.trim();
    let bytes = trimmed.as_bytes();
    if bytes.first().copied() != Some(b'"') {
        return None;
    }
    let mut out = String::with_capacity(trimmed.len().saturating_sub(2).min(64 * 1024));
    let mut chars = trimmed[1..].chars();
    while let Some(ch) = chars.next() {
        if ch == '"' {
            return Some(out);
        }
        if ch == '\\' {
            let esc = chars.next()?;
            match esc {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'b' => out.push('\x08'),
                'f' => out.push('\x0C'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'u' => {
                    let unit1 = parse_hex4(&mut chars)?;
                    if (0xD800..=0xDBFF).contains(&unit1) {
                        // High surrogate: must be followed immediately by \uXXXX low surrogate
                        if chars.next()? != '\\' || chars.next()? != 'u' {
                            return None;
                        }
                        let unit2 = parse_hex4(&mut chars)?;
                        if !(0xDC00..=0xDFFF).contains(&unit2) {
                            return None;
                        }
                        let combined = 0x10000 + (((unit1 - 0xD800) << 10) | (unit2 - 0xDC00));
                        out.push(char::from_u32(combined)?);
                    } else if (0xDC00..=0xDFFF).contains(&unit1) {
                        // Unpaired low surrogate is invalid
                        return None;
                    } else {
                        out.push(char::from_u32(unit1)?);
                    }
                }
                other => out.push(other),
            }
        } else {
            out.push(ch);
        }
    }
    None
}

fn parse_hex4(chars: &mut std::str::Chars<'_>) -> Option<u32> {
    let mut val = 0u32;
    for _ in 0..4 {
        let c = chars.next()?;
        let d = c.to_digit(16)?;
        val = (val << 4) | d;
    }
    Some(val)
}
