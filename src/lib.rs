pub mod error;
pub mod lexer;
pub mod lsp;

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;

pub use error::{
    byte_offset_to_utf16_line_col, line_col_at, push_json_escaped, sanitize_for_terminal,
    utf16_position_to_byte_offset, Severity, XmlError, XmlErrorKind,
};
pub use lexer::{
    is_name_char, is_name_start_char, is_xml_char, skip_xml_attr_bytes, skip_xml_text_bytes,
    BoundedVecRefSink, FxBuildHasher, FxHasher, KeySet, RawKeySet, StreamingEngine, XmlFrame,
};

/// Hard resource bound: 100 MiB maximum input buffer size.
pub const DEFAULT_MAX_INPUT_BYTES: usize = 100 * 1024 * 1024;

/// Hard resource bound: 256 MiB maximum formatted output buffer size.
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 256 * 1024 * 1024;

/// Hard resource bound: Maximum element nesting depth (zero recursion).
pub const MAX_DEPTH: usize = 512;

/// Hard resource bound: Maximum lint diagnostics collected per document.
pub const MAX_LINT_DIAGNOSTICS: usize = 50;

/// Default indentation width in spaces.
pub const DEFAULT_INDENT_WIDTH: usize = 2;

/// Default target line width for inline leaf element formatting.
pub const DEFAULT_LINE_WIDTH: usize = 100;

/// File extensions recognized by the bounded directory walker.
pub const SUPPORTED_EXTENSIONS: &[&str] = &[
    "xml", "xsd", "xsl", "xslt", "svg", "plist", "xhtml", "csproj", "pom",
];

/// Configuration for the single-pass XML 1.0 + Namespaces 1.0 engine.
///
/// # Examples
///
/// ```
/// use svol::{format_xml, Config, DEFAULT_INDENT_WIDTH, DEFAULT_LINE_WIDTH};
///
/// let config = Config {
///     sort_attributes: true,
///     disallow_doctype: true,
///     ..Config::default()
/// };
/// assert_eq!(config.indent_width, DEFAULT_INDENT_WIDTH);
/// assert_eq!(config.line_width, DEFAULT_LINE_WIDTH);
///
/// let formatted = format_xml(br#"<item b="2" a="1"/>"#, &config).unwrap();
/// assert_eq!(formatted, b"<item a=\"1\" b=\"2\"/>\n");
/// ```
#[derive(Debug, Clone)]
pub struct Config {
    pub indent_width: usize,
    pub use_tabs: bool,
    pub sort_attributes: bool,
    pub disallow_doctype: bool,
    pub line_width: usize,
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
    pub max_depth: usize,
    pub max_diagnostics: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            indent_width: DEFAULT_INDENT_WIDTH,
            use_tabs: false,
            sort_attributes: false,
            disallow_doctype: false,
            line_width: DEFAULT_LINE_WIDTH,
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_depth: MAX_DEPTH,
            max_diagnostics: MAX_LINT_DIAGNOSTICS,
        }
    }
}

/// Validates `input` in a single streaming pass without constructing a DOM.
/// Returns an empty `Vec` if the XML document is well-formed and namespace-well-formed.
///
/// # Examples
///
/// ```
/// use svol::{lint_xml, Config, XmlErrorKind};
///
/// let cfg = Config::default();
/// assert!(lint_xml(b"<root><child/></root>", &cfg).is_empty());
///
/// let errs = lint_xml(b"<root><mismatched></other></root>", &cfg);
/// assert_eq!(errs.len(), 1);
/// assert_eq!(errs[0].kind, XmlErrorKind::MismatchedClosingTag);
/// ```
pub fn lint_xml(input: &[u8], config: &Config) -> Vec<XmlError> {
    let engine = StreamingEngine::new(input, config, false);
    let (diagnostics, _) = engine.run();
    diagnostics
}

/// Validates and formats `input` in a single streaming pass without constructing a DOM.
/// Returns the formatted UTF-8 byte buffer or a list of diagnostics if ill-formed.
///
/// # Examples
///
/// ```
/// use svol::{format_xml, Config};
///
/// let cfg = Config {
///     sort_attributes: true,
///     ..Config::default()
/// };
/// let formatted = format_xml(br#"<root z="2" a="1"><child>hi</child></root>"#, &cfg).unwrap();
/// assert_eq!(
///     std::str::from_utf8(&formatted).unwrap(),
///     "<root a=\"1\" z=\"2\">\n  <child>hi</child>\n</root>\n"
/// );
///
/// assert!(format_xml(b"<root>", &cfg).is_err());
/// ```
pub fn format_xml(input: &[u8], config: &Config) -> Result<Vec<u8>, Vec<XmlError>> {
    let engine = StreamingEngine::new(input, config, true);
    let (diagnostics, output) = engine.run();
    if diagnostics.is_empty() {
        Ok(output.unwrap_or_default())
    } else {
        Err(diagnostics)
    }
}

/// Returns `true` if `path` has a supported XML family extension
/// (`.xml`, `.xsd`, `.xsl`, `.xslt`, `.svg`, `.plist`, `.xhtml`, `.csproj`, `.pom`).
///
/// # Examples
///
/// ```
/// use std::path::Path;
/// use svol::is_supported_xml_path;
///
/// assert!(is_supported_xml_path(Path::new("pom.xml")));
/// assert!(is_supported_xml_path(Path::new("icons/LOGO.SVG")));
/// assert!(!is_supported_xml_path(Path::new("README.md")));
/// ```
pub fn is_supported_xml_path(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    SUPPORTED_EXTENSIONS
        .iter()
        .any(|&supported| ext.eq_ignore_ascii_case(supported))
}

/// Reads a regular file up to `max_bytes`, rejecting symlinks, FIFOs/devices/directories,
/// and oversized files without allocating beyond the limit (CWE-59 / CWE-367).
pub fn read_file_bounded(path: &Path, max_bytes: usize) -> Result<Vec<u8>, XmlError> {
    let sym_meta = fs::symlink_metadata(path).map_err(|e| XmlError::io(&e))?;
    if sym_meta.file_type().is_symlink() {
        return Err(XmlError::io(&io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to read symlink target",
        )));
    }
    if !sym_meta.is_file() {
        return Err(XmlError::io(&io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to read non-regular file (FIFO, device, socket, or directory)",
        )));
    }

    let file = File::open(path).map_err(|e| XmlError::io(&e))?;
    let meta = file.metadata().map_err(|e| XmlError::io(&e))?;
    if !meta.is_file() {
        return Err(XmlError::io(&io::Error::new(
            io::ErrorKind::InvalidInput,
            "opened file handle is not a regular file",
        )));
    }
    if meta.len() > max_bytes as u64 {
        return Err(XmlError::new(
            XmlErrorKind::InputTooLarge,
            format!(
                "file size ({} bytes) exceeds maximum limit of {} bytes",
                meta.len(),
                max_bytes
            ),
            0,
            1,
            1,
        ));
    }
    let cap = (meta.len() as usize).min(max_bytes).min(64 * 1024);
    let mut buf = Vec::with_capacity(cap);
    file.take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| XmlError::io(&e))?;
    if buf.len() > max_bytes {
        return Err(XmlError::new(
            XmlErrorKind::InputTooLarge,
            format!(
                "file size ({} bytes) exceeds maximum limit of {} bytes",
                buf.len(),
                max_bytes
            ),
            0,
            1,
            1,
        ));
    }
    Ok(buf)
}

static TMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Atomically writes `contents` to an exclusively created sibling temporary file (`create_new(true)`)
/// in the same directory, flushes and syncs to disk, preserves permissions, and renames over `target`.
/// Refuses to overwrite symlinks, non-regular files, or read-only targets (CWE-59 / CWE-367).
pub fn atomic_replace_file(target: &Path, contents: &[u8]) -> io::Result<()> {
    let sym_meta = fs::symlink_metadata(target)?;
    if sym_meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to atomically replace a symlink target",
        ));
    }
    if !sym_meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to atomically replace a non-regular file",
        ));
    }
    if sym_meta.permissions().readonly() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing to replace a read-only file",
        ));
    }

    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("output.xml");
    let pid = std::process::id();
    let existing_perms = sym_meta.permissions();

    let mut tmp_path = None;
    let mut tmp_file = None;

    for attempt in 0..8 {
        let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
            .wrapping_add(attempt as u32);
        let candidate_name = format!(".{}.svol.{}.{}.{}.tmp", file_name, pid, seq, nanos);
        let candidate_path = parent.join(candidate_name);

        match File::options()
            .write(true)
            .create_new(true)
            .open(&candidate_path)
        {
            Ok(f) => {
                tmp_path = Some(candidate_path);
                tmp_file = Some(f);
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }

    let (Some(tmp_path), Some(mut file)) = (tmp_path, tmp_file) else {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "failed to create exclusive temporary file after 8 attempts",
        ));
    };

    let write_res = (|| -> io::Result<()> {
        file.write_all(contents)?;
        file.sync_all()?;
        let _ = file.set_permissions(existing_perms);
        Ok(())
    })();
    drop(file);

    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    if let Err(err) = fs::rename(&tmp_path, target) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bom_and_encoding_gate() {
        let cfg = Config::default();

        // Valid UTF-8 BOM + <?xml version="1.0" encoding="utf-8" standalone="yes"?>
        let mut valid_bom = vec![0xEF, 0xBB, 0xBF];
        valid_bom.extend_from_slice(
            b"<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n<root/>",
        );
        assert!(lint_xml(&valid_bom, &cfg).is_empty());

        // Reject UTF-16LE BOM
        let utf16le = [0xFF, 0xFE, b'<', 0x00, b'a', 0x00, b'/', 0x00, b'>', 0x00];
        let errs = lint_xml(&utf16le, &cfg);
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].kind, XmlErrorKind::UnsupportedEncoding);

        // Reject UTF-16BE BOM
        let utf16be = [0xFE, 0xFF, 0x00, b'<', 0x00, b'a', 0x00, b'/', 0x00, b'>'];
        let errs = lint_xml(&utf16be, &cfg);
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].kind, XmlErrorKind::UnsupportedEncoding);

        // Reject whitespace before <?xml
        let errs = lint_xml(b" <?xml version=\"1.0\"?><root/>", &cfg);
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].kind, XmlErrorKind::MisplacedXmlDecl);

        // Reject case-insensitive <?XML target
        let errs = lint_xml(b"<?XML version=\"1.0\"?><root/>", &cfg);
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].kind, XmlErrorKind::ReservedPiTarget);

        // Reject wrong attribute order in XMLDecl (standalone before encoding)
        let errs = lint_xml(
            b"<?xml version=\"1.0\" standalone=\"no\" encoding=\"UTF-8\"?><root/>",
            &cfg,
        );
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].kind, XmlErrorKind::MalformedXmlDecl);

        // Reject non-UTF-8 encoding declaration
        let errs = lint_xml(
            b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><root/>",
            &cfg,
        );
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].kind, XmlErrorKind::UnsupportedEncoding);
    }

    #[test]
    fn test_expanded_namespace_attribute_uniqueness_and_order() {
        let cfg = Config::default();

        // Raw QName duplicate
        let errs = lint_xml(b"<root a:id=\"1\" a:id=\"2\" xmlns:a=\"urn:x\"/>", &cfg);
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].kind, XmlErrorKind::DuplicateAttribute);

        // Expanded {namespaceURI}localName duplicate (xmlns:a and xmlns:b bound to same URI)
        let errs = lint_xml(
            b"<root xmlns:a=\"urn:x\" xmlns:b=\"urn:x\" a:id=\"1\" b:id=\"2\"/>",
            &cfg,
        );
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].kind, XmlErrorKind::DuplicateExpandedAttribute);

        // xmlns declaration appearing AFTER prefixed attribute in the same start tag is valid!
        let errs = lint_xml(b"<tag a:id=\"1\" xmlns:a=\"urn:x\"/>", &cfg);
        assert!(errs.is_empty(), "expected valid, got: {:?}", errs);

        // Expanded duplicate even when xmlns appears after the attributes
        let errs = lint_xml(
            b"<tag a:id=\"1\" b:id=\"2\" xmlns:a=\"urn:x\" xmlns:b=\"urn:x\"/>",
            &cfg,
        );
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].kind, XmlErrorKind::DuplicateExpandedAttribute);

        // Undeclared prefix
        let errs = lint_xml(b"<tag a:id=\"1\"/>", &cfg);
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].kind, XmlErrorKind::UndeclaredPrefix);
    }

    #[test]
    fn test_three_tier_keyset_transitions() {
        let mut ks = KeySet::<usize>::new();
        for i in 1..=8 {
            assert!(ks.insert(i));
            assert_eq!(ks.tier(), 1);
        }
        assert!(!ks.insert(5));
        assert!(ks.insert(9));
        assert_eq!(ks.tier(), 2);
        for i in 10..=64 {
            assert!(ks.insert(i));
            assert_eq!(ks.tier(), 2);
        }
        assert!(!ks.insert(42));
        assert!(ks.insert(65));
        assert_eq!(ks.tier(), 3);
        assert!(!ks.insert(1));
        assert!(!ks.insert(65));
        assert_eq!(ks.len(), 65);
        ks.clear();
        assert_eq!(ks.tier(), 1);
        assert!(ks.capacity() <= 8);
    }

    #[test]
    fn test_safe_dtd_and_xxe_rejection() {
        let mut cfg = Config::default();

        // Standard DOCTYPE passes in default mode
        let doc = b"<!DOCTYPE note [\n  <!ELEMENT note (#PCDATA)>\n]>\n<note>ok</note>";
        assert!(lint_xml(doc, &cfg).is_empty());

        // Rejected in --strict / --disallow-doctype mode
        cfg.disallow_doctype = true;
        let errs = lint_xml(doc, &cfg);
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].kind, XmlErrorKind::DisallowedDoctype);
        cfg.disallow_doctype = false;

        // Reject external SYSTEM entity in internal subset (XXE)
        let xxe = b"<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]><foo/>";
        let errs = lint_xml(xxe, &cfg);
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].kind, XmlErrorKind::ExternalEntityDisallowed);

        // Reject custom entity expansion in content (Billion Laughs protection)
        let custom_ent = b"<!DOCTYPE foo [ <!ENTITY lol \"haha\"> ]><foo>&lol;</foo>";
        let errs = lint_xml(custom_ent, &cfg);
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].kind, XmlErrorKind::CustomEntityDisallowed);
    }

    #[test]
    fn test_character_and_entity_references() {
        let cfg = Config::default();

        // Valid built-in and numeric references
        let valid = b"<r>&lt;&gt;&amp;&apos;&quot;&#9;&#10;&#13;&#32;&#x1F600;</r>";
        assert!(lint_xml(valid, &cfg).is_empty());

        // Reject &#0;
        let errs = lint_xml(b"<r>&#0;</r>", &cfg);
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].kind, XmlErrorKind::InvalidCharRef);

        // Reject control char &#x1;..&#x1F; (except 9, A, D), DEL (0x7F), and C1 (0x80..=0x9F)
        for bad in [
            0x1u32, 0x7, 0x8, 0xB, 0xC, 0xE, 0x1F, 0x7F, 0x80, 0x85, 0x9B, 0x9F,
        ] {
            let xml = format!("<r>&#x{:X};</r>", bad);
            let errs = lint_xml(xml.as_bytes(), &cfg);
            assert_eq!(errs.len(), 1, "expected error for &#x{:X};", bad);
            assert_eq!(errs[0].kind, XmlErrorKind::InvalidCharRef);
        }

        // Reject UTF-16 surrogates and 0xFFFE / 0xFFFF
        for bad in [0xD800u32, 0xDFFF, 0xFFFE, 0xFFFF, 0x110000] {
            let xml = format!("<r>&#x{:X};</r>", bad);
            let errs = lint_xml(xml.as_bytes(), &cfg);
            assert_eq!(errs.len(), 1, "expected error for &#x{:X};", bad);
            assert_eq!(errs[0].kind, XmlErrorKind::InvalidCharRef);
        }

        // Reject prohibited ]]> in plain character data
        let errs = lint_xml(b"<r>hello ]]> world</r>", &cfg);
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].kind, XmlErrorKind::CdataEndInText);
    }

    #[test]
    fn test_formatting_sort_attributes_and_whitespace_preservation() {
        let cfg = Config {
            sort_attributes: true,
            ..Default::default()
        };

        let input = b"<root z=\"1\" a=\"2\"><p>Hello <b>world</b>!</p><pre xml:space=\"preserve\">  keep \n  exact  </pre><item c=\"3\" b=\"4\"/></root>";
        let formatted = format_xml(input, &cfg).expect("should format cleanly");
        let formatted_str = std::str::from_utf8(&formatted).unwrap();

        let expected = concat!(
            "<root a=\"2\" z=\"1\">\n",
            "  <p>Hello <b>world</b>!</p>\n",
            "  <pre xml:space=\"preserve\">  keep \n  exact  </pre>\n",
            "  <item b=\"4\" c=\"3\"/>\n",
            "</root>\n"
        );
        assert_eq!(formatted_str, expected);
    }

    #[test]
    fn test_max_depth_enforced_without_recursion() {
        let cfg = Config {
            max_depth: 8,
            ..Default::default()
        };

        let mut deep = Vec::new();
        for _ in 0..9 {
            deep.extend_from_slice(b"<a>");
        }
        for _ in 0..9 {
            deep.extend_from_slice(b"</a>");
        }
        let errs = lint_xml(&deep, &cfg);
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].kind, XmlErrorKind::MaxDepthExceeded);
    }
}
