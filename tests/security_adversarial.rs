use std::env;
use std::fs;
use std::io::Cursor;
#[cfg(not(miri))]
use std::time::Instant;

use svol::error::{
    byte_offset_to_utf16_line_col, is_unsafe_terminal_char, sanitize_for_terminal,
    utf16_position_to_byte_offset, XmlErrorKind,
};
use svol::lexer::{skip_xml_attr_bytes_swar, skip_xml_text_bytes_swar};
use svol::lsp::{read_lsp_frame, LspServer};
use svol::{
    atomic_replace_file, format_xml, lint_xml, read_file_bounded, skip_xml_attr_bytes,
    skip_xml_text_bytes, BoundedVecRefSink, Config, KeySet, MAX_DEPTH,
};

#[test]
fn test_cwe776_billion_laughs_and_entity_chains() {
    let cfg = Config::default();

    // 10-level nested Billion Laughs payload
    let billion_laughs = br#"<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>"#;

    let errs = lint_xml(billion_laughs, &cfg);
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].kind, XmlErrorKind::CustomEntityDisallowed);

    // Smuggled %pe; inside <!ENTITY> value
    let smuggled_pe = b"<!DOCTYPE foo [ <!ENTITY e \"hello %pe; world\"> ]><foo/>";
    let errs = lint_xml(smuggled_pe, &cfg);
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].kind, XmlErrorKind::ExternalEntityDisallowed);

    // Smuggled raw NUL \x00 inside <!ENTITY> value
    let smuggled_nul = b"<!DOCTYPE foo [ <!ENTITY e \"bad\x00char\"> ]><foo/>";
    let errs = lint_xml(smuggled_nul, &cfg);
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].kind, XmlErrorKind::InvalidChar);

    // Smuggled numeric &#0; and &#x7F; inside <!ENTITY> value
    for bad_ref in [
        b"<!DOCTYPE foo [ <!ENTITY e \"&#0;\"> ]><foo/>".as_slice(),
        b"<!DOCTYPE foo [ <!ENTITY e \"&#x1B;\"> ]><foo/>".as_slice(),
        b"<!DOCTYPE foo [ <!ENTITY e \"&#x7F;\"> ]><foo/>".as_slice(),
        b"<!DOCTYPE foo [ <!ENTITY e \"&#xD800;\"> ]><foo/>".as_slice(),
    ] {
        let errs = lint_xml(bad_ref, &cfg);
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].kind, XmlErrorKind::InvalidCharRef);
    }
}

#[test]
fn test_cwe611_xxe_and_parameter_entities() {
    let mut cfg = Config::default();

    // Ruling 1: Reject external SYSTEM and PUBLIC DTD subsets at <!DOCTYPE> root level in default mode
    let ext_system_dtd = b"<!DOCTYPE foo SYSTEM \"file:///etc/passwd\"><foo/>";
    let errs = lint_xml(ext_system_dtd, &cfg);
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].kind, XmlErrorKind::ExternalEntityDisallowed);

    let ext_public_dtd =
        b"<!DOCTYPE foo PUBLIC \"-//W3C//DTD...\" \"http://127.0.0.1/evil.dtd\"><foo/>";
    let errs = lint_xml(ext_public_dtd, &cfg);
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].kind, XmlErrorKind::ExternalEntityDisallowed);

    // Case-insensitive system / public
    let ext_system_ci = b"<!DOCTYPE foo system \"http://127.0.0.1/evil.dtd\"><foo/>";
    let errs = lint_xml(ext_system_ci, &cfg);
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].kind, XmlErrorKind::ExternalEntityDisallowed);

    // External entity & parameter entity declarations inside [...]
    let xxe_internal = b"<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]><foo/>";
    let errs = lint_xml(xxe_internal, &cfg);
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].kind, XmlErrorKind::ExternalEntityDisallowed);

    let pe_decl = b"<!DOCTYPE foo [ <!ENTITY % pe SYSTEM \"http://127.0.0.1/evil.dtd\"> ]><foo/>";
    let errs = lint_xml(pe_decl, &cfg);
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].kind, XmlErrorKind::ExternalEntityDisallowed);

    // Parameter entity references %pe; both outside and inside [...]
    let pe_outside = b"<!DOCTYPE foo %pe;><foo/>";
    let errs = lint_xml(pe_outside, &cfg);
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].kind, XmlErrorKind::ExternalEntityDisallowed);

    let pe_inside = b"<!DOCTYPE foo [ %pe; ]><foo/>";
    let errs = lint_xml(pe_inside, &cfg);
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].kind, XmlErrorKind::ExternalEntityDisallowed);

    // --strict / disallow_doctype: true rejects <!DOCTYPE> at offset 0 with DisallowedDoctype
    cfg.disallow_doctype = true;
    let errs = lint_xml(b"<!DOCTYPE foo [ <!ELEMENT foo EMPTY> ]><foo/>", &cfg);
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].kind, XmlErrorKind::DisallowedDoctype);
}

#[test]
fn test_cwe407_attribute_and_namespace_hashdos() {
    let cfg = Config::default();

    // Verify 3-tier KeySet transitions up to 10,000 keys and shrinks back to Tier 1 on clear()
    let mut ks = KeySet::<usize>::new();
    for i in 1..=8 {
        assert!(ks.insert(i));
        assert_eq!(ks.tier(), 1);
    }
    for i in 9..=64 {
        assert!(ks.insert(i));
        assert_eq!(ks.tier(), 2);
    }
    for i in 65..=10_000 {
        assert!(ks.insert(i));
        assert_eq!(ks.tier(), 3);
    }
    assert_eq!(ks.len(), 10_000);
    assert!(!ks.insert(9_999));
    ks.clear();
    assert_eq!(ks.tier(), 1);
    assert!(ks.capacity() <= 8);

    // Single <elem> with 10,000 unique attributes
    let mut elem_10k = String::with_capacity(160_000);
    elem_10k.push_str("<elem");
    for i in 0..10_000 {
        elem_10k.push_str(&format!(" a{}=\"{}\"", i, i));
    }
    elem_10k.push_str("/>");
    let errs = lint_xml(elem_10k.as_bytes(), &cfg);
    assert!(errs.is_empty(), "expected 10k attrs to pass: {:?}", errs);

    // Single <elem> with 2,000 xmlns:pN="urn:nsN" bindings and 2,000 pN:attr="val" attributes
    // Must complete in < 100 ms (proving O(1) namespace prefix lookup via XmlFrame::ns_map)
    let mut ns_xml = String::with_capacity(120_000);
    ns_xml.push_str("<elem");
    for i in 0..2_000 {
        ns_xml.push_str(&format!(" xmlns:p{}=\"urn:ns:{}\"", i, i));
    }
    for i in 0..2_000 {
        ns_xml.push_str(&format!(" p{}:attr=\"val\"", i));
    }
    ns_xml.push_str("/>");

    #[cfg(not(miri))]
    let start = Instant::now();
    let errs = lint_xml(ns_xml.as_bytes(), &cfg);
    #[cfg(not(miri))]
    let elapsed = start.elapsed();
    assert!(errs.is_empty(), "expected 2k ns attrs to pass: {:?}", errs);
    #[cfg(not(miri))]
    assert!(
        elapsed.as_millis() < 100,
        "2,000 xmlns + 2,000 prefixed attributes took {:?} (>= 100 ms)",
        elapsed
    );
}

#[test]
fn test_cwe674_stack_and_depth_exhaustion() {
    let cfg = Config::default();

    // 10,000-level deep nesting handled iteratively and rejected at MAX_DEPTH = 512 without stack overflow
    let mut deep = Vec::with_capacity(70_000);
    for _ in 0..10_000 {
        deep.extend_from_slice(b"<a>");
    }
    for _ in 0..10_000 {
        deep.extend_from_slice(b"</a>");
    }
    let errs = lint_xml(&deep, &cfg);
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].kind, XmlErrorKind::MaxDepthExceeded);
    assert_eq!(MAX_DEPTH, 512);

    // Nested <!DOCTYPE [ <!ENTITY <!ENTITY ...> ]> markup declarations
    for nested_dtd in [
        b"<!DOCTYPE [ <!ENTITY <!ENTITY a \"b\">> ]><r/>".as_slice(),
        b"<!DOCTYPE r [ <!ENTITY <!ENTITY a \"b\">> ]><r/>".as_slice(),
        b"<!DOCTYPE r [ <!ELEMENT r <!ELEMENT a EMPTY>> ]><r/>".as_slice(),
    ] {
        let errs = lint_xml(nested_dtd, &cfg);
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].kind, XmlErrorKind::MalformedDoctype);
    }
}

#[test]
fn test_cwe400_amplification_dos_bounded_sink() {
    // Test BoundedVecRefSink directly: len + additional <= max_bytes and capacity <= max_bytes
    let mut backing = Vec::new();
    let max_bytes = 100usize;
    {
        let mut sink = BoundedVecRefSink::new(&mut backing, max_bytes);
        assert!(sink.write_slice(&[b'x'; 60]));
        assert_eq!(sink.len(), 60);
        assert!(sink.capacity() <= max_bytes);

        assert!(sink.write_slice(&[b'y'; 40]));
        assert_eq!(sink.len(), 100);
        assert_eq!(sink.capacity(), max_bytes);

        // 1 byte over max_bytes is rejected without growing capacity
        assert!(!sink.write_slice(b"z"));
        assert_eq!(sink.len(), 100);
        assert_eq!(sink.capacity(), max_bytes);
    }

    // Test format_xml amplification DoS with indent_width = 8 exceeding max_output_bytes
    let cfg = Config {
        indent_width: 8,
        max_output_bytes: 512,
        ..Default::default()
    };

    let mut input = Vec::new();
    input.extend_from_slice(b"<r>");
    for _ in 0..20 {
        input.extend_from_slice(b"<a><b><c><d><e/></d></c></b></a>");
    }
    input.extend_from_slice(b"</r>");

    let res = format_xml(&input, &cfg);
    let errs = res.expect_err("expected OutputTooLarge error");
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].kind, XmlErrorKind::OutputTooLarge);
}

#[test]
fn test_cwe20_smuggled_control_chars_and_ruling2_del_c1() {
    let cfg = Config::default();

    // Numeric references for control chars, DEL (0x7F), C1 (0x80..=0x9F), and unpaired surrogates
    for bad_cp in [0x0u32, 0x1B, 0x7F, 0x80, 0x9B, 0x9F, 0xD800, 0xDFFF] {
        let text_xml = format!("<r>&#x{:X};</r>", bad_cp);
        let errs = lint_xml(text_xml.as_bytes(), &cfg);
        assert_eq!(
            errs.len(),
            1,
            "expected InvalidCharRef in text for U+{:04X}",
            bad_cp
        );
        assert_eq!(errs[0].kind, XmlErrorKind::InvalidCharRef);

        let attr_xml = format!("<r a=\"&#x{:X};\"/>", bad_cp);
        let errs = lint_xml(attr_xml.as_bytes(), &cfg);
        assert_eq!(
            errs.len(),
            1,
            "expected InvalidCharRef in attr for U+{:04X}",
            bad_cp
        );
        assert_eq!(errs[0].kind, XmlErrorKind::InvalidCharRef);
    }

    // Raw 0x7F (DEL) and raw UTF-8 C1 controls (U+0080, U+0085, U+009B, U+009F) across SIMD/SWAR alignments (0..=40)
    let bad_sequences: &[&[u8]] = &[
        &[0x7F],       // DEL
        &[0xC2, 0x80], // U+0080
        &[0xC2, 0x85], // U+0085 (NEL)
        &[0xC2, 0x9B], // U+009B (C1 CSI)
        &[0xC2, 0x9F], // U+009F
    ];

    for pad_len in [0usize, 1, 7, 8, 15, 16, 31, 32, 39] {
        let padding = "a".repeat(pad_len);
        for seq in bad_sequences {
            // In character data
            let mut doc = Vec::new();
            doc.extend_from_slice(b"<r>");
            doc.extend_from_slice(padding.as_bytes());
            doc.extend_from_slice(seq);
            doc.extend_from_slice(b"</r>");
            let errs = lint_xml(&doc, &cfg);
            assert_eq!(
                errs.len(),
                1,
                "expected InvalidChar in text at pad_len={} for {:?}",
                pad_len,
                seq
            );
            assert_eq!(errs[0].kind, XmlErrorKind::InvalidChar);

            // In attribute value
            let mut attr_doc = Vec::new();
            attr_doc.extend_from_slice(b"<r attr=\"");
            attr_doc.extend_from_slice(padding.as_bytes());
            attr_doc.extend_from_slice(seq);
            attr_doc.extend_from_slice(b"\"/>");
            let errs = lint_xml(&attr_doc, &cfg);
            assert_eq!(
                errs.len(),
                1,
                "expected InvalidChar in attr at pad_len={} for {:?}",
                pad_len,
                seq
            );
            assert_eq!(errs[0].kind, XmlErrorKind::InvalidChar);
        }
    }
}

#[test]
fn test_cwe20_cwe436_exhaustive_256_byte_simd_swar_differential_parity() {
    let cfg = Config::default();

    // 1. Exhaustive 256-byte (0x00..=0xFF) fast-scanner differential parity between active SIMD
    //    path (`skip_xml_text_bytes` / `skip_xml_attr_bytes`) and portable SWAR fallback across all
    //    alignments 0..=40 for >= 40-byte slices (guaranteeing AVX2 32-byte and NEON 16-byte loops).
    let mut buf = [b'a'; 81];
    for byte in 0u8..=255 {
        for offset in 0..=40 {
            buf.fill(b'a');
            buf[offset] = byte;
            let slice = &buf[..offset + 41];

            assert_eq!(
                skip_xml_text_bytes(slice),
                skip_xml_text_bytes_swar(slice),
                "text scanner parity mismatch for byte 0x{:02X} at offset {}",
                byte,
                offset
            );

            for quote in [b'"', b'\''] {
                assert_eq!(
                    skip_xml_attr_bytes(slice, quote),
                    skip_xml_attr_bytes_swar(slice, quote),
                    "attr scanner (quote={:?}) parity mismatch for byte 0x{:02X} at offset {}",
                    quote as char,
                    byte,
                    offset
                );
            }
        }
    }

    // 2. End-to-end XML lint_xml differential parity across all 256 single-byte values (0x00..=0xFF)
    //    comparing short (< 32-byte SWAR) vs >= 40-byte (SIMD) inputs across SIMD/SWAR alignments.
    let alignments = [0usize, 1, 7, 8, 15, 16, 31, 32, 39];
    for byte in 0u8..=255 {
        // Skip ASCII syntax delimiters whose following payload changes grammar structure in short vs long docs;
        // their stop-byte parity is already exhaustively verified above.
        let text_comparable = !matches!(byte, b'<' | b'&');
        let attr_comparable = !matches!(byte, b'<' | b'&' | b'"');

        if text_comparable {
            let short_doc = [b'<', b'r', b'>', byte, b'<', b'/', b'r', b'>'];
            let short_kinds: Vec<XmlErrorKind> = lint_xml(&short_doc, &cfg)
                .into_iter()
                .map(|e| e.kind)
                .collect();

            for &pad_len in &alignments {
                let mut long_doc = Vec::with_capacity(pad_len + 48);
                long_doc.extend_from_slice(b"<r>");
                long_doc.resize(long_doc.len() + pad_len, b'a');
                long_doc.push(byte);
                long_doc.resize(long_doc.len() + 40, b'a');
                long_doc.extend_from_slice(b"</r>");

                let long_kinds: Vec<XmlErrorKind> = lint_xml(&long_doc, &cfg)
                    .into_iter()
                    .map(|e| e.kind)
                    .collect();
                assert_eq!(
                    long_kinds, short_kinds,
                    "lint_xml text parity mismatch for byte 0x{:02X} at pad_len={}",
                    byte, pad_len
                );
            }
        }

        if attr_comparable {
            let short_attr = [b'<', b'r', b' ', b'a', b'=', b'"', byte, b'"', b'/', b'>'];
            let short_kinds: Vec<XmlErrorKind> = lint_xml(&short_attr, &cfg)
                .into_iter()
                .map(|e| e.kind)
                .collect();

            for &pad_len in &alignments {
                let mut long_attr = Vec::with_capacity(pad_len + 52);
                long_attr.extend_from_slice(b"<r a=\"");
                long_attr.resize(long_attr.len() + pad_len, b'a');
                long_attr.push(byte);
                long_attr.resize(long_attr.len() + 40, b'a');
                long_attr.extend_from_slice(b"\"/>");

                let long_kinds: Vec<XmlErrorKind> = lint_xml(&long_attr, &cfg)
                    .into_iter()
                    .map(|e| e.kind)
                    .collect();
                assert_eq!(
                    long_kinds, short_kinds,
                    "lint_xml attr parity mismatch for byte 0x{:02X} at pad_len={}",
                    byte, pad_len
                );
            }
        }
    }

    // 3. Explicit Finding 1 regression check for 0x1F (Unit Separator) across every offset 0..40
    //    in both lint_xml and format_xml for text and attribute values.
    for offset in 0..40 {
        let mut text_doc = Vec::with_capacity(offset + 48);
        text_doc.extend_from_slice(b"<r>");
        text_doc.resize(text_doc.len() + offset, b'a');
        text_doc.push(0x1F);
        text_doc.resize(text_doc.len() + 40, b'a');
        text_doc.extend_from_slice(b"</r>");

        let lint_errs = lint_xml(&text_doc, &cfg);
        assert_eq!(lint_errs.len(), 1);
        assert_eq!(lint_errs[0].kind, XmlErrorKind::InvalidChar);
        let fmt_errs = format_xml(&text_doc, &cfg).expect_err("0x1F in text must fail format_xml");
        assert_eq!(fmt_errs.len(), 1);
        assert_eq!(fmt_errs[0].kind, XmlErrorKind::InvalidChar);

        let mut attr_doc = Vec::with_capacity(offset + 52);
        attr_doc.extend_from_slice(b"<r a=\"");
        attr_doc.resize(attr_doc.len() + offset, b'a');
        attr_doc.push(0x1F);
        attr_doc.resize(attr_doc.len() + 40, b'a');
        attr_doc.extend_from_slice(b"\"/>");

        let lint_errs = lint_xml(&attr_doc, &cfg);
        assert_eq!(lint_errs.len(), 1);
        assert_eq!(lint_errs[0].kind, XmlErrorKind::InvalidChar);
        let fmt_errs = format_xml(&attr_doc, &cfg).expect_err("0x1F in attr must fail format_xml");
        assert_eq!(fmt_errs.len(), 1);
        assert_eq!(fmt_errs[0].kind, XmlErrorKind::InvalidChar);
    }
}

#[test]
fn test_cwe150_cwe451_terminal_escape_and_trojan_source() {
    let raw = "alert\x1b[31m\x07\x7f\u{009B}\u{202E}\u{2066}\u{200B}\u{FEFF}end";
    let sanitized = sanitize_for_terminal(raw);
    assert_eq!(
        sanitized,
        "alert\u{FFFD}[31m\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}end"
    );
    assert_eq!(raw.chars().count(), sanitized.chars().count());
    assert!(!sanitized.chars().any(is_unsafe_terminal_char));

    // Feed malformed XML containing ANSI escapes and BiDi overrides into lint_xml
    let cfg = Config::default();
    let evil_xml = "<root xml:space=\"\u{202E}evil\u{2066}\"><\u{200B}bad/></root>";
    let errs = lint_xml(evil_xml.as_bytes(), &cfg);
    assert!(!errs.is_empty());
    assert!(
        !errs[0].message.chars().any(is_unsafe_terminal_char),
        "XmlError.message must be sanitized at construction: {:?}",
        errs[0].message
    );
    let rendered = errs[0].to_string();
    assert!(
        !rendered.chars().any(is_unsafe_terminal_char),
        "rendered error must not contain unsafe terminal or BiDi characters: {:?}",
        rendered
    );
}

#[test]
fn test_cwe444_cwe125_lsp_framing_and_utf16_desync() {
    // 1. Duplicate Content-Length header rejected
    let dup_frame = b"Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}";
    let mut cursor = Cursor::new(&dup_frame[..]);
    let res = read_lsp_frame(&mut cursor);
    assert!(res.is_err(), "duplicate Content-Length must be rejected");

    // 2. Content-Length > 64 MiB rejected immediately
    let huge_frame = b"Content-Length: 70000000\r\n\r\n{}";
    let mut cursor = Cursor::new(&huge_frame[..]);
    let res = read_lsp_frame(&mut cursor);
    assert!(res.is_err(), "Content-Length > 64 MiB must be rejected");

    // 3. Content-Length: 50000000 followed by immediate EOF returns UnexpectedEof without OOM
    let eof_frame = b"Content-Length: 50000000\r\n\r\n";
    let mut cursor = Cursor::new(&eof_frame[..]);
    let res = read_lsp_frame(&mut cursor);
    assert!(res.is_err());

    // 4. UTF-16 position converter and surrogate split detection on U+1F600 (😀, 4 UTF-8 bytes, 2 UTF-16 units)
    let doc = "<r>😀</r>";
    // '<' = 1 unit (byte 0..1), 'r' = 1 unit (byte 1..2), '>' = 1 unit (byte 2..3),
    // '😀' = 2 UTF-16 units (utf16 col 3..5, byte 3..7), '</r>' = utf16 col 5..9 (byte 7..11)
    assert_eq!(utf16_position_to_byte_offset(doc, 0, 3), Some(3));
    assert_eq!(
        utf16_position_to_byte_offset(doc, 0, 4),
        None,
        "splitting surrogate pair at UTF-16 offset 4 must return None"
    );
    assert_eq!(utf16_position_to_byte_offset(doc, 0, 5), Some(7));
    assert_eq!(byte_offset_to_utf16_line_col(doc.as_bytes(), 7), (0, 5));

    // 5. Incremental didChange with valid UTF-16 range vs surrogate-splitting UTF-16 range, plus oversized eviction
    let cfg = Config {
        max_input_bytes: 64,
        ..Default::default()
    };
    let mut server = LspServer::new(cfg);
    let mut out = Vec::new();

    // Open document with emoji via surrogate pair in JSON (\uD83D\uDE00 -> 😀)
    let open_msg = r#"{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":"file:///test.xml","version":1,"text":"<r>\uD83D\uDE00</r>"}}}"#;
    server.handle_message(open_msg, &mut out).unwrap();
    assert_eq!(server.get_document("file:///test.xml"), Some("<r>😀</r>"));

    // Attempt range edit splitting the surrogate pair (character 3..4) -> must be rejected without corrupting doc
    let bad_change = r#"{"jsonrpc":"2.0","method":"textDocument/didChange","params":{"textDocument":{"uri":"file:///test.xml","version":2},"contentChanges":[{"range":{"start":{"line":0,"character":3},"end":{"line":0,"character":4}},"text":"X"}]}}"#;
    server.handle_message(bad_change, &mut out).unwrap();
    assert_eq!(server.get_document("file:///test.xml"), Some("<r>😀</r>"));

    // Valid range edit replacing 😀 (character 3..5) with "ok"
    let good_change = r#"{"jsonrpc":"2.0","method":"textDocument/didChange","params":{"textDocument":{"uri":"file:///test.xml","version":3},"contentChanges":[{"range":{"start":{"line":0,"character":3},"end":{"line":0,"character":5}},"text":"ok"}]}}"#;
    server.handle_message(good_change, &mut out).unwrap();
    assert_eq!(server.get_document("file:///test.xml"), Some("<r>ok</r>"));

    // Oversized didChange (> 64 bytes) evicts the document from LspServer
    let huge_text = "a".repeat(100);
    let oversized_change = format!(
        r#"{{"jsonrpc":"2.0","method":"textDocument/didChange","params":{{"textDocument":{{"uri":"file:///test.xml","version":4}},"contentChanges":[{{"text":"<r>{}</r>"}}]}}}}"#,
        huge_text
    );
    server.handle_message(&oversized_change, &mut out).unwrap();
    assert!(
        !server.has_document("file:///test.xml"),
        "oversized didChange must evict document from LspServer"
    );

    // Incremental range edit on a previously evicted document must be rejected (not resurrected as partial buffer)
    let range_on_evicted = r#"{"jsonrpc":"2.0","method":"textDocument/didChange","params":{"textDocument":{"uri":"file:///test.xml","version":5},"contentChanges":[{"range":{"start":{"line":0,"character":0},"end":{"line":0,"character":0}},"text":"<r/>"}]}}"#;
    server.handle_message(range_on_evicted, &mut out).unwrap();
    assert!(
        !server.has_document("file:///test.xml"),
        "incremental range edit on evicted document must not resurrect document"
    );

    // Re-open and verify oversized didSave also evicts
    server.handle_message(open_msg, &mut out).unwrap();
    assert!(server.has_document("file:///test.xml"));
    let oversized_save = format!(
        r#"{{"jsonrpc":"2.0","method":"textDocument/didSave","params":{{"textDocument":{{"uri":"file:///test.xml"}},"text":"<r>{}</r>"}}}}"#,
        huge_text
    );
    server.handle_message(&oversized_save, &mut out).unwrap();
    assert!(
        !server.has_document("file:///test.xml"),
        "oversized didSave must evict document from LspServer"
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "uses OS temp_dir, permissions, and symlink syscalls unsupported under Miri isolation"
)]
fn test_cwe59_cwe367_filesystem_symlink_and_fifo_traps() {
    let tmp_dir = env::temp_dir().join(format!("svol_sec_fs_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp_dir);
    fs::create_dir_all(&tmp_dir).unwrap();

    // 1. Read-only file must be rejected by atomic_replace_file
    let ro_path = tmp_dir.join("readonly.xml");
    fs::write(&ro_path, b"<r/>").unwrap();
    let mut perms = fs::metadata(&ro_path).unwrap().permissions();
    perms.set_readonly(true);
    fs::set_permissions(&ro_path, perms.clone()).unwrap();

    let res = atomic_replace_file(&ro_path, b"<r>\n</r>\n");
    assert!(
        res.is_err(),
        "atomic_replace_file must refuse to overwrite read-only file"
    );

    // Restore write permission for cleanup
    #[allow(clippy::permissions_set_readonly_false)]
    {
        perms.set_readonly(false);
        let _ = fs::set_permissions(&ro_path, perms);
    }

    // 2. Normal writable file succeeds with atomic_replace_file and read_file_bounded
    let normal_path = tmp_dir.join("normal.xml");
    fs::write(&normal_path, b"<r/>").unwrap();
    atomic_replace_file(&normal_path, b"<r>updated</r>\n").unwrap();
    let read_back = read_file_bounded(&normal_path, 1024).unwrap();
    assert_eq!(read_back, b"<r>updated</r>\n");

    // 3. Directory passed to read_file_bounded or atomic_replace_file is rejected
    assert!(read_file_bounded(&tmp_dir, 1024).is_err());
    assert!(atomic_replace_file(&tmp_dir, b"<r/>").is_err());

    // 4. Symlink test (if OS/privilege allows creating symlinks)
    let link_path = tmp_dir.join("symlink.xml");
    let symlink_created = {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&normal_path, &link_path).is_ok()
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_file(&normal_path, &link_path).is_ok()
        }
        #[cfg(not(any(unix, windows)))]
        {
            false
        }
    };
    if symlink_created {
        assert!(
            read_file_bounded(&link_path, 1024).is_err(),
            "read_file_bounded must reject symlink targets"
        );
        assert!(
            atomic_replace_file(&link_path, b"<r/>").is_err(),
            "atomic_replace_file must reject symlink targets"
        );
    }

    let _ = fs::remove_dir_all(&tmp_dir);
}
