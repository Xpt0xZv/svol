use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static TEST_DIR_SEQ: AtomicUsize = AtomicUsize::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let seq = TEST_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let path =
            env::temp_dir().join(format!("svol_it_{}_{}_{}", prefix, std::process::id(), seq));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create temp test dir");
        Self { path }
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_svol")
}

fn run_svol(args: &[&str], stdin_data: Option<&[u8]>) -> Output {
    let mut cmd = Command::new(bin_path());
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());

    if stdin_data.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }

    let mut child = cmd.spawn().expect("spawn svol binary");
    if let Some(input) = stdin_data {
        let mut stdin = child.stdin.take().expect("stdin handle");
        stdin.write_all(input).expect("write stdin");
    }
    child.wait_with_output().expect("wait for svol")
}

fn write_lsp_frame<W: Write>(writer: &mut W, json_payload: &str) {
    let header = format!("Content-Length: {}\r\n\r\n", json_payload.len());
    writer
        .write_all(header.as_bytes())
        .expect("write LSP header");
    writer
        .write_all(json_payload.as_bytes())
        .expect("write LSP payload");
    writer.flush().expect("flush LSP frame");
}

fn read_lsp_frame<R: BufRead>(reader: &mut R) -> Option<String> {
    let mut content_length: Option<usize> = None;
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).expect("read LSP header line");
        if n == 0 {
            return None;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, val)) = trimmed.split_once(':') {
            if name.trim().eq_ignore_ascii_case("Content-Length") {
                content_length = Some(
                    val.trim()
                        .parse::<usize>()
                        .expect("valid Content-Length integer"),
                );
            }
        }
    }

    let len = content_length.expect("Content-Length header present");
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).expect("read LSP payload body");
    Some(String::from_utf8(buf).expect("LSP payload UTF-8"))
}

#[test]
fn test_cli_exit_codes_and_help_version() {
    let help_out = run_svol(&["--help"], None);
    assert_eq!(help_out.status.code(), Some(0));
    let help_stdout = String::from_utf8_lossy(&help_out.stdout);
    assert!(help_stdout.contains("USAGE:"));
    assert!(help_stdout.contains("svol"));

    let ver_out = run_svol(&["--version"], None);
    assert_eq!(ver_out.status.code(), Some(0));
    let ver_stdout = String::from_utf8_lossy(&ver_out.stdout);
    assert!(ver_stdout.starts_with("svol "));

    // Exit code 2 for unrecognized options or invalid flag values
    let bad_flag = run_svol(&["--definitely-not-a-flag"], None);
    assert_eq!(bad_flag.status.code(), Some(2));

    let bad_indent = run_svol(&["--indent", "99"], None);
    assert_eq!(bad_indent.status.code(), Some(2));

    let bad_fmt = run_svol(&["--format", "yaml"], None);
    assert_eq!(bad_fmt.status.code(), Some(2));
}

#[test]
fn test_cli_lint_valid_and_invalid_files() {
    let dir = TempDir::new("lint");
    let valid_path = dir.join("valid.xml");
    let invalid_path = dir.join("invalid.xml");

    fs::write(&valid_path, b"<root><item id=\"1\">ok</item></root>\n").unwrap();
    fs::write(&invalid_path, b"<root><open></wrong></root>").unwrap();

    // Default lint mode -> exit 0
    let ok_out = run_svol(&[valid_path.to_str().unwrap()], None);
    assert_eq!(ok_out.status.code(), Some(0));
    assert!(ok_out.stdout.is_empty());
    assert!(ok_out.stderr.is_empty());

    // Explicit lint subcommand -> exit 1 on ill-formed XML
    let err_out = run_svol(&["lint", invalid_path.to_str().unwrap()], None);
    assert_eq!(err_out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&err_out.stderr);
    assert!(stderr.contains("E028_MISMATCHED_CLOSING_TAG"));
}

#[test]
fn test_cli_fmt_stdout_write_check_and_sort_attributes() {
    let dir = TempDir::new("fmt");
    let xml_path = dir.join("sample.xml");
    let raw = b"<root z=\"2\" a=\"1\"><child>hello</child></root>";
    fs::write(&xml_path, raw).unwrap();
    let path_str = xml_path.to_str().unwrap();

    // 1. fmt stdout mode does not modify file
    let stdout_res = run_svol(&["fmt", "--sort-attributes", path_str], None);
    assert_eq!(stdout_res.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&stdout_res.stdout),
        "<root a=\"1\" z=\"2\">\n  <child>hello</child>\n</root>\n"
    );
    assert_eq!(fs::read(&xml_path).unwrap(), raw);

    // 2. check mode on unformatted file -> exit 1 + "would be reformatted"
    let check_fail = run_svol(&["check", path_str], None);
    assert_eq!(check_fail.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&check_fail.stderr).contains("would be reformatted"));

    // 3. fmt --write formats atomically in-place -> exit 0
    let write_res = run_svol(&["fmt", "--write", "--sort-attributes", path_str], None);
    assert_eq!(write_res.status.code(), Some(0));
    assert!(write_res.stdout.is_empty());
    assert_eq!(
        fs::read_to_string(&xml_path).unwrap(),
        "<root a=\"1\" z=\"2\">\n  <child>hello</child>\n</root>\n"
    );

    // 4. fmt --check now passes with exit 0
    let check_ok = run_svol(&["fmt", "--check", "--sort-attributes", path_str], None);
    assert_eq!(check_ok.status.code(), Some(0));
    assert!(check_ok.stderr.is_empty());
}

#[test]
fn test_cli_disallow_doctype_and_json_format() {
    let dir = TempDir::new("doctype_json");
    let doc_path = dir.join("doc.xml");
    fs::write(
        &doc_path,
        b"<!DOCTYPE note [<!ELEMENT note (#PCDATA)>]><note>hi</note>\n",
    )
    .unwrap();
    let path_str = doc_path.to_str().unwrap();

    // Safe internal DOCTYPE is allowed by default
    let default_res = run_svol(&["lint", path_str], None);
    assert_eq!(default_res.status.code(), Some(0));

    // Rejected when --disallow-doctype is enabled, with JSON diagnostics
    let strict_res = run_svol(
        &["lint", "--disallow-doctype", "--format", "json", path_str],
        None,
    );
    assert_eq!(strict_res.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&strict_res.stderr);
    let line = stderr.trim();
    assert!(line.starts_with('{') && line.ends_with('}'));
    assert!(line.contains("\"code\":\"E009_DISALLOWED_DOCTYPE\""));
    assert!(line.contains("\"severity\":\"error\""));
    assert!(line.contains("\"line\":1"));

    // Check mode with --format json on unformatted file emits JSON status
    let check_json = run_svol(&["check", "--format", "json", path_str], None);
    assert_eq!(check_json.status.code(), Some(1));
    let check_stderr = String::from_utf8_lossy(&check_json.stderr);
    assert!(check_stderr.contains("\"status\":\"unformatted\""));
}

#[test]
fn test_cli_stdin_modes_and_filepath_label() {
    // Implicit stdin (no path args) formatting
    let fmt_stdin = run_svol(
        &["fmt", "--sort-attributes"],
        Some(b"<r b=\"2\" a=\"1\"><c>x</c></r>"),
    );
    assert_eq!(fmt_stdin.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&fmt_stdin.stdout),
        "<r a=\"1\" b=\"2\">\n  <c>x</c>\n</r>\n"
    );

    // Explicit "-" stdin lint failure with --stdin-filepath and --format json
    let lint_stdin_err = run_svol(
        &[
            "lint",
            "--format",
            "json",
            "--stdin-filepath",
            "virtual/input.xml",
            "-",
        ],
        Some(b"<root><unclosed></root>"),
    );
    assert_eq!(lint_stdin_err.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&lint_stdin_err.stderr);
    assert!(stderr.contains("\"file\":\"virtual/input.xml\""));
    assert!(stderr.contains("\"code\":\"E028_MISMATCHED_CLOSING_TAG\""));

    // Check mode over stdin
    let check_stdin_fail = run_svol(&["check", "-"], Some(b"<root><child>a</child></root>"));
    assert_eq!(check_stdin_fail.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&check_stdin_fail.stderr).contains("would be reformatted"));

    let check_stdin_ok = run_svol(
        &["check", "-"],
        Some(b"<root>\n  <child>a</child>\n</root>\n"),
    );
    assert_eq!(check_stdin_ok.status.code(), Some(0));
}

#[test]
fn test_lsp_stdio_json_rpc_round_trip() {
    let mut child = Command::new(bin_path())
        .args(["lsp", "--sort-attributes"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn svol lsp");

    let mut stdin = child.stdin.take().expect("lsp stdin");
    let stdout = child.stdout.take().expect("lsp stdout");
    let mut reader = BufReader::new(stdout);

    // 1. initialize
    write_lsp_frame(
        &mut stdin,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"processId":null,"rootUri":null,"capabilities":{}}}"#,
    );
    let init_resp = read_lsp_frame(&mut reader).expect("initialize response");
    assert!(init_resp.contains(r#""id":1"#));
    assert!(init_resp.contains(r#""textDocumentSync":2"#));
    assert!(init_resp.contains(r#""documentFormattingProvider":true"#));
    assert!(init_resp.contains(r#""name":"svol""#));

    // 2. initialized notification
    write_lsp_frame(
        &mut stdin,
        r#"{"jsonrpc":"2.0","method":"initialized","params":{}}"#,
    );

    // 3. textDocument/didOpen with ill-formed XML -> publishDiagnostics with error
    let bad_uri = "file:///workspace/bad.xml";
    write_lsp_frame(
        &mut stdin,
        r#"{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":"file:///workspace/bad.xml","languageId":"xml","version":1,"text":"<root><a/></b ></root>"}}}"#,
    );
    let bad_diag = read_lsp_frame(&mut reader).expect("publishDiagnostics for bad doc");
    assert!(bad_diag.contains(r#""method":"textDocument/publishDiagnostics""#));
    assert!(bad_diag.contains(bad_uri));
    assert!(bad_diag.contains(r#""source":"svol""#));
    assert!(!bad_diag.contains(r#""diagnostics":[]"#));

    // 4. textDocument/didOpen with valid unformatted XML -> empty diagnostics
    let good_uri = "file:///workspace/good.xml";
    write_lsp_frame(
        &mut stdin,
        r#"{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":"file:///workspace/good.xml","languageId":"xml","version":1,"text":"<root z=\"2\" a=\"1\"><child>ok</child></root>"}}}"#,
    );
    let good_diag = read_lsp_frame(&mut reader).expect("publishDiagnostics for good doc");
    assert!(good_diag.contains(r#""method":"textDocument/publishDiagnostics""#));
    assert!(good_diag.contains(good_uri));
    assert!(good_diag.contains(r#""diagnostics":[]"#));

    // 5. textDocument/formatting -> returns single TextEdit with formatted XML
    write_lsp_frame(
        &mut stdin,
        r#"{"jsonrpc":"2.0","id":2,"method":"textDocument/formatting","params":{"textDocument":{"uri":"file:///workspace/good.xml"},"options":{"tabSize":2,"insertSpaces":true}}}"#,
    );
    let fmt_resp = read_lsp_frame(&mut reader).expect("formatting response");
    assert!(fmt_resp.contains(r#""id":2"#));
    assert!(
        fmt_resp.contains(r#""newText":"<root a=\"1\" z=\"2\">\n  <child>ok</child>\n</root>\n""#)
    );

    // 5b. textDocument/didOpen with already-formatted XML -> formatting returns result:[]
    write_lsp_frame(
        &mut stdin,
        r#"{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":"file:///workspace/clean.xml","languageId":"xml","version":1,"text":"<root>\n  <child>ok</child>\n</root>\n"}}}"#,
    );
    let clean_diag = read_lsp_frame(&mut reader).expect("publishDiagnostics for clean doc");
    assert!(clean_diag.contains(r#""diagnostics":[]"#));

    write_lsp_frame(
        &mut stdin,
        r#"{"jsonrpc":"2.0","id":22,"method":"textDocument/formatting","params":{"textDocument":{"uri":"file:///workspace/clean.xml"},"options":{"tabSize":2,"insertSpaces":true}}}"#,
    );
    let clean_fmt_resp = read_lsp_frame(&mut reader).expect("formatting response for clean doc");
    assert!(clean_fmt_resp.contains(r#"{"jsonrpc":"2.0","id":22,"result":[]}"#));

    // 6. shutdown
    write_lsp_frame(
        &mut stdin,
        r#"{"jsonrpc":"2.0","id":3,"method":"shutdown"}"#,
    );
    let shutdown_resp = read_lsp_frame(&mut reader).expect("shutdown response");
    assert!(shutdown_resp.contains(r#""id":3"#));
    assert!(shutdown_resp.contains(r#""result":null"#));

    // 7. exit
    write_lsp_frame(&mut stdin, r#"{"jsonrpc":"2.0","method":"exit"}"#);
    drop(stdin);

    let status = child.wait().expect("wait for lsp exit");
    assert_eq!(status.code(), Some(0));
}

#[test]
fn test_cli_fmt_write_skips_already_formatted_and_single_root_walk() {
    let dir = TempDir::new("fmt_noop_walk");
    let clean_path = dir.join("clean.xml");
    fs::write(&clean_path, b"<root>\n  <child>ok</child>\n</root>\n").unwrap();

    // Make clean.xml read-only: if fmt --write attempted atomic_replace_file, it would fail with PermissionDenied
    let mut perms = fs::metadata(&clean_path).unwrap().permissions();
    perms.set_readonly(true);
    fs::set_permissions(&clean_path, perms.clone()).unwrap();

    let res = run_svol(&["fmt", "--write", clean_path.to_str().unwrap()], None);
    assert_eq!(
        res.status.code(),
        Some(0),
        "fmt --write on already-formatted read-only file must skip rewrite: stderr={}",
        String::from_utf8_lossy(&res.stderr)
    );

    // Restore write permission for TempDir cleanup
    #[allow(clippy::permissions_set_readonly_false)]
    {
        perms.set_readonly(false);
        let _ = fs::set_permissions(&clean_path, perms);
    }

    // Single-root directory walk skips .git/target and processes supported XML files
    let git_dir = dir.join(".git");
    fs::create_dir_all(&git_dir).unwrap();
    fs::write(git_dir.join("broken.xml"), b"<unclosed>").unwrap();

    let sub_dir = dir.join("sub");
    fs::create_dir_all(&sub_dir).unwrap();
    let dirty_path = sub_dir.join("dirty.xml");
    fs::write(&dirty_path, b"<r b=\"2\" a=\"1\"><c/></r>").unwrap();

    let walk_res = run_svol(
        &[
            "fmt",
            "--write",
            "--sort-attributes",
            dir.path.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(
        walk_res.status.code(),
        Some(0),
        "single-root fmt --write must ignore .git/broken.xml and format dirty.xml: stderr={}",
        String::from_utf8_lossy(&walk_res.stderr)
    );
    assert_eq!(
        fs::read_to_string(&dirty_path).unwrap(),
        "<r a=\"1\" b=\"2\">\n  <c/>\n</r>\n"
    );
}
