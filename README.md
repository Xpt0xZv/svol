# svol

A zero-dependency, single-pass streaming **XML 1.0 (Fifth Edition)** and **Namespaces in XML 1.0** linter, formatter, and Language Server Protocol (LSP) server written in pure Rust (`std` only).

---

## Overview & Guarantees

- **Zero External Dependencies**: Compiled exclusively against the Rust standard library (`std`). No third-party crates, no Python runtime dependencies, and no dynamic system library requirements.
- **Single-Pass, Non-Recursive Engine**: Validates and formats UTF-8 XML streams in a single linear pass without constructing a DOM tree or using call-stack recursion. All state stacks live on the heap with bounded depth.
- **SIMD-Accelerated Byte Scanning**: Fast-path scanning of XML text and attribute values (`skip_xml_text_bytes`, `skip_xml_attr_bytes`) using:
  - **AVX2** (`x86_64`, selected via runtime `is_x86_feature_detected!("avx2")`)
  - **NEON** (`aarch64` baseline)
  - **SWAR** (64-bit word-at-a-time fallback on all other targets)
- **Strict Standards Validation**: Enforces XML 1.0 (Fifth Edition) and Namespaces in XML 1.0 well-formedness—including UTF-8/BOM gating, XML declaration attribute ordering, expanded `{namespaceURI}localName` attribute uniqueness, prefix scoping, valid character/entity references, `xml:space="preserve"` preservation during formatting, and `]]>` rejection in text.
- **Security Hardening**:
  - **XXE & External Entity Rejection**: Disallows `SYSTEM`/`PUBLIC` external entities and parameter entities (`E011_EXTERNAL_ENTITY_DISALLOWED`).
  - **Billion Laughs / Entity Expansion Protection**: Disallows custom entity references in content and attributes (`E012_CUSTOM_ENTITY_DISALLOWED`); only the five XML predefined entities (`&lt;`, `&gt;`, `&amp;`, `&apos;`, `&quot;`) and valid numeric character references are accepted. Optional `--strict` / `--disallow-doctype` mode rejects all `<!DOCTYPE>` declarations (`E009_DISALLOWED_DOCTYPE`).
  - **Symlink & TOCTOU Protection (`CWE-59` / `CWE-367`)**: Both bounded file reads (`read_file_bounded`), directory traversal, and atomic in-place writes (`atomic_replace_file`) inspect `symlink_metadata` and file handles to refuse symlinks, FIFOs, sockets, devices, directories, and read-only targets. Atomic writes use `File::options().create_new(true)` sibling temporary files with `sync_all()` before rename.
  - **OOM & Resource Exhaustion Bounds**: Hard limits enforced across all layers—`100 MiB` default max input, `256 MiB` default max output, `512` max element nesting depth, `50` max diagnostics per document, `64` max directory walk depth, `100,000` max discovered files, `64 MiB` max LSP message payload (with 64 KiB capped initial allocation and chunked reads), `16` max LSP headers, `1024` bytes max LSP header line, and `1024` max open LSP documents. Rejects duplicate `Content-Length` and `Transfer-Encoding` headers (`CWE-444` / `CWE-400`).
  - **Terminal Escape & BiDi Sanitization (`CWE-150` / `CWE-451`)**: `sanitize_for_terminal` neutralizes ASCII control characters, `DEL`, C1 controls, BiDi override/isolate/mark characters, and zero-width spoofing characters in all emitted error messages and paths.

---

## Installation

### Python (`pip` / `uv`)

`svol` is distributed as a self-contained native binary wheel (requires Python `>=3.8`, zero Python dependencies):

```bash
pip install svol
```

Or install globally as an isolated CLI tool with `uv`:

```bash
uv tool install svol
```

### Rust (`cargo`)

Requires Rust `1.79.0` or newer:

```bash
cargo install svol
```

### Prebuilt Binaries (GitHub Releases)

Download prebuilt release archives for your platform directly from [GitHub Releases](https://github.com/Xpt0xZv/svol/releases).

---

## CLI Usage

```text
svol [SUBCOMMAND] [OPTIONS] [PATHS...]
```

If no `PATHS` are provided, or if `-` is passed as the single path, `svol` reads XML from `stdin`.

When directories are passed, `svol` runs a bounded non-recursive walker (max depth `64`, max `100,000` files, skipping `.git`, `.hg`, `.svn`, `target`, `node_modules`, `.idea`, `.vscode`) and processes files with supported XML extensions:

`xml`, `xsd`, `xsl`, `xslt`, `svg`, `plist`, `xhtml`, `csproj`, `pom`

Explicitly specified regular files on the CLI are processed regardless of extension.

### Subcommands

| Subcommand | Aliases | Behavior |
| :--- | :--- | :--- |
| `lint` | `--lint` | Validate XML 1.0 + Namespaces well-formedness (**default** mode). |
| `fmt` | `format`, `--format-xml` | Format XML and write to `stdout` (unless `--write` or `--check` is set). |
| `check` | `-c`, `--check` | Verify well-formedness and formatting without modifying files. |
| `lsp` | `--lsp` | Start the Language Server Protocol (LSP) server over `stdio`. |
| `help` | `-h`, `--help` | Print help information and exit `0`. |
| `version` | `-V`, `--version` | Print version information and exit `0`. |

> **Mode precedence**: Explicit `lsp` / `lint` takes precedence, followed by `--write` (`-w`/`-i`/`--in-place`), then `--check` (`check`/`-c`), then `fmt` (`format`/`--format-xml`), defaulting to `lint`.

### Options

| Flag | Description |
| :--- | :--- |
| `-w`, `--write`, `-i`, `--in-place` | Format files in-place using atomic file replacement. |
| `-c`, `--check` | Check if files are well-formed and already formatted. |
| `-s`, `--sort-attributes` | Sort attributes lexicographically within each tag in-stream. |
| `--strict`, `--disallow-doctype` | Reject `<!DOCTYPE>` declarations (`E009_DISALLOWED_DOCTYPE`). |
| `--indent <N>` / `--indent=<N>` | Spaces per indent level (`0..=16`, default: `2`). |
| `--tab`, `--tabs` | Use tabs instead of spaces for indentation. |
| `--line-width <N>` / `--line-width=<N>` | Maximum line width for inline leaf elements (`20..=10000`, default: `100`). |
| `--format <FMT>` / `--format=<FMT>` | Diagnostic output format: `text` (default) or `json`. |
| `--json` | Shorthand for `--format json`. |
| `-j`, `--threads <N>` / `--threads=<N>` | Worker threads for directory processing (`1..=256`, pool capped at `64`). |
| `--stdin-filepath <PATH>` | Display path label for diagnostics when reading from `stdin` (default: `<stdin>`). |
| `--` | Stop flag parsing; treat all subsequent arguments as file/directory paths. |
| `-h`, `--help` | Print help information. |
| `-V`, `--version` | Print version information. |

### Examples

```bash
# Lint all supported XML files in a directory
svol lint src/

# Lint from stdin with JSON diagnostics
cat pom.xml | svol --format json --stdin-filepath pom.xml

# Format a file to stdout with sorted attributes
svol fmt --sort-attributes config.xml

# Format all XML files in-place atomically
svol fmt --write --indent 4 assets/

# Check formatting in CI
svol check .
```

### Exit Codes

| Exit Code | Meaning |
| :--- | :--- |
| `0` | Success (all inputs well-formed, and formatted in `--check` mode; or `--help`/`--version`). |
| `1` | Validation/lint error, unformatted file in `--check` mode, I/O or symlink/walk error, or LSP server I/O failure. |
| `2` | Invalid CLI arguments or unrecognized option. |

---

## LSP Server (`svol lsp`)

`svol` includes a built-in, zero-dependency Language Server Protocol (LSP) server communicating via `Content-Length` JSON-RPC 2.0 frames over `stdin`/`stdout`.

### Supported Capabilities & Methods

- **Capabilities**: `textDocumentSync: 2` (incremental UTF-16 & full document sync) and `documentFormattingProvider: true`.
- **Lifecycle**: `initialize`, `initialized`, `shutdown`, `exit`.
- **Documents & Diagnostics**: `textDocument/didOpen`, `textDocument/didChange`, `textDocument/didSave`, `textDocument/didClose` (publishes `textDocument/publishDiagnostics` with UTF-16 line/character ranges and `E001`–`E035` error codes).
- **Formatting**: `textDocument/formatting` (honors LSP `options.tabSize` within `1..=16` and `options.insertSpaces`, plus any CLI flags such as `--sort-attributes` or `--disallow-doctype`).

### Editor Setup

Point your editor's XML language client to invoke `svol lsp`:

```json
{
  "command": "svol",
  "args": ["lsp"]
}
```

To enforce strict `DOCTYPE` rejection or sorted attributes in the editor, append flags directly:

```json
{
  "command": "svol",
  "args": ["lsp", "--sort-attributes", "--disallow-doctype"]
}
```

---

## Rust Library API

Add `svol` to your `Cargo.toml` and call the streaming engine directly via `lint_xml`, `format_xml`, and `Config`:

```rust
use svol::{format_xml, lint_xml, Config};

fn main() {
    let xml = br#"<root z="1" a="2"><child>hello</child></root>"#;

    let config = Config {
        indent_width: 2,
        sort_attributes: true,
        disallow_doctype: true,
        ..Config::default()
    };

    let diagnostics = lint_xml(xml, &config);
    assert!(diagnostics.is_empty());

    let formatted = format_xml(xml, &config).expect("valid XML");
    assert_eq!(
        std::str::from_utf8(&formatted).unwrap(),
        "<root a=\"2\" z=\"1\">\n  <child>hello</child>\n</root>\n"
    );
}
```

Additional public utilities in `svol`:

- `is_supported_xml_path(path: &Path) -> bool` — checks for supported XML family extensions (`SUPPORTED_EXTENSIONS`).
- `read_file_bounded(path: &Path, max_bytes: usize) -> Result<Vec<u8>, XmlError>` — symlink-safe, bounded regular-file reader.
- `atomic_replace_file(target: &Path, contents: &[u8]) -> std::io::Result<()>` — symlink-safe atomic file replacement.
- `svol::lsp::LspServer` / `svol::lsp::run_lsp_server` — embeddable pure-`std` LSP server.

---

## License

Dual-licensed under either of:

- **MIT License** ([LICENSE-MIT](LICENSE-MIT))
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE))

at your option.
