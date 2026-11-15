# Security Policy

## Supported Versions

Security updates and fixes are provided for the latest release on the active minor branch:

| Version | Supported |
| :--- | :--- |
| `0.1.x` | Yes |
| `< 0.1.0` | No |

---

## Reporting a Vulnerability (Private Disclosure)

**Please do NOT file public GitHub issues, pull requests, or discussions for exploitable bugs or security vulnerabilities.**

Report security vulnerabilities privately via GitHub Security Advisories:

- **Private Advisory Form**: <https://github.com/Xpt0xZv/svol/security/advisories/new>

When submitting a report, please include:

- The affected `svol` version and target platform/architecture.
- A clear description of the vulnerability and its potential security impact (e.g., crash/panic, DoS/OOM, XML parser bypass, filesystem/TOCTOU issue, LSP framing issue, or supply-chain concern).
- Minimal reproduction steps or a proof-of-concept input (XML payload, CLI invocation, or LSP JSON-RPC frame).

### Response & Disclosure Expectations

- **Acknowledgment**: We aim to acknowledge new advisory reports within **72 hours** (3 business days).
- **Triage & Updates**: We will assess severity, reproduce the issue, and provide status updates as a fix is developed and verified.
- **Coordinated Disclosure**: Please keep details confidential until a patched release and advisory are published. Reporters may request credit in the published advisory or remain anonymous.

---

## Architectural Security Invariants

`svol` is designed to process untrusted XML documents, directory trees, and LSP JSON-RPC streams safely. The following invariants are enforced in the live codebase and verified by automated CI and adversarial security tests (`tests/security_adversarial.rs`):

### 1. Supply-Chain & Zero-Dependency Policy
- **Zero External Rust Crates**: `Cargo.toml` declares an empty `[dependencies]` section; `svol` compiles exclusively against the Rust standard library (`std`). `cargo tree --locked --edges normal,build,dev --prefix none` must list only `svol`.
- **Zero External Python Dependencies**: `pyproject.toml` declares `dependencies = []` and packages only the stripped native binary (`maturin` with `locked = true`, `strip = true`).
- **No `build.rs` Scripts**: Build scripts (`build.rs`) are strictly forbidden anywhere in the repository and enforced by CI.

### 2. Compile-Time `unsafe` Isolation
- `#![forbid(unsafe_code)]` is enforced in `src/main.rs` (CLI & directory walker), `src/error.rs` (diagnostics, JSON serialization, terminal sanitization, UTF-16 mapping), and `src/lsp.rs` (LSP framing & server).
- `#![deny(unsafe_op_in_unsafe_fn)]` is enforced at the crate root (`src/lib.rs`).
- Audited `unsafe` code is confined solely to the SIMD byte-scanning fast paths in `src/lexer.rs` (`skip_xml_text_bytes_avx2` / `skip_xml_attr_bytes_avx2` gated by runtime `is_x86_feature_detected!("avx2")` on `x86_64`, and `skip_xml_text_bytes_neon` / `skip_xml_attr_bytes_neon` on baseline `aarch64`), each documented with explicit `// SAFETY:` invariants and backed by a pure-safe portable SWAR fallback (`skip_xml_text_bytes_swar` / `skip_xml_attr_bytes_swar`).

### 3. Non-Recursive Streaming Engine & Hard Resource Caps (`CWE-674` / `CWE-400` / `CWE-407`)
- **Explicit Heap Stack**: `StreamingEngine` (`src/lexer.rs`) processes XML in a single linear pass with zero call-stack recursion, bounding element nesting depth to `MAX_DEPTH = 512` (clamped from `Config::max_depth`).
- **Bounded Buffers & Diagnostics**: Default hard caps in `src/lib.rs` clamp `Config` ceilings at:
  - `DEFAULT_MAX_INPUT_BYTES = 100 MiB` (`100 * 1024 * 1024` bytes)
  - `DEFAULT_MAX_OUTPUT_BYTES = 256 MiB` (`256 * 1024 * 1024` bytes, enforced via `BoundedVecRefSink` with `try_reserve_exact` so formatted output capacity never exceeds the limit)
  - `MAX_LINT_DIAGNOSTICS = 50` diagnostics per document
- **HashDoS Resistance**: Attribute and expanded-namespace uniqueness checks use a 3-tier `KeySet` (`Vec` up to 8 keys, ASLR-seeded `FxBuildHasher` for `9..=64` keys, and `std::collections::hash_map::RandomState` SipHash-1-3 above 64 keys).

### 4. XXE, Billion Laughs & Malicious Character Rejection (`CWE-611` / `CWE-776` / `CWE-20`)
- **XXE Rejection**: External `SYSTEM`/`PUBLIC` DTD subsets, external entities, and parameter entities (`%pe;`) are unconditionally rejected (`E011_EXTERNAL_ENTITY_DISALLOWED`).
- **Billion Laughs / Entity Expansion Protection**: Custom entity expansion in content and attributes is disallowed (`E012_CUSTOM_ENTITY_DISALLOWED`); only the five XML 1.0 predefined entities (`&lt;`, `&gt;`, `&amp;`, `&apos;`, `&quot;`) and validated numeric character references are permitted.
- **Strict DOCTYPE Mode**: `--strict` / `--disallow-doctype` rejects all `<!DOCTYPE>` declarations (`E009_DISALLOWED_DOCTYPE`).
- **Hardened Character Production**: Rejects `NUL`, C0 controls (except `\t`, `\n`, `\r`), `DEL` (`0x7F`), C1 controls (`0x80..=0x9F`), and UTF-16 surrogates (`E017_INVALID_CHAR` / `E018_INVALID_CHAR_REF`).

### 5. Filesystem Symlink, Special-File & TOCTOU Protection (`CWE-59` / `CWE-367`)
- **`read_file_bounded` (`src/lib.rs`)**: Inspects `fs::symlink_metadata` to reject symlinks, FIFOs, sockets, devices, and directories before opening; re-validates `file.metadata().is_file()` on the opened descriptor; rejects oversized files; and bounds reads with `.take(max_bytes + 1)`.
- **`atomic_replace_file` (`src/lib.rs`)**: Rejects symlinks, non-regular files, and read-only targets via `fs::symlink_metadata`; creates an exclusive sibling temporary file using `File::options().write(true).create_new(true)`; calls `sync_all()`; preserves permissions; and atomically renames over the target.
- **Bounded Non-Recursive Walker (`src/main.rs`)**: Uses an explicit stack bounded by `MAX_WALK_DEPTH = 64` and `MAX_DISCOVERED_FILES = 100_000`, refuses symlinks and non-regular files, skips VCS/build directories (`.git`, `.hg`, `.svn`, `target`, `node_modules`, `.idea`, `.vscode`), deduplicates canonical paths, and caps worker threads (`1..=64`). `stdin` reads are similarly bounded via `.take(max_bytes + 1)`.

### 6. LSP Framing & UTF-16 Surrogate Safety (`CWE-444` / `CWE-400` / `CWE-125`)
- **Hardened Framing (`src/lsp.rs`)**: `read_lsp_frame` enforces `MAX_LSP_MESSAGE_BYTES = 64 MiB` (`64 * 1024 * 1024` bytes), `MAX_LSP_HEADERS = 16`, and `MAX_LSP_HEADER_LINE_BYTES = 1024`; rejects duplicate `Content-Length` and any `Transfer-Encoding` header; caps initial payload allocation at `64 KiB`; and streams bodies in `16 KiB` chunks to prevent pre-allocation OOM.
- **Document & UTF-16 Safety**: `LspServer` limits open documents to `MAX_OPEN_DOCUMENTS = 1024`, enforces the `100 MiB` `DEFAULT_MAX_INPUT_BYTES` (or smaller configured) document cap across `didOpen`, `didChange`, and `didSave` (evicting oversized documents), and validates incremental edits via `utf16_position_to_byte_offset` so out-of-bounds or mid-surrogate-pair UTF-16 coordinates never panic or corrupt UTF-8 buffers.

### 7. Terminal ANSI & Trojan Source BiDi Sanitization (`CWE-150` / `CWE-451`)
- `sanitize_for_terminal` (`src/error.rs`) replaces C0 control bytes (`<= 0x1F`), `DEL` (`0x7F`), C1 controls (`0x80..=0x9F`), BiDi overrides/isolates/marks (`U+061C`, `U+200B..=U+200F`, `U+202A..=U+202E`, `U+2066..=U+2069`), and `U+FEFF` 1-for-1 with `U+FFFD` at `XmlError` construction and terminal `Display` rendering.
- `push_json_escaped` escapes control, `DEL`, C1, BiDi, and zero-width characters in JSON diagnostics.

### 8. Release Provenance & OIDC Supply-Chain Security
- CI and release workflows (`.github/workflows/ci.yml`, `.github/workflows/release.yml`) enforce top-level `permissions: {}` default-deny, `persist-credentials: false` on every checkout, and 40-character immutable commit SHA pinning for all GitHub Actions.
- Release archives and `SHA256SUMS` receive SLSA build provenance attestations via `actions/attest-build-provenance`.
- Package publishing to PyPI (`pypa/gh-action-pypi-publish` with `attestations: true`) and `crates.io` (`rust-lang/crates-io-auth-action`) uses secretless OIDC Trusted Publishing restricted to protected `pypi` and `crates-io` GitHub environments.
