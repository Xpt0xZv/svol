# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-15

### Added
- Zero-dependency (`std`-only) single-pass, non-recursive XML 1.0 (Fifth Edition) + Namespaces in XML 1.0 streaming engine (`lint_xml`, `format_xml`, `Config`).
- SIMD-accelerated byte scanning for XML text and attribute values with runtime AVX2 detection on `x86_64`, baseline NEON on `aarch64`, and SWAR fallback.
- CLI (`svol`) supporting `lint`, `fmt`/`format`, `check`, and `lsp` subcommands, stdin processing (`-` or no path), multi-threaded bounded directory traversal (`-j`/`--threads`), attribute sorting (`-s`/`--sort-attributes`), strict DOCTYPE rejection (`--strict`/`--disallow-doctype`), configurable indentation/line-width, and `text`/`json` diagnostic formats.
- Built-in pure-`std` Language Server Protocol (`svol lsp`) stdio server supporting `initialize`, `initialized`, `textDocument/didOpen`, `textDocument/didChange` (incremental UTF-16 & full sync), `textDocument/didSave`, `textDocument/didClose`, `textDocument/formatting`, `shutdown`, and `exit`.
- Atomic in-place file replacement (`atomic_replace_file`) and bounded regular-file reader (`read_file_bounded`).
- Support for XML family extensions: `xml`, `xsd`, `xsl`, `xslt`, `svg`, `plist`, `xhtml`, `csproj`, `pom`.
- Rust library doc-tests and end-to-end CLI/LSP integration test suite.
- Dual licensing under `MIT OR Apache-2.0`.

### Security
- Hardened against XXE and Billion Laughs entity expansion by disallowing external/parameter entities (`E011_EXTERNAL_ENTITY_DISALLOWED`) and custom entity expansion (`E012_CUSTOM_ENTITY_DISALLOWED`), with optional strict DOCTYPE rejection (`--strict` / `--disallow-doctype`).
- Bounded resource consumption without recursion: 100 MiB default max input, 256 MiB max output, 512 max element nesting depth, 50 max diagnostics per document, 64 max directory walk depth, and 100,000 max discovered files.
- Symlink and special-file protection (`CWE-59` / `CWE-367`) in file reading, directory traversal, and atomic replacement.
- Terminal escape, control character, and BiDi override sanitization (`sanitize_for_terminal`) across all emitted diagnostics and paths (`CWE-150` / `CWE-451`).
- Hardened LSP `Content-Length` framing rejecting duplicate `Content-Length` headers, `Transfer-Encoding`, oversized headers, and upfront pre-allocation OOM (`CWE-444` / `CWE-400`).

[Unreleased]: https://github.com/Xpt0xZv/svol/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Xpt0xZv/svol/releases/tag/v0.1.0
