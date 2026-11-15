## Summary & Motivation

<!-- Describe what this pull request changes and why. Reference any related issue numbers (e.g., Fixes #123). -->

## Module Changes

<!-- Check all areas modified by this PR and briefly summarize key changes per module. -->

- [ ] `src/lexer.rs` — Core single-pass streaming XML 1.0 + Namespaces lexer / SIMD byte scanners
- [ ] `src/lib.rs` — Public library API, formatter, `BoundedVecRefSink`, or safe filesystem I/O
- [ ] `src/error.rs` — Diagnostic error codes (`E001`–`E035`), JSON serializer, terminal sanitizer, or UTF-16 offset mapping
- [ ] `src/lsp.rs` — Language Server (`Content-Length` framing, document store, diagnostics, formatting)
- [ ] `src/main.rs` — CLI argument parser, bounded non-recursive directory walker, or worker pool
- [ ] `tests/` — Unit, CLI/LSP integration (`tests/cli_and_lsp_integration.rs`), or adversarial security tests (`tests/security_adversarial.rs`)
- [ ] `.github/` / Manifests / Docs — Workflows, `Cargo.toml`, `pyproject.toml`, `README.md`, `SECURITY.md`, `CONTRIBUTING.md`

## Verification Checklist

<!-- Confirm all verification commands pass locally with zero warnings before requesting review. -->

- [ ] `cargo fmt --all -- --check` exits `0`
- [ ] `cargo clippy --locked --all-targets -- -D warnings` exits `0` with zero warnings
- [ ] `cargo test --locked` passes all unit, integration, adversarial security, and doc-tests
- [ ] MSRV `1.79.0` compatibility verified (`cargo +1.79.0 test --locked --all-targets`)

## Security & Supply-Chain Invariants

<!-- All pull requests must preserve svol's architectural and supply-chain security invariants (see SECURITY.md and CONTRIBUTING.md). -->

- [ ] **Zero External Crates**: `cargo tree --locked --edges normal,build,dev --prefix none` outputs exclusively `svol v<version>` (`Cargo.toml` has zero runtime, build, or dev dependencies; `pyproject.toml` keeps `dependencies = []`).
- [ ] **No `build.rs`**: No `build.rs` script is introduced anywhere in the repository.
- [ ] **Compile-Time `unsafe` Isolation & Miri Check**:
  - `#![forbid(unsafe_code)]` remains intact in `src/main.rs`, `src/error.rs`, and `src/lsp.rs`.
  - `#![deny(unsafe_op_in_unsafe_fn)]` remains intact in `src/lib.rs`.
  - Any `unsafe` in `src/lexer.rs` is restricted to audited SIMD fast paths with explicit `// SAFETY:` comments, portable safe SWAR fallback parity, and clean execution under Miri (`MIRIFLAGS="-Zmiri-strict-provenance" cargo +nightly miri test --locked --lib --bins --test security_adversarial`).
- [ ] **Resource & Parser Caps Preserved**: Non-recursive `StreamingEngine` (`MAX_DEPTH = 512`), `DEFAULT_MAX_INPUT_BYTES = 100 MiB`, `DEFAULT_MAX_OUTPUT_BYTES = 256 MiB`, `MAX_LINT_DIAGNOSTICS = 50`, `MAX_WALK_DEPTH = 64`, `MAX_DISCOVERED_FILES = 100_000`, `MAX_LSP_MESSAGE_BYTES = 64 MiB`, and `MAX_OPEN_DOCUMENTS = 1024` are maintained.
