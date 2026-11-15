# Contributing to `svol`

Thank you for your interest in contributing to `svol`! Please review the architectural policies, coding rules, and verification steps below before opening a pull request.

---

## Development Setup

### Prerequisites
- **Rust Toolchain**: Minimum Supported Rust Version (**MSRV**) is **Rust `1.79.0`** (`edition = "2021"`). Install via [`rustup`](https://rustup.rs/) with `rustfmt` and `clippy` components:
  ```bash
  rustup toolchain install 1.79.0
  rustup component add rustfmt clippy
  ```
- **Git**: Standard Git CLI.
- **Optional (Python Wheel Builds)**: Python `>=3.8` and `maturin` (`>=1.7,<2.0`) if testing Python binary wheel packaging (`maturin build --release --locked`).

### Clone & Build
```bash
git clone https://github.com/Xpt0xZv/svol.git
cd svol
cargo test --locked
```

---

## Strict Architectural & Supply-Chain Rules

### 1. Zero External Dependencies
- **Rust**: `Cargo.toml` must remain **100% dependency-free** (`std` only—zero `[dependencies]`, `[build-dependencies]`, or `[dev-dependencies]`).
- **Python**: `pyproject.toml` must keep `dependencies = []`.
- Pull requests that introduce third-party crates or Python packages will be rejected.

### 2. No `build.rs` Allowed
- Adding a `build.rs` script anywhere in the repository is **strictly forbidden** and enforced by CI. All functionality must compile purely with standard `rustc` and `cargo`.

### 3. Compile-Time `unsafe` Isolation Rules
- **Forbidden Modules**: `src/main.rs`, `src/error.rs`, and `src/lsp.rs` enforce `#![forbid(unsafe_code)]`. `unsafe` code must never be introduced into the CLI, directory walker, diagnostics/JSON serializer, terminal sanitizer, or LSP server.
- **Crate-Wide Guard**: `src/lib.rs` enforces `#![deny(unsafe_op_in_unsafe_fn)]`.
- **SIMD Fast Paths Only**: `unsafe` is permitted only for vetted, minimal SIMD byte-scanning fast paths in `src/lexer.rs` (`x86_64` AVX2 behind `is_x86_feature_detected!("avx2")` and `aarch64` baseline NEON), with:
  - Minimal `unsafe { ... }` blocks inside `unsafe fn` definitions so code compiles cleanly on both MSRV `1.79.0` and modern Rust toolchains without `unused_unsafe` warnings.
  - Explicit `// SAFETY:` comments documenting every invariant at both `unsafe fn` call sites and `unsafe { ... }` blocks.
  - Identical behavior to the portable safe SWAR fallback (`skip_xml_text_bytes_swar` / `skip_xml_attr_bytes_swar`).
- **Miri Compatibility**: Keep core parser, XXE, namespace, UTF-16, and sanitization tests in `tests/security_adversarial.rs` runnable under Miri. Only gate tests that perform OS filesystem/symlink syscalls or 100+ MiB allocations with `#[cfg_attr(miri, ignore = "...")]`.

### 4. MSRV `1.79.0` Compatibility
- All production code and tests must compile and pass on **Rust `1.79.0`** (`cargo test --locked --all-targets`). Do not use Rust standard library APIs or language features stabilized after `1.79.0`.

---

## Commit Message Format (Conventional Commits 1.0)

`svol` follows [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/):

```text
<type>[optional scope]: <description>
```

Common types:
- `feat`: A new feature (corresponds to a MINOR version bump)
- `fix`: A bug fix (corresponds to a PATCH version bump)
- `docs`: Documentation-only changes (`README.md`, `SECURITY.md`, `CONTRIBUTING.md`, rustdoc)
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `perf`: Performance improvement
- `test`: Adding or updating tests
- `chore`: Maintenance, governance, or release preparation
- `ci`: CI/CD workflow or packaging updates

Use `!` after the type/scope (or a `BREAKING CHANGE:` footer) for breaking changes.

---

## Required Pre-PR Verification Commands

Run all of the following commands locally and confirm zero warnings and 100% passing tests before opening or updating a pull request:

```bash
# 1. Verify formatting
cargo fmt --all -- --check

# 2. Run Clippy with all warnings denied
cargo clippy --locked --all-targets -- -D warnings

# 3. Run all unit, integration, adversarial security, and doc-tests
cargo test --locked
```

Additional checks verified in CI:
```bash
# Verify zero external crates in the dependency graph
cargo tree --locked --edges normal,build,dev --prefix none

# Verify MSRV 1.79.0 compatibility (if toolchain 1.79.0 is installed)
cargo +1.79.0 test --locked --all-targets
```

---

## Reporting Security Issues

Do **not** open a public issue or PR for security vulnerabilities. Follow the private disclosure instructions in [SECURITY.md](SECURITY.md).
