#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use svol::error::{push_json_escaped, sanitize_for_terminal, XmlError};
use svol::lsp::run_lsp_server;
use svol::{
    atomic_replace_file, format_xml, format_xml_with_scratch, is_supported_xml_path, lint_xml,
    lint_xml_with_scratch, read_file_bounded_into, Config, EngineScratch, DEFAULT_INDENT_WIDTH,
    DEFAULT_LINE_WIDTH, DEFAULT_MAX_INPUT_BYTES, SUPPORTED_EXTENSIONS,
};

/// Maximum directory recursion depth for the non-recursive directory walker.
const MAX_WALK_DEPTH: usize = 64;

/// Maximum number of files collected in a single invocation.
const MAX_DISCOVERED_FILES: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Lint,
    FormatStdout,
    FormatWrite,
    FormatCheck,
    Lsp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone)]
struct CliOptions {
    mode: Mode,
    output_format: OutputFormat,
    config: Config,
    threads: usize,
    paths: Vec<PathBuf>,
    stdin_filepath: Option<String>,
}

impl Default for CliOptions {
    fn default() -> Self {
        let default_threads = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .clamp(1, 64);
        Self {
            mode: Mode::Lint,
            output_format: OutputFormat::Text,
            config: Config::default(),
            threads: default_threads,
            paths: Vec::new(),
            stdin_filepath: None,
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let opts = match parse_cli_args(&args) {
        Ok(Some(opts)) => opts,
        Ok(None) => return ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("svol: error: {}", sanitize_for_terminal(&msg));
            eprintln!("Run 'svol --help' for usage information.");
            return ExitCode::from(2);
        }
    };

    if opts.mode == Mode::Lsp {
        if let Err(err) = run_lsp_server(&opts.config) {
            eprintln!(
                "svol lsp error: {}",
                sanitize_for_terminal(&err.to_string())
            );
            return ExitCode::from(1);
        }
        return ExitCode::SUCCESS;
    }

    // Stdin mode if no paths provided or single "-" path provided
    if opts.paths.is_empty() || (opts.paths.len() == 1 && opts.paths[0].as_os_str() == "-") {
        return run_stdin(&opts);
    }

    // Discover & deduplicate target files using bounded non-recursive walker
    let (files, walk_errors) = discover_and_deduplicate_files(&opts.paths);
    let mut had_error = !walk_errors.is_empty();
    for err in &walk_errors {
        eprintln!("svol: {}", sanitize_for_terminal(err));
    }

    if files.is_empty() {
        if had_error {
            return ExitCode::from(1);
        }
        return ExitCode::SUCCESS;
    }

    // Execute across scoped worker pool
    let results = run_worker_pool(&files, &opts);
    let stdout = io::stdout();
    let stderr = io::stderr();
    let mut out_lock = stdout.lock();
    let mut err_lock = stderr.lock();

    for res in results {
        if !res.diagnostics.is_empty() {
            had_error = true;
            emit_diagnostics(
                &mut err_lock,
                Some(&res.display_path),
                &res.diagnostics,
                opts.output_format,
            );
        }
        if res.check_failed {
            had_error = true;
            match opts.output_format {
                OutputFormat::Text => {
                    let _ = writeln!(
                        err_lock,
                        "{}: would be reformatted",
                        sanitize_for_terminal(&res.display_path)
                    );
                }
                OutputFormat::Json => {
                    let mut line = String::from("{\"file\":\"");
                    push_json_escaped(&mut line, &res.display_path);
                    line.push_str("\",\"status\":\"unformatted\"}");
                    let _ = writeln!(err_lock, "{}", line);
                }
            }
        }
        if let Some(formatted) = res.stdout_output {
            let _ = out_lock.write_all(&formatted);
        }
    }

    if had_error {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn parse_cli_args(args: &[String]) -> Result<Option<CliOptions>, String> {
    let mut opts = CliOptions::default();
    let mut i = 0;
    let mut explicit_mode: Option<Mode> = None;
    let mut write_flag = false;
    let mut check_flag = false;
    let mut fmt_subcommand = false;
    let mut positional_only = false;

    while i < args.len() {
        let arg = &args[i];
        if positional_only {
            opts.paths.push(PathBuf::from(arg));
            i += 1;
            continue;
        }
        match arg.as_str() {
            "--" => {
                positional_only = true;
            }
            "-h" | "--help" | "help" => {
                print_help();
                return Ok(None);
            }
            "-V" | "--version" | "version" => {
                println!("svol {}", env!("CARGO_PKG_VERSION"));
                return Ok(None);
            }
            "lsp" | "--lsp" => {
                explicit_mode = Some(Mode::Lsp);
            }
            "lint" | "--lint" => {
                explicit_mode = Some(Mode::Lint);
            }
            "check" => {
                check_flag = true;
            }
            "fmt" | "format" | "--format-xml" => {
                fmt_subcommand = true;
            }
            "-c" | "--check" => {
                check_flag = true;
            }
            "-w" | "--write" | "-i" | "--in-place" => {
                write_flag = true;
            }
            "-s" | "--sort-attributes" => {
                opts.config.sort_attributes = true;
            }
            "--strict" | "--disallow-doctype" => {
                opts.config.disallow_doctype = true;
            }
            "--tab" | "--tabs" => {
                opts.config.use_tabs = true;
            }
            "--json" => {
                opts.output_format = OutputFormat::Json;
            }
            "--indent" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| "missing value for '--indent'".to_string())?;
                let width = val
                    .parse::<usize>()
                    .map_err(|_| format!("invalid indent width '{}'", val))?;
                if width > 16 {
                    return Err("indent width must be between 0 and 16".to_string());
                }
                opts.config.indent_width = width;
            }
            "--line-width" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| "missing value for '--line-width'".to_string())?;
                let width = val
                    .parse::<usize>()
                    .map_err(|_| format!("invalid line width '{}'", val))?;
                if !(20..=10_000).contains(&width) {
                    return Err("line width must be between 20 and 10000".to_string());
                }
                opts.config.line_width = width;
            }
            "--format" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| "missing value for '--format'".to_string())?;
                match val.as_str() {
                    "text" => opts.output_format = OutputFormat::Text,
                    "json" => opts.output_format = OutputFormat::Json,
                    other => {
                        return Err(format!(
                            "unsupported output format '{}'; expected 'text' or 'json'",
                            other
                        ))
                    }
                }
            }
            "-j" | "--threads" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| "missing value for '--threads'".to_string())?;
                let threads = val
                    .parse::<usize>()
                    .map_err(|_| format!("invalid thread count '{}'", val))?;
                if threads == 0 || threads > 256 {
                    return Err("thread count must be between 1 and 256".to_string());
                }
                opts.threads = threads;
            }
            "--stdin-filepath" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| "missing value for '--stdin-filepath'".to_string())?;
                opts.stdin_filepath = Some(val.clone());
            }
            _ if arg.starts_with("--indent=") => {
                let val = &arg["--indent=".len()..];
                let width = val
                    .parse::<usize>()
                    .map_err(|_| format!("invalid indent width '{}'", val))?;
                if width > 16 {
                    return Err("indent width must be between 0 and 16".to_string());
                }
                opts.config.indent_width = width;
            }
            _ if arg.starts_with("--line-width=") => {
                let val = &arg["--line-width=".len()..];
                let width = val
                    .parse::<usize>()
                    .map_err(|_| format!("invalid line width '{}'", val))?;
                if !(20..=10_000).contains(&width) {
                    return Err("line width must be between 20 and 10000".to_string());
                }
                opts.config.line_width = width;
            }
            _ if arg.starts_with("--format=") => {
                let val = &arg["--format=".len()..];
                match val {
                    "text" => opts.output_format = OutputFormat::Text,
                    "json" => opts.output_format = OutputFormat::Json,
                    other => {
                        return Err(format!(
                            "unsupported output format '{}'; expected 'text' or 'json'",
                            other
                        ))
                    }
                }
            }
            _ if arg.starts_with("--threads=") => {
                let val = &arg["--threads=".len()..];
                let threads = val
                    .parse::<usize>()
                    .map_err(|_| format!("invalid thread count '{}'", val))?;
                if threads == 0 || threads > 256 {
                    return Err("thread count must be between 1 and 256".to_string());
                }
                opts.threads = threads;
            }
            _ if arg.starts_with('-') && arg != "-" => {
                return Err(format!("unrecognized option '{}'", arg));
            }
            _ => {
                opts.paths.push(PathBuf::from(arg));
            }
        }
        i += 1;
    }

    opts.mode = if let Some(m) = explicit_mode {
        m
    } else if write_flag {
        Mode::FormatWrite
    } else if check_flag {
        Mode::FormatCheck
    } else if fmt_subcommand {
        Mode::FormatStdout
    } else {
        Mode::Lint
    };

    Ok(Some(opts))
}

fn print_help() {
    println!(
        "\
svol {version}
Single-pass streaming XML 1.0 (Fifth Edition) + Namespaces in XML 1.0 linter, formatter, and LSP

USAGE:
    svol [SUBCOMMAND] [OPTIONS] [PATHS...]

SUBCOMMANDS:
    lint                    Validate XML 1.0 + Namespaces well-formedness (default)
    fmt, format             Format XML streams (writes to stdout unless --write is set)
    check                   Verify XML well-formedness and formatting without modifying files
    lsp                     Start the Language Server Protocol (LSP) server over stdio

OPTIONS:
    -w, --write             Format files in-place using atomic file replacement
    -c, --check             Check if files are formatted and well-formed
    -s, --sort-attributes   Sort attributes lexicographically within each tag in-stream
        --strict            Reject <!DOCTYPE> declarations (--disallow-doctype)
        --disallow-doctype  Reject <!DOCTYPE> declarations
        --indent <N>        Number of spaces per indent level (default: {indent})
        --tab               Use tabs instead of spaces for indentation
        --line-width <N>    Maximum line width for inline leaf elements (default: {width})
        --format <FMT>      Diagnostic output format: 'text' (default) or 'json'
    -j, --threads <N>       Number of worker threads for directory traversal
        --stdin-filepath <P> File path label when reading from stdin
    -h, --help              Print help information
    -V, --version           Print version information

SUPPORTED EXTENSIONS:
    {exts}",
        version = env!("CARGO_PKG_VERSION"),
        indent = DEFAULT_INDENT_WIDTH,
        width = DEFAULT_LINE_WIDTH,
        exts = SUPPORTED_EXTENSIONS.join(", "),
    );
}

fn run_stdin(opts: &CliOptions) -> ExitCode {
    let label = opts.stdin_filepath.as_deref().unwrap_or("<stdin>");
    let max_bytes = opts.config.max_input_bytes.min(DEFAULT_MAX_INPUT_BYTES);
    let mut buf = Vec::new();
    let stdin = io::stdin();
    if let Err(err) = stdin
        .lock()
        .take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut buf)
    {
        let xml_err = XmlError::io(&err);
        let stderr = io::stderr();
        emit_diagnostics(
            &mut stderr.lock(),
            Some(label),
            &[xml_err],
            opts.output_format,
        );
        return ExitCode::from(1);
    }

    let stderr = io::stderr();
    let stdout = io::stdout();
    let mut err_lock = stderr.lock();
    let mut out_lock = stdout.lock();

    match opts.mode {
        Mode::Lint => {
            let errs = lint_xml(&buf, &opts.config);
            if !errs.is_empty() {
                emit_diagnostics(&mut err_lock, Some(label), &errs, opts.output_format);
                return ExitCode::from(1);
            }
            ExitCode::SUCCESS
        }
        Mode::FormatStdout | Mode::FormatWrite => match format_xml(&buf, &opts.config) {
            Ok(formatted) => {
                if out_lock.write_all(&formatted).is_err() {
                    return ExitCode::from(1);
                }
                ExitCode::SUCCESS
            }
            Err(errs) => {
                emit_diagnostics(&mut err_lock, Some(label), &errs, opts.output_format);
                ExitCode::from(1)
            }
        },
        Mode::FormatCheck => match format_xml(&buf, &opts.config) {
            Ok(formatted) => {
                if formatted != buf {
                    let _ = writeln!(
                        err_lock,
                        "{}: would be reformatted",
                        sanitize_for_terminal(label)
                    );
                    return ExitCode::from(1);
                }
                ExitCode::SUCCESS
            }
            Err(errs) => {
                emit_diagnostics(&mut err_lock, Some(label), &errs, opts.output_format);
                ExitCode::from(1)
            }
        },
        Mode::Lsp => ExitCode::SUCCESS,
    }
}

/// Bounded non-recursive directory walker and canonical path deduplicator.
fn discover_and_deduplicate_files(roots: &[PathBuf]) -> (Vec<PathBuf>, Vec<String>) {
    let mut discovered = Vec::new();
    let mut seen = HashSet::new();
    let mut errors = Vec::new();
    let need_dedup = roots.len() > 1;

    for root in roots {
        let meta = match fs::symlink_metadata(root) {
            Ok(m) => m,
            Err(e) => {
                errors.push(format!("{}: {}", root.display(), e));
                continue;
            }
        };

        if meta.file_type().is_symlink() {
            errors.push(format!(
                "{}: refusing to follow symlink target passed on CLI",
                root.display()
            ));
            continue;
        }

        if meta.is_file() {
            // Explicitly specified regular file on CLI is accepted regardless of extension
            try_insert_unique_file(root.clone(), &mut seen, &mut discovered, need_dedup);
            continue;
        }

        if !meta.is_dir() {
            errors.push(format!(
                "{}: refusing to process non-regular file (FIFO, socket, or device)",
                root.display()
            ));
            continue;
        }

        // Explicit stack for bounded non-recursive directory walk
        let mut stack: Vec<(PathBuf, usize)> = vec![(root.clone(), 0)];
        while let Some((dir, depth)) = stack.pop() {
            if depth > MAX_WALK_DEPTH {
                errors.push(format!(
                    "{}: maximum directory traversal depth ({}) exceeded",
                    dir.display(),
                    MAX_WALK_DEPTH
                ));
                continue;
            }

            let read_dir = match fs::read_dir(&dir) {
                Ok(rd) => rd,
                Err(e) => {
                    errors.push(format!("{}: {}", dir.display(), e));
                    continue;
                }
            };

            let mut entries: Vec<(PathBuf, bool)> = Vec::new();
            for entry_res in read_dir {
                let entry = match entry_res {
                    Ok(e) => e,
                    Err(e) => {
                        errors.push(format!("{}: {}", dir.display(), e));
                        continue;
                    }
                };
                let ft = match entry.file_type() {
                    Ok(ft) => ft,
                    Err(e) => {
                        errors.push(format!("{}: {}", entry.path().display(), e));
                        continue;
                    }
                };
                if ft.is_symlink() {
                    continue;
                }
                let file_name = entry.file_name();
                if ft.is_dir() {
                    if !should_skip_dir_name(&file_name) {
                        entries.push((entry.path(), true));
                    }
                } else if ft.is_file() && is_supported_xml_path(Path::new(&file_name)) {
                    entries.push((entry.path(), false));
                }
            }
            // Sort descending so LIFO stack visits entries in deterministic ascending order
            entries.sort_unstable_by(|(a, _), (b, _)| b.cmp(a));

            for (path, is_dir) in entries {
                if discovered.len() >= MAX_DISCOVERED_FILES {
                    errors.push(format!(
                        "maximum discovered file limit ({}) reached",
                        MAX_DISCOVERED_FILES
                    ));
                    return (discovered, errors);
                }

                if is_dir {
                    stack.push((path, depth + 1));
                } else {
                    try_insert_unique_file(path, &mut seen, &mut discovered, need_dedup);
                }
            }
        }
    }

    (discovered, errors)
}

fn should_skip_dir_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    matches!(
        name,
        ".git" | ".hg" | ".svn" | "target" | "node_modules" | ".idea" | ".vscode"
    )
}

fn try_insert_unique_file(
    path: PathBuf,
    seen: &mut HashSet<PathBuf>,
    discovered: &mut Vec<PathBuf>,
    need_dedup: bool,
) {
    if !need_dedup {
        discovered.push(path);
        return;
    }
    let key = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
    if seen.insert(key) {
        discovered.push(path);
    }
}

struct WorkerScratch {
    input_buf: Vec<u8>,
    engine: EngineScratch,
}

impl WorkerScratch {
    fn new() -> Self {
        Self {
            input_buf: Vec::new(),
            engine: EngineScratch::new(),
        }
    }
}

struct FileProcessResult {
    display_path: String,
    diagnostics: Vec<XmlError>,
    check_failed: bool,
    stdout_output: Option<Vec<u8>>,
}

/// Runs `process_single_file` across a bounded `std::thread::scope` worker pool.
fn run_worker_pool(files: &[PathBuf], opts: &CliOptions) -> Vec<FileProcessResult> {
    if files.len() == 1 || opts.threads <= 1 {
        let mut scratch = WorkerScratch::new();
        return files
            .iter()
            .map(|p| process_single_file(p, opts, &mut scratch))
            .collect();
    }

    let worker_count = opts.threads.min(files.len()).clamp(1, 64);
    let next_idx = AtomicUsize::new(0);

    let mut worker_outputs: Vec<Vec<(usize, FileProcessResult)>> = Vec::with_capacity(worker_count);

    thread::scope(|s| {
        let mut handles = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let next_ref = &next_idx;
            handles.push(s.spawn(move || {
                let mut local = Vec::new();
                let mut scratch = WorkerScratch::new();
                loop {
                    let idx = next_ref.fetch_add(1, Ordering::Relaxed);
                    if idx >= files.len() {
                        break;
                    }
                    let res = process_single_file(&files[idx], opts, &mut scratch);
                    local.push((idx, res));
                }
                local
            }));
        }
        for h in handles {
            if let Ok(local) = h.join() {
                worker_outputs.push(local);
            }
        }
    });

    let mut indexed: Vec<(usize, FileProcessResult)> =
        worker_outputs.into_iter().flatten().collect();
    indexed.sort_unstable_by_key(|(idx, _)| *idx);
    indexed.into_iter().map(|(_, r)| r).collect()
}

fn process_single_file(
    path: &Path,
    opts: &CliOptions,
    scratch: &mut WorkerScratch,
) -> FileProcessResult {
    let display_path = path.to_string_lossy().into_owned();
    let max_in = opts.config.max_input_bytes.min(DEFAULT_MAX_INPUT_BYTES);

    if let Err(err) = read_file_bounded_into(path, max_in, &mut scratch.input_buf) {
        return FileProcessResult {
            display_path,
            diagnostics: vec![err],
            check_failed: false,
            stdout_output: None,
        };
    }

    match opts.mode {
        Mode::Lint => {
            let diagnostics =
                lint_xml_with_scratch(&scratch.input_buf, &opts.config, &mut scratch.engine);
            FileProcessResult {
                display_path,
                diagnostics,
                check_failed: false,
                stdout_output: None,
            }
        }
        Mode::FormatStdout => {
            match format_xml_with_scratch(&scratch.input_buf, &opts.config, &mut scratch.engine) {
                Ok(formatted) => FileProcessResult {
                    display_path,
                    diagnostics: Vec::new(),
                    check_failed: false,
                    stdout_output: Some(formatted.to_vec()),
                },
                Err(diagnostics) => FileProcessResult {
                    display_path,
                    diagnostics,
                    check_failed: false,
                    stdout_output: None,
                },
            }
        }
        Mode::FormatCheck => {
            match format_xml_with_scratch(&scratch.input_buf, &opts.config, &mut scratch.engine) {
                Ok(formatted) => FileProcessResult {
                    display_path,
                    diagnostics: Vec::new(),
                    check_failed: formatted != scratch.input_buf.as_slice(),
                    stdout_output: None,
                },
                Err(diagnostics) => FileProcessResult {
                    display_path,
                    diagnostics,
                    check_failed: false,
                    stdout_output: None,
                },
            }
        }
        Mode::FormatWrite => {
            match format_xml_with_scratch(&scratch.input_buf, &opts.config, &mut scratch.engine) {
                Ok(formatted) => {
                    if formatted != scratch.input_buf.as_slice() {
                        if let Err(io_err) = atomic_replace_file(path, formatted) {
                            return FileProcessResult {
                                display_path,
                                diagnostics: vec![XmlError::io(&io_err)],
                                check_failed: false,
                                stdout_output: None,
                            };
                        }
                    }
                    FileProcessResult {
                        display_path,
                        diagnostics: Vec::new(),
                        check_failed: false,
                        stdout_output: None,
                    }
                }
                Err(diagnostics) => FileProcessResult {
                    display_path,
                    diagnostics,
                    check_failed: false,
                    stdout_output: None,
                },
            }
        }
        Mode::Lsp => FileProcessResult {
            display_path,
            diagnostics: Vec::new(),
            check_failed: false,
            stdout_output: None,
        },
    }
}

fn emit_diagnostics<W: Write>(
    writer: &mut W,
    file_path: Option<&str>,
    diagnostics: &[XmlError],
    format: OutputFormat,
) {
    let safe_path = file_path.map(sanitize_for_terminal);
    for diag in diagnostics {
        match format {
            OutputFormat::Text => {
                if let Some(ref path) = safe_path {
                    let _ = writeln!(writer, "{}:{}", path, diag);
                } else {
                    let _ = writeln!(writer, "{}", diag);
                }
            }
            OutputFormat::Json => {
                let _ = writeln!(writer, "{}", diag.to_json(file_path));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_flag_parser() {
        let args = vec![
            "fmt".to_string(),
            "--write".to_string(),
            "--sort-attributes".to_string(),
            "--strict".to_string(),
            "--indent".to_string(),
            "4".to_string(),
            "--line-width=120".to_string(),
            "--format=json".to_string(),
            "-j".to_string(),
            "2".to_string(),
            "sample.xml".to_string(),
        ];
        let opts = parse_cli_args(&args)
            .expect("valid flags")
            .expect("not help/version");
        assert_eq!(opts.mode, Mode::FormatWrite);
        assert!(opts.config.sort_attributes);
        assert!(opts.config.disallow_doctype);
        assert_eq!(opts.config.indent_width, 4);
        assert_eq!(opts.config.line_width, 120);
        assert_eq!(opts.output_format, OutputFormat::Json);
        assert_eq!(opts.threads, 2);
        assert_eq!(opts.paths, vec![PathBuf::from("sample.xml")]);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "uses OS temp_dir, directory walker, canonicalize, and atomic_replace_file syscalls unsupported under Miri isolation"
    )]
    fn test_directory_walker_dedup_and_atomic_write() {
        let tmp_dir = env::temp_dir().join(format!("svol_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(tmp_dir.join("sub")).unwrap();

        // Create files across all 9 supported extensions + 1 unsupported extension
        for ext in SUPPORTED_EXTENSIONS {
            let p = tmp_dir.join("sub").join(format!("test.{}", ext));
            fs::write(&p, b"<root z=\"1\" a=\"2\"><child>ok</child></root>").unwrap();
        }
        fs::write(tmp_dir.join("sub").join("ignore.txt"), b"not xml").unwrap();

        let explicit_xml = tmp_dir.join("sub").join("test.xml");
        let roots = vec![tmp_dir.clone(), explicit_xml.clone(), tmp_dir.join("sub")];
        let (files, errs) = discover_and_deduplicate_files(&roots);
        assert!(errs.is_empty(), "unexpected walk errors: {:?}", errs);
        assert_eq!(
            files.len(),
            SUPPORTED_EXTENSIONS.len(),
            "all 9 XML extensions should be discovered and duplicates removed"
        );

        let opts = CliOptions {
            mode: Mode::FormatWrite,
            config: Config {
                sort_attributes: true,
                ..Default::default()
            },
            threads: 4,
            ..Default::default()
        };

        let results = run_worker_pool(&files, &opts);
        assert_eq!(results.len(), SUPPORTED_EXTENSIONS.len());
        for r in &results {
            assert!(r.diagnostics.is_empty());
        }

        let updated = fs::read_to_string(&explicit_xml).unwrap();
        assert_eq!(
            updated,
            "<root a=\"2\" z=\"1\">\n  <child>ok</child>\n</root>\n"
        );

        let _ = fs::remove_dir_all(&tmp_dir);
    }
}
