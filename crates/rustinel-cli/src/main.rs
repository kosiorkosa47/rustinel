//! `cargo-rustinel` — the CLI front-end for the rustinel supply-chain scanner.
//!
//! Invoked either directly (`cargo-rustinel ...`) or via cargo's subcommand
//! mechanism (`cargo rustinel ...`). The defensive analysis lives entirely in
//! `rustinel-core`; this binary only handles argument parsing, I/O, and exit
//! codes.

#[cfg(feature = "online")]
mod registry;

use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use rustinel_core::policy;
use rustinel_core::report;
use rustinel_core::{AnalysisOptions, OutputFormat};
use std::collections::BTreeSet;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(name = "cargo-rustinel")]
#[command(about = "Defensive supply-chain risk diff for Rust projects", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Analyze one Cargo.lock and report supply-chain risk.
    Check {
        #[arg(long, default_value = "Cargo.lock")]
        lockfile: PathBuf,

        /// Path to a rustinel.toml policy file.
        #[arg(long)]
        policy: Option<PathBuf>,

        #[arg(long, value_enum, default_value_t = CliFormat::Human)]
        format: CliFormat,

        /// Write the report to a file instead of stdout.
        #[arg(long)]
        output: Option<PathBuf>,

        /// Disable network access (cached advisory data only).
        #[arg(long)]
        offline: bool,

        /// Directory of unpacked crate sources for static analysis (read-only).
        #[arg(long)]
        source_path: Option<PathBuf>,

        /// RustSec advisory database directory.
        #[arg(long)]
        advisory_db: Option<PathBuf>,

        /// Query the crates.io sparse index for yanked versions (network).
        #[arg(long)]
        online_metadata: bool,

        /// Omit the `generated_at` timestamp for byte-identical output.
        #[arg(long)]
        no_timestamp: bool,

        /// Exit non-zero when the decision is `review_required`.
        #[arg(long)]
        fail_on_review_required: bool,

        /// Append a score breakdown to the human report.
        #[arg(long)]
        explain: bool,
    },

    /// Compare two Cargo.lock files and report how risk changes.
    Diff {
        #[arg(long)]
        base_lockfile: PathBuf,
        #[arg(long)]
        head_lockfile: PathBuf,

        #[arg(long)]
        policy: Option<PathBuf>,

        #[arg(long, value_enum, default_value_t = CliFormat::Human)]
        format: CliFormat,

        #[arg(long)]
        output: Option<PathBuf>,

        #[arg(long)]
        offline: bool,

        #[arg(long)]
        source_path: Option<PathBuf>,

        #[arg(long)]
        advisory_db: Option<PathBuf>,

        #[arg(long)]
        online_metadata: bool,

        #[arg(long)]
        no_timestamp: bool,

        #[arg(long)]
        fail_on_review_required: bool,

        /// Append a score breakdown to the human report.
        #[arg(long)]
        explain: bool,
    },

    /// Policy helpers.
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },

    /// Manage the RustSec advisory database cache.
    Advisory {
        #[command(subcommand)]
        command: AdvisoryCommands,
    },

    /// Show the rustinel splash animation (no Cargo.lock required).
    Demo,

    /// Export a standards-based artifact (SBOM / OSV / VEX) for a lockfile.
    Export {
        #[arg(long, value_enum)]
        format: ExportFmt,

        #[arg(long, default_value = "Cargo.lock")]
        lockfile: PathBuf,

        #[arg(long)]
        output: Option<PathBuf>,

        #[arg(long)]
        policy: Option<PathBuf>,

        #[arg(long)]
        offline: bool,

        #[arg(long)]
        source_path: Option<PathBuf>,

        #[arg(long)]
        advisory_db: Option<PathBuf>,

        #[arg(long)]
        online_metadata: bool,

        #[arg(long)]
        no_timestamp: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ExportFmt {
    /// CycloneDX 1.5 SBOM (JSON), with embedded vulnerabilities.
    Cyclonedx,
    /// SPDX 2.3 SBOM (JSON).
    Spdx,
    /// OSV records (osv.dev schema) for matched advisories.
    Osv,
    /// OpenVEX document for matched advisories.
    Openvex,
}

impl From<ExportFmt> for rustinel_core::sbom::ExportFormat {
    fn from(value: ExportFmt) -> Self {
        use rustinel_core::sbom::ExportFormat;
        match value {
            ExportFmt::Cyclonedx => ExportFormat::CycloneDx,
            ExportFmt::Spdx => ExportFormat::Spdx,
            ExportFmt::Osv => ExportFormat::Osv,
            ExportFmt::Openvex => ExportFormat::OpenVex,
        }
    }
}

#[derive(Debug, Subcommand)]
enum AdvisoryCommands {
    /// Sync the RustSec advisory database into the local cache (requires git + network).
    Update {
        /// Override the cache directory (default: ~/.cargo/advisory-db).
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Override the advisory-db git URL.
        #[arg(long, default_value = "https://github.com/RustSec/advisory-db")]
        url: String,
    },
    /// Show the local advisory cache status (offline).
    Status {
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyCommands {
    /// Create a starter rustinel.toml.
    Init {
        #[arg(long, default_value = "balanced")]
        profile: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliFormat {
    Human,
    Json,
    Markdown,
    Sarif,
}

impl From<CliFormat> for OutputFormat {
    fn from(value: CliFormat) -> Self {
        match value {
            CliFormat::Human => OutputFormat::Human,
            CliFormat::Json => OutputFormat::Json,
            CliFormat::Markdown => OutputFormat::Markdown,
            CliFormat::Sarif => OutputFormat::Sarif,
        }
    }
}

fn load_policy(path: &Option<PathBuf>) -> anyhow::Result<Option<policy::Policy>> {
    match path {
        Some(path) => {
            let input = std::fs::read_to_string(path)
                .with_context(|| format!("reading policy {}", path.display()))?;
            Ok(Some(policy::parse_policy_toml(&input)?))
        }
        None => Ok(None),
    }
}

/// Gather yanked `name@version`s for the given lockfiles via the crates.io
/// sparse index, but only when `online_metadata` is set and we are not offline.
/// Returns an empty set otherwise (and on any parse/network failure).
fn gather_yanked(online_metadata: bool, offline: bool, lockfiles: &[&Path]) -> BTreeSet<String> {
    if !online_metadata || offline {
        return BTreeSet::new();
    }
    #[cfg(feature = "online")]
    {
        let mut yanked = BTreeSet::new();
        eprintln!("rustinel: querying crates.io sparse index for yanked versions...");
        for lf in lockfiles {
            if let Ok(lock) = rustinel_core::lockfile::parse_lockfile(lf) {
                yanked.extend(registry::fetch_yanked(&lock));
            }
        }
        yanked
    }
    #[cfg(not(feature = "online"))]
    {
        let _ = lockfiles;
        eprintln!(
            "rustinel: this binary was built without the `online` feature; \
             --online-metadata is ignored."
        );
        BTreeSet::new()
    }
}

fn timestamp(no_timestamp: bool) -> Option<String> {
    if no_timestamp {
        None
    } else {
        Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
    }
}

fn emit(rendered: &str, output: &Option<PathBuf>) -> anyhow::Result<()> {
    match output {
        Some(path) => {
            std::fs::write(path, rendered)
                .with_context(|| format!("writing output {}", path.display()))?;
        }
        None => print!("{rendered}"),
    }
    Ok(())
}

/// Resolve the lockfile to analyze. If the caller did not override the default
/// and `Cargo.lock` is not in the current directory, walk up the directory tree
/// (like cargo itself) to find the nearest one. Returns a friendly error when no
/// lockfile can be found.
fn resolve_lockfile(arg: PathBuf) -> anyhow::Result<PathBuf> {
    if arg.exists() {
        return Ok(arg);
    }
    let was_default = arg == Path::new("Cargo.lock");
    if was_default {
        if let Ok(cwd) = std::env::current_dir() {
            let mut dir = cwd.as_path();
            loop {
                let candidate = dir.join("Cargo.lock");
                if candidate.is_file() {
                    return Ok(candidate);
                }
                match dir.parent() {
                    Some(parent) => dir = parent,
                    None => break,
                }
            }
        }
        anyhow::bail!(
            "no Cargo.lock found in this directory or any parent.\n       \
             Run rustinel inside a Rust project, or point it at one:\n       \
             cargo rustinel check --lockfile <path/to/Cargo.lock>"
        );
    }
    anyhow::bail!("lockfile not found: {}", arg.display());
}

/// Resolve where to read unpacked crate sources for the static signals
/// (build.rs intent, unsafe, secret-exfil). An explicit `--source-path` wins;
/// otherwise default to the local Cargo registry cache so `cargo rustinel check`
/// scans real dependency sources out of the box. Set `RUSTINEL_NO_SOURCE_SCAN`
/// to disable. Read-only, offline.
fn resolve_source_path(explicit: Option<PathBuf>) -> Option<PathBuf> {
    if explicit.is_some() {
        return explicit;
    }
    if std::env::var_os("RUSTINEL_NO_SOURCE_SCAN").is_some() {
        return None;
    }
    let base = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cargo")))?;
    let src = base.join("registry").join("src");
    src.is_dir().then_some(src)
}

/// Find a `rustinel.toml` policy by walking up from the current directory.
fn discover_policy() -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    let mut dir = cwd.as_path();
    loop {
        let candidate = dir.join("rustinel.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        dir = dir.parent()?;
    }
}

/// Whether to print the decorative startup banner: only for human output to an
/// interactive stdout (never to a file or a pipe, so machine output stays
/// clean), and suppressible with `RUSTINEL_NO_BANNER`.
fn want_banner(format: CliFormat, output: &Option<PathBuf>) -> bool {
    matches!(format, CliFormat::Human)
        && output.is_none()
        && std::env::var_os("RUSTINEL_NO_BANNER").is_none()
        && std::io::stdout().is_terminal()
}

/// The 6 rows of the "RUSTINEL" ASCII logo (ANSI Shadow style).
const LOGO: [&str; 6] = [
    "██████╗  ██╗   ██╗ ███████╗ ████████╗ ██╗ ███╗   ██╗ ███████╗ ██╗",
    "██╔══██╗ ██║   ██║ ██╔════╝ ╚══██╔══╝ ██║ ████╗  ██║ ██╔════╝ ██║",
    "██████╔╝ ██║   ██║ ███████╗    ██║    ██║ ██╔██╗ ██║ █████╗   ██║",
    "██╔══██╗ ██║   ██║ ╚════██║    ██║    ██║ ██║╚██╗██║ ██╔══╝   ██║",
    "██║  ██║ ╚██████╔╝ ███████║    ██║    ██║ ██║ ╚████║ ███████╗ ███████╗",
    "╚═╝  ╚═╝  ╚═════╝  ╚══════╝    ╚═╝    ╚═╝ ╚═╝  ╚═══╝ ╚══════╝ ╚══════╝",
];
const TAGLINE: &str = "       defensive supply-chain risk diff for Cargo   ·   shields your PRs";
const RUST_ORANGE: (u8, u8, u8) = (255, 140, 0);

/// HSV (h in degrees, s/v in 0..1) -> RGB. Used for the animated gradient.
fn hsv_to_rgb(h: f32, s: f32, v: f32) -> (u8, u8, u8) {
    let c = v * s;
    let hp = (h.rem_euclid(360.0)) / 60.0;
    let x = c * (1.0 - ((hp % 2.0) - 1.0).abs());
    let (r1, g1, b1) = match hp as u32 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    let m = v - c;
    (
        (((r1 + m) * 255.0).round()) as u8,
        (((g1 + m) * 255.0).round()) as u8,
        (((b1 + m) * 255.0).round()) as u8,
    )
}

/// Nearest xterm-256 colour for an RGB triple (6×6×6 cube + grayscale ramp).
fn rgb_to_256(r: u8, g: u8, b: u8) -> u8 {
    let to6 = |v: u8| -> u8 {
        if v < 48 {
            0
        } else if v < 115 {
            1
        } else {
            ((v as u16 - 35) / 40) as u8
        }
    };
    16 + 36 * to6(r) + 6 * to6(g) + to6(b)
}

/// True if the terminal advertises 24-bit colour (`COLORTERM`); else we emit
/// 256-colour escapes for broad compatibility (e.g. Terminal.app).
fn truecolor() -> bool {
    static TC: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *TC.get_or_init(|| {
        std::env::var("COLORTERM")
            .map(|v| v.contains("truecolor") || v.contains("24bit"))
            .unwrap_or(false)
    })
}

fn fg(r: u8, g: u8, b: u8) -> String {
    if truecolor() {
        format!("\x1b[38;2;{r};{g};{b}m")
    } else {
        format!("\x1b[38;5;{}m", rgb_to_256(r, g, b))
    }
}

/// Render the 6 logo rows, colouring each non-space cell via `color(col)`.
/// Each line clears to EOL and ends with `\n` so frames overwrite cleanly.
fn render_logo<F: Fn(usize) -> (u8, u8, u8)>(color: F) -> String {
    let mut out = String::new();
    for line in LOGO {
        for (col, ch) in line.chars().enumerate() {
            if ch == ' ' {
                out.push(' ');
                continue;
            }
            let (r, g, b) = color(col);
            out.push_str(&fg(r, g, b));
            out.push(ch);
        }
        out.push_str("\x1b[0m\x1b[K\n");
    }
    out
}

/// Animate a flowing colour gradient across the logo for ~0.8s, then settle on
/// rust-orange. Falls back to a static banner when animation is disabled.
fn print_banner(color: bool) {
    let animate =
        color && std::env::var_os("RUSTINEL_NO_ANIM").is_none() && std::io::stdout().is_terminal();

    if animate {
        animate_logo();
    } else if color {
        let (r, g, b) = RUST_ORANGE;
        print!("\n{}", render_logo(|_| (r, g, b)));
    } else {
        println!("\n{}", LOGO.join("\n"));
    }

    if color {
        println!("\x1b[2m{TAGLINE}\x1b[0m\n");
    } else {
        println!("{TAGLINE}\n");
    }
}

fn animate_logo() {
    use std::io::Write;
    let mut out = std::io::stdout();
    const FRAMES: u32 = 28;
    const FRAME_MS: u64 = 30;
    // Hue change across columns and per frame — produces a left-to-right flow.
    const COL_STEP: f32 = 4.0;
    const FRAME_STEP: f32 = 16.0;

    let _ = write!(out, "\n\x1b[?25l"); // spacing + hide cursor
    for f in 0..FRAMES {
        if f > 0 {
            let _ = write!(out, "\x1b[{}A", LOGO.len()); // back to top of logo
        }
        let phase = f as f32 * FRAME_STEP;
        let frame = render_logo(|col| hsv_to_rgb(phase + col as f32 * COL_STEP, 1.0, 1.0));
        let _ = write!(out, "{frame}");
        let _ = out.flush();
        std::thread::sleep(std::time::Duration::from_millis(FRAME_MS));
    }
    // Settle on the brand colour and restore the cursor.
    let _ = write!(out, "\x1b[{}A", LOGO.len());
    let (r, g, b) = RUST_ORANGE;
    let _ = write!(out, "{}", render_logo(|_| (r, g, b)));
    let _ = write!(out, "\x1b[?25h");
    let _ = out.flush();
}

/// Whether to colorize: only for human output to an interactive stdout, and only
/// when `NO_COLOR` is unset (https://no-color.org/).
fn want_color(format: CliFormat, output: &Option<PathBuf>) -> bool {
    matches!(format, CliFormat::Human)
        && output.is_none()
        && std::env::var_os("NO_COLOR").is_none()
        && std::io::stdout().is_terminal()
}

/// ANSI color for a risk-level word.
fn level_color(level: &str) -> &'static str {
    match level {
        "CRITICAL" => "\x1b[1;31m",   // bold red
        "HIGH" => "\x1b[1;38;5;208m", // bold orange
        "MEDIUM" => "\x1b[1;33m",     // bold yellow
        "LOW" => "\x1b[1;32m",        // bold green
        _ => "\x1b[0m",
    }
}

/// Apply ANSI colors to the human report: risk line + gauge bar (by level),
/// severity-tagged findings, and the decision line.
fn colorize_human(text: &str) -> String {
    const RESET: &str = "\x1b[0m";
    let mut out = String::with_capacity(text.len() + 128);
    let mut bar_color = "\x1b[0m"; // carried from the preceding risk line to the gauge

    for line in text.lines() {
        let trimmed = line.trim_start();
        let colored = if line.starts_with("Project risk:") || line.starts_with("Supply-chain risk:")
        {
            // Color the whole line by the trailing LEVEL word.
            let lvl = line
                .rsplit([' ', ',', ')'])
                .find(|w| matches!(*w, "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"))
                .unwrap_or("");
            bar_color = level_color(lvl);
            format!("{bar_color}{line}{RESET}")
        } else if trimmed.starts_with('[') && (trimmed.contains('█') || trimmed.contains('░')) {
            format!("{bar_color}{line}{RESET}")
        } else if let Some(rest) = line.strip_prefix("Decision: ") {
            let code = match rest.trim() {
                "FAIL" => "\x1b[1;31m",
                "REVIEW_REQUIRED" | "WARN" => "\x1b[1;33m",
                "PASS" => "\x1b[1;32m",
                _ => "",
            };
            if code.is_empty() {
                line.to_string()
            } else {
                format!("Decision: {code}{rest}{RESET}")
            }
        } else if let Some(code) = severity_color(line) {
            format!("{code}{line}{RESET}")
        } else {
            line.to_string()
        };
        out.push_str(&colored);
        out.push('\n');
    }
    out
}

fn severity_color(line: &str) -> Option<&'static str> {
    let t = line.trim_start();
    if t.starts_with("[CRIT]") || t.starts_with("[HIGH]") {
        Some("\x1b[31m") // red
    } else if t.starts_with("[MED ]") {
        Some("\x1b[33m") // yellow
    } else if t.starts_with("[LOW ]") {
        Some("\x1b[34m") // blue
    } else if t.starts_with("[INFO]") {
        Some("\x1b[2m") // dim
    } else {
        None
    }
}

fn main() -> anyhow::Result<()> {
    // `cargo rustinel ...` invokes this binary as `cargo-rustinel rustinel ...`.
    // Direct invocation is `cargo-rustinel ...`. Normalize both forms.
    let mut args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if args.get(1).map(|a| a == "rustinel").unwrap_or(false) {
        args.remove(1);
    }
    let cli = Cli::parse_from(args);

    match cli.command {
        Commands::Check {
            lockfile,
            policy,
            format,
            output,
            offline,
            source_path,
            advisory_db,
            online_metadata,
            no_timestamp,
            fail_on_review_required,
            explain,
        } => {
            let lockfile = resolve_lockfile(lockfile)?;
            // Auto-discover rustinel.toml when no policy was passed explicitly.
            let policy_path = policy.or_else(discover_policy);
            let yanked = gather_yanked(online_metadata, offline, &[&lockfile]);
            let options = AnalysisOptions {
                offline,
                policy: load_policy(&policy_path)?,
                source_path: resolve_source_path(source_path),
                advisory_db_path: advisory_db,
                yanked,
                generated_at: timestamp(no_timestamp),
            };
            let report = rustinel_core::analyze_lockfile(&lockfile, options)
                .with_context(|| format!("analyzing {}", lockfile.display()))?;
            if want_banner(format, &output) {
                print_banner(want_color(format, &output));
            }
            let mut rendered = report::render(&report, format.into())?;
            if want_color(format, &output) {
                rendered = colorize_human(&rendered);
            }
            if explain && matches!(format, CliFormat::Human) {
                rendered.push_str(&report::score_explanation(&report));
            }
            emit(&rendered, &output)?;
            if report::is_failing(&report, fail_on_review_required) {
                std::process::exit(1);
            }
        }

        Commands::Diff {
            base_lockfile,
            head_lockfile,
            policy,
            format,
            output,
            offline,
            source_path,
            advisory_db,
            online_metadata,
            no_timestamp,
            fail_on_review_required,
            explain,
        } => {
            let policy_path = policy.or_else(discover_policy);
            let yanked = gather_yanked(online_metadata, offline, &[&base_lockfile, &head_lockfile]);
            let options = AnalysisOptions {
                offline,
                policy: load_policy(&policy_path)?,
                source_path: resolve_source_path(source_path),
                advisory_db_path: advisory_db,
                yanked,
                generated_at: timestamp(no_timestamp),
            };
            let report = rustinel_core::analyze_diff(&base_lockfile, &head_lockfile, options)
                .context("computing risk diff")?;
            if want_banner(format, &output) {
                print_banner(want_color(format, &output));
            }
            let mut rendered = report::render(&report, format.into())?;
            if want_color(format, &output) {
                rendered = colorize_human(&rendered);
            }
            if explain && matches!(format, CliFormat::Human) {
                rendered.push_str(&report::score_explanation(&report));
            }
            emit(&rendered, &output)?;
            if report::is_failing(&report, fail_on_review_required) {
                std::process::exit(1);
            }
        }

        Commands::Policy { command } => match command {
            PolicyCommands::Init { profile, output } => {
                let template = policy_template(&profile);
                emit(&template, &output)?;
            }
        },

        Commands::Demo => {
            let color = std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal();
            print_banner(color);
            println!(
                "  v{}   ·   try:  cargo rustinel check\n",
                env!("CARGO_PKG_VERSION")
            );
        }

        Commands::Advisory { command } => match command {
            AdvisoryCommands::Update { dir, url } => advisory_update(dir, &url)?,
            AdvisoryCommands::Status { dir } => advisory_status(dir)?,
        },

        Commands::Export {
            format,
            lockfile,
            output,
            policy,
            offline,
            source_path,
            advisory_db,
            online_metadata,
            no_timestamp,
        } => {
            let lockfile = resolve_lockfile(lockfile)?;
            let policy_path = policy.or_else(discover_policy);
            let yanked = gather_yanked(online_metadata, offline, &[&lockfile]);
            let options = AnalysisOptions {
                offline,
                policy: load_policy(&policy_path)?,
                source_path: resolve_source_path(source_path),
                advisory_db_path: advisory_db,
                yanked,
                generated_at: timestamp(no_timestamp),
            };
            // Parse once for the component list, analyze for the vulnerability set.
            let lock = rustinel_core::lockfile::parse_lockfile(&lockfile)
                .with_context(|| format!("parsing {}", lockfile.display()))?;
            let report = rustinel_core::analyze_lockfile(&lockfile, options)
                .with_context(|| format!("analyzing {}", lockfile.display()))?;
            let rendered = rustinel_core::sbom::render(format.into(), &lock, &report)?;
            // Interchange formats are machine artifacts: emit with a trailing newline.
            emit(&format!("{rendered}\n"), &output)?;
        }
    }

    Ok(())
}

fn resolve_advisory_dir(dir: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    dir.or_else(rustinel_core::advisory::AdvisoryDb::default_cache_dir)
        .context("could not resolve a cache directory (set --dir or CARGO_HOME/HOME)")
}

/// Sync the advisory DB via the system `git` (clone or fast-forward pull).
fn advisory_update(dir: Option<PathBuf>, url: &str) -> anyhow::Result<()> {
    let dir = resolve_advisory_dir(dir)?;
    let git_dir = dir.join(".git");
    let status = if git_dir.is_dir() {
        println!("Updating advisory database in {} ...", dir.display());
        std::process::Command::new("git")
            .args(["-C", &dir.to_string_lossy(), "pull", "--ff-only", "--quiet"])
            .status()
    } else {
        if let Some(parent) = dir.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        println!("Cloning advisory database into {} ...", dir.display());
        std::process::Command::new("git")
            .args(["clone", "--depth", "1", url, &dir.to_string_lossy()])
            .status()
    };

    let status = status.context("failed to run `git` — is it installed and on PATH?")?;
    if !status.success() {
        anyhow::bail!("git exited with status {status}");
    }

    let db = rustinel_core::advisory::AdvisoryDb::load_from_dir(&dir)
        .with_context(|| format!("loading advisory DB at {}", dir.display()))?;
    println!("Done. {} advisories available.", db.len());
    Ok(())
}

fn advisory_status(dir: Option<PathBuf>) -> anyhow::Result<()> {
    let dir = resolve_advisory_dir(dir)?;
    if !dir.exists() {
        println!("Advisory cache: not present at {}", dir.display());
        println!("Run `cargo rustinel advisory update` to sync it.");
        return Ok(());
    }
    let db = rustinel_core::advisory::AdvisoryDb::load_from_dir(&dir)
        .with_context(|| format!("loading advisory DB at {}", dir.display()))?;
    println!("Advisory cache: {}", dir.display());
    println!("Advisories loaded: {}", db.len());
    Ok(())
}

struct ProfileTemplate {
    max_project: u8,
    max_pkg: u8,
    fail_delta: i32,
    warn_delta: i32,
    adv_fail: &'static str,
    adv_warn: &'static str,
    require_review_on_build_rs: bool,
    require_review_on_native_ffi: bool,
    warn_on_unknown_license: bool,
    fail_on_unknown_license: bool,
    license_allow: &'static str,
    deny_lic: &'static str,
}

/// Generate a starter policy for a named profile. Unknown profile names fall
/// back to a balanced baseline with the requested name preserved.
fn policy_template(profile: &str) -> String {
    // Per-profile tuning. The `signals`/`licenses` blocks differ so that the
    // generated file actually behaves like the named profile (matching the
    // built-in defaults in rustinel-core and `examples/policies/`).
    let p = match profile {
        "strict" => ProfileTemplate {
            max_project: 50,
            max_pkg: 70,
            fail_delta: 20,
            warn_delta: 5,
            adv_fail: "\"critical\", \"high\", \"medium\"",
            adv_warn: "\"low\"",
            require_review_on_build_rs: true,
            require_review_on_native_ffi: true,
            warn_on_unknown_license: false,
            fail_on_unknown_license: true,
            license_allow: "\"MIT\", \"Apache-2.0\", \"BSD-2-Clause\", \"BSD-3-Clause\", \"ISC\"",
            deny_lic: "\"GPL-3.0\", \"AGPL-3.0\", \"LGPL-3.0\"",
        },
        "permissive" => ProfileTemplate {
            max_project: 90,
            max_pkg: 95,
            fail_delta: 60,
            warn_delta: 25,
            adv_fail: "\"critical\"",
            adv_warn: "\"high\", \"medium\", \"low\"",
            require_review_on_build_rs: false,
            require_review_on_native_ffi: false,
            warn_on_unknown_license: true,
            fail_on_unknown_license: false,
            license_allow: "",
            deny_lic: "\"AGPL-3.0\"",
        },
        _ => ProfileTemplate {
            max_project: 70,
            max_pkg: 85,
            fail_delta: 35,
            warn_delta: 10,
            adv_fail: "\"critical\", \"high\"",
            adv_warn: "\"medium\", \"low\"",
            require_review_on_build_rs: false,
            require_review_on_native_ffi: true,
            warn_on_unknown_license: true,
            fail_on_unknown_license: false,
            license_allow: "\"MIT\", \"Apache-2.0\", \"BSD-2-Clause\", \"BSD-3-Clause\", \"ISC\"",
            deny_lic: "\"GPL-3.0\", \"AGPL-3.0\"",
        },
    };
    let ProfileTemplate {
        max_project,
        max_pkg,
        fail_delta,
        warn_delta,
        adv_fail,
        adv_warn,
        require_review_on_build_rs,
        require_review_on_native_ffi,
        warn_on_unknown_license,
        fail_on_unknown_license,
        license_allow,
        deny_lic,
    } = p;
    format!(
        r#"version = 1

[profile]
name = "{profile}"

[risk]
max_project_score = {max_project}
max_package_score = {max_pkg}
fail_on_delta_above = {fail_delta}
warn_on_delta_above = {warn_delta}

[advisories]
fail_on = [{adv_fail}]
warn_on = [{adv_warn}]
ignore = []

[signals]
fail_on_yanked = true
warn_on_build_rs = false
require_review_on_build_rs = {require_review_on_build_rs}
require_review_on_native_ffi = {require_review_on_native_ffi}
warn_on_unsafe_increase = true
fail_on_denied_license = true
warn_on_unknown_license = {warn_on_unknown_license}
fail_on_unknown_license = {fail_on_unknown_license}

[licenses]
allow = [{license_allow}]
deny = [{deny_lic}]

[allow]
crates = []

[deny]
crates = []
"#
    )
}
