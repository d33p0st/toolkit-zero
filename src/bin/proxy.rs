#![crate_name = "zero_compile"]
//! `zero-compile` — compile a Rust project using the toolkit-zero embedded toolchain.
//!
//! # Usage
//!
//! ```text
//! rzc --dir <path>  [--release] [--verbose]
//! rzc --path <file> [--dep <name>[@<version>][:<feat1,feat2>] ...] [--release] [--verbose]
//! ```
//!
//! # Examples
//!
//! ```text
//! # Compile an existing Cargo project in release mode
//! rzc --dir ./my-project --release
//!
//! # Compile a single .rs file with dependencies, streaming output
//! rzc --path ./hello.rs --dep serde@1:derive --dep tokio@1:full --release --verbose
//! ```

use std::path::PathBuf;

use clap::Parser;
use toolkit_zero::compiler::{compile, Dependency, Input};

// ── CLI definition ────────────────────────────────────────────────────────────

/// Compile a Rust project using the embedded stable toolchain.
#[derive(Parser)]
#[command(name = "rzc", author, version, about, long_about = None)]
struct Cli {
    /// Path to an existing Cargo project directory.
    #[arg(long, conflicts_with = "path", value_name = "DIR")]
    dir: Option<PathBuf>,

    /// Path to a single `.rs` file to compile (generates a temporary Cargo project).
    #[arg(long, conflicts_with = "dir", value_name = "FILE")]
    path: Option<PathBuf>,

    /// Dependency for `--path` mode.
    ///
    /// Shorthand (crates.io):  name[@version][:feat1,feat2]
    ///
    /// Full key=value form:    name[,key=value,...]
    /// Keys: version, path, git, branch, tag, rev, package,
    ///       features=f1;f2 (semicolon-separated), no-default-features, optional
    ///
    /// Examples:
    ///   --dep serde@1:derive,std
    ///   --dep "mylib,path=../mylib"
    ///   --dep "mylib,path=../mylib,features=serde;log,optional"
    ///   --dep "myfork,git=https://github.com/foo/bar,branch=dev"
    ///   --dep "serde,version=1,features=derive;std,no-default-features"
    #[arg(long = "dep", value_name = "SPEC", requires = "path")]
    deps: Vec<String>,

    /// Compile with the release profile (`--release`).
    #[arg(long)]
    release: bool,

    /// Stream cargo output live to the terminal.
    ///
    /// Without this flag a progress spinner is shown instead and the full
    /// stdout/stderr is printed after the build finishes.
    #[arg(long)]
    verbose: bool,
}

// ── Dependency spec parser ────────────────────────────────────────────────────
//
// General format (key=value pairs after the crate name, comma-separated):
//
//   name[,key=value,...]
//
// Recognised keys:
//   version=<req>          e.g. version=1  (may also use shorthand @1, see below)
//   path=<local/path>      local path dependency
//   git=<url>              git URL dependency
//   branch=<b>             git branch (only with git=)
//   tag=<t>                git tag     (only with git=)
//   rev=<r>                git revision (only with git=)
//   features=<f1;f2;f3>    semicolon-separated feature list
//   no-default-features    disable default features
//   optional               mark as optional
//   package=<crate-name>   crate name when it differs from the dep key
//
// Shorthand (for simple crates.io deps):
//   name@version[:feat1,feat2]
//   — e.g.  serde@1:derive,std
//
// Full key=value examples:
//   mylib,path=../mylib
//   mylib,path=../mylib,features=serde;log,optional
//   myfork,git=https://github.com/foo/bar,branch=dev,features=full
//   serde,version=1,features=derive;std,no-default-features
//   mycrate,git=https://github.com/foo/bar,rev=abc123,package=actual-crate-name

fn parse_dep(spec: &str) -> Result<Dependency, String> {
    // ── Shorthand detection: if the spec contains '@' before any ',' ─────────
    // Treat it as the old  name[@version][:feat1,feat2] format.
    let at_pos    = spec.find('@');
    let comma_pos = spec.find(',');
    let use_shorthand = at_pos.is_some()
        && comma_pos.map(|c| at_pos.unwrap() < c).unwrap_or(true);

    if use_shorthand {
        // name[@version][:feat1,feat2]
        let (name_ver, feat_str) = match spec.split_once(':') {
            Some((nv, f)) => (nv, Some(f)),
            None           => (spec, None),
        };
        let (name, version) = match name_ver.split_once('@') {
            Some((n, v)) => (n, Some(v)),
            None          => (name_ver, None),
        };
        if name.is_empty() {
            return Err(format!("invalid dep spec (empty name): '{spec}'"));
        }
        let mut dep = Dependency::new(name);
        if let Some(v) = version { dep = dep.version(v); }
        if let Some(fs) = feat_str {
            for f in fs.split(',').filter(|s| !s.is_empty()) {
                dep = dep.feature(f);
            }
        }
        return Ok(dep);
    }

    // ── Key=value format ──────────────────────────────────────────────────────
    // First token is the dep name; remaining are key=value or bare flags.
    let mut parts = spec.splitn(2, ',');
    let name = parts.next().unwrap_or("").trim();
    if name.is_empty() {
        return Err(format!("invalid dep spec (empty name): '{spec}'"));
    }
    let mut dep = Dependency::new(name);

    if let Some(rest) = parts.next() {
        for token in rest.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if let Some((k, v)) = token.split_once('=') {
                match k.trim() {
                    "version"  => { dep = dep.version(v.trim()); }
                    "path"     => { dep = dep.path(v.trim()); }
                    "git"      => { dep = dep.git(v.trim()); }
                    "branch"   => { dep = dep.branch(v.trim()); }
                    "tag"      => { dep = dep.tag(v.trim()); }
                    "rev"      => { dep = dep.rev(v.trim()); }
                    "package"  => { dep = dep.package(v.trim()); }
                    "features" => {
                        // semicolons so users can still use commas as the outer separator
                        for f in v.split(';').map(str::trim).filter(|s| !s.is_empty()) {
                            dep = dep.feature(f);
                        }
                    }
                    other => {
                        return Err(format!("unknown dep key '{other}' in spec '{spec}'"));
                    }
                }
            } else {
                // Bare flags
                match token {
                    "no-default-features" => { dep = dep.default_features(false); }
                    "optional"            => { dep = dep.optional(true); }
                    other => {
                        return Err(format!("unknown dep flag '{other}' in spec '{spec}'"));
                    }
                }
            }
        }
    }

    Ok(dep)
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    // ── Build the Input ───────────────────────────────────────────────────────
    let input = if let Some(dir) = cli.dir {
        if !dir.exists() {
            eprintln!("error: directory does not exist: {}", dir.display());
            std::process::exit(1);
        }
        Input::Dir(dir)
    } else if let Some(path) = cli.path {
        if !path.exists() {
            eprintln!("error: file does not exist: {}", path.display());
            std::process::exit(1);
        }

        // Parse dependency specs
        let mut deps = Vec::new();
        for spec in &cli.deps {
            match parse_dep(spec) {
                Ok(d)  => deps.push(d),
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Input::File { path, deps }
    } else {
        eprintln!("error: one of --dir or --path is required");
        eprintln!("Try `rzc --help` for usage.");
        std::process::exit(1);
    };

    // ── Run compile ───────────────────────────────────────────────────────────
    if cli.verbose {
        // Live streaming — compile handles output directly.
        match compile(input, cli.release, true, true) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    } else {
        // Progress bars (decompress → compile → cleanup) are driven inside compile().
        let result = compile(input, cli.release, false, true);

        match result {
            Ok(Some(_)) | Ok(None) => {}
            Err(toolkit_zero::compiler::CompileError::BuildFailed(out)) => {
                if !out.stdout.is_empty() {
                    print!("{}", out.stdout);
                }
                if !out.stderr.is_empty() {
                    eprint!("{}", out.stderr);
                }
                eprintln!("Build failed.");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    }
}
