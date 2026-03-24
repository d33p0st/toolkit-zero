//! Embedded-toolchain compiler.
//!
//! The `compiler` feature embeds the Rust stable toolchain for the current build
//! target directly into the binary (via `include_bytes!` in `build.rs`). At
//! runtime [`compile`] unpacks that toolchain into a temporary directory, runs
//! `cargo build --release` against the supplied Rust project, returns the
//! compilation output, and then deletes the extracted toolchain.
//!
//! # Quick start
//!
//! ```rust,ignore
//! use toolkit_zero::compiler::{compile, Input, ToolchainChannel};
//!
//! // Compile a directory (stable, release, live output, with progress)
//! let _ = compile(Input::Dir("/path/to/my/project"), true, true, true, None, ToolchainChannel::Stable).unwrap();
//!
//! // Compile a single .rs file in dev mode, capture output silently
//! if let Some(out) = compile(Input::File {
//!     path: "/tmp/hello.rs".into(),
//!     deps: vec![],
//! }, false, false, true, None, ToolchainChannel::Stable).unwrap() {
//!     println!("{}", out.stdout);
//! }
//!
//! // Compile a single .rs file with dependencies (nightly, release, live output)
//! use toolkit_zero::compiler::Dependency;
//! let _ = compile(Input::File {
//!     path: "/tmp/hello.rs".into(),
//!     deps: vec![
//!         Dependency::new("serde").version("1").feature("derive"),
//!         Dependency::new("tokio").version("1").feature("full"),
//!     ],
//! }, true, true, true, None, ToolchainChannel::Nightly).unwrap();
//! ```

#[cfg(target_arch = "wasm32")]
compile_error!("The `compiler` feature is not supported on wasm32 targets.");

use std::{
    io,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

// ── Embedded toolchains ────────────────────────────────────────────────────────────────

/// The stable toolchain tarball for the current target, embedded at compile time.
#[cfg(not(target_arch = "wasm32"))]
static TOOLCHAIN_STABLE: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/toolchain-stable.tar.xz"));

/// The nightly toolchain tarball for the current target, embedded at compile time.
#[cfg(not(target_arch = "wasm32"))]
static TOOLCHAIN_NIGHTLY: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/toolchain-nightly.tar.xz"));

// ── Toolchain channel ──────────────────────────────────────────────────────────────

/// Which Rust toolchain release channel to use for compilation.
///
/// Both `stable` and `nightly` tarballs are embedded at build time.
/// Defaults to [`ToolchainChannel::Stable`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ToolchainChannel {
    #[default]
    Stable,
    Nightly,
}

impl ToolchainChannel {
    /// The manifest channel name used in `channel-rust-<name>.toml`.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Stable  => "stable",
            Self::Nightly => "nightly",
        }
    }
}

// ── Public types ──────────────────────────────────────────────────────────────

/// What to compile.
pub enum Input {
    /// Path to an existing directory that contains a `Cargo.toml` and a valid
    /// Rust project structure (`src/main.rs` or `src/lib.rs`).
    Dir(PathBuf),

    /// A single `.rs` source file.  A temporary Cargo project is synthesised
    /// around it; the project name matches the file stem.
    ///
    /// `deps` lists extra crate dependencies to inject.  If empty the
    /// generated `Cargo.toml` has no `[dependencies]` entries.
    File {
        path: PathBuf,
        deps: Vec<Dependency>,
    },
}

impl Input {
    /// Convenience constructor for [`Input::Dir`] from any `AsRef<Path>`.
    pub fn dir(p: impl AsRef<Path>) -> Self {
        Self::Dir(p.as_ref().to_path_buf())
    }

    /// Convenience constructor for [`Input::File`] with no dependencies.
    pub fn file(p: impl AsRef<Path>) -> Self {
        Self::File { path: p.as_ref().to_path_buf(), deps: vec![] }
    }

    /// Convenience constructor for [`Input::File`] with a dependency list.
    pub fn file_with_deps(p: impl AsRef<Path>, deps: Vec<Dependency>) -> Self {
        Self::File { path: p.as_ref().to_path_buf(), deps }
    }
}

/// A single Cargo dependency specification.
///
/// Only the name is required; all other fields mirror what `Cargo.toml`
/// supports and are optional.
///
/// ```rust,ignore
/// Dependency::new("serde")
///     .version("1")
///     .feature("derive")
///     .feature("std")
///
/// Dependency::new("my-local-crate")
///     .path("/workspace/my-local-crate")
/// ```
#[derive(Debug, Clone, Default)]
pub struct Dependency {
    /// Crate name (required).
    pub name: String,
    /// SemVer requirement, e.g. `"1"` or `"0.4.3"`. Defaults to `"*"` when absent.
    pub version: Option<String>,
    /// Local path — makes this a path dependency. `version` is still accepted
    /// alongside `path` for compatibility.
    pub path: Option<PathBuf>,
    /// `git` URL, e.g. `"https://github.com/user/repo"`.
    pub git: Option<String>,
    /// Git branch (only meaningful with `git`).
    pub branch: Option<String>,
    /// Git tag (only meaningful with `git`).
    pub tag: Option<String>,
    /// Git revision (only meaningful with `git`).
    pub rev: Option<String>,
    /// Features to enable for this dependency.
    pub features: Vec<String>,
    /// Whether to enable the dependency's default features. `None` = omit the
    /// key (cargo uses `true` by default).
    pub default_features: Option<bool>,
    /// Mark as optional. `None` = omit the key (cargo uses `false` by default).
    pub optional: Option<bool>,
    /// Package name when the crate name on crates.io differs from the dep key.
    pub package: Option<String>,
}

impl Dependency {
    /// Create a new dependency with the given crate name.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), ..Default::default() }
    }

    /// Set the version requirement.
    pub fn version(mut self, v: impl Into<String>) -> Self {
        self.version = Some(v.into());
        self
    }

    /// Set a local path.
    pub fn path(mut self, p: impl AsRef<Path>) -> Self {
        self.path = Some(p.as_ref().to_path_buf());
        self
    }

    /// Set a git URL.
    pub fn git(mut self, url: impl Into<String>) -> Self {
        self.git = Some(url.into());
        self
    }

    /// Set a git branch.
    pub fn branch(mut self, b: impl Into<String>) -> Self {
        self.branch = Some(b.into());
        self
    }

    /// Set a git tag.
    pub fn tag(mut self, t: impl Into<String>) -> Self {
        self.tag = Some(t.into());
        self
    }

    /// Set a git revision.
    pub fn rev(mut self, r: impl Into<String>) -> Self {
        self.rev = Some(r.into());
        self
    }

    /// Enable a feature for this dependency. May be called multiple times.
    pub fn feature(mut self, f: impl Into<String>) -> Self {
        self.features.push(f.into());
        self
    }

    /// Set `default-features`.
    pub fn default_features(mut self, enabled: bool) -> Self {
        self.default_features = Some(enabled);
        self
    }

    /// Set `optional`.
    pub fn optional(mut self, opt: bool) -> Self {
        self.optional = Some(opt);
        self
    }

    /// Set `package` (when the crate name differs from the dep key).
    pub fn package(mut self, pkg: impl Into<String>) -> Self {
        self.package = Some(pkg.into());
        self
    }

    /// Render this dependency as a TOML inline table string, e.g.
    /// `{ version = "1", features = ["derive"] }`.
    fn to_toml_value(&self) -> String {
        let mut parts: Vec<String> = vec![];

        // version / path / git are mutually exclusive in practice but we emit
        // whatever the caller set.
        if let Some(v) = &self.version {
            parts.push(format!("version = \"{}\"", v));
        }
        if let Some(p) = &self.path {
            parts.push(format!("path = \"{}\"", p.display()));
        }
        if let Some(g) = &self.git {
            parts.push(format!("git = \"{}\"", g));
        }
        if let Some(b) = &self.branch {
            parts.push(format!("branch = \"{}\"", b));
        }
        if let Some(t) = &self.tag {
            parts.push(format!("tag = \"{}\"", t));
        }
        if let Some(r) = &self.rev {
            parts.push(format!("rev = \"{}\"", r));
        }
        if !self.features.is_empty() {
            let fs: Vec<String> = self.features.iter().map(|f| format!("\"{}\"", f)).collect();
            parts.push(format!("features = [{}]", fs.join(", ")));
        }
        if let Some(df) = self.default_features {
            parts.push(format!("default-features = {}", df));
        }
        if let Some(opt) = self.optional {
            parts.push(format!("optional = {}", opt));
        }
        if let Some(pkg) = &self.package {
            parts.push(format!("package = \"{}\"", pkg));
        }

        if parts.is_empty() {
            // No constraints — just use "*"
            "\"*\"".to_string()
        } else {
            format!("{{ {} }}", parts.join(", "))
        }
    }
}

/// The result of a compilation run.
///
/// Mirrors [`std::process::Output`] but owns its strings for ergonomics.
#[derive(Debug)]
pub struct CompileOutput {
    /// Whether cargo exited successfully (`exit status 0`).
    pub success: bool,
    /// Standard output from `cargo build --release`.
    pub stdout: String,
    /// Standard error from `cargo build --release` (contains most of cargo's
    /// diagnostic output).
    pub stderr: String,
}

/// Errors returned by [`compile`].
#[derive(Debug)]
pub enum CompileError {
    /// I/O error (temp dir creation, file copy, extraction, …).
    Io(io::Error),
    /// The supplied directory does not look like a valid Rust project.
    InvalidProject(String),
    /// `cargo build` exited with a non-zero status. The [`CompileOutput`] is
    /// included so the caller can inspect stdout/stderr.
    BuildFailed(CompileOutput),
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e)              => write!(f, "I/O error: {e}"),
            Self::InvalidProject(s)  => write!(f, "invalid project: {s}"),
            Self::BuildFailed(o)     => write!(f, "cargo build failed:\n{}", o.stderr),
        }
    }
}

impl std::error::Error for CompileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _           => None,
        }
    }
}

impl From<io::Error> for CompileError {
    fn from(e: io::Error) -> Self { Self::Io(e) }
}

// ── Cross-compilation targets ─────────────────────────────────────────────────

/// Simple ALL-CAPS name for a cross-compilation target.
///
/// Pass one of these to [`compile`] via the `cross_target` parameter to
/// download the matching `rust-std` component at runtime and compile for that
/// target.  The host toolchain (rustc + cargo) comes from the embedded tarball;
/// only the standard library for the new target is fetched from
/// `static.rust-lang.org` and merged into the sysroot.
///
/// The `rust-std` tarball for the selected target is cached in
/// `$CARGO_HOME/toolchain-cache/<triple>/rust-std.tar.xz` so the network
/// request happens only once per target.
///
/// # Linker note
///
/// `rustc` requires a linker for the target to be available on `PATH`
/// (e.g. `aarch64-linux-gnu-gcc` for `LINUX_ARM64`).  The only exception is
/// `WASM` / `WASM_WASI` which use the built-in LLD bundled inside the
/// embedded rustc binary.
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum CrossTarget {
    #[value(name = "LINUX_X64")]    LinuxX64,
    #[value(name = "LINUX_X86")]    LinuxX86,
    #[value(name = "LINUX_ARM64")]  LinuxArm64,
    #[value(name = "LINUX_ARM")]    LinuxArm,
    #[value(name = "LINUX_MUSL_X64")]   LinuxMuslX64,
    #[value(name = "LINUX_MUSL_ARM64")] LinuxMuslArm64,
    #[value(name = "WIN_X64")]      WinX64,
    #[value(name = "WIN_X86")]      WinX86,
    #[value(name = "WIN_X64_GNU")]  WinX64Gnu,
    #[value(name = "WIN_ARM64")]    WinArm64,
    #[value(name = "MAC_X64")]      MacX64,
    #[value(name = "MAC_ARM64")]    MacArm64,
    #[value(name = "WASM")]         Wasm,
    #[value(name = "WASM_WASI")]    WasmWasi,
    #[value(name = "ANDROID_ARM64")] AndroidArm64,
    #[value(name = "ANDROID_X64")]  AndroidX64,
    #[value(name = "ANDROID_ARM")]  AndroidArm,
    #[value(name = "ANDROID_X86")]  AndroidX86,
    #[value(name = "FREEBSD_X64")] FreebsdX64,
    #[value(name = "IOS_ARM64")]    IosArm64,
}

impl CrossTarget {
    /// The actual Rust target triple string used by rustc/cargo.
    pub fn triple(&self) -> &'static str {
        match self {
            Self::LinuxX64       => "x86_64-unknown-linux-gnu",
            Self::LinuxX86       => "i686-unknown-linux-gnu",
            Self::LinuxArm64     => "aarch64-unknown-linux-gnu",
            Self::LinuxArm       => "armv7-unknown-linux-gnueabihf",
            Self::LinuxMuslX64   => "x86_64-unknown-linux-musl",
            Self::LinuxMuslArm64 => "aarch64-unknown-linux-musl",
            Self::WinX64         => "x86_64-pc-windows-msvc",
            Self::WinX86         => "i686-pc-windows-msvc",
            Self::WinX64Gnu      => "x86_64-pc-windows-gnu",
            Self::WinArm64       => "aarch64-pc-windows-msvc",
            Self::MacX64         => "x86_64-apple-darwin",
            Self::MacArm64       => "aarch64-apple-darwin",
            Self::Wasm           => "wasm32-unknown-unknown",
            Self::WasmWasi       => "wasm32-wasip1",
            Self::AndroidArm64   => "aarch64-linux-android",
            Self::AndroidX64     => "x86_64-linux-android",
            Self::AndroidArm     => "armv7-linux-androideabi",
            Self::AndroidX86     => "i686-linux-android",
            Self::FreebsdX64     => "x86_64-unknown-freebsd",
            Self::IosArm64       => "aarch64-apple-ios",
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Compile a Rust project using the embedded toolchain.
///
/// Steps:
/// 1. Extract the embedded `toolchain.tar.xz` into a `tempdir`.
/// 2. Validate or synthesise the project under `input`.
/// 3. Run `cargo build` (release or dev depending on `release`) with `RUSTC`
///    and `PATH` set to the extracted toolchain binaries.
/// 4. Collect and return [`CompileOutput`].
/// 5. Delete the extracted toolchain (the tempdir).
///
/// Set `release` to `true` to build with `--release`; `false` uses the dev
/// profile (no extra flag).
///
/// Set `live_output` to `true` to stream cargo's stdout and stderr directly
/// to the terminal in real time. When `true`, returns `Ok(None)` on success
/// since output is not captured. When `false`, output is captured silently
/// and returned as `Ok(Some(`[`CompileOutput`]`))` on success.
///
/// Set `show_progress` to `true` to display sequential terminal progress bars
/// (decompress → compile → cleanup). Always shown for the cross-std download
/// step regardless of this flag.
///
/// Pass a [`CrossTarget`] to cross-compile for a different platform. The
/// matching `rust-std` is downloaded and cached on first use.
///
/// The *project* tempdir (for [`Input::File`]) is *also* cleaned up after the
/// build regardless of success.
///
/// # Errors
///
/// Returns [`CompileError::Io`] for filesystem/network failures,
/// [`CompileError::InvalidProject`]
/// when the supplied directory lacks `Cargo.toml` or `src/`, and
/// [`CompileError::BuildFailed`] when cargo exits non-zero.
///
/// # Availability
///
/// Not available on `wasm32-*` targets (no pre-built toolchain is embedded).
#[cfg(not(target_arch = "wasm32"))]
pub fn compile(input: Input, release: bool, live_output: bool, show_progress: bool, cross_target: Option<CrossTarget>, channel: ToolchainChannel) -> Result<Option<CompileOutput>, CompileError> {
    // ── Step 0: validate input before the expensive decompression ─────────────
    match &input {
        Input::Dir(p) => validate_project(p)?,
        Input::File { path, .. } => {
            if !path.exists() {
                return Err(CompileError::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("{}: file not found", path.display()),
                )));
            }
        }
    }

    // ── Step 1: extract the embedded toolchain into a temp dir ────────────────
    let tarball = match channel {
        ToolchainChannel::Stable  => TOOLCHAIN_STABLE,
        ToolchainChannel::Nightly => TOOLCHAIN_NIGHTLY,
    };
    let toolchain_tmp = tempdir()?;
    extract_tarball(tarball, toolchain_tmp.path(), show_progress, "toolchain")?;

    // The tarball unpacks into a single top-level directory
    // (e.g. rust-1.94.0-x86_64-unknown-linux-gnu/).  Find it.
    let toolchain_root = find_single_subdir(toolchain_tmp.path())
        .ok_or_else(|| CompileError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "could not locate toolchain root inside the extracted tarball",
        )))?;

    let rustc_bin  = toolchain_root.join("rustc/bin/rustc");
    let cargo_bin  = toolchain_root.join("cargo/bin/cargo");

    // Merge rust-std-* component(s) into the rustc sysroot so that rustc
    // can find the standard library without an explicit --sysroot flag.
    // The tarball ships rustc and rust-std-<target> as separate component
    // subdirectories; rustc only looks inside its own lib/rustlib/ tree.
    merge_std_into_sysroot(&toolchain_root)?;

    // ── Step 1b: fetch + merge cross-std (when --target is used) ─────────────
    if let Some(ref ct) = cross_target {
        fetch_cross_std(ct.triple(), &toolchain_root, show_progress, channel)?;
    };

    let path_with_toolchain = format!(
        "{}:{}:{}",
        toolchain_root.join("rustc/bin").display(),
        toolchain_root.join("cargo/bin").display(),
        std::env::var("PATH").unwrap_or_default(),
    );

    // ── Step 2: resolve/synthesise the project directory ─────────────────────
    // For File inputs we create a temp project dir and remember it for cleanup.
    let (project_dir, _project_tmp) = match &input {
        Input::Dir(p) => {

            (p.clone(), None::<TempDir>)
        }
        Input::File { path, deps } => {
            let tmp = tempdir()?;
            let proj = synthesise_project(path, deps, tmp.path())?;
            (proj, Some(tmp))
        }
    };

    // ── Step 3: cargo build ───────────────────────────────────────────────────
    let mut cmd = Command::new(&cargo_bin);
    cmd.arg("build");
    if release {
        cmd.arg("--release");
    }
    if let Some(ref ct) = cross_target {
        cmd.arg("--target").arg(ct.triple());
    }
    cmd.env("RUSTC", &rustc_bin)
        .env("PATH", &path_with_toolchain)
        // Prevent the outer build's flags from leaking in.
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .current_dir(&project_dir);

    // ── Step 4: collect result ────────────────────────────────────────────────
    let result = if live_output {
        // Stream directly to the parent terminal; nothing is captured.
        let status = cmd
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()?;

        if status.success() {
            Ok(None)
        } else {
            Err(CompileError::BuildFailed(CompileOutput {
                success: false,
                stdout:  String::new(),
                stderr:  String::new(),
            }))
        }
    } else {
        let compile_pb = if show_progress {
            use indicatif::{ProgressBar, ProgressStyle};
            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::with_template("{spinner:.cyan} {msg}")
                    .unwrap()
                    .tick_strings(&["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]),
            );
            pb.set_message("Compiling\u{2026}");
            pb.tick(); // force initial render before async tick fires
            pb.enable_steady_tick(std::time::Duration::from_millis(80));
            Some(pb)
        } else {
            None
        };

        let output: Output = cmd.output()?;

        if let Some(pb) = compile_pb { pb.finish_and_clear(); }

        let res = CompileOutput {
            success: output.status.success(),
            stdout:  String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr:  String::from_utf8_lossy(&output.stderr).into_owned(),
        };
        if res.success { Ok(Some(res)) } else { Err(CompileError::BuildFailed(res)) }
    };

    // ── Step 5: cleanup with optional progress ────────────────────────────────
    if show_progress {
        use indicatif::{ProgressBar, ProgressStyle};
        let tp = toolchain_tmp.into_path();
        let pp = _project_tmp.map(|t| t.into_path());

        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg}")
                .unwrap()
                .tick_strings(&["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]),
        );
        pb.set_message("Cleaning up\u{2026}");
        pb.tick(); // force initial render before async tick fires
        pb.enable_steady_tick(std::time::Duration::from_millis(80));
        let _ = std::fs::remove_dir_all(&tp);
        if let Some(p) = pp { let _ = std::fs::remove_dir_all(&p); }
        pb.finish_with_message("Done");
    }
    // else: toolchain_tmp and _project_tmp are dropped here → cleaned up automatically.

    result
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Minimal owned tempdir wrapper that deletes itself on drop.
#[cfg(not(target_arch = "wasm32"))]
struct TempDir(PathBuf);

#[cfg(not(target_arch = "wasm32"))]
impl TempDir {
    fn path(&self) -> &Path { &self.0 }

    /// Consume the wrapper without running `Drop`, handing the path to the
    /// caller who then becomes responsible for deleting the directory.
    fn into_path(self) -> PathBuf {
        let path = self.0.clone();
        std::mem::forget(self);
        path
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn tempdir() -> io::Result<TempDir> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("toolkit-zero-compiler-{}-{}", std::process::id(), nonce));
    std::fs::create_dir_all(&dir)?;
    Ok(TempDir(dir))
}

/// Stream-decompress and unpack a `.tar.xz` byte slice into `dest`.
/// When `show_progress` is `true`, displays a terminal progress bar while
/// reading the compressed stream. `label` appears in the bar message.
#[cfg(not(target_arch = "wasm32"))]
fn extract_tarball(bytes: &[u8], dest: &Path, show_progress: bool, label: &str) -> Result<(), CompileError> {
    if show_progress {
        use indicatif::{ProgressBar, ProgressStyle};
        let total = bytes.len() as u64;
        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.cyan} {msg}  [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})"
            )
            .unwrap()
            .progress_chars("=>-"),
        );
        pb.set_message(format!("decompressing {label}"));

        // Wrap the raw byte slice so reads advance the progress bar.
        let tracked = pb.wrap_read(bytes);
        let xz      = xz2::read::XzDecoder::new(tracked);
        let mut archive = tar::Archive::new(xz);
        archive.unpack(dest).map_err(CompileError::Io)?;

        pb.finish_with_message(format!("decompressed {label}"));
    } else {
        let xz = xz2::read::XzDecoder::new(bytes);
        let mut archive = tar::Archive::new(xz);
        archive.unpack(dest).map_err(CompileError::Io)?;
    }
    Ok(())
}

/// Copy every `rust-std-*/lib/rustlib/` subtree found directly inside `src_root`
/// into `dest_rustlib`, merging the two directory trees.
#[cfg(not(target_arch = "wasm32"))]
fn merge_std_components(src_root: &Path, dest_rustlib: &Path) -> Result<(), CompileError> {
    for entry in std::fs::read_dir(src_root).map_err(CompileError::Io)? {
        let entry = entry.map_err(CompileError::Io)?;
        let name = entry.file_name();
        if name.to_string_lossy().starts_with("rust-std-") {
            let std_rustlib = entry.path().join("lib/rustlib");
            if std_rustlib.exists() {
                copy_dir_merge(&std_rustlib, dest_rustlib).map_err(CompileError::Io)?;
            }
        }
    }
    Ok(())
}

/// Merge every `rust-std-*/lib/rustlib/` directory found inside
/// `toolchain_root` into `toolchain_root/rustc/lib/rustlib/` so that rustc
/// can locate the standard library from its own sysroot path.
///
/// The official Rust dist tarball ships `rustc` and the platform stdlib as
/// separate component subdirectories.  Without this merge, rustc cannot find
/// `std` / `core` / `alloc` and fails with `error[E0463]`.
#[cfg(not(target_arch = "wasm32"))]
fn merge_std_into_sysroot(toolchain_root: &Path) -> Result<(), CompileError> {
    let rustc_rustlib = toolchain_root.join("rustc/lib/rustlib");
    merge_std_components(toolchain_root, &rustc_rustlib)
}

/// Extract a cross-std tarball in `cross_tmp` and merge its `lib/rustlib/`
/// contents into the live toolchain sysroot at `toolchain_root/rustc/lib/rustlib/`.
///
/// The cross-std tarball has the structure:
/// ```text
/// rust-std-<version>-<triple>/
///   rust-std-<triple>/
///     lib/rustlib/<triple>/lib/*.rlib  …
/// ```
/// We navigate past the outer version directory and merge from there.
#[cfg(not(target_arch = "wasm32"))]
fn merge_cross_std(cross_tmp: &Path, toolchain_root: &Path) -> Result<(), CompileError> {
    let outer = find_single_subdir(cross_tmp)
        .ok_or_else(|| CompileError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "cross-std tarball has unexpected structure (no single top-level dir)",
        )))?;
    let dest_rustlib = toolchain_root.join("rustc/lib/rustlib");
    merge_std_components(&outer, &dest_rustlib)
}

/// Recursively copy the contents of `src` into `dst`, merging directories
/// (equivalent to `cp -r src/. dst/`).
#[cfg(not(target_arch = "wasm32"))]
fn copy_dir_merge(src: &Path, dst: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let dst_path = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_merge(&entry.path(), &dst_path)?;
        } else {
            std::fs::copy(entry.path(), &dst_path)?;
        }
    }
    Ok(())
}

/// Persistent cache directory for the cross-std tarball of `triple`.
/// `$CARGO_HOME/toolchain-cache/<triple>/<channel>/rust-std.tar.xz`
#[cfg(not(target_arch = "wasm32"))]
fn cross_std_cache_dir(triple: &str, channel: &str) -> PathBuf {
    let cargo_home = std::env::var("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .unwrap_or_else(|_| ".cargo".to_string());
            PathBuf::from(home).join(".cargo")
        });
    cargo_home.join("toolchain-cache").join(triple).join(channel)
}

/// Finds the `xz_url` and `xz_hash` values from `section` (e.g.
/// `[pkg.rust-std.target.aarch64-unknown-linux-gnu]`) in the manifest text.
#[cfg(not(target_arch = "wasm32"))]
fn parse_manifest_section_rt(text: &str, section: &str) -> Option<(String, String)> {
    let mut in_section = false;
    let mut xz_url: Option<String> = None;
    let mut xz_hash: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            if line == section { in_section = true; }
            else if in_section { break; }
            continue;
        }
        if !in_section { continue; }
        if let Some(rest) = line.strip_prefix("xz_url = \"") {
            xz_url = Some(rest.trim_end_matches('"').to_string());
        } else if let Some(rest) = line.strip_prefix("xz_hash = \"") {
            xz_hash = Some(rest.trim_end_matches('"').to_string());
        }
        if xz_url.is_some() && xz_hash.is_some() { break; }
    }
    Some((xz_url?, xz_hash?))
}

/// Download the `rust-std-<triple>` component, cache it, and merge its
/// `lib/rustlib/` tree into the live toolchain sysroot.
///
/// A progress bar is always shown regardless of the `show_progress` flag on
/// the parent [`compile`] call.
#[cfg(not(target_arch = "wasm32"))]
fn fetch_cross_std(triple: &str, toolchain_root: &Path, _show_progress: bool, channel: ToolchainChannel) -> Result<(), CompileError> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    use indicatif::{ProgressBar, ProgressStyle};

    let cache_dir  = cross_std_cache_dir(triple, channel.as_str());
    let cache_file = cache_dir.join("rust-std.tar.xz");

    let tarball_bytes: Vec<u8> = if cache_file.exists() {
        std::fs::read(&cache_file).map_err(CompileError::Io)?
    } else {
        // ── 1. Show download spinner ───────────────────────────────────────────
        let dl_pb = ProgressBar::new_spinner();
        dl_pb.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg}")
                .unwrap()
                .tick_strings(&["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]),
        );
        let manifest_url = format!("https://static.rust-lang.org/dist/channel-rust-{}.toml", channel.as_str());
        dl_pb.set_message(format!("fetching manifest for {triple}…"));
        dl_pb.tick();
        dl_pb.enable_steady_tick(std::time::Duration::from_millis(80));

        // ── 2. Fetch manifest (stable or nightly) ──────────────────────────────
        let mut manifest_bytes = Vec::new();
        ureq::get(&manifest_url)
            .call()
            .map_err(|e| CompileError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?
            .into_reader()
            .read_to_end(&mut manifest_bytes)
            .map_err(CompileError::Io)?;
        let manifest = String::from_utf8(manifest_bytes)
            .map_err(|e| CompileError::Io(io::Error::new(io::ErrorKind::InvalidData, e.to_string())))?;

        // ── 3. Parse xz_url + xz_hash ─────────────────────────────────────────
        let section = format!("[pkg.rust-std.target.{triple}]");
        let (xz_url, xz_hash) = parse_manifest_section_rt(&manifest, &section)
            .ok_or_else(|| CompileError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("target '{triple}' has no rust-std entry in the {} manifest", channel.as_str()),
            )))?;

        // ── 4. Download tarball ─────────────────────────────────────────────
        dl_pb.set_message(format!("downloading rust-std for {triple}…"));
        let response = ureq::get(&xz_url)
            .call()
            .map_err(|e| CompileError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?;

        // Upgrade to a proper bytes/total bar if Content-Length is known.
        let total_opt: Option<u64> = response
            .header("content-length")
            .and_then(|v| v.parse().ok());
        dl_pb.finish_and_clear();

        let dl_pb2 = if let Some(total) = total_opt {
            let pb = ProgressBar::new(total);
            pb.set_style(
                ProgressStyle::with_template(
                    "{spinner:.cyan} {msg}  [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})"
                )
                .unwrap()
                .progress_chars("=>-"),
            );
            pb.set_message(format!("downloading rust-std for {triple}"));
            pb
        } else {
            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::with_template("{spinner:.cyan} {msg} {bytes}")
                    .unwrap()
                    .tick_strings(&["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]),
            );
            pb.set_message(format!("downloading rust-std for {triple}…"));
            pb
        };
        dl_pb2.tick();
        dl_pb2.enable_steady_tick(std::time::Duration::from_millis(80));
        let mut reader = dl_pb2.wrap_read(response.into_reader());
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).map_err(CompileError::Io)?;
        dl_pb2.finish_with_message(format!("downloaded rust-std for {triple}"));

        // ── 5. Verify SHA-256 ───────────────────────────────────────────────
        let expected = xz_hash.strip_prefix("sha256:").unwrap_or(&xz_hash).to_string();
        let hash = Sha256::digest(&bytes);
        let actual: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        if actual != expected {
            return Err(CompileError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("SHA-256 mismatch for rust-std-{triple}: expected {expected}, got {actual}"),
            )));
        }

        // ── 6. Cache ─────────────────────────────────────────────────────────
        std::fs::create_dir_all(&cache_dir).map_err(CompileError::Io)?;
        std::fs::write(&cache_file, &bytes).map_err(CompileError::Io)?;

        bytes
    };

    // ── 7. Extract and merge into sysroot ──────────────────────────────────
    let cross_tmp = tempdir()?;
    extract_tarball(&tarball_bytes, cross_tmp.path(), true, &format!("rust-std for {triple}"))?;
    merge_cross_std(cross_tmp.path(), toolchain_root)?;

    Ok(())
}

/// After extraction the tarball contains one top-level directory.
/// Returns that directory's path, or `None` if there is not exactly one.
fn find_single_subdir(parent: &Path) -> Option<PathBuf> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(parent)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    if entries.len() == 1 { entries.pop() } else { None }
}

/// Validate that `dir` is a plausible Rust project (has `Cargo.toml` and
/// either `src/main.rs` or `src/lib.rs`).
fn validate_project(dir: &Path) -> Result<(), CompileError> {
    if !dir.join("Cargo.toml").exists() {
        return Err(CompileError::InvalidProject(format!(
            "{}: missing Cargo.toml", dir.display()
        )));
    }
    let src = dir.join("src");
    if !src.join("main.rs").exists() && !src.join("lib.rs").exists() {
        return Err(CompileError::InvalidProject(format!(
            "{}: missing src/main.rs or src/lib.rs", dir.display()
        )));
    }
    Ok(())
}

/// Build a minimal Cargo project scaffold around a single `.rs` file.
///
/// Layout:
/// ```text
/// <tmp>/
///   Cargo.toml
///   src/
///     main.rs   ← copy of `src_file`
/// ```
///
/// Returns the path to the project root inside `tmp`.
fn synthesise_project(
    src_file: &Path,
    deps:     &[Dependency],
    tmp:      &Path,
) -> Result<PathBuf, CompileError> {
    let stem = src_file
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("project");

    // Sanitise the name: Cargo requires snake_case / kebab-case names.
    let project_name: String = stem
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '_' })
        .collect();

    let project_dir = tmp.join(&project_name);
    let src_dir     = project_dir.join("src");
    std::fs::create_dir_all(&src_dir)?;

    // Copy the source file as src/main.rs
    std::fs::copy(src_file, src_dir.join("main.rs"))?;

    // Write Cargo.toml
    let mut toml = format!(
        "[package]\n\
         name    = \"{}\"\n\
         version = \"0.1.0\"\n\
         edition = \"2021\"\n",
        project_name
    );

    if !deps.is_empty() {
        toml.push_str("\n[dependencies]\n");
        for dep in deps {
            toml.push_str(&format!("{} = {}\n", dep.name, dep.to_toml_value()));
        }
    }

    std::fs::write(project_dir.join("Cargo.toml"), &toml)?;

    Ok(project_dir)
}
