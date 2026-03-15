//! Runtime reader for the `ironprint.json` fingerprint embedded in the binary.
//!
//! The companion `build` module (feature `dependency-graph-build`) writes
//! `ironprint.json` to `$OUT_DIR` at compile time. The downstream binary
//! embeds it with:
//!
//! ```rust,ignore
//! const IRONPRINT: &str = include_str!(concat!(env!("OUT_DIR"), "/ironprint.json"));
//! ```
//!
//! ## Functions
//!
//! * [`parse`] — deserialises the embedded JSON into a typed [`IronprintData`]
//!   struct. Returns [`CaptureError`] if the JSON is malformed or a required
//!   section is absent.
//! * [`as_bytes`] — returns the raw JSON bytes. Because the JSON is normalised
//!   and sorted at build time, the returned bytes are stable and deterministic
//!   across equivalent builds.
//!
//! ## Concerns
//!
//! * The data is a **read-only snapshot** fixed at compile time. It reflects the
//!   build environment at the time of compilation, not the current runtime state.
//! * The fingerprint resides as plain text in the binary's read-only data
//!   section. It is neither encrypted nor obfuscated and is visible to anyone
//!   with access to the binary.

use std::collections::BTreeMap;

use serde_json::Value;

// ─── error ────────────────────────────────────────────────────────────────────

/// Errors that can occur while reading a captured ironprint.
#[derive(Debug)]
pub enum CaptureError {
    /// The embedded JSON is not valid.
    InvalidJson(String),
    /// A required top-level section is missing.
    MissingSection(&'static str),
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidJson(e)      => write!(f, "ironprint JSON is invalid: {e}"),
            Self::MissingSection(key) => write!(f, "ironprint is missing section: {key}"),
        }
    }
}

impl std::error::Error for CaptureError {}

// ─── typed data ───────────────────────────────────────────────────────────────

/// Parsed contents of `ironprint.json`.
///
/// All fields map directly onto the sections produced by
/// [`build::generate_ironprint`](super::build::generate_ironprint).
#[derive(Debug, Clone)]
pub struct IronprintData {
    /// Package name and version.
    pub package: PackageInfo,
    /// Build-environment snapshot.
    pub build: BuildInfo,
    /// SHA-256 hex digest of `Cargo.lock` (comments stripped).
    pub cargo_lock_sha256: String,
    /// Normalised `cargo metadata` dependency graph (raw JSON value).
    pub deps: Value,
    /// Per-file SHA-256 digests of every `.rs` file under `src/`.
    pub source: BTreeMap<String, String>,
}

/// Package identity section.
#[derive(Debug, Clone)]
pub struct PackageInfo {
    pub name:    String,
    pub version: String,
}

/// Build environment section.
#[derive(Debug, Clone)]
pub struct BuildInfo {
    /// Active cargo feature names, sorted.
    pub features:      Vec<String>,
    /// Optimisation level (`"0"` / `"1"` / `"2"` / `"3"` / `"s"` / `"z"`).
    pub opt_level:     String,
    /// Cargo profile (`"debug"` / `"release"` / …).
    pub profile:       String,
    /// Full `rustc --version` string.
    pub rustc_version: String,
    /// Target triple, e.g. `"x86_64-apple-darwin"`.
    pub target:        String,
}

// ─── public API ───────────────────────────────────────────────────────────────

/// Parse the embedded ironprint JSON into a typed [`IronprintData`].
///
/// Pass the `&str` produced by
/// `include_str!(concat!(env!("OUT_DIR"), "/ironprint.json"))`.
pub fn parse(json: &str) -> Result<IronprintData, CaptureError> {
    let root: Value = serde_json::from_str(json)
        .map_err(|e| CaptureError::InvalidJson(e.to_string()))?;

    let obj = root.as_object()
        .ok_or(CaptureError::InvalidJson("root is not an object".into()))?;

    // ── package ───────────────────────────────────────────────────────────────
    let pkg = obj.get("package")
        .and_then(|v| v.as_object())
        .ok_or(CaptureError::MissingSection("package"))?;

    let package = PackageInfo {
        name:    pkg.get("name").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
        version: pkg.get("version").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
    };

    // ── build ─────────────────────────────────────────────────────────────────
    let bld = obj.get("build")
        .and_then(|v| v.as_object())
        .ok_or(CaptureError::MissingSection("build"))?;

    let features = bld.get("features")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
               .filter_map(|v| v.as_str())
               .map(str::to_owned)
               .collect()
        })
        .unwrap_or_default();

    let build = BuildInfo {
        features,
        opt_level:     bld.get("opt_level").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
        profile:       bld.get("profile").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
        rustc_version: bld.get("rustc_version").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
        target:        bld.get("target").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
    };

    // ── cargo_lock_sha256 ─────────────────────────────────────────────────────
    let cargo_lock_sha256 = obj.get("cargo_lock_sha256")
        .and_then(|v| v.as_str())
        .ok_or(CaptureError::MissingSection("cargo_lock_sha256"))?
        .to_owned();

    // ── deps ──────────────────────────────────────────────────────────────────
    let deps = obj.get("deps")
        .ok_or(CaptureError::MissingSection("deps"))?
        .clone();

    // ── source ────────────────────────────────────────────────────────────────
    let source = obj.get("source")
        .and_then(|v| v.as_object())
        .map(|map| {
            map.iter()
               .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_owned()))
               .collect()
        })
        .unwrap_or_default();

    Ok(IronprintData { package, build, cargo_lock_sha256, deps, source })
}

/// Return the raw bytes of the ironprint JSON string.
///
/// Because `ironprint.json` is already normalised (sorted keys, no whitespace,
/// no absolute paths) at build time, the returned bytes are stable and
/// deterministic across equivalent builds.
///
/// ```rust,ignore
/// const IRONPRINT: &str = include_str!(concat!(env!("OUT_DIR"), "/ironprint.json"));
///
/// let bytes: &[u8] = toolkit_zero::dependency_graph::capture::as_bytes(IRONPRINT);
/// ```
pub fn as_bytes(json: &str) -> &[u8] {
    json.as_bytes()
}
