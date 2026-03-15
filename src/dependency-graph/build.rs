//! Build-time fingerprint generator for use in a downstream `build.rs`.
//!
//! Produces **`fingerprint.json`** in `$OUT_DIR`: a compact, normalised,
//! deterministically sorted JSON document capturing a stable snapshot of the
//! build environment.
//!
//! ## Functions
//!
//! | Function | Description |
//! |---|---|
//! | [`generate_fingerprint`] | Always call this. Writes compact `fingerprint.json` to `$OUT_DIR` and emits `cargo:rerun-if-changed` directives. |
//! | [`export`] | Optional. Writes a pretty-printed `fingerprint.json` alongside `Cargo.toml` for local inspection. Pass `false` or condition on `cfg!(debug_assertions)` to suppress in release builds. |
//!
//! ## Sections captured
//!
//! | Section | Contents |
//! |---|---|
//! | `package` | Crate name and version |
//! | `build` | Profile, opt-level, target triple, rustc version, and active feature flags |
//! | `deps` | Full normalised `cargo metadata` dependency graph (sorted, no absolute paths) |
//! | `cargo_lock_sha256` | SHA-256 of `Cargo.lock` (comment lines stripped) |
//! | `source` | SHA-256 of every `.rs` file under `src/` |
//!
//! ## Usage
//!
//! In the downstream crate's `build.rs`:
//!
//! ```rust,ignore
//! fn main() {
//!     toolkit_zero::dependency_graph::build::generate_fingerprint()
//!         .expect("fingerprint generation failed");
//!     // optional — pretty-print alongside Cargo.toml for local inspection
//!     toolkit_zero::dependency_graph::build::export(cfg!(debug_assertions))
//!         .expect("fingerprint export failed");
//! }
//! ```
//!
//! Embed the fingerprint in the binary:
//!
//! ```rust,ignore
//! const BUILD_TIME_FINGERPRINT: &str = include_str!(concat!(env!("OUT_DIR"), "/fingerprint.json"));
//! ```
//!
//! ## Concerns
//!
//! * **Not tamper-proof** — the fingerprint resides as plain text in the binary's
//!   read-only data section. It is informational in nature; it does not constitute
//!   a security boundary.
//! * **Export file** — `export(true)` writes `fingerprint.json` to the crate root.
//!   Add it to `.gitignore` to prevent unintentional commits.
//! * **Build-time overhead** — `cargo metadata` is executed on every rebuild.
//!   The `cargo:rerun-if-changed` directives restrict this to changes in `src/`,
//!   `Cargo.toml`, or `Cargo.lock`.
//! * **Path stripping** — absolute paths (`workspace_root`, `manifest_path`,
//!   `src_path`, `path`, and others) are removed from `cargo metadata` output
//!   to ensure the fingerprint is stable across machines and checkout locations.
//! * **Feature scope** — `build.features` captures the active features of the
//!   crate being built, not toolkit-zero's own features.
//! * **Compile-time only** — the snapshot does not update at runtime.

use std::{collections::BTreeMap, env, fs, path::Path, process::Command};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

// ─── public error ────────────────────────────────────────────────────────────

/// Errors that can occur while generating `fingerprint.json`.
#[derive(Debug)]
pub enum BuildTimeFingerprintError {
    /// `cargo metadata` process failed or returned non-zero.
    CargoMetadataFailed(String),
    /// `cargo metadata` stdout was not valid UTF-8.
    CargoMetadataNotUtf8,
    /// `cargo metadata` stdout could not be parsed as JSON.
    CargoMetadataInvalidJson(String),
    /// `Cargo.lock` was not found at the expected path.
    CargoLockNotFound(String),
    /// A filesystem operation failed.
    IoError(std::io::Error),
    /// The final JSON could not be serialised.
    SerializationFailed(String),
}

impl std::fmt::Display for BuildTimeFingerprintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CargoMetadataFailed(e)      => write!(f, "cargo metadata failed: {e}"),
            Self::CargoMetadataNotUtf8        => write!(f, "cargo metadata output is not valid UTF-8"),
            Self::CargoMetadataInvalidJson(e) => write!(f, "cargo metadata output is invalid JSON: {e}"),
            Self::CargoLockNotFound(p)        => write!(f, "Cargo.lock not found at: {p}"),
            Self::IoError(e)                  => write!(f, "I/O error: {e}"),
            Self::SerializationFailed(e)      => write!(f, "serialisation failed: {e}"),
        }
    }
}

impl std::error::Error for BuildTimeFingerprintError {}

impl From<std::io::Error> for BuildTimeFingerprintError {
    fn from(e: std::io::Error) -> Self { Self::IoError(e) }
}

// ─── public entry point ──────────────────────────────────────────────────────

/// Generate `fingerprint.json` in `$OUT_DIR`.
///
/// All inputs are read from the environment variables that Cargo sets for
/// `build.rs` scripts. The necessary `cargo:rerun-if-changed` directives are
/// emitted automatically; no additional boilerplate is required in the
/// calling `build.rs`.
///
/// To obtain a pretty-printed copy alongside `Cargo.toml` for local
/// inspection, also call [`export`]`(true)`.
///
/// ```rust,ignore
/// fn main() {
///     toolkit_zero::dependency_graph::build::generate_fingerprint()
///         .expect("fingerprint generation failed");
/// }
/// ```
pub fn generate_fingerprint() -> Result<(), BuildTimeFingerprintError> {
    // Emit rerun directives — cargo reads these from build script stdout
    // regardless of which function in the call stack prints them.
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=Cargo.lock");

    let out_dir = env::var("OUT_DIR").unwrap_or_default();

    let fingerprint = build_fingerprint()?;
    let compact = serde_json::to_string(&fingerprint)
        .map_err(|e| BuildTimeFingerprintError::SerializationFailed(e.to_string()))?;

    fs::write(format!("{out_dir}/fingerprint.json"), compact)?;
    Ok(())
}

/// Write a pretty-printed `fingerprint.json` alongside the crate's `Cargo.toml`
/// when `enabled` is `true`.
///
/// This file is intended for **local inspection only**. It is distinct from
/// the compact `fingerprint.json` written to `$OUT_DIR`; the binary always
/// embeds the `$OUT_DIR` copy. Pass `false`, or condition the call on
/// `cfg!(debug_assertions)`, to suppress the file in release builds.
///
/// # Concerns
///
/// The exported file contains the full dependency graph, per-file source
/// hashes, target triple, and compiler version. **Add `fingerprint.json` to
/// `.gitignore`** to prevent unintentional commits. If an error occurs and
/// `enabled` is `true`, the file may be partially written; the error is
/// propagated to the caller.
///
/// ```rust,ignore
/// fn main() {
///     toolkit_zero::dependency_graph::build::generate_fingerprint()
///         .expect("fingerprint generation failed");
///     toolkit_zero::dependency_graph::build::export(cfg!(debug_assertions))
///         .expect("fingerprint export failed");
/// }
/// ```
pub fn export(enabled: bool) -> Result<(), BuildTimeFingerprintError> {
    if !enabled { return Ok(()); }

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_default();

    let fingerprint = build_fingerprint()?;
    let pretty = serde_json::to_string_pretty(&fingerprint)
        .map_err(|e| BuildTimeFingerprintError::SerializationFailed(e.to_string()))?;

    fs::write(format!("{manifest_dir}/fingerprint.json"), pretty)?;
    Ok(())
}

// ─── core fingerprint builder (shared by generate_fingerprint + export) ────────

fn build_fingerprint() -> Result<Value, BuildTimeFingerprintError> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_default();

    // ── 1. Package identity ───────────────────────────────────────────────────
    let pkg_name    = env::var("CARGO_PKG_NAME").unwrap_or_default();
    let pkg_version = env::var("CARGO_PKG_VERSION").unwrap_or_default();

    // ── 2. Build environment ──────────────────────────────────────────────────
    let profile   = env::var("PROFILE").unwrap_or_default();
    let opt_level = env::var("OPT_LEVEL").unwrap_or_default();
    let target    = env::var("TARGET").unwrap_or_default();

    // Collect all active features (CARGO_FEATURE_<NAME> → "feature-name")
    let mut features: Vec<String> = env::vars()
        .filter_map(|(k, _)| {
            k.strip_prefix("CARGO_FEATURE_")
                .map(|feat| feat.to_lowercase().replace('_', "-"))
        })
        .collect();
    features.sort_unstable();

    // ── 3. rustc version ──────────────────────────────────────────────────────
    let rustc_version = Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|| "unknown".to_owned());

    // ── 4. Normalised cargo metadata ──────────────────────────────────────────
    let cargo_bin = env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());

    let meta_out = Command::new(&cargo_bin)
        .args([
            "metadata",
            "--format-version=1",
            "--manifest-path",
            &format!("{manifest_dir}/Cargo.toml"),
        ])
        .output()
        .map_err(|e| BuildTimeFingerprintError::CargoMetadataFailed(e.to_string()))?;

    if !meta_out.status.success() {
        let err = String::from_utf8_lossy(&meta_out.stderr).to_string();
        return Err(BuildTimeFingerprintError::CargoMetadataFailed(err));
    }

    let meta_str = String::from_utf8(meta_out.stdout)
        .map_err(|_| BuildTimeFingerprintError::CargoMetadataNotUtf8)?;

    let meta_raw: Value = serde_json::from_str(&meta_str)
        .map_err(|e| BuildTimeFingerprintError::CargoMetadataInvalidJson(e.to_string()))?;

    let meta_clean      = strip_absolute_paths(meta_raw);
    let meta_normalised = normalise_json(meta_clean);

    // ── 5. Cargo.lock SHA-256 ─────────────────────────────────────────────────
    let lock_path = format!("{manifest_dir}/Cargo.lock");
    if !Path::new(&lock_path).exists() {
        return Err(BuildTimeFingerprintError::CargoLockNotFound(lock_path));
    }
    let lock_raw = fs::read(&lock_path)?;
    let lock_stripped: Vec<u8> = lock_raw
        .split(|&b| b == b'\n')
        .filter(|line| !line.starts_with(b"#"))
        .flat_map(|line| line.iter().chain(std::iter::once(&b'\n')))
        .copied()
        .collect();
    let lock_sha256 = hex_sha256(&lock_stripped);

    // ── 6. Source file hashes ─────────────────────────────────────────────────
    let src_dir = format!("{manifest_dir}/src");
    let source_hashes = hash_source_tree(&src_dir, &manifest_dir)?;

    // ── 7. Assemble & normalise ───────────────────────────────────────────────
    let fingerprint = json!({
        "package": {
            "name":    pkg_name,
            "version": pkg_version,
        },
        "build": {
            "features":      features,
            "opt_level":     opt_level,
            "profile":       profile,
            "rustc_version": rustc_version,
            "target":        target,
        },
        "cargo_lock_sha256": lock_sha256,
        "deps":   meta_normalised,
        "source": source_hashes,
    });

    Ok(normalise_json(fingerprint))
}

// ─── JSON normalisation ───────────────────────────────────────────────────────

/// Recursively normalise a [`Value`]:
///
/// * **Objects** — keys are sorted alphabetically (serde_json's default `Map`
///   is `BTreeMap`-backed, so collecting into it sorts automatically).
/// * **Arrays** — items are recursively normalised *and* reordered by a stable
///   derived key so that cargo-version-dependent ordering differences vanish.
/// * **Primitives** — unchanged.
fn normalise_json(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            // BTreeMap-backed Map: inserting via collect() automatically sorts keys.
            let sorted: Map<String, Value> = map
                .into_iter()
                .map(|(k, v)| (k, normalise_json(v)))
                .collect();
            Value::Object(sorted)
        }
        Value::Array(arr) => {
            let mut items: Vec<Value> = arr.into_iter().map(normalise_json).collect();
            items.sort_by(|a, b| array_sort_key(a).cmp(&array_sort_key(b)));
            Value::Array(items)
        }
        other => other,
    }
}

/// Derive a stable sort key for an element inside a JSON array.
///
/// Preference order:
/// 1. `"id"` field (cargo package IDs are globally unique and stable)
/// 2. `"name"` + `"version"` concatenated
/// 3. Compact JSON serialisation as a last resort
fn array_sort_key(v: &Value) -> String {
    if let Some(obj) = v.as_object() {
        if let Some(id) = obj.get("id").and_then(|v| v.as_str()) {
            return id.to_owned();
        }
        let name = obj.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let ver  = obj.get("version").and_then(|v| v.as_str()).unwrap_or("");
        if !name.is_empty() {
            return format!("{name}@{ver}");
        }
    }
    serde_json::to_string(v).unwrap_or_default()
}

/// Remove fields that carry absolute or machine-specific paths from the
/// `cargo metadata` JSON so the digest is stable across different machines
/// and checkout locations.
///
/// Removed fields (all carry machine-specific absolute paths):
/// * `workspace_root` — absolute path to workspace checkout
/// * `target_directory` / `build_directory` — absolute path to `target/`
/// * `manifest_path` — per-package absolute `Cargo.toml` path
/// * `src_path` — per-target absolute source file path
/// * `workspace_members` / `workspace_default_members` — IDs with `file://` paths
fn strip_absolute_paths(value: Value) -> Value {
    match value {
        Value::Object(mut map) => {
            for key in &[
                "workspace_root",
                "workspace_members",
                "workspace_default_members",
                "target_directory",
                "build_directory",
                "manifest_path",
                "src_path",
                "path",
            ] {
                map.remove(*key);
            }
            Value::Object(
                map.into_iter()
                    .map(|(k, v)| (k, strip_absolute_paths(v)))
                    .collect(),
            )
        }
        Value::Array(arr) => {
            Value::Array(arr.into_iter().map(strip_absolute_paths).collect())
        }
        other => other,
    }
}

// ─── hashing helpers ─────────────────────────────────────────────────────────

/// SHA-256 of `data`, returned as a lowercase hex string.
fn hex_sha256(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

/// Walk `src_dir` recursively, hash every `.rs` file, and return a
/// `BTreeMap<relative_path, "sha256:<hex>">`.
///
/// Paths are relative to `manifest_dir` and always use `/` as the separator.
fn hash_source_tree(
    src_dir:      &str,
    manifest_dir: &str,
) -> Result<BTreeMap<String, String>, BuildTimeFingerprintError> {
    let mut map = BTreeMap::new();
    visit_rs_files(Path::new(src_dir), Path::new(manifest_dir), &mut map)?;
    Ok(map)
}

fn visit_rs_files(
    dir:  &Path,
    base: &Path,
    map:  &mut BTreeMap<String, String>,
) -> Result<(), BuildTimeFingerprintError> {
    if !dir.exists() {
        return Ok(());
    }
    let mut entries: Vec<_> = fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    // Sort for determinism across file-systems that don't guarantee readdir order.
    entries.sort_by_key(|e| e.path());

    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            visit_rs_files(&path, base, map)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            let rel = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let contents = fs::read(&path)?;
            map.insert(rel, format!("sha256:{}", hex_sha256(&contents)));
        }
    }
    Ok(())
}
