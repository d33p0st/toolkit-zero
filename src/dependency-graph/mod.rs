//! Build-time dependency-graph fingerprinting (**IronPrint**).
//!
//! Two mutually independent feature gates control the facility:
//!
//! | Feature | Provided symbols |
//! |---|---|
//! | `dependency-graph-build` | [`build::generate_ironprint`] — writes a compact, normalised `ironprint.json` to `$OUT_DIR`;<br>[`build::export`] — optionally writes a pretty-printed copy alongside `Cargo.toml` |
//! | `dependency-graph-capture` | [`capture::parse`] — deserialises the embedded snapshot into a typed [`capture::IronprintData`];<br>[`capture::as_bytes`] — returns the raw, deterministic JSON bytes |
//!
//! Place `dependency-graph-build` in `[build-dependencies]` and
//! `dependency-graph-capture` in `[dependencies]`; neither implies the other.
//!
//! ## Concerns
//!
//! * The fingerprint is stored as **plain text** in the binary's read-only data
//!   section. It is informational in nature; it does not constitute a security
//!   boundary and is not tamper-evident.
//! * Calling `export(true)` writes `ironprint.json` to the crate root. Add this
//!   file to `.gitignore` to prevent unintentional exposure of build-environment
//!   details.
//! * The snapshot is fixed at compile time and does not reflect runtime state.

#[cfg(feature = "dependency-graph-build")]
pub mod build;

#[cfg(feature = "dependency-graph-capture")]
pub mod capture;

#[cfg(feature = "backend-deps")]
pub mod backend_deps;
