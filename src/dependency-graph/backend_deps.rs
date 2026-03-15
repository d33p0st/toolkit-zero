//! Re-exports all backend dependencies used by the `dependency-graph` module.
//!
//! Only available when the `backend-deps` feature is enabled together with
//! `dependency-graph-build` and/or `dependency-graph-capture`.

#[cfg(any(feature = "dependency-graph-build", feature = "dependency-graph-capture"))]
pub use serde_json;

#[cfg(feature = "dependency-graph-build")]
pub use sha2;
