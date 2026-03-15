//! Re-exports all backend dependencies used by the `socket` module and its
//! sub-modules (`server`, `client`).
//!
//! Only available when the `backend-deps` feature is enabled together with at
//! least one of `socket-server` or `socket-client`.

// ── Shared by both server and client ─────────────────────────────────────────

#[cfg(any(feature = "socket-server", feature = "socket-client"))]
pub use bincode;

#[cfg(any(feature = "socket-server", feature = "socket-client"))]
pub use base64;

#[cfg(any(feature = "socket-server", feature = "socket-client"))]
pub use serde;

#[cfg(any(feature = "socket-server", feature = "socket-client"))]
pub use tokio;

#[cfg(any(feature = "socket-server", feature = "socket-client"))]
pub use log;

// ── socket-server only ───────────────────────────────────────────────────────

#[cfg(feature = "socket-server")]
pub use bytes;

#[cfg(feature = "socket-server")]
pub use serde_urlencoded;

#[cfg(feature = "socket-server")]
pub use hyper;

#[cfg(feature = "socket-server")]
pub use http;

#[cfg(feature = "socket-server")]
pub use hyper_util;

#[cfg(feature = "socket-server")]
pub use http_body_util;

// ── socket-client only ───────────────────────────────────────────────────────

#[cfg(feature = "socket-client")]
pub use reqwest;