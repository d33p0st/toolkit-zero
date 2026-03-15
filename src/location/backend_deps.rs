//! Re-exports all backend dependencies used by the `location` module and its
//! sub-module (`browser`).
//!
//! Only available when the `backend-deps` feature is enabled together with
//! `location` (or `location-browser`).

// browser sub-module deps
#[cfg(feature = "location-browser")]
pub use tokio;

#[cfg(feature = "location-browser")]
pub use serde;

#[cfg(feature = "location-browser")]
pub use webbrowser;

#[cfg(feature = "location-browser")]
pub use rand;
