//! Re-exports all backend dependencies used by the `location` module and its
//! sub-module (`browser`).
//!
//! Only available when the `backend-deps` feature is enabled together with
//! `location` (or `location-native`).

// browser sub-module deps
#[cfg(feature = "location-native")]
pub use tokio;

#[cfg(feature = "location-native")]
pub use serde;

#[cfg(feature = "location-native")]
pub use webbrowser;

#[cfg(feature = "location-native")]
pub use rand;
