//! Geographic location acquisition API.
//!
//! This module serves as the authoritative entry point for all geographic
//! coordinate retrieval within the toolkit. It is structured around the
//! concept of interchangeable *acquisition strategies*: each sub-module
//! implements a self-contained mechanism for obtaining location data,
//! allowing new strategies to be introduced incrementally without disrupting
//! the existing public interface.
//!
//! # Acquisition strategies
//!
//! | Sub-module | Mechanism | Platform support |
//! |---|---|---|
//! | [`browser`] | Instantiates a transient local HTTP server and directs the
//! system's default browser to a consent page, which acquires coordinates
//! through the standardised [Web Geolocation API]. | Platform-independent |
//!
//! [Web Geolocation API]: https://developer.mozilla.org/en-US/docs/Web/API/Geolocation_API
//!
//! # Feature flag
//!
//! This module is compiled when the `location` (or `location-native`) feature is enabled:
//!
//! ```toml
//! [dependencies]
//! toolkit-zero = { version = "...", features = ["location"] }
//! ```

#[cfg(feature = "location-native")]
pub mod browser;

#[cfg(feature = "backend-deps")]
pub mod backend_deps;