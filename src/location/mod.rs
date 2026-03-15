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
//! # Attribute macro
//!
//! The [`browser::browser`] attribute macro wraps the call to
//! [`browser::__location__`] or [`browser::__location_async__`] and builds the
//! [`browser::PageTemplate`] for you.
//!
//! ```rust,ignore
//! use toolkit_zero::location::browser::{browser, LocationData, LocationError};
//!
//! async fn run() -> Result<LocationData, LocationError> {
//!     #[browser(title = "My App")]
//!     fn loc() {}
//!     Ok(loc)
//! }
//! ```
//!
//! # Feature flag
//!
//! This module is compiled when the `location` (or `location-browser`) feature is enabled:
//!
//! ```toml
//! [dependencies]
//! toolkit-zero = { version = "...", features = ["location"] }
//! ```

#[cfg(feature = "location-browser")]
pub mod browser;

#[cfg(feature = "backend-deps")]
pub mod backend_deps;