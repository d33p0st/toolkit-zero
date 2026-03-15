//! Demonstrates the `location-browser` feature: acquire device coordinates via
//! the browser's standard Geolocation API.
//!
//! What this example covers:
//!   - All three [`PageTemplate`] variants (Default, Tickbox, Custom)
//!   - Blocking call ([`__location__`]) — safe from any context
//!   - Async call ([`__location_async__`]) — preferred inside `#[tokio::main]`
//!   - The `#[browser]` attribute macro shorthand (compile check only)
//!   - [`LocationData`] field access
//!   - Error handling with [`LocationError`]
//!
//! > **Note:** This example opens the system's default browser and spins up a
//! > temporary local HTTP server.  It requires a browser with Geolocation API
//! > support and an internet connection may be needed for the browser to provide
//! > accurate coordinates.  The call blocks until the user grants or denies the
//! > permission prompt.
//!
//! Run with:
//! ```sh
//! cargo run --example location_browser --features location
//! ```

use toolkit_zero::location::browser::{
    PageTemplate, LocationData, LocationError,
    __location__, __location_async__,
    browser,
};

// ─── PageTemplate construction ────────────────────────────────────────────────

/// Shows how to build each [`PageTemplate`] variant.
/// This function is intentionally `#[allow(dead_code)]` — it is a compile-check
/// and documentation aid; the templates are not actually served in this example.
#[allow(dead_code)]
fn template_examples() {
    // 1. Built-in default — a simple single-button consent page.
    let _default = PageTemplate::default();

    // 2. Default with a custom title.
    let _custom_title = PageTemplate::Default {
        title:     Some("My App — Share Location".into()),
        body_text: Some("This app needs your location to show nearby results.".into()),
    };

    // 3. Tickbox variant — user must check a box before the button becomes active.
    let _tickbox = PageTemplate::Tickbox {
        title:        Some("Location Consent".into()),
        body_text:    None,
        consent_text: Some("I agree to share my location with this application.".into()),
    };

    // 4. Fully custom HTML — place `{}` where the capture button should appear.
    let _custom_html = PageTemplate::Custom(
        r#"<!DOCTYPE html>
<html>
<head><title>Where are you?</title></head>
<body>
  <h1>Share your location</h1>
  {}
  <p id="status"></p>
</body>
</html>"#
        .into(),
    );
}

// ─── #[browser] macro compile check ──────────────────────────────────────────

/// Compile-check for the `#[browser]` attribute macro.
/// Each decorated `fn` is replaced in-place with a location-capture statement.
/// The function **name** becomes the binding that holds the
/// [`LocationData`] (or propagates the [`LocationError`]).
#[allow(dead_code)]
async fn browser_macro_forms() -> Result<LocationData, LocationError> {
    // Async, plain Default template.
    #[browser]
    fn loc() {}
    Ok(loc)
}

#[allow(dead_code)]
async fn browser_macro_tickbox() -> Result<LocationData, LocationError> {
    // Async, Tickbox with custom consent text.
    #[browser(tickbox, title = "Verify Location", consent = "I agree")]
    fn loc() {}
    Ok(loc)
}

#[allow(dead_code)]
fn browser_macro_sync() -> Result<LocationData, LocationError> {
    // Blocking, custom title only.
    #[browser(sync, title = "My App")]
    fn loc() {}
    Ok(loc)
}

// ─── Runtime helpers ──────────────────────────────────────────────────────────

/// Pretty-print a [`LocationData`] value.
fn print_location(label: &str, data: &LocationData) {
    println!("{label}");
    println!("  latitude  : {:.6}°", data.latitude);
    println!("  longitude : {:.6}°", data.longitude);
    println!("  accuracy  : {:.1} m (95% confidence radius)", data.accuracy);
    if let Some(alt) = data.altitude {
        println!("  altitude  : {alt:.1} m");
    }
    if let Some(spd) = data.speed {
        println!("  speed     : {spd:.1} m/s");
    }
}

// ─── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    println!("=== location_browser example ===\n");

    // ── 1. Async call (preferred inside #[tokio::main]) ───────────────────────
    println!("Opening browser to acquire location (async)…");
    match __location_async__(PageTemplate::default()).await {
        Ok(data) => print_location("Async result:", &data),
        Err(LocationError::PermissionDenied) => {
            eprintln!("Location permission denied — skipping async call.");
        }
        Err(e) => eprintln!("Async location error: {e}"),
    }

    println!();

    // ── 2. Blocking call (also safe inside #[tokio::main]) ────────────────────
    // __location__ detects the existing Tokio runtime and offloads to a
    // dedicated OS thread automatically — no runtime nesting issue.
    println!("Opening browser to acquire location (blocking)…");
    let template = PageTemplate::Tickbox {
        title:        Some("Confirm Location".into()),
        body_text:    None,
        consent_text: Some("I allow this example to read my location.".into()),
    };
    match __location__(template) {
        Ok(data) => print_location("Blocking result:", &data),
        Err(LocationError::PermissionDenied) => {
            eprintln!("Location permission denied — skipping blocking call.");
        }
        Err(e) => eprintln!("Blocking location error: {e}"),
    }
}
