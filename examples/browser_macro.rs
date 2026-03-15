//! Demonstrates the `#[browser]` attribute macro and the `PageTemplate` enum
//! from the `location` feature.
//!
//! ## What `#[browser]` does
//!
//! `#[browser]` is a statement-level macro that expands inside an `async fn`
//! (or a sync fn when `sync` is specified).  It:
//!
//! 1. Spins up a local HTTP server on a random port.
//! 2. Opens the system's default browser to a locally-served HTML page that
//!    calls the browser's `navigator.geolocation.getCurrentPosition()` API.
//! 3. Waits for the user to grant location permission.
//! 4. Returns the latitude/longitude/accuracy as a [`LocationData`] value bound
//!    to a local variable whose name matches the annotated function.
//!
//! The HTML page can be customised through the macro arguments:
//!
//! | Form                                        | Template used              |
//! |---------------------------------------------|----------------------------|
//! | `#[browser]`                                | Default (blank page)       |
//! | `#[browser(title = "…")]`                   | Default with title         |
//! | `#[browser(title = "…", body = "…")]`       | Default with title + body  |
//! | `#[browser(tickbox)]`                       | Tickbox consent UI         |
//! | `#[browser(tickbox, title = "…", body = "…", consent = "…")]` | Full tickbox |
//! | `#[browser(html = "<html>…{lat}…{lon}…")]`  | Fully custom HTML          |
//! | `#[browser(sync)]`                          | Synchronous variant        |
//! | `#[browser(sync, title = "…")]`             | Sync + title               |
//!
//! ## Running this example
//!
//! ```sh
//! cargo run --example browser_macro --features location
//! ```
//!
//! The `main` function **does not open any browser windows** — it only demonstrates
//! `PageTemplate` construction.  The `#[browser]`-annotated functions further down
//! the file are compile-verified but not called by `main`.  To actually capture the
//! user's location, uncomment the relevant `// let loc = …` lines.

use toolkit_zero::location::browser::{PageTemplate, LocationData, LocationError, browser};

fn main() {
    println!("=== browser macro demo (PageTemplate construction) ===\n");
    demo_page_templates();
    println!("PageTemplate demos complete ✓");
    println!();
    println!("The #[browser] macro forms below are compiled but not executed.");
    println!("To capture a real location, call one of the async fns defined");
    println!("further down the file from a #[tokio::main] async fn main.");
}

// ─── PageTemplate construction ────────────────────────────────────────────────
//
// These are pure enum-value constructions — no browser is opened and no network
// I/O occurs.  This block is always executed when the example runs.

fn demo_page_templates() {
    // ── Default template ──────────────────────────────────────────────────────
    let _blank = PageTemplate::Default {
        title:     None,
        body_text: None,
    };
    println!("  Default (blank)");

    let _with_title = PageTemplate::Default {
        title:     Some("My App — Location".into()),
        body_text: None,
    };
    println!("  Default (title only)");

    let _with_both = PageTemplate::Default {
        title:     Some("Location Access".into()),
        body_text: Some("We need your location to show nearby results.".into()),
    };
    println!("  Default (title + body)");

    // ── Tickbox template ──────────────────────────────────────────────────────
    let _tickbox_blank = PageTemplate::Tickbox {
        title:        None,
        body_text:    None,
        consent_text: None,
    };
    println!("  Tickbox (all defaults)");

    let _tickbox_full = PageTemplate::Tickbox {
        title:        Some("Verify Your Location".into()),
        body_text:    Some("Tick to grant access and continue.".into()),
        consent_text: Some("I agree to share my location with this app.".into()),
    };
    println!("  Tickbox (fully populated)");

    // ── Custom HTML template ──────────────────────────────────────────────────
    let _custom = PageTemplate::Custom(
        "<html><head><title>Loc</title></head>\
         <body><p>Getting your location…</p></body></html>"
            .into(),
    );
    println!("  Custom HTML");
}

// ─── #[browser] macro forms — compile-verified, not called from main ──────────
//
// Each function below is annotated with one of the valid `#[browser]` forms.
// They compile but are never invoked here so that running the example does not
// open a browser window.  Remove `#[allow(dead_code)]` and call any of these
// from an async `main` to capture a real geolocation.

#[allow(dead_code)]
async fn location_default() -> Result<LocationData, LocationError> {
    // Minimal form: async, Default template with no customisation.
    // Expands roughly to:
    //   let loc: LocationData = browser_internal::get(PageTemplate::Default { .. }).await?;
    #[browser]
    fn loc() {}
    Ok(loc)
}

#[allow(dead_code)]
async fn location_with_title() -> Result<LocationData, LocationError> {
    // Default template + a custom page title.
    #[browser(title = "Share Your Location")]
    fn loc() {}
    Ok(loc)
}

#[allow(dead_code)]
async fn location_with_title_and_body() -> Result<LocationData, LocationError> {
    // Default template + title + body paragraph.
    #[browser(title = "Location Required", body = "Please allow access to continue.")]
    fn loc() {}
    Ok(loc)
}

#[allow(dead_code)]
async fn location_tickbox() -> Result<LocationData, LocationError> {
    // Tickbox consent UI — user must tick a checkbox before the location is read.
    #[browser(tickbox)]
    fn loc() {}
    Ok(loc)
}

#[allow(dead_code)]
async fn location_tickbox_full() -> Result<LocationData, LocationError> {
    // Fully customised tickbox with all three text fields.
    #[browser(tickbox, title = "Location Consent", body = "Click the box below.", consent = "I agree")]
    fn loc() {}
    Ok(loc)
}

#[allow(dead_code)]
async fn location_custom_html() -> Result<LocationData, LocationError> {
    // Completely custom HTML page.  The library injects the JS callback and
    // POSTs the result; your HTML is served as-is otherwise.
    #[browser(html = "<html><body><h1>Fetching location…</h1></body></html>")]
    fn loc() {}
    Ok(loc)
}

// ─── Synchronous variants ─────────────────────────────────────────────────────
//
// `#[browser(sync)]` produces a blocking call — useful when no async executor
// is available.  It must be called from a non-Tokio thread (e.g. via
// `tokio::task::spawn_blocking`).

#[allow(dead_code)]
fn location_sync() -> Result<LocationData, LocationError> {
    // Sync variant: wraps the async internals in a one-shot runtime.
    #[browser(sync)]
    fn loc() {}
    Ok(loc)
}

#[allow(dead_code)]
fn location_sync_with_title() -> Result<LocationData, LocationError> {
    #[browser(sync, title = "Location (sync)")]
    fn loc() {}
    Ok(loc)
}

#[allow(dead_code)]
fn location_sync_custom_html() -> Result<LocationData, LocationError> {
    #[browser(sync, html = "<html><body><p>Getting location…</p></body></html>")]
    fn loc() {}
    Ok(loc)
}
