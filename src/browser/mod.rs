//! # Browser
//!
//! A cross-platform, WebKit-backed browser window with:
//! - Squircle floating tabs
//! - Perimeter-tracing blue loading indicator
//! - Back / forward buttons (+ native two-finger swipe on macOS)
//! - `file://`, `https://` URL support, and programmatic raw-HTML injection
//!
//! ## Quick start
//!
//! ```no_run
//! # #[cfg(feature = "browser")]
//! use toolkit_zero::browser::{self, Target};
//!
//! # #[cfg(feature = "browser")]
//! fn main() -> Result<(), browser::BrowserError> {
//!     // Open a URL
//!     browser::launch(Target::Url("https://example.com".into()))?;
//!
//!     // Open a local HTML file
//!     browser::launch(Target::File("/path/to/index.html".into()))?;
//!
//!     // Inject raw HTML directly
//!     browser::launch(Target::Html("<h1>Hello from Rust!</h1>".into()))?;
//!
//!     Ok(())
//! }
//! ```

use std::path::PathBuf;

pub use app::Message;

/// Homepage HTML embedded at compile time via build.rs (copied to `$OUT_DIR`).
/// In development mode the file is copied from `assets/browser-index.html`.
/// In published-crate mode the same asset is shipped alongside the crate and
/// copied by build.rs — no external toolchain is required.
pub(crate) const HOMEPAGE_HTML: &str =
    include_str!(concat!(env!("OUT_DIR"), "/browser-index.html"));

/// Returns a shared `Arc<str>` wrapping [`HOMEPAGE_HTML`].
/// The Arc is created once (lazily) and cloned cheaply thereafter,
/// so opening new tabs doesn't allocate a fresh 30 KB copy each time.
pub(crate) fn homepage_html_arc() -> std::sync::Arc<str> {
    static ONCE: std::sync::OnceLock<std::sync::Arc<str>> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| std::sync::Arc::from(HOMEPAGE_HTML)).clone()
}

mod app;
pub mod api;
mod downloads;
mod downloader;
mod history;
mod loader;
mod quicklinks;
mod settings;
mod stash;
mod tab;
mod webview;

pub use quicklinks::{QuickLink, load as load_quicklinks};
pub use api::{BrowserHandle, TabTarget, ThemeMode, ApiReceiver};

// ── public types ─────────────────────────────────────────────────────────────

/// What the browser should display on launch.
#[derive(Debug, Clone)]
pub enum Target {
    /// Open the built-in homepage. Equivalent to calling [`launch_default`].
    Default,
    /// Navigate to an `http://` or `https://` URL.
    Url(String),
    /// Load a local HTML file via `file://`.
    /// Relative CSS / JS references inside the file are resolved automatically.
    File(PathBuf),
    /// Inject a raw HTML string directly into the WebView (no file required).
    Html(String),
    /// Navigate to a URL, but first load the built-in homepage so that the
    /// webview back-stack contains the homepage. Pressing the browser's back
    /// button from the target URL will return the user to the homepage.
    UrlFromHome(String),
}

/// Errors returned by [`launch`] / [`launch_default`].
#[derive(Debug)]
pub enum BrowserError {
    Iced(iced::Error),
}

impl std::fmt::Display for BrowserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrowserError::Iced(e) => write!(f, "iced: {e}"),
        }
    }
}

impl std::error::Error for BrowserError {}

impl From<iced::Error> for BrowserError {
    fn from(e: iced::Error) -> Self {
        BrowserError::Iced(e)
    }
}

// ── events that flow wry → iced ───────────────────────────────────────────────

/// Internal events produced by wry callbacks and consumed by the iced tick.
#[derive(Debug)]
pub(crate) enum BrowserEvent {
    PageStarted(String),
    PageFinished(String),
    TitleChanged(String),
    /// Raw IPC message string sent from JavaScript via `window.ipc.postMessage()`.
    Ipc(String),
    /// A file download has started (url, temp_dest with .tkz extension, final_dest without).
    DownloadStarted(String, std::path::PathBuf, std::path::PathBuf),
    /// A file download finished (url, success).
    DownloadCompleted(String, bool),
}

// ── entry points ─────────────────────────────────────────────────────────────

/// Launch the browser with a specific [`Target`].
///
/// This call **blocks** the current thread until the window is closed.
/// It must be called from the main thread.
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "browser")]
/// toolkit_zero::browser::launch(
///     toolkit_zero::browser::Target::Url("https://www.rust-lang.org".into())
/// ).unwrap();
/// ```
pub fn launch(target: Target) -> Result<(), BrowserError> {
    use iced::{Size, window};

    // Build a window icon for non-macOS platforms.
    // On macOS, the dock icon is set via NSApplication after the window opens.
    let icon: Option<window::Icon> = {
        #[allow(unused_mut)]
        let mut ico = None;
        #[cfg(all(not(target_os = "macos"), has_app_icon))]
        {
            static BYTES: &[u8] =
                include_bytes!(concat!(env!("OUT_DIR"), "/app-icon.png"));
            ico = window::icon::from_file_data(BYTES, None).ok();
        }
        ico
    };

    iced::application(
        move || app::BrowserState::new(target.clone()),
        app::update,
        app::view,
    )
    .subscription(app::subscription)
    .theme(app::theme)
    .window(window::Settings {
        size: Size::new(1280.0, 820.0),
        position: window::Position::Centered,
        icon,
        ..Default::default()
    })
    .title("duct-tape")
    .run()
    .map_err(BrowserError::Iced)
}

/// Launch the browser showing the built-in homepage (`assets/browser-index.html`).
///
/// This is the standard entry-point for end-users who want to hand the browser
/// to a user without a pre-set URL.
pub fn launch_default() -> Result<(), BrowserError> {
    launch(Target::Html(HOMEPAGE_HTML.to_string()))
}

/// Launch the browser with a [`BrowserHandle`] wired in for programmatic control.
///
/// This is identical to [`launch`] except the running browser will listen for
/// commands sent through `api`. The call **blocks** the current thread until
/// the window is closed — use `tokio::task::block_in_place` to keep the async
/// executor alive for your spawned tasks.
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "browser")]
/// use toolkit_zero::browser::{self, Target, api::BrowserHandle};
///
/// # #[cfg(feature = "browser")]
/// #[tokio::main(flavor = "multi_thread")]
/// async fn main() {
///     let (handle, receiver) = BrowserHandle::new();
///
///     let h = handle.clone();
///     tokio::spawn(async move {
///         tokio::time::sleep(std::time::Duration::from_secs(2)).await;
///         h.navigate(browser::api::TabTarget::Active, "https://example.com");
///     });
///
///     tokio::task::block_in_place(|| {
///         browser::launch_with_api(Target::Default, receiver)
///     }).unwrap();
/// }
/// ```
pub fn launch_with_api(target: Target, api: api::ApiReceiver) -> Result<(), BrowserError> {
    // Park the receiver in the global slot before iced calls the init fn.
    api::install_receiver(api.0);
    launch(target)
}

/// The ergonomic all-in-one launch entry-point with a controller closure.
///
/// Creates a [`BrowserHandle`] / [`ApiReceiver`] pair internally, spawns
/// `controller(handle)` as a tokio task, then calls `block_in_place` to start
/// the browser window — all in a single call.  No manual channel setup or
/// `block_in_place` boilerplate required.
///
/// The receiver is installed into the browser's internal command queue before
/// the window opens. Your closure receives the [`BrowserHandle`] — clone it
/// freely and send commands from any async task.
///
/// # Why a single closure parameter?
///
/// [`ApiReceiver`] is consumed by the browser's internal routing machinery the
/// moment the window starts.  Handing it to the controller would leave it with
/// nowhere useful to go.  The [`BrowserHandle`] (which is `Clone + Send`) is
/// the correct tool for all post-launch communication.
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "browser")]
/// use toolkit_zero::browser::{self, Target, api::{BrowserHandle, TabTarget, ThemeMode}};
///
/// # #[cfg(feature = "browser")]
/// #[tokio::main(flavor = "multi_thread")]
/// async fn main() -> Result<(), browser::BrowserError> {
///     browser::launch_with_controller(Target::Default, |handle: BrowserHandle| async move {
///         tokio::time::sleep(std::time::Duration::from_secs(3)).await;
///         handle.navigate(TabTarget::Active, "https://docs.rs");
///         handle.set_theme(ThemeMode::Dark);
///         handle.start_download("https://example.com/archive.zip");
///     })
/// }
/// ```
pub fn launch_with_controller<F, Fut>(
    target: Target,
    controller: F,
) -> Result<(), BrowserError>
where
    F: FnOnce(api::BrowserHandle) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let (handle, receiver) = api::BrowserHandle::new();
    api::install_receiver(receiver.0);
    // Spawn on the current tokio runtime.  block_in_place (called inside
    // launch) keeps the runtime's worker threads alive and available, so the
    // spawned task will actually run while the window is open.
    tokio::runtime::Handle::current().spawn(controller(handle));
    tokio::task::block_in_place(|| launch(target))
}

// ── URL encoding (avoid a heavy dep just for this) ────────────────────────────

/// Very small percent-encoder used to build Google search fallback URLs.
///
/// Only exists internally; not re-exported.
pub(crate) mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
                | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
                b' ' => out.push('+'),
                _ => {
                    out.push('%');
                    out.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
                    out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap_or('0'));
                }
            }
        }
        out
    }
}

// ── macOS dock icon ───────────────────────────────────────────────────────────

/// Set the macOS Dock / application icon at runtime.
///
/// On macOS, winit/iced's `window::Settings::icon` is a no-op (winit's
/// `set_window_icon` is intentionally left unimplemented on macOS because
/// macOS does not have per-window icons). To change the Dock tile we call
/// `NSApplication::setApplicationIconImage:` directly via `objc2`.
///
/// The PNG is embedded from `$OUT_DIR/app-icon.png`, which is copied there by
/// `build.rs` whenever `assets/app-icon.png` exists in the crate root.
/// The entire function is cfg-gated on `has_app_icon` (emitted by build.rs)
/// so a missing icon never causes a compile error.
#[cfg(all(target_os = "macos", has_app_icon))]
pub(super) fn set_dock_icon() {
    use std::ffi::c_void;

    use objc2::{AnyThread, MainThreadMarker};
    use objc2_app_kit::{NSApplication, NSImage};
    use objc2_foundation::NSData;

    static ICON: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/app-icon.png"));

    // SAFETY:
    // • We are on the main thread (launch() is called from main before any
    //   threads are spawned by iced).
    // • ICON is a static byte slice; its pointer stays valid for the lifetime
    //   of this call, after which NSData makes its own internal copy.
    unsafe {
        let Some(mtm) = MainThreadMarker::new() else { return };

        let data = NSData::initWithBytes_length(
            NSData::alloc(),
            ICON.as_ptr() as *const c_void,
            ICON.len(),
        );

        if let Some(image) = NSImage::initWithData(NSImage::alloc(), &data) {
            let app = NSApplication::sharedApplication(mtm);
            app.setApplicationIconImage(Some(&image));
        }
    }
}
