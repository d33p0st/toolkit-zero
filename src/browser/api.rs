//! Programmatic control of a running browser window.
//!
//! There are two patterns for wiring up a [`BrowserHandle`]:
//!
//! ## Pattern A — `launch_with_controller` (recommended, zero boilerplate)
//!
//! Pass an async closure; the channel pair and `block_in_place` are managed
//! for you.
//!
//! ```no_run
//! # #[cfg(feature = "browser")]
//! use toolkit_zero::browser::{self, Target, api::{BrowserHandle, TabTarget, ThemeMode}};
//!
//! # #[cfg(feature = "browser")]
//! #[tokio::main(flavor = "multi_thread")]
//! async fn main() -> Result<(), browser::BrowserError> {
//!     browser::launch_with_controller(Target::Default, |handle: BrowserHandle| async move {
//!         tokio::time::sleep(std::time::Duration::from_secs(2)).await;
//!         handle.navigate(TabTarget::Active, "https://docs.rs");
//!         handle.set_theme(ThemeMode::Dark);
//!     })
//! }
//! ```
//!
//! ## Pattern B — `launch_with_api` (explicit, full control)
//!
//! Create the [`BrowserHandle`] / [`ApiReceiver`] pair yourself, spawn your
//! own tasks, then hand the receiver to [`super::launch_with_api`].
//!
//! ```no_run
//! # #[cfg(feature = "browser")]
//! use toolkit_zero::browser::{self, Target, api::{BrowserHandle, TabTarget, ThemeMode}};
//!
//! # #[cfg(feature = "browser")]
//! #[tokio::main(flavor = "multi_thread")]
//! async fn main() {
//!     let (handle, receiver) = BrowserHandle::new();
//!
//!     let h = handle.clone();
//!     tokio::spawn(async move {
//!         tokio::time::sleep(std::time::Duration::from_secs(3)).await;
//!         h.navigate(TabTarget::Active, "https://example.com");
//!         h.open_new_tab(Some("https://docs.rs"));
//!         h.set_theme(ThemeMode::Dark);
//!     });
//!
//!     // Blocks the main thread until the window is closed.
//!     tokio::task::block_in_place(|| {
//!         browser::launch_with_api(Target::Default, receiver)
//!     }).unwrap();
//! }
//! ```
//!
//! ## How it works
//!
//! Both patterns keep the tokio executor alive on other threads while the iced
//! event-loop blocks the calling thread (`tokio::task::block_in_place`).
//! Commands sent through the handle are picked up by the browser's Tick loop
//! (≤ 16 ms latency).

use std::path::PathBuf;
use std::sync::Mutex;
use tokio::sync::mpsc;

// Re-export ThemeMode so callers only need to import from api.
pub use super::app::ThemeMode;

// ── Internal message type ─────────────────────────────────────────────────────

/// Commands sent from [`BrowserHandle`] to the running browser.
/// `pub(super)` — external code enqueues via the typed `BrowserHandle` methods.
pub(super) enum ApiMessage {
    Navigate(TabTarget, String),
    StartDownload(String),
    SetTheme(ThemeMode),
    OpenNewTab(Option<String>),
}

// ─ Safety: all fields are Send (String, ThemeMode: Copy, TabTarget: primitive) ─
unsafe impl Send for ApiMessage {}

// ── Global receiver slot ──────────────────────────────────────────────────────
//
// The iced init closure is `Fn` (not `FnOnce`), so we cannot move the receiver
// directly into it.  We park it in a global `Mutex<Option<…>>` before calling
// `launch_with_api`; `BrowserState::new` takes it out exactly once.

static RECEIVER: Mutex<Option<mpsc::UnboundedReceiver<ApiMessage>>> = Mutex::new(None);

/// Park `rx` in the global slot so `BrowserState::new` can retrieve it.
/// Called by `launch_with_api` before iced starts.
pub(super) fn install_receiver(rx: mpsc::UnboundedReceiver<ApiMessage>) {
    *RECEIVER.lock().unwrap() = Some(rx);
}

/// Pull the receiver out of the global slot.  Returns `None` if
/// `install_receiver` was never called (plain `launch` / `launch_default`).
/// Called exactly once by `BrowserState::new`.
pub(super) fn take_receiver() -> Option<mpsc::UnboundedReceiver<ApiMessage>> {
    RECEIVER.lock().unwrap().take()
}

// ── Public types ──────────────────────────────────────────────────────────────

/// Which tab a navigation or new-tab command should target.
#[derive(Debug, Clone)]
pub enum TabTarget {
    /// The currently active (visible) tab.
    Active,
    /// Always open a brand-new tab.
    New,
    /// An existing tab by 0-based index.
    ///
    /// If the index is out of range a new tab is created automatically.
    Index(usize),
}

/// A cloneable handle to a running browser window.
///
/// All methods are **fire-and-forget**: they enqueue a command and return
/// immediately.  The browser processes commands on the next Tick (≤16 ms).
///
/// Obtain one with [`BrowserHandle::new`] and pass the accompanying
/// [`ApiReceiver`] to [`super::launch_with_api`].
#[derive(Clone)]
pub struct BrowserHandle {
    tx: mpsc::UnboundedSender<ApiMessage>,
}

/// The receiving end of the API channel.
///
/// Pass this **once** to [`super::launch_with_api`].  Keep the
/// [`BrowserHandle`] for all subsequent communication.
pub struct ApiReceiver(pub(super) mpsc::UnboundedReceiver<ApiMessage>);

impl BrowserHandle {
    /// Create a new `(BrowserHandle, ApiReceiver)` pair.
    ///
    /// The `BrowserHandle` can be cloned freely and sent across threads/tasks.
    /// The `ApiReceiver` must be handed to [`super::launch_with_api`] exactly once.
    pub fn new() -> (Self, ApiReceiver) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { tx }, ApiReceiver(rx))
    }

    /// Navigate `tab` to `url`.
    ///
    /// URL resolution mirrors the address bar:
    /// - Explicit `https://` / `http://` / `file://` → used verbatim
    /// - Looks like a domain (contains `.`, no spaces) → `https://` prepended
    /// - Anything else → Google search
    pub fn navigate(&self, tab: TabTarget, url: impl Into<String>) {
        let _ = self.tx.send(ApiMessage::Navigate(tab, url.into()));
    }

    /// Trigger a download of `url`, appearing in the downloads panel exactly
    /// as if the user clicked a download link on the page.
    ///
    /// The file lands in `~/Downloads/<filename>` where `<filename>` comes from
    /// the URL's last path segment (query strings stripped).  A `-2`, `-3`, …
    /// suffix is appended automatically when the file already exists.
    pub fn start_download(&self, url: impl Into<String>) {
        let _ = self.tx.send(ApiMessage::StartDownload(url.into()));
    }

    /// Switch the browser's colour theme.
    pub fn set_theme(&self, mode: ThemeMode) {
        let _ = self.tx.send(ApiMessage::SetTheme(mode));
    }

    /// Open a new tab.
    ///
    /// - `None` → homepage
    /// - `Some(url)` → navigates to that URL (same resolution as [`navigate`](Self::navigate))
    pub fn open_new_tab(&self, url: Option<impl Into<String>>) {
        let _ = self.tx.send(ApiMessage::OpenNewTab(url.map(Into::into)));
    }
}

impl Default for BrowserHandle {
    fn default() -> Self {
        // Required for ergonomics; the sender half of a closed channel is fine
        // until new() is called properly.
        let (tx, _) = mpsc::unbounded_channel();
        Self { tx }
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Compute `(temp_dest, final_dest)` for an API-initiated download.
///
/// Files land in `~/Downloads/` (or `%USERPROFILE%\Downloads` on Windows).
/// The filename is the last URL path segment with the query string stripped.
pub(super) fn download_paths_for_url(url: &str) -> (PathBuf, PathBuf) {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_default();
    let downloads_dir = PathBuf::from(home).join("Downloads");

    // Extract filename from URL: take last segment, strip query/fragment.
    let raw_segment = url.split('/').last().unwrap_or("download");
    let raw_segment = raw_segment.split('?').next().unwrap_or(raw_segment);
    let raw_segment = raw_segment.split('#').next().unwrap_or(raw_segment);
    let filename = if raw_segment.is_empty() { "download" } else { raw_segment };

    let final_dest = downloads_dir.join(filename);
    let temp_dest = downloads_dir.join(format!("{}.tkz", filename));
    (temp_dest, final_dest)
}
