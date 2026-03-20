//! Persistent browser settings stored at `~/toolkit-zero/.browser-settings`.
//!
//! File format — one `key=value` pair per line; lines beginning with `#` are
//! comments and are ignored.  Unknown keys are silently skipped so that older
//! binaries can read files written by newer ones without crashing.
//!
//! Example file:
//! ```text
//! history_recording=true
//! session_persistence=true
//! ```

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

// ── path helpers ─────────────────────────────────────────────────────────────

fn settings_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join("toolkit-zero").join(".browser-settings")
}

// ── public types ──────────────────────────────────────────────────────────────

/// In-memory snapshot of all persisted browser settings.
#[derive(Debug, Clone)]
pub struct BrowserSettings {
    /// When `true`, every visited page is appended to `history.hist`.
    ///
    /// This flag does **not** affect the WebView's own back/forward stack —
    /// per-tab navigation history always works regardless of this setting.
    pub history_recording: bool,

    /// When `true`, cookies and site data (localStorage, IndexedDB, …) are
    /// preserved across restarts via a named WKWebsiteDataStore on macOS.
    ///
    /// This field is persisted to disk and loaded at startup so the UI can
    /// reflect the user's choice.  The actual WebView uses the value that
    /// was active when the process started (changing it requires a restart).
    pub session_persistence: bool,
}

impl Default for BrowserSettings {
    fn default() -> Self {
        BrowserSettings {
            history_recording:   true,
            session_persistence: true,
        }
    }
}

// ── I/O ──────────────────────────────────────────────────────────────────────

/// Load settings from `~/toolkit-zero/.browser-settings`.
///
/// Missing keys fall back to their defaults.  A missing file is treated as
/// "all defaults" and is not an error.
pub fn load() -> BrowserSettings {
    let mut s = BrowserSettings::default();
    let Ok(file) = fs::File::open(settings_path()) else { return s };

    for line in BufReader::new(file).lines() {
        let Ok(line) = line else { continue };
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() { continue; }
        let Some((key, val)) = line.split_once('=') else { continue };
        match key.trim() {
            "history_recording"   => s.history_recording   = val.trim() == "true",
            "session_persistence" => s.session_persistence = val.trim() == "true",
            _ => {}
        }
    }
    s
}

/// Persist `settings` to `~/toolkit-zero/.browser-settings`, creating the
/// directory if it does not exist yet.
pub fn save(settings: &BrowserSettings) {
    let path = settings_path();
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let content = format!(
        "history_recording={}\nsession_persistence={}\n",
        settings.history_recording,
        settings.session_persistence,
    );
    let _ = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .and_then(|mut f| f.write_all(content.as_bytes()));
}
