//! Persistent browser history stored at `~/toolkit-zero/history.hist`.
//!
//! File format — one record per line, tab-separated:
//! ```text
//! unix_ms TAB title TAB url NEWLINE
//! ```
//! Tabs inside the title are replaced with spaces; tabs in URLs are
//! percent-encoded as `%09` (rare in practice).

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

// ── types ────────────────────────────────────────────────────────────────────

/// A single history entry loaded from disk.
#[derive(Debug, Clone)]
pub struct HistoryEntry {
    /// Unix timestamp in milliseconds.
    pub timestamp_ms: u64,
    pub title: String,
    pub url: String,
}

// ── paths ─────────────────────────────────────────────────────────────────────

/// Returns the path `~/toolkit-zero/history.hist`, creating the directory if
/// it does not exist yet.
pub fn history_path() -> PathBuf {
    let mut p = toolkit_dir();
    p.push("history.hist");
    p
}

fn toolkit_dir() -> PathBuf {
    let mut p = home_dir();
    p.push("toolkit-zero");
    p
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

// ── time helpers ─────────────────────────────────────────────────────────────

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Returns the Unix-ms timestamp for `hours` hours ago from now.
///
/// Used to pass as the `since_ms` argument of [`delete_since`].
#[allow(unused)]
pub fn ms_hours_ago(hours: u64) -> u64 {
    now_ms().saturating_sub(hours * 3_600_000)
}

// ── I/O ──────────────────────────────────────────────────────────────────────

/// Append a single visit to the history file (creates file and dirs if needed).
///
/// Silently skips blank URLs, `about:blank`, and internal `tkz:` URIs.
pub fn append_entry(title: &str, url: &str) {
    if url.is_empty() || url == "about:blank" || url.starts_with("tkz:") {
        return;
    }
    let path = history_path();
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let ts = now_ms();
    // Replace control characters to keep the TSV format intact.
    let title_clean = title.replace('\t', " ").replace('\n', " ");
    let url_clean   = url.replace('\t', "%09");
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{}\t{}\t{}", ts, title_clean, url_clean);
    }
}

/// Load all history entries from disk, oldest entry first.
pub fn load_history() -> Vec<HistoryEntry> {
    let path = history_path();
    let file = match fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => return vec![],
    };
    BufReader::new(file)
        .lines()
        .filter_map(|line| {
            let line = line.ok()?;
            let mut parts = line.splitn(3, '\t');
            let ts: u64 = parts.next()?.parse().ok()?;
            let title   = parts.next()?.to_string();
            let url     = parts.next()?.to_string();
            if url.is_empty() { return None; }
            Some(HistoryEntry { timestamp_ms: ts, title, url })
        })
        .collect()
}

/// Delete all history entries whose `timestamp_ms >= since_ms` (i.e. erase
/// everything from `since_ms` up to now).  Rewrites the file in-place and
/// returns the kept entries so callers don't need a second disk read.
pub fn delete_since(since_ms: u64) -> Vec<HistoryEntry> {
    let path = history_path();
    let mut entries = load_history();
    entries.retain(|e| e.timestamp_ms < since_ms);
    let kept_refs: Vec<&HistoryEntry> = entries.iter().collect();
    let _ = write_entries(&path, &kept_refs);
    entries
}

/// Truncate the history file to zero bytes (erases everything).
pub fn delete_all() {
    let path = history_path();
    // Ensure the file exists before truncating.
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let _ = fs::write(&path, "");
}

// ── internal helpers ─────────────────────────────────────────────────────────

fn write_entries(path: &PathBuf, entries: &[&HistoryEntry]) -> std::io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(path)?;
    for e in entries {
        writeln!(
            f,
            "{}\t{}\t{}",
            e.timestamp_ms,
            e.title.replace('\t', " "),
            e.url.replace('\t', "%09")
        )?;
    }
    Ok(())
}
