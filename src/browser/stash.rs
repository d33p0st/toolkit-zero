//! Persistent stash of in-progress downloads.
//!
//! When the browser closes with active downloads, their URLs and file paths are
//! written to `~/toolkit-zero/pending-downloads.stash`. On the next launch,
//! these entries are loaded and re-started so the download continues from where
//! it left off (HTTP resume is attempted via a `Range` header).
//!
//! ## File format
//! One download per line, tab-separated:
//! ```text
//! url TAB temp_dest TAB final_dest TAB filename NEWLINE
//! ```
//! Tabs inside any field are replaced with a space during write and will not
//! appear in practice (URLs encode tabs as `%09`; file paths never contain them
//! on any supported platform).

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use super::downloads::{DownloadEntry, DownloadStatus};

// ── public types ─────────────────────────────────────────────────────────────

/// A single download entry loaded from the stash file.
#[derive(Debug, Clone)]
pub struct StashedEntry {
    pub url: String,
    pub temp_dest: PathBuf,
    pub final_dest: PathBuf,
    pub filename: String,
}

// ── path helper ───────────────────────────────────────────────────────────────

fn stash_path() -> PathBuf {
    let mut p = home_dir();
    p.push("toolkit-zero");
    p.push("pending-downloads.stash");
    p
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

// ── public API ────────────────────────────────────────────────────────────────

/// Persist all `InProgress` download entries to disk.
///
/// Called whenever the downloads list changes (start / complete / cancel) so
/// the stash is always consistent even after an unexpected termination.
pub fn save_stash(downloads: &[DownloadEntry]) {
    let path = stash_path();
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }

    let in_progress: Vec<&DownloadEntry> = downloads
        .iter()
        .filter(|d| d.status == DownloadStatus::InProgress)
        .collect();

    // Truncate to empty if nothing is in-progress.
    let result = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .and_then(|mut f| {
            for d in &in_progress {
                writeln!(
                    f,
                    "{}\t{}\t{}\t{}",
                    d.url.replace('\t', " "),
                    d.temp_dest.to_string_lossy().replace('\t', " "),
                    d.final_dest.to_string_lossy().replace('\t', " "),
                    d.filename.replace('\t', " "),
                )?;
            }
            Ok(())
        });

    if let Err(e) = result {
        eprintln!("[stash] save failed: {e}");
    }
}

/// Load the stash from disk and return entries whose `.tkz` partial file still
/// exists (entries whose files were deleted are silently skipped).
pub fn load_stash() -> Vec<StashedEntry> {
    let path = stash_path();
    let file = match fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    let entries: Vec<StashedEntry> = BufReader::new(file)
        .lines()
        .filter_map(|line| {
            let line = line.ok()?;
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            let mut parts = line.splitn(4, '\t');
            let url       = parts.next()?.to_string();
            let temp_dest = PathBuf::from(parts.next()?);
            let final_dest = PathBuf::from(parts.next()?);
            let filename  = parts.next()?.to_string();
            Some(StashedEntry { url, temp_dest, final_dest, filename })
        })
        .filter(|e| e.temp_dest.exists()) // skip if partial file was removed
        .collect();

    // Clear the stash file after load — entries will be re-saved if downloads
    // are restarted, keeping the state accurate.
    let _ = fs::write(&path, "");

    entries
}
