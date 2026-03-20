//! Download tracking types for the browser downloads panel.

use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq)]
pub enum DownloadStatus {
    InProgress,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct DownloadEntry {
    pub id: u64,
    pub url: String,
    /// Final filename without any temporary extension (e.g., `"video.mp4"`).
    pub filename: String,
    /// Path where the browser writes the file while downloading (ends in `.tkz`).
    pub temp_dest: PathBuf,
    /// Path the file will be renamed to once the download completes.
    pub final_dest: PathBuf,
    /// Bytes written so far (updated by the parallel downloader).
    pub bytes_downloaded: u64,
    /// Total file size in bytes, if known from the server's Content-Length.
    pub total_bytes: Option<u64>,
    /// Current transfer speed in bytes/second (smoothed over the last tick interval).
    pub speed_bps: u64,
    pub status: DownloadStatus,
}
