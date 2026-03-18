//! Parallel chunk downloader using reqwest.
//!
//! When the wry `download_started_handler` returns `false` (cancelling WebKit's
//! built-in download), this module handles the actual transfer. It performs a
//! HEAD request first to discover `Content-Length` and `Accept-Ranges`; when
//! the server supports byte ranges and the file is large enough, the download
//! is split into [`CHUNK_COUNT`] parallel requests that each write their slice
//! directly into the pre-allocated output file. A streaming fallback is used
//! for servers that do not support ranges, and HTTP resume is attempted for
//! partially-downloaded `.tkz` files found on disk at startup.
//!
//! Progress is reported via a process-global `Mutex<Vec<ProgressUpdate>>` queue
//! that the iced [`Tick`](super::app::Message::Tick) handler drains each frame.

use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// ── progress queue ────────────────────────────────────────────────────────────

/// An in-flight progress notification from a background download task.
pub enum ProgressUpdate {
    /// Bytes downloaded so far, and optional total.
    Progress { id: u64, bytes: u64, total: Option<u64> },
    /// Download finished; temp file has already been renamed to final path.
    Completed { id: u64 },
    /// Download failed.
    Failed { id: u64 },
}

static PROGRESS_QUEUE: Mutex<Vec<ProgressUpdate>> = Mutex::new(Vec::new());

fn push_progress(update: ProgressUpdate) {
    if let Ok(mut q) = PROGRESS_QUEUE.lock() {
        q.push(update);
    }
}

/// Drain all pending progress updates. Called from the main thread on each Tick.
pub fn drain_progress() -> Vec<ProgressUpdate> {
    match PROGRESS_QUEUE.lock() {
        Ok(mut q) if !q.is_empty() => q.drain(..).collect(),
        _ => Vec::new(),
    }
}

// ── public API ────────────────────────────────────────────────────────────────

/// Number of parallel byte-range chunks to use for large downloads.
const CHUNK_COUNT: usize = 8;

/// Only use parallel chunks when the file is at least this large (4 MiB).
const PARALLEL_THRESHOLD: u64 = 4 * 1024 * 1024;

/// Spawn a download as a detached tokio task. Returns immediately; use
/// [`drain_progress`] on each tick to receive status updates.
pub fn spawn_download(id: u64, url: String, temp_dest: PathBuf, final_dest: PathBuf) {
    tokio::task::spawn(async move {
        run_download(id, url, temp_dest, final_dest).await;
    });
}

// ── internals ─────────────────────────────────────────────────────────────────

async fn run_download(id: u64, url: String, temp_dest: PathBuf, final_dest: PathBuf) {
    let client = match reqwest::Client::builder()
        .user_agent(concat!(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ",
            "AppleWebKit/537.36 (KHTML, like Gecko) ",
            "Chrome/124.0 Safari/537.36"
        ))
        .redirect(reqwest::redirect::Policy::limited(20))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[downloader] client build failed: {e}");
            push_progress(ProgressUpdate::Failed { id });
            return;
        }
    };

    // Check for a partial file left over from a previous session.
    let resume_from = tokio::fs::metadata(&temp_dest)
        .await
        .ok()
        .map(|m| m.len())
        .unwrap_or(0);

    // HEAD request to check server capabilities.
    let (content_length, accepts_ranges) = match client.head(&url).send().await {
        Ok(resp) => {
            let cl = resp.content_length();
            let ar = resp
                .headers()
                .get("accept-ranges")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().eq_ignore_ascii_case("bytes"))
                .unwrap_or(false);
            (cl, ar)
        }
        Err(_) => (None, false),
    };

    // Let the UI know the total size immediately, if known.
    if content_length.is_some() || resume_from > 0 {
        push_progress(ProgressUpdate::Progress {
            id,
            bytes: resume_from,
            total: content_length,
        });
    }

    let use_parallel = accepts_ranges
        && content_length.map(|l| l > PARALLEL_THRESHOLD).unwrap_or(false)
        && resume_from == 0; // parallel only for fresh downloads; resume is single-stream

    if use_parallel {
        let total = content_length.unwrap(); // safe: checked above
        parallel_download(id, &client, &url, &temp_dest, &final_dest, total).await;
    } else {
        streaming_download(
            id,
            &client,
            &url,
            &temp_dest,
            &final_dest,
            resume_from,
            content_length,
        )
        .await;
    }
}

/// Download `total` bytes using [`CHUNK_COUNT`] concurrent Range requests.
async fn parallel_download(
    id: u64,
    client: &reqwest::Client,
    url: &str,
    temp_dest: &PathBuf,
    final_dest: &PathBuf,
    total: u64,
) {
    // Create the output file without pre-allocating its full size.
    // Pre-allocation would make the file appear at its final size on disk
    // before any bytes are written, which looks like an instant completion.
    // Instead each chunk opens its own handle and seeks to its start offset;
    // the OS fills the gaps with zero pages lazily.
    if let Err(e) = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(temp_dest)
        .await
    {
        eprintln!("[downloader] couldn't create {}: {e}", temp_dest.display());
        push_progress(ProgressUpdate::Failed { id });
        return;
    }

    let chunk_size = total.div_ceil(CHUNK_COUNT as u64);
    let downloaded = Arc::new(AtomicU64::new(0));
    let mut set = tokio::task::JoinSet::new();

    for i in 0..CHUNK_COUNT {
        let start = i as u64 * chunk_size;
        if start >= total {
            break;
        }
        let end = (start + chunk_size).min(total) - 1;

        let client = client.clone();
        let url = url.to_string();
        let temp_dest = temp_dest.clone();
        let downloaded = Arc::clone(&downloaded);

        set.spawn(async move {
            let mut resp = client
                .get(&url)
                .header("Range", format!("bytes={start}-{end}"))
                .send()
                .await
                .map_err(|e| format!("request: {e}"))?;

            use tokio::io::{AsyncSeekExt, AsyncWriteExt};
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .open(&temp_dest)
                .await
                .map_err(|e| format!("open: {e}"))?;
            file.seek(std::io::SeekFrom::Start(start))
                .await
                .map_err(|e| format!("seek: {e}"))?;

            // Stream byte-by-byte HTTP chunks and push progress on each one
            // so the UI updates continuously rather than once per 500 MB.
            loop {
                match resp.chunk().await {
                    Ok(Some(chunk)) => {
                        file.write_all(&chunk)
                            .await
                            .map_err(|e| format!("write: {e}"))?;
                        let global = downloaded
                            .fetch_add(chunk.len() as u64, Ordering::Relaxed)
                            + chunk.len() as u64;
                        push_progress(ProgressUpdate::Progress {
                            id,
                            bytes: global,
                            total: Some(total),
                        });
                    }
                    Ok(None) => break,
                    Err(e) => return Err::<(), String>(format!("stream: {e}")),
                }
            }

            file.flush().await.map_err(|e| format!("flush: {e}"))?;
            Ok::<(), String>(())
        });
    }

    let mut all_ok = true;
    while let Some(result) = set.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                eprintln!("[downloader] chunk error: {e}");
                all_ok = false;
            }
            Err(e) => {
                eprintln!("[downloader] task panicked: {e}");
                all_ok = false;
            }
        }
    }

    if all_ok {
        match tokio::fs::rename(temp_dest, final_dest).await {
            Ok(()) => push_progress(ProgressUpdate::Completed { id }),
            Err(e) => {
                eprintln!(
                    "[downloader] rename '{}' → '{}': {e}",
                    temp_dest.display(),
                    final_dest.display()
                );
                push_progress(ProgressUpdate::Failed { id });
            }
        }
    } else {
        push_progress(ProgressUpdate::Failed { id });
    }
}

/// Single-stream download with optional HTTP resume.
async fn streaming_download(
    id: u64,
    client: &reqwest::Client,
    url: &str,
    temp_dest: &PathBuf,
    final_dest: &PathBuf,
    resume_from: u64,
    total: Option<u64>,
) {
    let mut req = client.get(url);
    if resume_from > 0 {
        req = req.header("Range", format!("bytes={resume_from}-"));
    }

    let mut resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[downloader] GET {url}: {e}");
            push_progress(ProgressUpdate::Failed { id });
            return;
        }
    };

    // Re-derive total from the response Content-Length if we didn't have it.
    let total = total.or_else(|| {
        resp.content_length().map(|cl| cl + resume_from)
    });

    use tokio::io::AsyncWriteExt;
    let mut file = match if resume_from > 0 {
        tokio::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(temp_dest)
            .await
    } else {
        tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(temp_dest)
            .await
    } {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[downloader] open {}: {e}", temp_dest.display());
            push_progress(ProgressUpdate::Failed { id });
            return;
        }
    };

    let mut bytes_written = resume_from;
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if let Err(e) = file.write_all(&chunk).await {
                    eprintln!("[downloader] write: {e}");
                    push_progress(ProgressUpdate::Failed { id });
                    return;
                }
                bytes_written += chunk.len() as u64;
                push_progress(ProgressUpdate::Progress {
                    id,
                    bytes: bytes_written,
                    total,
                });
            }
            Ok(None) => break, // done
            Err(e) => {
                eprintln!("[downloader] stream: {e}");
                push_progress(ProgressUpdate::Failed { id });
                return;
            }
        }
    }

    if let Err(e) = file.flush().await {
        eprintln!("[downloader] flush: {e}");
        push_progress(ProgressUpdate::Failed { id });
        return;
    }

    match tokio::fs::rename(temp_dest, final_dest).await {
        Ok(()) => push_progress(ProgressUpdate::Completed { id }),
        Err(e) => {
            eprintln!(
                "[downloader] rename '{}' → '{}': {e}",
                temp_dest.display(),
                final_dest.display()
            );
            push_progress(ProgressUpdate::Failed { id });
        }
    }
}
