//! Persistent quick links stored at `~/toolkit-zero/.quicklinks`.
//!
//! File format — one record per line, tab-separated:
//! ```text
//! url TAB label TAB icon_emoji NEWLINE
//! ```
//! The order in the file is the display order.

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

// ── types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct QuickLink {
    pub url:   String,
    pub label: String,
    pub icon:  String,
}

// ── paths ─────────────────────────────────────────────────────────────────────

fn quicklinks_path() -> PathBuf {
    let mut p = toolkit_dir();
    p.push(".quicklinks");
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

// ── defaults ─────────────────────────────────────────────────────────────────

pub fn default_links() -> Vec<QuickLink> {
    vec![
        QuickLink { url: "https://github.com".into(),           label: "GitHub".into(),   icon: "🐙".into() },
        QuickLink { url: "https://www.rust-lang.org".into(),    label: "Rust".into(),     icon: "🦀".into() },
        QuickLink { url: "https://crates.io".into(),            label: "Crates".into(),   icon: "📦".into() },
        QuickLink { url: "https://doc.rust-lang.org".into(),    label: "Docs".into(),     icon: "📖".into() },
        QuickLink { url: "https://news.ycombinator.com".into(), label: "HN".into(),       icon: "🔶".into() },
        QuickLink { url: "https://www.youtube.com".into(),      label: "YouTube".into(),  icon: "▶️".into() },
    ]
}

// ── I/O ──────────────────────────────────────────────────────────────────────

/// Load saved quick links; falls back to defaults if the file is missing/empty.
pub fn load() -> Vec<QuickLink> {
    let path = quicklinks_path();
    let file = match fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => return default_links(),
    };
    let mut links: Vec<QuickLink> = BufReader::new(file)
        .lines()
        .filter_map(|l| {
            let l = l.ok()?;
            let l = l.trim();
            if l.is_empty() || l.starts_with('#') {
                return None;
            }
            let mut p = l.splitn(3, '\t');
            let url   = p.next()?.to_string();
            let label = p.next().unwrap_or("Link").to_string();
            let icon  = p.next().unwrap_or("🔗").to_string();
            if url.is_empty() { return None; }
            Some(QuickLink { url, label, icon })
        })
        .collect();
    if links.is_empty() {
        links = default_links();
    }
    links
}

/// Persist the given list (order is preserved).
pub fn save(links: &[QuickLink]) {
    let path = quicklinks_path();
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    if let Ok(mut f) = OpenOptions::new()
        .write(true).truncate(true).create(true).open(&path)
    {
        for ql in links {
            let url   = ql.url.replace('\t', "%09");
            let label = ql.label.replace('\t', " ");
            let icon  = ql.icon.replace('\t', " ");
            let _ = writeln!(f, "{}\t{}\t{}", url, label, icon);
        }
    }
}

/// Add a new link (or update the label/icon if URL already exists).
/// Returns the updated list so callers can inject it without a second disk read.
pub fn add(url: String, label: String) -> Vec<QuickLink> {
    let mut links = load();
    // Derive a compact label if the caller passed a full title.
    let short = short_label(&label, &url);
    if let Some(existing) = links.iter_mut().find(|l| l.url == url) {
        existing.label = short;
    } else {
        let icon = guess_icon(&url);
        links.push(QuickLink { url, label: short, icon });
        save(&links);
    }
    links
}

/// Remove the link with the given URL.
/// Returns the updated list so callers can inject it without a second disk read.
pub fn remove(url: &str) -> Vec<QuickLink> {
    let mut links = load();
    links.retain(|l| l.url != url);
    save(&links);
    links
}

/// Move the link at `from` to `to` position (0-based).
#[allow(dead_code)]
pub fn reorder(from: usize, to: usize) {
    let mut links = load();
    if from < links.len() && to < links.len() && from != to {
        let item = links.remove(from);
        links.insert(to, item);
        save(&links);
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn short_label(title: &str, url: &str) -> String {
    // If title is short enough, use it
    let t = title.trim();
    if t.len() <= 12 && !t.is_empty() {
        return t.to_string();
    }
    // Otherwise derive from domain
    let stripped = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host = stripped.split('/').next().unwrap_or(stripped);
    let host = host.trim_start_matches("www.");
    let name = host.split('.').next().unwrap_or(host);
    let mut chars = name.chars();
    match chars.next() {
        None => t.chars().take(10).collect(),
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

fn guess_icon(url: &str) -> String {
    let u = url.to_lowercase();
    if u.contains("github")      { "🐙" }
    else if u.contains("rust")   { "🦀" }
    else if u.contains("crates") { "📦" }
    else if u.contains("doc")    { "📖" }
    else if u.contains("youtube") { "▶️" }
    else if u.contains("twitter") || u.contains("x.com") { "🐦" }
    else if u.contains("reddit") { "🤖" }
    else if u.contains("news.ycombinator") { "🔶" }
    else                         { "🔗" }
    .to_string()
}

// ── JSON serialization (used to inject into JS) ───────────────────────────────

/// Serialize the link list to a compact JSON array string.
pub fn to_json(links: &[QuickLink]) -> String {
    let items: Vec<String> = links.iter().map(|l| {
        format!(
            r#"{{"url":{},"label":{},"icon":{}}}"#,
            json_str(&l.url),
            json_str(&l.label),
            json_str(&l.icon),
        )
    }).collect();
    format!("[{}]", items.join(","))
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"'  => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c    => out.push(c),
        }
    }
    out.push('"');
    out
}

