use std::path::PathBuf;
use toolkit_zero::browser::{launch, launch_default, Target};

// ── CLI argument parsing ──────────────────────────────────────────────────────

enum LaunchMode {
    Default,
    Url(String),
    Search(String),
    File(PathBuf),
}

fn parse_args() -> Result<LaunchMode, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.is_empty() {
        return Ok(LaunchMode::Default);
    }

    // Only the first recognised flag is used; unknown flags are rejected.
    let arg = &args[0];

    if let Some(val) = arg.strip_prefix("--url=") {
        let val = val.trim();
        if val.is_empty() {
            return Err("--url requires a non-empty value, e.g. --url=https://example.com".into());
        }
        return Ok(LaunchMode::Url(val.to_string()));
    }

    if let Some(val) = arg.strip_prefix("--search=") {
        let val = val.trim();
        if val.is_empty() {
            return Err("--search requires a non-empty value, e.g. --search=\"rust programming\"".into());
        }
        return Ok(LaunchMode::Search(val.to_string()));
    }

    if let Some(val) = arg.strip_prefix("--file=") {
        let val = val.trim();
        if val.is_empty() {
            return Err("--file requires a non-empty path, e.g. --file=/path/to/page.html".into());
        }
        return Ok(LaunchMode::File(PathBuf::from(val)));
    }

    Err(format!(
        "Unknown argument: {arg}\n\
         \n\
         Usage:\n\
           duct-tape                       Open the homepage\n\
           duct-tape --url=<url>           Open a URL (back button returns home)\n\
           duct-tape --search=<query>      Search Google immediately\n\
           duct-tape --file=<path>         Open a local HTML file\n"
    ))
}

/// Resolve a raw `--url` value the same way the address bar does:
/// - Explicit scheme  →  used as-is
/// - Looks like a domain (contains `.`, no spaces)  →  prepend `https://`
/// - Everything else  →  Google search
fn resolve_url(input: &str) -> String {
    let t = input.trim();
    if t.starts_with("http://") || t.starts_with("https://") || t.starts_with("file://") {
        t.to_string()
    } else if t.contains('.') && !t.contains(' ') {
        format!("https://{t}")
    } else {
        format!("https://www.google.com/search?q={}", urlencode(t))
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
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

// ── entry-point ───────────────────────────────────────────────────────────────

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let mode = match parse_args() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("duct-tape: {e}");
            std::process::exit(1);
        }
    };

    // iced's EventLoop must run on the main thread; block_in_place keeps us on
    // the main tokio thread while yielding the async scheduler for spawned tasks.
    let result = tokio::task::block_in_place(|| match mode {
        LaunchMode::Default => launch_default(),

        LaunchMode::Url(raw) => {
            // Resolve the input (add scheme, or fall back to search).
            // Use UrlFromHome so the webview back-stack is seeded with the
            // homepage — pressing Back from the opened URL returns home.
            launch(Target::UrlFromHome(resolve_url(&raw)))
        }

        LaunchMode::Search(query) => {
            let search_url = format!("https://www.google.com/search?q={}", urlencode(&query));
            launch(Target::Url(search_url))
        }

        LaunchMode::File(path) => launch(Target::File(path)),
    });

    if let Err(e) = result {
        eprintln!("duct-tape: {e}");
        std::process::exit(1);
    }
}
