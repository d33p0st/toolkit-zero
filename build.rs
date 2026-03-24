//! build.rs — makes `chacha20poly1305.wasm` available at `$OUT_DIR/chacha20poly1305.wasm`
//! so it can be embedded via
//! `include_bytes!(concat!(env!("OUT_DIR"), "/chacha20poly1305.wasm"))`.
//!
//! **Development mode** (when `chacha20poly1305-wasm/Cargo.toml` is present in the
//! source tree): compiles the `chacha20poly1305-wasm` crate from source using
//! `wasm32-unknown-unknown`. Requires the target to be installed:
//! `rustup target add wasm32-unknown-unknown`.
//!
//! **Published-crate mode** (downstream users installing from crates.io):
//! the `chacha20poly1305-wasm/` directory is excluded from the published package, but
//! a pre-built `assets/chacha20poly1305.wasm` is included instead. This script
//! copies that pre-built file, so downstream users never need the WASM
//! toolchain.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    // Declare custom cfg keys so rustc doesn't emit "unexpected cfg" warnings.
    println!("cargo::rustc-check-cfg=cfg(has_app_icon)");

    // ── Browser feature: embed the homepage HTML ──────────────────────────────
    // Copy assets/browser-index.html → $OUT_DIR/browser-index.html so it can
    // be embedded via include_str!(concat!(env!("OUT_DIR"), "/browser-index.html")).
    // This mirrors how the WASM binary is handled: dev mode reads from the source
    // tree; published-crate mode reads from the assets/ directory that ships with
    // the crate (listed in Cargo.toml's `include` field).
    let browser_enabled = std::env::var("CARGO_FEATURE_BROWSER").is_ok();
    if browser_enabled {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let out_dir      = PathBuf::from(std::env::var("OUT_DIR").unwrap());
        let html_src     = manifest_dir.join("assets/browser-index.html");
        let html_dst     = out_dir.join("browser-index.html");

        println!("cargo:rerun-if-changed=assets/browser-index.html");

        assert!(
            html_src.exists(),
            "assets/browser-index.html not found — this is a packaging error. \
             Please report it at https://github.com/d33p0st/toolkit-zero/issues"
        );
        std::fs::copy(&html_src, &html_dst)
            .expect("failed to copy assets/browser-index.html to OUT_DIR");

        // ── Application dock icon (optional) ────────────────────────────────
        // If `assets/app-icon.png` is present, copy it to OUT_DIR and signal
        // that it can be embedded.  Build without the file is still valid —
        // the dock will just show the default macOS exec icon.
        let icon_src = manifest_dir.join("assets/app-icon.png");
        println!("cargo:rerun-if-changed=assets/app-icon.png");
        if icon_src.exists() {
            let icon_dst = out_dir.join("app-icon.png");
            std::fs::copy(&icon_src, &icon_dst)
                .expect("failed to copy assets/app-icon.png to OUT_DIR");
            println!("cargo:rustc-cfg=has_app_icon");
        }
    }

    // ── Compiler feature: download + embed the current-target toolchain tarball ──
    // The tarball is fetched from static.rust-lang.org on first use and cached
    // in $CARGO_HOME/toolchain-cache/<TARGET>/toolchain.tar.xz so that
    // subsequent builds don't re-download.  Copying it into $OUT_DIR makes it
    // available for include_bytes!(concat!(env!("OUT_DIR"), "/toolchain.tar.xz")).
    let compiler_enabled = std::env::var("CARGO_FEATURE_COMPILER").is_ok();
    if compiler_enabled {
        let target = std::env::var("TARGET").unwrap();

        // wasm32-* targets have no pre-built rustc/cargo toolchain bundle — skip.
        if !target.starts_with("wasm32-") {
            let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
            let cache_dir = toolchain_cache_dir(&target);
            let cached = cache_dir.join("toolchain.tar.xz");

            // Re-run this build script only when the cached tarball changes
            // (e.g. user manually deletes it to force a re-download).
            println!("cargo:rerun-if-changed={}", cached.display());

            if !cached.exists() {
                std::fs::create_dir_all(&cache_dir)
                    .expect("compiler feature: failed to create toolchain cache dir");
                download_toolchain(&target, &cached);
            }

            std::fs::copy(&cached, out_dir.join("toolchain.tar.xz"))
                .expect("compiler feature: failed to copy toolchain tarball to OUT_DIR");
        }
    }

    // ── Location feature: compile / copy chacha20poly1305.wasm ───────────────
    // The WASM binary is only needed when the location feature is active.
    // Skip the work entirely for other feature combinations to keep build times low.
    let location_enabled = std::env::var("CARGO_FEATURE_LOCATION").is_ok()
        || std::env::var("CARGO_FEATURE_LOCATION_BROWSER").is_ok();

    if !location_enabled {
        return;
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let chacha20poly1305_wasm_dir = manifest_dir.join("chacha20poly1305-wasm");
    let out_dir      = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let wasm_dst     = out_dir.join("chacha20poly1305.wasm");

    if chacha20poly1305_wasm_dir.join("Cargo.toml").exists() {
        // ── Development mode: compile from source ─────────────────
        // Rerun only when the WASM source changes.
        println!("cargo:rerun-if-changed=chacha20poly1305-wasm/src/lib.rs");
        println!("cargo:rerun-if-changed=chacha20poly1305-wasm/Cargo.toml");

        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

        let status = Command::new(&cargo)
            .args([
                "build",
                "--manifest-path", chacha20poly1305_wasm_dir.join("Cargo.toml").to_str().unwrap(),
                "--target", "wasm32-unknown-unknown",
                "--release",
                "--quiet",
            ])
            // Prevent the inner build from picking up profiling/instrumentation
            // flags that the outer build may have set.
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .env_remove("RUSTFLAGS")
            .status()
            .expect("failed to invoke cargo for chacha20poly1305-wasm");

        assert!(
            status.success(),
            "chacha20poly1305-wasm WASM compilation failed.\n\
             Tip: make sure the wasm32-unknown-unknown target is installed:\n\
             rustup target add wasm32-unknown-unknown"
        );

        let wasm_src = chacha20poly1305_wasm_dir
            .join("target/wasm32-unknown-unknown/release/chacha20poly1305_wasm.wasm");
        std::fs::copy(&wasm_src, &wasm_dst)
            .expect("failed to copy chacha20poly1305.wasm to OUT_DIR");
    } else {
        // ── Published-crate mode: use the pre-built asset ─────────────────
        // chacha20poly1305-wasm/ is excluded from the published package; assets/chacha20poly1305.wasm
        // is the pre-built binary that was committed alongside the source.
        println!("cargo:rerun-if-changed=assets/chacha20poly1305.wasm");

        let prebuilt = manifest_dir.join("assets/chacha20poly1305.wasm");
        assert!(
            prebuilt.exists(),
            "assets/chacha20poly1305.wasm not found — this is a packaging error. \
             Please report it at https://github.com/d33p0st/toolkit-zero/issues"
        );

        std::fs::copy(&prebuilt, &wasm_dst)
            .expect("failed to copy assets/chacha20poly1305.wasm to OUT_DIR");
    }
}

// ── Compiler feature helpers ──────────────────────────────────────────────────

/// Returns the persistent cache directory for the toolchain tarball.
///
/// Uses `$CARGO_HOME/toolchain-cache/<target>/` — writable on all platforms
/// and shared across workspaces so the tarball is only ever downloaded once.
fn toolchain_cache_dir(target: &str) -> PathBuf {
    let cargo_home = std::env::var("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            // Fallback: ~/.cargo (Linux/macOS) or %USERPROFILE%\.cargo (Windows)
            let home = std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .expect("neither CARGO_HOME, HOME, nor USERPROFILE is set");
            PathBuf::from(home).join(".cargo")
        });
    cargo_home.join("toolchain-cache").join(target)
}

/// Downloads the stable Rust toolchain tarball for `target` and writes it to
/// `dest`, verifying its SHA-256 hash against the official manifest.
fn download_toolchain(target: &str, dest: &Path) {
    use std::io::Read;

    eprintln!("compiler feature: fetching channel-rust-stable.toml …");

    // ── Step 1: fetch the release manifest ───────────────────────────────────
    let mut manifest_bytes = Vec::new();
    ureq::get("https://static.rust-lang.org/dist/channel-rust-stable.toml")
        .call()
        .expect("compiler feature: failed to fetch channel-rust-stable.toml")
        .into_reader()
        .read_to_end(&mut manifest_bytes)
        .expect("compiler feature: failed to read manifest body");
    let manifest = String::from_utf8(manifest_bytes)
        .expect("compiler feature: manifest is not valid UTF-8");

    // ── Step 2: find the xz_url / xz_hash for this target ───────────────────
    let section = format!("[pkg.rust.target.{}]", target);
    let (xz_url, xz_hash) = parse_manifest_section(&manifest, &section)
        .unwrap_or_else(|| panic!(
            "compiler feature: target '{target}' not found in channel-rust-stable.toml.\n\
             This target may not have a pre-built toolchain bundle."
        ));

    // ── Step 3: download the tarball ─────────────────────────────────────────
    eprintln!("compiler feature: downloading {xz_url}");
    let mut tarball_bytes = Vec::new();
    ureq::get(&xz_url)
        .call()
        .expect("compiler feature: failed to download toolchain tarball")
        .into_reader()
        .read_to_end(&mut tarball_bytes)
        .expect("compiler feature: failed to read toolchain tarball body");

    // ── Step 4: verify SHA-256 ────────────────────────────────────────────────
    let expected_hex = xz_hash.strip_prefix("sha256:").unwrap_or(&xz_hash);
    verify_sha256(&tarball_bytes, expected_hex, &xz_url);

    // ── Step 5: write to cache ────────────────────────────────────────────────
    std::fs::write(dest, &tarball_bytes)
        .expect("compiler feature: failed to write toolchain tarball to cache");
    eprintln!("compiler feature: cached at {}", dest.display());
}

/// Finds `section` (e.g. `[pkg.rust.target.x86_64-unknown-linux-gnu]`) in the
/// manifest text and extracts `xz_url` and `xz_hash` values from that section.
fn parse_manifest_section(text: &str, section: &str) -> Option<(String, String)> {
    let mut in_section = false;
    let mut xz_url: Option<String> = None;
    let mut xz_hash: Option<String> = None;

    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            if line == section {
                in_section = true;
            } else if in_section {
                break; // left the section
            }
            continue;
        }
        if !in_section {
            continue;
        }
        if let Some(rest) = line.strip_prefix("xz_url = \"") {
            xz_url = Some(rest.trim_end_matches('"').to_string());
        } else if let Some(rest) = line.strip_prefix("xz_hash = \"") {
            xz_hash = Some(rest.trim_end_matches('"').to_string());
        }
        if xz_url.is_some() && xz_hash.is_some() {
            break;
        }
    }

    Some((xz_url?, xz_hash?))
}

/// Panics if `data`'s SHA-256 digest does not match `expected_hex`.
fn verify_sha256(data: &[u8], expected_hex: &str, url: &str) {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(data);
    let actual_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
    assert_eq!(
        actual_hex, expected_hex,
        "compiler feature: SHA-256 mismatch for {url}\n  expected: {expected_hex}\n  got:      {actual_hex}"
    );
}
