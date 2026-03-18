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

use std::path::PathBuf;
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
