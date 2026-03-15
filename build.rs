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
