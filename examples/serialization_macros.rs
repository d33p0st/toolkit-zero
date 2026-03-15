//! Demonstrates the `#[serializable]`, `#[serialize]`, and `#[deserialize]`
//! attribute macros from the `serialization` feature.
//!
//! All three macros are built on top of the same ChaCha20-Poly1305 AEAD
//! primitives exposed by [`toolkit_zero::serialization`].
//!
//! | Macro             | Purpose                                              |
//! |-------------------|------------------------------------------------------|
//! | `#[serializable]` | Derives `seal` / `open` methods on a struct          |
//! | `#[serialize]`    | Encrypts a value into a variable or a file           |
//! | `#[deserialize]`  | Decrypts a variable or a file into a typed value     |
//!
//! ## `#[serializable]`
//!
//! Attaching `#[serializable]` to a struct generates:
//!
//! - `instance.seal(key: Option<String>) -> Result<Vec<u8>, Error>` — encrypts
//! - `Type::open(bytes: &[u8], key: Option<String>) -> Result<Type, Error>` — decrypts
//!
//! Per-field keys are also supported via `#[serializable(key = "...")]` on a
//! field, which generates `instance.seal_<field>()` / `Type::open_<field>()`.
//!
//! ## `#[serialize]` / `#[deserialize]`
//!
//! These are statement-level macros that expand _inside_ a function body.
//!
//! **Variable mode** (`#[serialize(expr)]` / `#[deserialize(blob_var)]`):
//! ```text
//! #[serialize(cfg)]
//! fn blob() -> Vec<u8> {}
//! // ↑ expands to: let blob: Vec<u8> = toolkit_zero::serialization::seal(&cfg, None)?;
//!
//! #[deserialize(blob)]
//! fn cfg_back() -> Config {}
//! // ↑ expands to: let cfg_back: Config = toolkit_zero::serialization::open::<Config, _>(&blob, None)?;
//! ```
//!
//! **File mode** (add `path = "..."` to both):
//! ```text
//! #[serialize(cfg, path = "/tmp/config.bin")]
//! fn _write() {}
//! // ↑ writes the encrypted bytes to the file; no binding is produced.
//!
//! #[deserialize(path = "/tmp/config.bin")]
//! fn cfg_from_file() -> Config {}
//! // ↑ reads the file and decrypts it; binds the result to `cfg_from_file`.
//! ```
//!
//! An optional `key = "<expression>"` argument selects a custom encryption key on
//! both macros.
//!
//! Run with:
//! ```sh
//! cargo run --example serialization_macros --features serialization
//! ```

use toolkit_zero::serialization::{serializable, serialize, deserialize};

// ─── Shared data types ────────────────────────────────────────────────────────

/// A nested config struct exercised by `#[serializable]`.
#[serializable]
#[derive(Debug, PartialEq, Clone)]
struct AppConfig {
    debug: bool,
    max_conn: u32,
    hostname: String,
}

/// Per-field key annotation: `password` is sealed with a dedicated key.
#[serializable]
#[derive(Debug, PartialEq, Clone)]
struct Credentials {
    pub username: String,
    /// Sealed independently with the baked-in key `"per-field-secret"`.
    #[serializable(key = "per-field-secret")]
    pub password: String,
}

/// Struct used with `#[serialize]` / `#[deserialize]` variable mode.
#[serializable]
#[derive(Debug, PartialEq, Clone)]
struct Payload {
    id:   u64,
    data: String,
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== serialization macros demo ===\n");
    demo_serializable()?;
    demo_serializable_field_key()?;
    demo_serialize_variable_mode()?;
    demo_serialize_file_mode()?;
    println!("\nAll demos completed successfully ✓");
    Ok(())
}

// ─── Demo: #[serializable] — struct-level seal / open ─────────────────────────

fn demo_serializable() -> Result<(), Box<dyn std::error::Error>> {
    println!("── #[serializable] struct-level round-trips ──────────────────────");

    let cfg = AppConfig {
        debug:    true,
        max_conn: 64,
        hostname: "localhost".into(),
    };

    // ── Default key (None) ────────────────────────────────────────────────────
    // `seal` encrypts with the library's built-in default key.
    // `open` must use the same key to succeed.
    let blob = cfg.seal(None)?;
    let recovered = AppConfig::open(&blob, None)?;
    assert_eq!(cfg, recovered);
    println!("  default key  : seal → {} bytes, open → {:?}", blob.len(), recovered);

    // ── Custom key ────────────────────────────────────────────────────────────
    let blob2 = cfg.seal(Some("my-secret-key".into()))?;
    let recovered2 = AppConfig::open(&blob2, Some("my-secret-key".into()))?;
    assert_eq!(cfg, recovered2);
    println!("  custom key   : seal → {} bytes, open → {:?}", blob2.len(), recovered2);

    // ── Wrong key must fail ───────────────────────────────────────────────────
    let bad = AppConfig::open(&blob2, Some("wrong-key".into()));
    assert!(bad.is_err(), "opening with the wrong key must fail");
    println!("  wrong key    : open → Err (expected) ✓");

    println!();
    Ok(())
}

// ─── Demo: #[serializable] — per-field key annotation ────────────────────────

fn demo_serializable_field_key() -> Result<(), Box<dyn std::error::Error>> {
    println!("── #[serializable(key = \"...\")]  per-field helpers ───────────────");

    let creds = Credentials {
        username: "alice".into(),
        password: "hunter2".into(),
    };

    // Per-field helpers use the key baked into the annotation.
    // `seal_password()` uses `"per-field-secret"` without the caller supplying it.
    let pw_bytes  = creds.seal_password()?;
    let pw_back   = Credentials::open_password(&pw_bytes)?;
    assert_eq!("hunter2", pw_back);
    println!("  seal_password  → {} bytes", pw_bytes.len());
    println!("  open_password  → {:?}", pw_back);

    // Full-struct helpers still exist alongside the per-field ones.
    let full_blob = creds.seal(None)?;
    let full_back = Credentials::open(&full_blob, None)?;
    assert_eq!(creds, full_back);
    println!("  full seal/open → {:?}", full_back);

    println!();
    Ok(())
}

// ─── Demo: #[serialize] / #[deserialize] — variable mode ─────────────────────

fn demo_serialize_variable_mode() -> Result<(), Box<dyn std::error::Error>> {
    println!("── #[serialize] / #[deserialize]  variable mode ─────────────────");

    let payload = Payload { id: 42, data: "hello, world".into() };

    // ── Default key ───────────────────────────────────────────────────────────
    // `#[serialize(payload)]` expands to:
    //     let blob: Vec<u8> = toolkit_zero::serialization::seal(&payload, None)?;
    #[serialize(payload)]
    fn blob() -> Vec<u8> {}

    // `#[deserialize(blob)]` expands to:
    //     let restored: Payload = toolkit_zero::serialization::open::<Payload, _>(&blob, None)?;
    #[deserialize(blob)]
    fn restored() -> Payload {}

    assert_eq!(payload, restored);
    println!("  default key  : {} bytes → {:?}", blob.len(), restored);

    // ── Custom key ────────────────────────────────────────────────────────────
    // The `key = <expr>` argument accepts any expression that evaluates to `String`.
    #[serialize(payload, key = "custom-key".to_string())]
    fn blob_keyed() -> Vec<u8> {}

    #[deserialize(blob_keyed, key = "custom-key".to_string())]
    fn restored_keyed() -> Payload {}

    assert_eq!(payload, restored_keyed);
    println!("  custom key   : {} bytes → {:?}", blob_keyed.len(), restored_keyed);

    // ── Cross-key failure check ───────────────────────────────────────────────
    let wrong = toolkit_zero::serialization::open::<Payload, String>(&blob_keyed, None);
    assert!(wrong.is_err(), "decrypting with the wrong key must fail");
    println!("  wrong key    : open → Err (expected) ✓");

    println!();
    Ok(())
}

// ─── Demo: #[serialize] / #[deserialize] — file mode ─────────────────────────

fn demo_serialize_file_mode() -> Result<(), Box<dyn std::error::Error>> {
    println!("── #[serialize] / #[deserialize]  file mode ─────────────────────");

    let payload = Payload { id: 99, data: "persisted value".into() };

    // ── Default key, written to /tmp ──────────────────────────────────────────
    // `path = "..."` writes the encrypted bytes to the given file.
    // No variable binding is produced; the function name is ignored.
    #[serialize(payload, path = "/tmp/toolkit_zero_demo.bin")]
    fn _write() {}

    // `#[deserialize(path = "...")]` reads the file and decrypts it.
    #[deserialize(path = "/tmp/toolkit_zero_demo.bin")]
    fn loaded() -> Payload {}

    assert_eq!(payload, loaded);
    println!("  default key  : wrote /tmp/toolkit_zero_demo.bin → {:?}", loaded);

    // ── Custom key, different file ─────────────────────────────────────────────
    #[serialize(payload, path = "/tmp/toolkit_zero_demo_keyed.bin", key = "file-key".to_string())]
    fn _write_keyed() {}

    #[deserialize(path = "/tmp/toolkit_zero_demo_keyed.bin", key = "file-key".to_string())]
    fn loaded_keyed() -> Payload {}

    assert_eq!(payload, loaded_keyed);
    println!("  custom key   : wrote /tmp/toolkit_zero_demo_keyed.bin → {:?}", loaded_keyed);

    // Clean up temp files.
    std::fs::remove_file("/tmp/toolkit_zero_demo.bin").ok();
    std::fs::remove_file("/tmp/toolkit_zero_demo_keyed.bin").ok();

    println!();
    Ok(())
}
