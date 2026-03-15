//! Demonstrates ChaCha20-Poly1305 authenticated encryption: seal any
//! `bincode`-encodable struct into an opaque, authenticated byte blob and open
//! it back with the same key.
//!
//! What ChaCha20-Poly1305 (IETF AEAD) guarantees:
//!   - **Confidentiality** — ciphertext reveals nothing about the plaintext without the key
//!   - **Integrity & authenticity** — any bit-level modification is detected by the Poly1305 tag
//!   - **Semantic security** — a fresh random nonce is generated per seal call, so encrypting
//!     the same value twice produces different ciphertexts
//!
//! Format: `nonce (12 B) ‖ ciphertext ‖ Poly1305 tag (16 B)`
//!
//! Run with:
//! ```sh
//! cargo run --example seal_open --features serialization
//! ```

use bincode::{Encode, Decode};
use toolkit_zero::serialization::{seal, open};

// Any struct that derives bincode::Encode + bincode::Decode can be sealed.
#[derive(Debug, PartialEq, Encode, Decode)]
struct Payload {
    user:  String,
    score: u32,
    tags:  Vec<String>,
}

fn main() {
    let key = "my-secret-key";

    let original = Payload {
        user:  "alice".into(),
        score: 9001,
        tags:  vec!["rust".into(), "crypto".into()],
    };

    println!("Original : {original:?}");

    // ── Seal ──────────────────────────────────────────────────────────────────
    // String literals and &str both work; K: AsRef<str> handles the conversion.
    let blob = seal(&original, Some(key)).expect("seal failed");
    println!("Sealed   : {} bytes  (nonce ‖ ciphertext ‖ Poly1305 tag)", blob.len());

    // ── Semantic security ─────────────────────────────────────────────────────
    // A fresh random 12-byte nonce is generated on every seal call, so identical
    // plaintext + key still produces a different ciphertext each time.
    let blob2 = seal(&original, Some(key)).expect("seal failed");
    assert_ne!(blob, blob2, "ciphertexts should differ (different nonces)");
    println!("Semantic security   : two seals of the same value differ ✓");

    // ── Open ──────────────────────────────────────────────────────────────────
    // Reconstructs Payload from the opaque blob using the same key.
    let recovered: Payload = open(&blob, Some(key)).expect("open failed");
    println!("Recovered: {recovered:?}");

    assert_eq!(original, recovered, "round-trip mismatch!");
    println!("\nRound-trip successful ✓");

    // ── Wrong key rejects ─────────────────────────────────────────────────────
    let bad: Result<Payload, _> = open(&blob, Some("wrong-key"));
    assert!(bad.is_err(), "wrong key should fail to open");
    println!("Wrong-key rejection ✓");

    // ── Default key ───────────────────────────────────────────────────────────
    // Pass None::<&str> to use the built-in default key.
    let blob3 = seal(&original, None::<&str>).expect("seal with default key failed");
    let back3: Payload = open(&blob3, None::<&str>).expect("open with default key failed");
    assert_eq!(original, back3);
    println!("Default-key round-trip ✓");
}
