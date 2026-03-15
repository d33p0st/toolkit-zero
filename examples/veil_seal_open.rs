//! Demonstrates the VEIL cipher: seal any `bincode`-encodable struct into opaque
//! bytes and open it back with the same key.
//!
//! What VEIL guarantees:
//!   - Output has no recognisable structure
//!   - Every output byte depends on the full input AND the key
//!   - Without the exact key the bytes cannot be inverted
//!
//! Run with:
//! ```sh
//! cargo run --example veil_seal_open --features serialization
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
    // Transforms Payload into an opaque byte blob.
    let blob = seal(&original, Some(key.to_string())).expect("seal failed");
    println!("Sealed   : {} bytes  (opaque — no structure visible)", blob.len());

    // ── Open ──────────────────────────────────────────────────────────────────
    // Reconstructs Payload from the opaque blob using the same key.
    let recovered: Payload = open(&blob, Some(key.to_string())).expect("open failed");
    println!("Recovered: {recovered:?}");

    assert_eq!(original, recovered, "round-trip mismatch!");
    println!("\nRound-trip successful ✓");

    // ── Wrong key rejects ─────────────────────────────────────────────────────
    let bad: Result<Payload, _> = open(&blob, Some("wrong-key".to_string()));
    assert!(bad.is_err(), "wrong key should fail to open");
    println!("Wrong-key rejection ✓");
}
