//! Struct-to-binary serialization with authenticated encryption.
//!
//! This module converts any [`bincode`]-encodable value into an opaque,
//! authenticated byte blob and back, using **ChaCha20-Poly1305** (IETF AEAD).
//! A fresh random 12-byte nonce is generated for every [`seal`] call, so
//! ciphertexts are non-deterministic even for identical plaintext and key.
//!
//! # What is guaranteed
//!
//! * **Confidentiality.** The ciphertext reveals nothing about the plaintext
//!   without the key.
//! * **Integrity and authenticity.** The Poly1305 tag detects any bit-level
//!   modification; [`open`] returns an error on tampered or truncated blobs.
//! * **Semantic security.** The random nonce ensures that encrypting the same
//!   value twice produces different ciphertexts, preventing chosen-plaintext
//!   attacks.
//! * **No magic bytes / constant header.** Every output byte depends on the
//!   key and a fresh nonce; there is no static recognisable prefix.
//!
//! # Format
//!
//! ```text
//! blob = nonce (12 B) ‖ AEAD_ciphertext (bincode(value)) ‖ Poly1305 tag (16 B)
//! ```
//!
//! # Default key
//!
//! When no key is supplied, the string `"serialization/deserialization"` is
//! used.
//!
//! # Example
//!
//! ```no_run
//! use toolkit_zero::serialization::{seal, open, Encode, Decode};
//!
//! #[derive(Encode, Decode, Debug, PartialEq)]
//! struct Point { x: f64, y: f64 }
//!
//! let p = Point { x: 1.5, y: -3.0 };
//!
//! // default key — string literals work directly
//! let blob = seal(&p, None::<&str>).unwrap();
//! let back: Point = open(&blob, None::<&str>).unwrap();
//! assert_eq!(p, back);
//!
//! // explicit key — str literals or String are both accepted
//! let blob2 = seal(&p, Some("my secret key")).unwrap();
//! let back2: Point = open(&blob2, Some("my secret key")).unwrap();
//! assert_eq!(p, back2);
//! ```

mod aead;

pub use aead::{seal, open, SerializationError};
pub use bincode::{Encode, Decode};
// Re-exported so that `#[serializable]` users don't need a direct `bincode` dep.
// bincode's proc-macro derive generates code that resolves `bincode::` against
// this path (via `#[bincode(crate = "::toolkit_zero::serialization::bincode")]`
// injected by the macro).
pub use bincode;
pub use toolkit_zero_macros::{serializable, serialize, deserialize};

#[cfg(feature = "backend-deps")]
pub mod backend_deps;