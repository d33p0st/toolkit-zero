//! Struct-to-binary serialization via the VEIL cipher.
//!
//! This module converts any [`bincode`]-encodable value into an opaque,
//! key-dependent byte sequence and back.  The conversion is performed by the
//! **VEIL** (Variable-Expansion Interleaved Lattice) cipher designed
//! specifically for this toolkit.
//!
//! # What VEIL guarantees
//!
//! * **No magic bytes / constant header.** The output has no recognisable
//!   structure — it looks like uniformly random bytes.
//! * **Key-dependent, irreversible without the key.** Every step of the
//!   cipher is keyed.  Without the exact key an attacker cannot invert any
//!   individual step, let alone the full pipeline.
//! * **Position-sensitive.** Identical plaintext bytes at different offsets
//!   always produce different ciphertext bytes.
//! * **Diffusion across the entire message.** Every output byte depends on
//!   all preceding input bytes (sequential block accumulator).
//! * **No standard crypto primitives.** The key schedule, S-box, stream, and
//!   shuffle are all derived from a custom PRNG seeded with a keyed hash.
//!
//! # VEIL pipeline (seal direction)
//!
//! ```text
//! struct  ──bincode──►  raw bytes
//!                           │
//!              ┌────────────▼────────────┐
//!              │  1. keyed S-box sub     │  each byte replaced via key-derived
//!              │  2. key-stream XOR      │  permutation table + stream
//!              │  3. position mixing     │  byte ⊕ f(index, neighbours)
//!              │  4. block diffusion     │  16-byte blocks, sequential acc
//!              │  5. block byte shuffle  │  keyed permutation per block
//!              └────────────┬────────────┘
//!                           │
//!              bincode wrap (Vec<u8> envelope)
//!                           │
//!                       `Vec<u8>`
//! ```
//!
//! `open` reverses every step in exact reverse order.
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
//! let blob = seal(&p, None).unwrap();
//! let back: Point = open(&blob, None).unwrap();
//! assert_eq!(p, back);
//!
//! // with an explicit key
//! let blob2 = seal(&p, Some("my secret key")).unwrap();
//! let back2: Point = open(&blob2, Some("my secret key")).unwrap();
//! assert_eq!(p, back2);
//! ```

mod veil;

pub use veil::{seal, open, SerializationError};
pub use bincode::{Encode, Decode};