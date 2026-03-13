//! Re-exports all backend dependencies used by the `timelock` module.
//!
//! Only available when the `backend-deps` feature is enabled together with
//! one or more `enc-timelock-*` features.

/// Argon2id KDF — used in passes 1 and 3 of the key-derivation chain.
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
pub use argon2;

/// scrypt KDF — used in pass 2 of the key-derivation chain.
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
pub use scrypt;

/// Zeroize — secure memory wiping for keys and salts.
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
pub use zeroize;

/// Chrono — wall-clock time for `derive_key_now`.
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
pub use chrono;

/// Rand — CSPRNG for salt generation.
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
pub use rand;

/// Tokio — async runtime for `derive_key_now_async` / `derive_key_at_async`.
#[cfg(any(feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
pub use tokio;
