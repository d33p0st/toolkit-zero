// Serialization — sealed byte blobs via ChaCha20-Poly1305.
//
// This file implements the full seal/open pipeline using a proper AEAD cipher.
// ChaCha20-Poly1305 provides authenticated encryption: confidentiality,
// integrity, and authenticity. A unique random 12-byte nonce is generated for
// every call to `seal`, ensuring ciphertexts are non-deterministic (same
// plaintext + key → different ciphertext each time), which is required for
// semantic security under CPA/CCA models.
//
// Key derivation: the caller-supplied key string is hashed with SHA-256 to
// produce the 32-byte ChaCha20 key. An opaque blob format is used:
//   blob = nonce(12 bytes) ‖ AEAD_ciphertext(bincode(value)) ‖ GCM tag(16 bytes)

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use bincode::{
    config::standard,
    encode_to_vec, decode_from_slice,
    Encode, Decode,
    error::{EncodeError, DecodeError},
};
use rand::RngCore as _;
use zeroize::Zeroizing;

// ─── public error type ────────────────────────────────────────────────────────

/// Errors returned by [`seal`] and [`open`].
#[derive(Debug)]
pub enum SerializationError {
    /// The struct could not be encoded to bytes by `bincode`.
    Encode(EncodeError),
    /// The byte blob could not be decoded (wrong key, corrupted data, or truncated blob).
    Decode(DecodeError),
    /// AEAD authentication failed — the key is wrong or the ciphertext has been tampered with.
    Cipher,
}

impl std::fmt::Display for SerializationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encode(e)  => write!(f, "seal encode error: {e}"),
            Self::Decode(e)  => write!(f, "open decode error: {e}"),
            Self::Cipher     => write!(f, "AEAD cipher error: wrong key or tampered ciphertext"),
        }
    }
}

impl std::error::Error for SerializationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encode(e) => Some(e),
            Self::Decode(e) => Some(e),
            Self::Cipher    => None,
        }
    }
}

impl From<EncodeError> for SerializationError {
    fn from(e: EncodeError) -> Self { Self::Encode(e) }
}

impl From<DecodeError> for SerializationError {
    fn from(e: DecodeError) -> Self { Self::Decode(e) }
}

// ─── constants ────────────────────────────────────────────────────────────────

const DEFAULT_KEY: &str = "serialization/deserialization";
const NONCE_LEN:   usize = 12;

// ─── public API ──────────────────────────────────────────────────────────────

/// Encode `value` to an authenticated, encrypted byte blob sealed with `key`.
///
/// Encryption uses **ChaCha20-Poly1305** (IETF) with a freshly generated
/// 12-byte random nonce prepended to the output. Every call produces a
/// different ciphertext even for the same plaintext and key.
///
/// If `key` is `None` the default key `"serialization/deserialization"` is
/// used. String literals (`Some("key")`) and owned `String`s are both accepted.
/// The resulting blob can only be decoded by [`open`] with the same key.
///
/// # Errors
///
/// Returns [`SerializationError::Encode`] if `bincode` cannot serialise the
/// value.
pub fn seal<T, K>(value: &T, key: Option<K>) -> Result<Vec<u8>, SerializationError>
where
    T: Encode,
    K: AsRef<str>,
{
    let key_str = key.as_ref().map(|k| k.as_ref()).unwrap_or(DEFAULT_KEY);
    let cipher_key = derive_key(key_str.as_bytes());

    // Encode the struct to raw bytes with bincode.
    let plain: Zeroizing<Vec<u8>> = Zeroizing::new(encode_to_vec(value, standard())?);

    // Generate a fresh random nonce for every call.
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*cipher_key));
    let ciphertext = cipher
        .encrypt(nonce, plain.as_slice())
        .map_err(|_| SerializationError::Cipher)?;

    // blob = nonce ‖ ciphertext (which already includes the 16-byte Poly1305 tag).
    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Decode a byte blob produced by [`seal`] back into `T`.
///
/// If `key` is `None` the default key is used. String literals and owned
/// `String`s are both accepted. Returns an error if the key is wrong, the blob
/// is truncated, or the ciphertext has been tampered with — the Poly1305 tag
/// prevents decryption of modified data.
///
/// # Errors
///
/// - [`SerializationError::Cipher`] if authentication fails (wrong key or tampered blob).
/// - [`SerializationError::Decode`] if the decrypted bytes cannot be interpreted as `T`.
pub fn open<T, K>(blob: &[u8], key: Option<K>) -> Result<T, SerializationError>
where
    T: Decode<()>,
    K: AsRef<str>,
{
    if blob.len() < NONCE_LEN {
        return Err(SerializationError::Cipher);
    }

    let key_str = key.as_ref().map(|k| k.as_ref()).unwrap_or(DEFAULT_KEY);
    let cipher_key = derive_key(key_str.as_bytes());

    let nonce = Nonce::from_slice(&blob[..NONCE_LEN]);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*cipher_key));

    let plain: Zeroizing<Vec<u8>> = Zeroizing::new(
        cipher
            .decrypt(nonce, &blob[NONCE_LEN..])
            .map_err(|_| SerializationError::Cipher)?,
    );

    let (value, _): (T, _) = decode_from_slice(&*plain, standard())?;
    Ok(value)
}

// ─── key derivation ───────────────────────────────────────────────────────────

/// Derive a 32-byte ChaCha20 key from a key string using SHA-256.
///
/// SHA-256 produces a uniformly distributed 256-bit output from the string,
/// which is used directly as the symmetric key. This is appropriate for
/// caller-supplied keys that already have sufficient entropy (e.g. random
/// tokens, passphrase hashes). For low-entropy passphrases consider
/// pre-processing with Argon2id before passing to `seal`/`open`.
#[inline]
fn derive_key(key_bytes: &[u8]) -> Zeroizing<[u8; 32]> {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(key_bytes);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(digest.as_slice());
    out
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bincode::{Encode, Decode};

    #[derive(Encode, Decode, Debug, PartialEq)]
    struct Point { x: f64, y: f64, label: String }

    #[derive(Encode, Decode, Debug, PartialEq)]
    struct Nested { id: u64, inner: Point, tags: Vec<String> }

    #[test]
    fn round_trip_default_key() {
        let p = Point { x: 1.5, y: -3.0, label: "origin".into() };
        let blob = seal(&p, None::<&str>).unwrap();
        let back: Point = open(&blob, None::<&str>).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn round_trip_custom_key_str_literal() {
        let p = Point { x: 42.0, y: 0.001, label: "custom".into() };
        let blob = seal(&p, Some("hunter2")).unwrap();
        let back: Point = open(&blob, Some("hunter2")).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn round_trip_custom_key_owned_string() {
        let p = Point { x: 42.0, y: 0.001, label: "owned".into() };
        let key = String::from("hunter2");
        let blob = seal(&p, Some(key.as_str())).unwrap();
        let back: Point = open(&blob, Some(key.as_str())).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn round_trip_nested() {
        let n = Nested {
            id: 9999,
            inner: Point { x: -1.0, y: 2.5, label: "nested".into() },
            tags: vec!["a".into(), "bb".into(), "ccc".into()],
        };
        let blob = seal(&n, Some("nested-key")).unwrap();
        let back: Nested = open(&blob, Some("nested-key")).unwrap();
        assert_eq!(n, back);
    }

    #[test]
    fn wrong_key_fails() {
        let p = Point { x: 1.0, y: 2.0, label: "x".into() };
        let blob = seal(&p, Some("correct")).unwrap();
        let result: Result<Point, _> = open(&blob, Some("wrong"));
        assert!(result.is_err());
    }

    #[test]
    fn ciphertext_differs_from_plaintext() {
        let p = Point { x: 0.0, y: 0.0, label: "zero".into() };
        let plain = bincode::encode_to_vec(&p, bincode::config::standard()).unwrap();
        let blob = seal(&p, None::<&str>).unwrap();
        assert_ne!(blob, plain);
    }

    #[test]
    fn same_plaintext_same_key_produces_different_ciphertext_each_time() {
        // ChaCha20-Poly1305 uses a fresh random nonce per seal — ciphertext MUST differ.
        let p = Point { x: 1.0, y: 2.0, label: "det".into() };
        let b1 = seal(&p, Some("k")).unwrap();
        let b2 = seal(&p, Some("k")).unwrap();
        assert_ne!(b1, b2, "random nonces must produce distinct ciphertexts");
    }

    #[test]
    fn tampered_blob_rejected() {
        let p = Point { x: 3.0, y: 4.0, label: "t".into() };
        let mut blob = seal(&p, Some("key")).unwrap();
        // Flip a byte in the ciphertext portion (after the nonce).
        let len = blob.len();
        blob[len - 1] ^= 0xff;
        let result: Result<Point, _> = open(&blob, Some("key"));
        assert!(result.is_err(), "tampered ciphertext must be rejected");
    }
}
