//! ChaCha20-Poly1305 sealing, compiled to WebAssembly.
//!
//! Exposed as raw C-ABI exports — no wasm-bindgen required.
//!
//! Call sequence from JavaScript:
//!
//! 1. Write key bytes to `KEY_BUF` via `key_buf_ptr()`.
//! 2. Write a 12-byte nonce to `NONCE_BUF` via `nonce_buf_ptr()`
//!    (generate it with `crypto.getRandomValues` in the browser).
//! 3. Write the bincode-encoded plaintext to `PLAIN_BUF` via `plain_buf_ptr()`.
//! 4. Call `encrypt(key_len, plain_len)`.  Returns 0 on success, -1 on error.
//! 5. Read `cipher_len()` bytes from `cipher_buf_ptr()`.
//!    Layout: `nonce (12 B) || ChaCha20-Poly1305 ciphertext+tag (plain_len + 16 B)`.
//!
//! The output format exactly matches `toolkit_zero::serialization::seal`, so the
//! sealed bytes can be POSTed directly and decrypted by the server's
//! `.encryption::<T>(key)` route builder.

#![no_std]

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use sha2::{Sha256, Digest};

// ─── Static buffers ───────────────────────────────────────────────────────────

/// Maximum key-string length (bytes).
const KEY_MAX: usize = 256;
/// Maximum plaintext length (bytes).
/// BrowserLocationBody worst case ≈ 68 B; BrowserErrorBody ≈ 256 B — 512 is safe.
const PLAIN_MAX: usize = 512;
/// Output: nonce(12) + ciphertext(PLAIN_MAX) + tag(16).
const CIPHER_MAX: usize = 12 + PLAIN_MAX + 16;

static mut KEY_BUF:   [u8; KEY_MAX]     = [0u8; KEY_MAX];
static mut NONCE_BUF: [u8; 12]          = [0u8; 12];
static mut PLAIN_BUF: [u8; PLAIN_MAX]   = [0u8; PLAIN_MAX];
static mut CIPHER_BUF: [u8; CIPHER_MAX] = [0u8; CIPHER_MAX];
static mut CIPHER_LEN: usize            = 0;

// ─── Exports ─────────────────────────────────────────────────────────────────

/// Returns a pointer to the key input buffer (writable, KEY_MAX bytes).
#[no_mangle]
pub extern "C" fn key_buf_ptr() -> *mut u8 {
    core::ptr::addr_of_mut!(KEY_BUF) as *mut u8
}

/// Returns a pointer to the nonce input buffer (writable, exactly 12 bytes).
#[no_mangle]
pub extern "C" fn nonce_buf_ptr() -> *mut u8 {
    core::ptr::addr_of_mut!(NONCE_BUF) as *mut u8
}

/// Returns a pointer to the plaintext input buffer (writable, PLAIN_MAX bytes).
#[no_mangle]
pub extern "C" fn plain_buf_ptr() -> *mut u8 {
    core::ptr::addr_of_mut!(PLAIN_BUF) as *mut u8
}

/// Returns a pointer to the ciphertext output buffer (readable after `encrypt`).
#[no_mangle]
pub extern "C" fn cipher_buf_ptr() -> *const u8 {
    core::ptr::addr_of!(CIPHER_BUF) as *const u8
}

/// Returns the number of bytes written to the cipher buffer by the last `encrypt` call.
#[no_mangle]
pub extern "C" fn cipher_len() -> usize {
    unsafe { core::ptr::read(core::ptr::addr_of!(CIPHER_LEN)) }
}

/// Seal `PLAIN_BUF[..plain_len]` with the ChaCha20-Poly1305 key derived from
/// `KEY_BUF[..key_len]` (SHA-256) and the nonce in `NONCE_BUF`.
///
/// Writes `nonce(12) || ciphertext+tag(plain_len + 16)` to `CIPHER_BUF` and
/// updates `CIPHER_LEN`.
///
/// Returns `0` on success, `-1` on error (buffer overflow or AEAD failure).
#[no_mangle]
pub extern "C" fn encrypt(key_len: usize, plain_len: usize) -> i32 {
    if key_len > KEY_MAX || plain_len > PLAIN_MAX {
        return -1;
    }

    unsafe {
        // Derive 32-byte ChaCha20 key from the UTF-8 key string via SHA-256.
        // This matches `derive_key` in toolkit-zero's serialization::aead module.
        let key_slice = core::slice::from_raw_parts(
            core::ptr::addr_of!(KEY_BUF) as *const u8, key_len
        );
        let hash = Sha256::digest(key_slice);
        let cipher_key = Key::from_slice(hash.as_slice());
        let cipher = ChaCha20Poly1305::new(cipher_key);

        let nonce_slice = core::slice::from_raw_parts(
            core::ptr::addr_of!(NONCE_BUF) as *const u8, 12
        );
        let nonce = Nonce::from_slice(nonce_slice);

        // Stack work-buffer to avoid aliasing CIPHER_BUF while we write into it.
        let mut work = [0u8; PLAIN_MAX];
        let plain_slice = core::slice::from_raw_parts(
            core::ptr::addr_of!(PLAIN_BUF) as *const u8, plain_len
        );
        work[..plain_len].copy_from_slice(plain_slice);

        match cipher.encrypt_in_place_detached(nonce, b"", &mut work[..plain_len]) {
            Ok(tag) => {
                // Write: nonce(12) || ciphertext(plain_len) || tag(16)
                let out = core::slice::from_raw_parts_mut(
                    core::ptr::addr_of_mut!(CIPHER_BUF) as *mut u8,
                    12 + plain_len + 16,
                );
                out[..12].copy_from_slice(nonce_slice);
                out[12..12 + plain_len].copy_from_slice(&work[..plain_len]);
                out[12 + plain_len..].copy_from_slice(tag.as_slice());
                core::ptr::write(core::ptr::addr_of_mut!(CIPHER_LEN), 12 + plain_len + 16);
                0
            }
            Err(_) => -1,
        }
    }
}

// ─── no_std glue ─────────────────────────────────────────────────────────────

#[cfg(not(test))]
#[panic_handler]
fn panic_handler(_info: &core::panic::PanicInfo) -> ! {
    // In WASM the `unreachable` instruction traps immediately.
    core::arch::wasm32::unreachable()
}
