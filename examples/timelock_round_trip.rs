//! Full encrypt → store-header → decrypt round-trip using the timelock API.
//!
//! Demonstrates:
//!   - Deriving an encryption key from an explicit time (`params = None` → `_at` path)
//!   - Packing all settings (precision, format, cadence, salts, KDF params) into a
//!     self-contained [`TimeLockParams`] header for plaintext storage in the ciphertext
//!   - Re-deriving the key from the live system clock (`params = Some(header)` → `_now` path)
//!
//! Run with:
//! ```sh
//! cargo run --example timelock_round_trip --features encryption
//! ```
//!
//! If you run this at exactly the right minute the keys will match.  Because
//! `TimePrecision::Minute` is used the window is 60 seconds wide — any run
//! within the same minute as the lock-time will succeed.

use toolkit_zero::encryption::timelock::{
    timelock, pack,
    TimeLockCadence, TimeLockSalts, TimeLockTime,
    TimePrecision, TimeFormat, KdfPreset, Weekday,
};

fn main() {
    // ── Encryption side ───────────────────────────────────────────────────────
    // Generate fresh salts.  Salts are NOT secret — store them in plaintext
    // alongside the ciphertext so the decryption side can reproduce the key.
    let salts = TimeLockSalts::generate();

    // Use a deliberately fast preset so the example finishes quickly.
    // In production use KdfPreset::Balanced or stronger.
    let kdf = KdfPreset::Balanced.params();

    // Lock to any Tuesday at 18:00 (hour-precision window = the full 18:00–18:59 block).
    let cadence   = TimeLockCadence::DayOfWeek(Weekday::Tuesday);
    let lock_time = TimeLockTime::new(18, 0).unwrap();

    println!("Deriving encryption key (this may take a few seconds)…");
    let enc_key = timelock(
        Some(cadence.clone()),
        Some(lock_time),
        Some(TimePrecision::Hour),
        Some(TimeFormat::Hour24),
        Some(salts.clone()),
        Some(kdf),
        None,   // params = None → _at (encryption) path
    )
    .expect("encryption-side key derivation failed");

    println!("enc_key[:8] = {:02x?}", &enc_key.as_bytes()[..8]);

    // Pack every setting — including salts and KDF params — into a compact header.
    // This header goes into the ciphertext in plaintext; nothing here is secret.
    let header = pack(
        TimePrecision::Hour,
        TimeFormat::Hour24,
        &cadence,
        salts,
        kdf,
    );

    // ── Decryption side ───────────────────────────────────────────────────────
    // Load `header` from the ciphertext and call timelock() at the matching
    // time slot with params = Some(header).
    println!("Deriving decryption key from system clock…");
    let dec_key = timelock(
        None, None, None, None, None, None,
        Some(header),   // params = Some → _now (decryption) path
    )
    .expect("decryption-side key derivation failed");

    println!("dec_key[:8] = {:02x?}", &dec_key.as_bytes()[..8]);

    // ── Verdict ───────────────────────────────────────────────────────────────
    if enc_key.as_bytes() == dec_key.as_bytes() {
        println!("\nKeys match ✓  — running on a Tuesday at 18:xx");
    } else {
        println!("\nKeys differ — not running on a Tuesday at 18:xx (expected outside that window)");
    }
}
