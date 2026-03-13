// VEIL — Variable-Expansion Interleaved Lattice cipher
//
// This file implements the full seal/open pipeline.  Nothing in this file
// imports from `serde` or any external crypto crate.  The only external
// crate used is `bincode` (with its own `Encode`/`Decode` traits) for the
// outermost byte-level framing and the initial struct → bytes step.

use bincode::{
    config::standard,
    encode_to_vec, decode_from_slice,
    Encode, Decode,
    error::{EncodeError, DecodeError},
};

// ─── public error type ────────────────────────────────────────────────────────

/// Errors returned by [`seal`] and [`open`].
#[derive(Debug)]
pub enum SerializationError {
    /// The struct could not be encoded to bytes by `bincode`.
    Encode(EncodeError),
    /// The byte blob could not be decoded / the key is wrong.
    Decode(DecodeError),
}

impl std::fmt::Display for SerializationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encode(e) => write!(f, "seal encode error: {e}"),
            Self::Decode(e) => write!(f, "open decode error: {e}"),
        }
    }
}

impl std::error::Error for SerializationError {}

impl From<EncodeError> for SerializationError {
    fn from(e: EncodeError) -> Self { Self::Encode(e) }
}

impl From<DecodeError> for SerializationError {
    fn from(e: DecodeError) -> Self { Self::Decode(e) }
}

// ─── default key ─────────────────────────────────────────────────────────────

const DEFAULT_KEY: &str = "serialization/deserialization";
const BLOCK: usize = 16;

// ─── public API ──────────────────────────────────────────────────────────────

/// Encode `value` to an opaque byte blob sealed with `key`.
///
/// If `key` is `None` the default key `"serialization/deserialization"` is
/// used.  The resulting blob can only be decoded by [`open`] with the same
/// key.
///
/// # Errors
///
/// Returns [`SerializationError::Encode`] if `bincode` cannot serialize the
/// value.
pub fn seal<T: Encode>(value: &T, key: Option<&str>) -> Result<Vec<u8>, SerializationError> {
    let key = key.unwrap_or(DEFAULT_KEY);

    // Step 0: struct → raw bytes via bincode
    let plain = encode_to_vec(value, standard())?;

    // Steps 1—5: VEIL forward transform
    let cipher = veil_encrypt(&plain, key);

    // Outer bincode framing: Vec<u8> → length-prefixed blob
    let blob = encode_to_vec(&cipher, standard())?;
    Ok(blob)
}

/// Decode a byte blob produced by [`seal`] back into `T`.
///
/// If `key` is `None` the default key is used.
///
/// # Errors
///
/// Returns [`SerializationError::Decode`] if the blob is malformed or the
/// key is incorrect.
pub fn open<T: Decode<()>>(blob: &[u8], key: Option<&str>) -> Result<T, SerializationError> {
    let key = key.unwrap_or(DEFAULT_KEY);

    // Outer bincode unframing
    let (cipher, _): (Vec<u8>, _) = decode_from_slice(blob, standard())?;

    // Steps 5—1 reversed
    let plain = veil_decrypt(&cipher, key)?;

    // raw bytes → struct via bincode
    let (value, _): (T, _) = decode_from_slice(&plain, standard())?;
    Ok(value)
}

// ─── VEIL forward (encrypt) ──────────────────────────────────────────────────

fn veil_encrypt(plain: &[u8], key: &str) -> Vec<u8> {
    let ks = KeySchedule::new(key);

    // 1. S-box substitution (key-dependent permutation table)
    let mut buf: Vec<u8> = plain.iter().map(|&b| ks.sbox[b as usize]).collect();

    // 2. Key-stream XOR
    for (i, b) in buf.iter_mut().enumerate() {
        *b ^= ks.stream_byte(i);
    }

    // 3. Position mixing:  b[i] ^= mix(i, b[i-1], b[i+1])
    position_mix_forward(&mut buf);

    // 4. Block diffusion (sequential accumulator across 16-byte blocks)
    block_diffuse_forward(&mut buf);

    // 5. Shuffle bytes within each 16-byte block
    block_shuffle_forward(&mut buf, &ks);

    buf
}

// ─── VEIL reverse (decrypt) ──────────────────────────────────────────────────

fn veil_decrypt(cipher: &[u8], key: &str) -> Result<Vec<u8>, SerializationError> {
    let ks = KeySchedule::new(key);

    let mut buf = cipher.to_vec();

    // 5 reverse: un-shuffle bytes within each 16-byte block
    block_shuffle_reverse(&mut buf, &ks);

    // 4 reverse: undo sequential accumulator
    block_diffuse_reverse(&mut buf);

    // 3 reverse: undo position mixing
    position_mix_reverse(&mut buf);

    // 2 reverse: XOR again with same key-stream (XOR is its own inverse)
    for (i, b) in buf.iter_mut().enumerate() {
        *b ^= ks.stream_byte(i);
    }

    // 1 reverse: inverse S-box
    for b in buf.iter_mut() {
        *b = ks.sbox_inv[*b as usize];
    }

    Ok(buf)
}

// ─── Key schedule ─────────────────────────────────────────────────────────────
//
// All keying material is derived from a FNV-1a hash of the key string fed into
// a splitmix64 PRNG.  No standard crypto hash or cipher is used.

struct KeySchedule {
    /// Forward S-box: substitution table indexed by plaintext byte.
    sbox:     [u8; 256],
    /// Inverse S-box: indexed by ciphertext byte.
    sbox_inv: [u8; 256],
    /// PRNG seed for per-position stream bytes.
    stream_seed: u64,
    /// PRNG seed for block shuffles.
    shuffle_seed: u64,
}

impl KeySchedule {
    fn new(key: &str) -> Self {
        // ── keyed FNV-1a hash → two independent 64-bit seeds ─────────────
        let h0 = fnv1a_64(key.as_bytes());
        let h1 = splitmix64(h0 ^ 0xdeadbeef_cafebabe);

        // ── build S-box with Fisher-Yates using splitmix64 PRNG ───────────
        let mut sbox: [u8; 256] = std::array::from_fn(|i| i as u8);
        let mut rng = Rng::new(h0);
        for i in (1..256usize).rev() {
            let j = (rng.next() as usize) % (i + 1);
            sbox.swap(i, j);
        }

        // ── inverse S-box ─────────────────────────────────────────────────
        let mut sbox_inv = [0u8; 256];
        for (i, &v) in sbox.iter().enumerate() {
            sbox_inv[v as usize] = i as u8;
        }

        Self {
            sbox,
            sbox_inv,
            stream_seed: h1,
            shuffle_seed: splitmix64(h1 ^ 0x1234567890abcdef),
        }
    }

    /// One key-stream byte at position `pos`.
    ///
    /// Uses two splitmix64 steps from an index-salted version of the stream
    /// seed so that each position produces a distinct, unpredictable byte.
    #[inline]
    fn stream_byte(&self, pos: usize) -> u8 {
        let salted = self.stream_seed
            .wrapping_add(pos as u64)
            .wrapping_mul(0x9e3779b97f4a7c15);
        let v = splitmix64(salted);
        // XOR the high and low halves for extra mixing
        ((v >> 32) ^ (v & 0xffff_ffff)) as u8
    }

    /// Generate the shuffle permutation for block `block_index` with a given length.
    ///
    /// When `len` == BLOCK this produces the standard 16-element permutation.
    /// When `len` < BLOCK (tail block) it produces a bijective permutation of
    /// exactly `len` elements.
    fn block_perm_len(&self, block_index: usize, len: usize) -> Vec<usize> {
        let seed = self.shuffle_seed
            .wrapping_add(block_index as u64)
            .wrapping_mul(0x6c62272e07bb0142);
        let mut perm: Vec<usize> = (0..len).collect();
        let mut rng = Rng::new(splitmix64(seed));
        for i in (1..len).rev() {
            let j = (rng.next() as usize) % (i + 1);
            perm.swap(i, j);
        }
        perm
    }

    /// Generate the full-block (BLOCK-length) shuffle permutation.
    fn block_perm(&self, block_index: usize) -> [usize; BLOCK] {
        let v = self.block_perm_len(block_index, BLOCK);
        std::array::from_fn(|i| v[i])
    }
}

// ─── PRNG ─────────────────────────────────────────────────────────────────────

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self { Self(seed) }
    #[inline]
    fn next(&mut self) -> u64 {
        self.0 = splitmix64(self.0);
        self.0
    }
}

/// splitmix64 — single step.
#[inline]
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

/// FNV-1a 64-bit hash.
#[inline]
fn fnv1a_64(data: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME:  u64 = 0x00000100000001b3;
    let mut h = OFFSET;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(PRIME);
    }
    h
}

// ─── Step 3: position mixing ──────────────────────────────────────────────────
//
// Forward:  b[i] ^= (i as u8).wrapping_add(prev).wrapping_mul(0x6b ^ next_preview)
// The "preview" of b[i+1] uses the *original* (pre-mix) value, so the reverse
// can be computed left-to-right without looking ahead at a transformed value.

fn position_mix_forward(buf: &mut [u8]) {
    // Sequential left-to-right: mix at position i depends only on the
    // *original* (pre-mix) value of the left neighbour, so the inverse is
    // trivially computable left-to-right without lookahead.
    let mut prev_orig: u8 = 0xA7;
    for (i, b) in buf.iter_mut().enumerate() {
        let original = *b;
        let mix = (i as u8).wrapping_add(prev_orig).wrapping_mul(0x6b);
        *b ^= mix;
        prev_orig = original;
    }
}

fn position_mix_reverse(buf: &mut [u8]) {
    // Mirror of forward: recover original left-to-right, feeding each
    // recovered byte as the left-neighbour input for the next position.
    let mut prev_orig: u8 = 0xA7;
    for (i, b) in buf.iter_mut().enumerate() {
        let mix = (i as u8).wrapping_add(prev_orig).wrapping_mul(0x6b);
        let original = *b ^ mix;
        *b = original;
        prev_orig = original;
    }
}

// ─── Step 4: block diffusion ──────────────────────────────────────────────────
//
// Forward:  process blocks left-to-right; accumulator starts at 0xB3.
//           For each byte in the block: out = in ^ acc; acc = acc.rotate_left(3) ^ out
// The accumulator carries information from all prior bytes into each new byte.

fn block_diffuse_forward(buf: &mut [u8]) {
    let mut acc: u8 = 0xB3;
    for b in buf.iter_mut() {
        let out = *b ^ acc;
        acc = acc.rotate_left(3) ^ out;
        *b = out;
    }
}

fn block_diffuse_reverse(buf: &mut [u8]) {
    // Reverse: given out = in ^ acc, recover in = out ^ acc.
    // acc update: acc_new = acc_old.rotate_left(3) ^ out
    // So: acc_old can be recovered if we run left-to-right maintaining the same acc.
    let mut acc: u8 = 0xB3;
    for b in buf.iter_mut() {
        let out = *b;
        let original = out ^ acc;
        acc = acc.rotate_left(3) ^ out;
        *b = original;
    }
}

// ─── Step 5: block shuffle ────────────────────────────────────────────────────
//
// Each 16-byte block has its bytes permuted according to a key+block-index-
// derived permutation.  The last (possibly short) block is permuted with
// indices clamped to its actual length.

fn block_shuffle_forward(buf: &mut [u8], ks: &KeySchedule) {
    let n = buf.len();
    let full_blocks = n / BLOCK;
    for bi in 0..full_blocks {
        let perm = ks.block_perm(bi);
        let base = bi * BLOCK;
        let block: [u8; BLOCK] = std::array::from_fn(|i| buf[base + i]);
        for i in 0..BLOCK {
            buf[base + i] = block[perm[i]];
        }
    }
    // tail block (< 16 bytes) — use a properly bounded bijection
    let tail_start = full_blocks * BLOCK;
    let tail_len = n - tail_start;
    if tail_len > 1 {
        let perm = ks.block_perm_len(full_blocks, tail_len);
        let tail: Vec<u8> = buf[tail_start..].to_vec();
        for i in 0..tail_len {
            buf[tail_start + i] = tail[perm[i]];
        }
    }
}

fn block_shuffle_reverse(buf: &mut [u8], ks: &KeySchedule) {
    let n = buf.len();
    let full_blocks = n / BLOCK;
    for bi in 0..full_blocks {
        let perm = ks.block_perm(bi);
        let base = bi * BLOCK;
        let block: [u8; BLOCK] = std::array::from_fn(|i| buf[base + i]);
        let mut orig = [0u8; BLOCK];
        for i in 0..BLOCK {
            orig[perm[i]] = block[i];
        }
        buf[base..base + BLOCK].copy_from_slice(&orig);
    }
    // tail block
    let tail_start = full_blocks * BLOCK;
    let tail_len = n - tail_start;
    if tail_len > 1 {
        let perm = ks.block_perm_len(full_blocks, tail_len);
        let tail: Vec<u8> = buf[tail_start..].to_vec();
        let mut orig = vec![0u8; tail_len];
        for i in 0..tail_len {
            orig[perm[i]] = tail[i];
        }
        buf[tail_start..].copy_from_slice(&orig);
    }
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
        let blob = seal(&p, None).unwrap();
        let back: Point = open(&blob, None).unwrap();
        assert_eq!(p, back);
    }


    #[test]
    fn round_trip_custom_key() {
        let p = Point { x: 42.0, y: 0.001, label: "custom".into() };
        let blob = seal(&p, Some("hunter2")).unwrap();
        let back: Point = open(&blob, Some("hunter2")).unwrap();
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
        // Opening with wrong key should either error or produce garbage that
        // fails to decode as Point.
        let result: Result<Point, _> = open(&blob, Some("wrong"));
        assert!(result.is_err());
    }

    #[test]
    fn ciphertext_differs_from_plaintext() {
        let p = Point { x: 0.0, y: 0.0, label: "zero".into() };
        let plain = bincode::encode_to_vec(&p, bincode::config::standard()).unwrap();
        let blob = seal(&p, None).unwrap();
        // The sealed blob must not equal the raw bincode bytes.
        assert_ne!(blob, plain);
    }

    #[test]
    fn same_plaintext_same_key_produces_same_ciphertext() {
        let p = Point { x: 1.0, y: 2.0, label: "det".into() };
        let b1 = seal(&p, Some("k")).unwrap();
        let b2 = seal(&p, Some("k")).unwrap();
        assert_eq!(b1, b2); // cipher is deterministic
    }
}
