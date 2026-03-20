//! Zero-knowledge credential vault.
//!
//! Credentials are stored on-disk as ChaCha20-Poly1305 ciphertexts.
//! The symmetric key is derived from the user's master password with
//! Argon2id (64 MiB, 3 iterations, 1 thread).  The master password
//! itself is never stored or logged.
//!
//! Vault file: `$XDG_CONFIG_HOME/duct-tape/vault.json` (or
//! `~/.config/duct-tape/vault.json`).

use argon2::{Argon2, Algorithm, Version, Params};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

// ── Nonce length for ChaCha20-Poly1305 ───────────────────────────────────────
const NONCE_LEN: usize = 12;

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum VaultError {
    Io(std::io::Error),
    /// Master password is incorrect or vault is corrupt.
    WrongPassword,
    /// Encryption or decryption failure.
    Crypto,
    /// JSON serialisation failure.
    Json(serde_json::Error),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::Io(e)          => write!(f, "vault I/O error: {e}"),
            VaultError::WrongPassword  => write!(f, "wrong master password or corrupt vault"),
            VaultError::Crypto         => write!(f, "vault encryption error"),
            VaultError::Json(e)        => write!(f, "vault JSON error: {e}"),
        }
    }
}

// ── On-disk serialisation types ───────────────────────────────────────────────

/// Full vault file (JSON).
#[derive(Serialize, Deserialize)]
struct VaultFile {
    /// Argon2id salt — base64.
    argon2_salt: String,
    /// Encrypted sentinel value used to verify the master password — base64.
    sentinel_ct: String,
    /// Nonce for the sentinel — base64.
    sentinel_nonce: String,
    /// Encrypted entries.
    entries: Vec<EncryptedEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
struct EncryptedEntry {
    domain:   String,
    username: String,
    /// ChaCha20-Poly1305 ciphertext of the password (UTF-8) — base64.
    ciphertext: String,
    /// 12-byte nonce — base64.
    nonce: String,
}

// ── Public entry type (plaintext) ─────────────────────────────────────────────

#[derive(Clone)]
pub struct VaultEntry {
    pub domain:   String,
    pub username: String,
    pub password: String,
}

// ── Vault ─────────────────────────────────────────────────────────────────────

/// An unlocked in-memory vault.
///
/// Drop to "lock" the vault — the key is zeroized on drop.
pub struct Vault {
    /// 256-bit ChaCha20-Poly1305 key (zeroized on drop).
    key:       [u8; 32],
    /// Plaintext entries (only in memory while the vault is unlocked).
    entries:   Vec<VaultEntry>,
    /// Argon2id salt (kept to avoid re-reading the file for saves).
    salt:      Vec<u8>,
    /// Path to the on-disk vault file.
    file_path: std::path::PathBuf,
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Vault {
    // ── Constructor helpers ───────────────────────────────────────────────────

    /// Create a brand-new vault protected by `master`.
    /// Fails if a vault file already exists.
    pub fn create(master: &str) -> Result<Self, VaultError> {
        let path = vault_path();
        if path.exists() {
            return Err(VaultError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "vault already exists — call Vault::open instead",
            )));
        }
        let salt = random_bytes::<16>().to_vec();
        let key  = derive_key(master, &salt)?;
        let mut vault = Vault { key, entries: Vec::new(), salt, file_path: path };
        vault.save()?;
        Ok(vault)
    }

    /// Open an existing vault with `master`.  Returns `VaultError::WrongPassword`
    /// if the password is incorrect.
    pub fn open(master: &str) -> Result<Self, VaultError> {
        let path = vault_path();
        let raw  = std::fs::read_to_string(&path).map_err(VaultError::Io)?;
        let vf: VaultFile = serde_json::from_str(&raw).map_err(VaultError::Json)?;

        let salt = B64.decode(&vf.argon2_salt).map_err(|_| VaultError::WrongPassword)?;
        let key  = derive_key(master, &salt)?;

        // Verify the password by decrypting the sentinel value.
        let sentinel_ct    = B64.decode(&vf.sentinel_ct).map_err(|_| VaultError::WrongPassword)?;
        let sentinel_nonce = B64.decode(&vf.sentinel_nonce).map_err(|_| VaultError::WrongPassword)?;
        let sentinel_plain = aead_decrypt(&key, &sentinel_nonce, &sentinel_ct)?;
        if sentinel_plain != b"duct-tape-v1" {
            return Err(VaultError::WrongPassword);
        }

        // Decrypt all entries.
        let mut entries = Vec::with_capacity(vf.entries.len());
        for enc in &vf.entries {
            let ct    = B64.decode(&enc.ciphertext).map_err(|_| VaultError::Crypto)?;
            let nonce = B64.decode(&enc.nonce).map_err(|_| VaultError::Crypto)?;
            let pwd   = aead_decrypt(&key, &nonce, &ct)?;
            entries.push(VaultEntry {
                domain:   enc.domain.clone(),
                username: enc.username.clone(),
                password: String::from_utf8(pwd).map_err(|_| VaultError::Crypto)?,
            });
        }

        Ok(Vault { key, entries, salt, file_path: path })
    }

    // ── Entry management ──────────────────────────────────────────────────────

    /// Store or update a credential.
    pub fn upsert(&mut self, domain: String, username: String, password: String)
        -> Result<(), VaultError>
    {
        match self.entries.iter_mut().find(|e| e.domain == domain && e.username == username) {
            Some(e) => e.password = password,
            None    => self.entries.push(VaultEntry { domain, username, password }),
        }
        self.save()
    }

    /// Remove a credential.  Returns `true` if an entry was removed.
    pub fn remove(&mut self, domain: &str, username: &str) -> Result<bool, VaultError> {
        let before = self.entries.len();
        self.entries.retain(|e| !(e.domain == domain && e.username == username));
        let removed = self.entries.len() < before;
        if removed { self.save()?; }
        Ok(removed)
    }

    /// All entries for a domain (ordered as stored).
    pub fn for_domain(&self, domain: &str) -> Vec<&VaultEntry> {
        self.entries.iter().filter(|e| e.domain == domain).collect()
    }

    /// All entries.
    pub fn all(&self) -> &[VaultEntry] { &self.entries }

    // ── Persistence ───────────────────────────────────────────────────────────

    fn save(&self) -> Result<(), VaultError> {
        // Encrypt sentinel.
        let (s_ct, s_nonce) = aead_encrypt(&self.key, b"duct-tape-v1")?;

        // Encrypt each entry's password with an independent nonce.
        let mut enc_entries = Vec::with_capacity(self.entries.len());
        for e in &self.entries {
            let (ct, nonce) = aead_encrypt(&self.key, e.password.as_bytes())?;
            enc_entries.push(EncryptedEntry {
                domain:     e.domain.clone(),
                username:   e.username.clone(),
                ciphertext: B64.encode(&ct),
                nonce:      B64.encode(&nonce),
            });
        }

        let vf = VaultFile {
            argon2_salt:     B64.encode(&self.salt),
            sentinel_ct:     B64.encode(&s_ct),
            sentinel_nonce:  B64.encode(&s_nonce),
            entries:         enc_entries,
        };

        let json = serde_json::to_string_pretty(&vf).map_err(VaultError::Json)?;
        if let Some(parent) = self.file_path.parent() {
            std::fs::create_dir_all(parent).map_err(VaultError::Io)?;
        }
        // Atomic write: write to a temp file, then rename.
        let tmp = self.file_path.with_extension("json.tmp");
        std::fs::write(&tmp, &json).map_err(VaultError::Io)?;
        std::fs::rename(&tmp, &self.file_path).map_err(VaultError::Io)?;
        Ok(())
    }

    // ── Utility ───────────────────────────────────────────────────────────────

    /// Returns `true` if a vault file exists on disk.
    pub fn exists() -> bool { vault_path().exists() }

    /// Return the JS snippet that fills `<input type=password>` and the
    /// associated username field for the first matching credential.
    pub fn fill_js(&self, domain: &str) -> Option<String> {
        let entry = self.for_domain(domain).into_iter().next()?;
        // Escape single-quote characters in the stored values.
        let u = entry.username.replace('\'', "\\'");
        let p = entry.password.replace('\'', "\\'");
        Some(format!(
            "(function(){{\
               var u=document.querySelector('input[type=email],input[type=text][autocomplete*=user],input[name*=user],input[id*=user][type=text]');\
               var p=document.querySelector('input[type=password]');\
               if(u){{ u.value='{u}'; u.dispatchEvent(new Event('input',{{bubbles:true}})); }}\
               if(p){{ p.value='{p}'; p.dispatchEvent(new Event('input',{{bubbles:true}})); }}\
             }})();"
        ))
    }
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

fn derive_key(master: &str, salt: &[u8]) -> Result<[u8; 32], VaultError> {
    // Argon2id: 64 MiB memory, 3 iterations, 1 thread, 32-byte output.
    let params = Params::new(65536, 3, 1, Some(32)).map_err(|_| VaultError::Crypto)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(master.as_bytes(), salt, &mut key)
        .map_err(|_| VaultError::Crypto)?;
    Ok(key)
}

fn aead_encrypt(key: &[u8; 32], plaintext: &[u8])
    -> Result<(Vec<u8>, Vec<u8>), VaultError>
{
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_bytes = random_bytes::<NONCE_LEN>();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, plaintext).map_err(|_| VaultError::Crypto)?;
    Ok((ct, nonce_bytes.to_vec()))
}

fn aead_decrypt(key: &[u8; 32], nonce_bytes: &[u8], ciphertext: &[u8])
    -> Result<Vec<u8>, VaultError>
{
    if nonce_bytes.len() != NONCE_LEN {
        return Err(VaultError::Crypto);
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce  = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext).map_err(|_| VaultError::WrongPassword)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut buf = [0u8; N];
    rand::rng().fill_bytes(&mut buf);
    buf
}

// ── File-system helpers ───────────────────────────────────────────────────────

pub(super) fn vault_path() -> std::path::PathBuf {
    config_dir().join("duct-tape/vault.json")
}

pub(super) fn config_dir() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("XDG_CONFIG_HOME") {
        return std::path::PathBuf::from(p);
    }
    if let Ok(home) = std::env::var("HOME") {
        return std::path::PathBuf::from(home).join(".config");
    }
    std::path::PathBuf::from(".")
}
