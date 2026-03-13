use super::{
    Argon2PassParams, KdfParams, ScryptPassParams,
    TimeLockError, TimeLockKey, TimeLockSalts,
    TimePrecision, TimeFormat,
};

#[cfg(feature = "enc-timelock-keygen-input")]
use super::TimeLockTime;

#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input"))]
use {
    argon2::{Algorithm, Argon2, Params as Argon2Params, Version},
    scrypt::{scrypt as do_scrypt, Params as ScryptParams},
    zeroize::{Zeroize as _, Zeroizing},
};

#[cfg(feature = "enc-timelock-keygen-now")]
use chrono::Timelike as _;

// ─── KDF chain ───────────────────────────────────────────────────────────────

/// Core three-pass KDF chain. Accepts an already-formatted time string as
/// bytes.  All intermediates are zeroized before each subsequent pass.
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input"))]
pub(super) fn run_kdf_chain(
    mut time_bytes: Vec<u8>,
    salts:  &TimeLockSalts,
    params: &KdfParams,
) -> Result<TimeLockKey, TimeLockError> {
    let mut tb: Zeroizing<Vec<u8>> = Zeroizing::new(std::mem::take(&mut time_bytes));

    // Pass 1 — Argon2id
    let p1 = argon2id_pass(&tb, &salts.s1, &params.pass1)?;
    tb.zeroize();

    // Pass 2 — scrypt
    let p2 = scrypt_pass(&p1, &salts.s2, &params.pass2)?;
    drop(p1); // Zeroizing — overwritten on drop

    // Pass 3 — Argon2id (different params + distinct salt)
    let p3 = argon2id_pass(&p2, &salts.s3, &params.pass3)?;
    drop(p2);

    let mut raw = [0u8; 32];
    raw.copy_from_slice(&p3);
    drop(p3);

    Ok(TimeLockKey(raw))
}

// ─── time formatters ─────────────────────────────────────────────────────────

/// Format the **OS wall clock** as a short ASCII time string.
#[cfg(feature = "enc-timelock-keygen-now")]
pub(super) fn format_time_now(
    precision: TimePrecision,
    format:    TimeFormat,
) -> Result<String, TimeLockError> {
    let now = chrono::Local::now();
    let h24 = now.hour();
    let min = now.minute();
    Ok(format_components(h24, min, precision, format))
}

/// Format an **explicit [`TimeLockTime`]** as a short ASCII time string.
#[cfg(feature = "enc-timelock-keygen-input")]
pub(super) fn format_time_at(
    time:      TimeLockTime,
    precision: TimePrecision,
    format:    TimeFormat,
) -> Result<String, TimeLockError> {
    if time.hour() > 23 {
        return Err(TimeLockError::InvalidTime(
            format!("hour {} out of range 0–23", time.hour())
        ));
    }
    if time.minute() > 59 {
        return Err(TimeLockError::InvalidTime(
            format!("minute {} out of range 0–59", time.minute())
        ));
    }
    Ok(format_components(time.hour(), time.minute(), precision, format))
}

/// Shared formatting logic used by both `format_time_now` and `format_time_at`.
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input"))]
pub(super) fn format_components(
    h24:       u32,
    min:       u32,
    precision: TimePrecision,
    format:    TimeFormat,
) -> String {
    let h12: u32 = match h24 { 0 => 12, 1..=12 => h24, _ => h24 - 12 };
    let ampm      = if h24 < 12 { "AM" } else { "PM" };
    let q         = (min / 15) * 15; // snap to 0 / 15 / 30 / 45

    match (precision, format) {
        (TimePrecision::Hour,    TimeFormat::Hour24) => format!("{h24:02}"),
        (TimePrecision::Hour,    TimeFormat::Hour12) => format!("{h12:02}{ampm}"),
        (TimePrecision::Quarter, TimeFormat::Hour24) => format!("{h24:02}:{q:02}"),
        (TimePrecision::Quarter, TimeFormat::Hour12) => format!("{h12:02}:{q:02}{ampm}"),
        (TimePrecision::Minute,  TimeFormat::Hour24) => format!("{h24:02}:{min:02}"),
        (TimePrecision::Minute,  TimeFormat::Hour12) => format!("{h12:02}:{min:02}{ampm}"),
    }
}

// ─── KDF passes ──────────────────────────────────────────────────────────────

/// One Argon2id pass → 32-byte output wrapped in [`Zeroizing`].
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input"))]
pub(super) fn argon2id_pass(
    password: &[u8],
    salt:     &[u8; 32],
    p:        &Argon2PassParams,
) -> Result<Zeroizing<Vec<u8>>, TimeLockError> {
    let params = Argon2Params::new(p.m_cost, p.t_cost, p.p_cost, Some(32))
        .map_err(|e| TimeLockError::Argon2(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new(vec![0u8; 32]);
    argon2
        .hash_password_into(password, salt.as_ref(), &mut out[..])
        .map_err(|e| TimeLockError::Argon2(e.to_string()))?;
    Ok(out)
}

/// One scrypt pass → 32-byte output wrapped in [`Zeroizing`].
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input"))]
pub(super) fn scrypt_pass(
    password: &[u8],
    salt:     &[u8; 32],
    p:        &ScryptPassParams,
) -> Result<Zeroizing<Vec<u8>>, TimeLockError> {
    let params = ScryptParams::new(p.log_n, p.r, p.p, 32)
        .map_err(|e| TimeLockError::Scrypt(e.to_string()))?;
    let mut out = Zeroizing::new(vec![0u8; 32]);
    do_scrypt(password, salt.as_ref(), &params, &mut out[..])
        .map_err(|e| TimeLockError::Scrypt(e.to_string()))?;
    Ok(out)
}
