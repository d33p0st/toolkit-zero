use super::{TimeLockCadence, TimeLockSalts, KdfParams, TimePrecision, TimeFormat};

/// Compact, self-contained encoding of **all** encryption-time settings —
/// suitable for plaintext storage within a ciphertext header.
///
/// Produced by [`pack`] and supplied to [`timelock`](super::timelock) or
/// [`timelock_async`](super::timelock_async) as `params: Some(header)` on the
/// **decryption side**. Only the cadence variant discriminant is recorded; the
/// actual calendar values (weekday, day-of-month, month) are not stored and
/// are instead read from the live system clock during decryption.
///
/// | Field              | Encoding / Notes                                          |
/// |--------------------|-----------------------------------------------------------|
/// | `time_precision`   | `0`=Hour · `1`=Quarter · `2`=Minute                      |
/// | `time_format`      | `0`=12 hr (`Hour12`) · `1`=24 hr (`Hour24`)              |
/// | `cadence_variant`  | `0`=None · `1`=DayOfWeek · `2`=DayOfMonth                |
/// |                    | `3`=MonthOfYear · `4`=DayOfWeekInMonth                   |
/// |                    | `5`=DayOfMonthInMonth · `6`=DayOfWeekAndDayOfMonth       |
/// | `salts`            | Three 32-byte salts (not secret; prevent precomputation) |
/// | `kdf_params`       | Argon2id + scrypt work factors                           |
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
#[derive(Debug, Clone)]
pub struct TimeLockParams {
    /// `0` = [`TimePrecision::Hour`],
    /// `1` = [`TimePrecision::Quarter`],
    /// `2` = [`TimePrecision::Minute`].
    pub time_precision: u8,
    /// `0` = [`TimeFormat::Hour12`] (12-hour clock),
    /// `1` = [`TimeFormat::Hour24`] (24-hour clock).
    pub time_format: u8,
    /// [`TimeLockCadence`] variant discriminant (0–6).  The actual calendar
    /// values for that variant (which weekday, which month, etc.) are
    /// **not** stored here — the decryption path reads them from the clock.
    pub cadence_variant: u8,
    /// Three KDF salts generated at encryption time.
    ///
    /// Salts are **not secret**; storing them in the header is standard practice
    /// and prevents precomputation attacks.
    pub salts: TimeLockSalts,
    /// The KDF work-factor parameters used at encryption time.
    ///
    /// Stored so the decryption side uses identical memory and iteration costs.
    pub kdf_params: KdfParams,
}

/// Encode [`TimePrecision`], [`TimeFormat`], and a [`TimeLockCadence`] reference
/// into a compact [`TimeLockParams`] for storage in a ciphertext header.
///
/// Only the **variant discriminant** of `cadence` is recorded; the actual day,
/// weekday, or month values are intentionally discarded.
///
/// # Example
///
/// ```no_run
/// # use toolkit_zero::encryption::timelock::*;
/// let salts = TimeLockSalts::generate();
/// let kdf   = KdfPreset::Balanced.params();
/// let p = pack(
///     TimePrecision::Minute,
///     TimeFormat::Hour24,
///     &TimeLockCadence::DayOfWeek(Weekday::Tuesday),
///     salts,
///     kdf,
/// );
/// // p.time_precision == 2, p.time_format == 1, p.cadence_variant == 1
/// ```
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
pub fn pack(
    precision:  TimePrecision,
    format:     TimeFormat,
    cadence:    &TimeLockCadence,
    salts:      TimeLockSalts,
    kdf_params: KdfParams,
) -> TimeLockParams {
    let tp = match precision {
        TimePrecision::Hour    => 0,
        TimePrecision::Quarter => 1,
        TimePrecision::Minute  => 2,
    };
    let tf = match format {
        TimeFormat::Hour12 => 0,
        TimeFormat::Hour24 => 1,
    };
    TimeLockParams { time_precision: tp, time_format: tf, cadence_variant: cadence.variant_id(), salts, kdf_params }
}

/// Decode a [`TimeLockParams`] into its constituent [`TimePrecision`],
/// [`TimeFormat`], and raw cadence variant discriminant.
///
/// The returned `u8` maps as follows:
/// `0` = None, `1` = DayOfWeek, `2` = DayOfMonth, `3` = MonthOfYear,
/// `4` = DayOfWeekInMonth, `5` = DayOfMonthInMonth, `6` = DayOfWeekAndDayOfMonth.
/// Any unrecognised value defaults to `0` (None).
///
/// # Example
///
/// ```no_run
/// # use toolkit_zero::encryption::timelock::*;
/// let params = pack(
///     TimePrecision::Minute,
///     TimeFormat::Hour24,
///     &TimeLockCadence::DayOfWeekInMonth(Weekday::Tuesday, Month::February),
///     TimeLockSalts::generate(),
///     KdfPreset::Balanced.params(),
/// );
/// let (precision, format, variant) = unpack(&params);
/// // precision == TimePrecision::Minute, format == TimeFormat::Hour24, variant == 4
/// ```
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
pub fn unpack(p: &TimeLockParams) -> (TimePrecision, TimeFormat, u8) {
    let precision = match p.time_precision {
        0 => TimePrecision::Hour,
        1 => TimePrecision::Quarter,
        _ => TimePrecision::Minute,
    };
    let format = match p.time_format {
        0 => TimeFormat::Hour12,
        _ => TimeFormat::Hour24,
    };
    (precision, format, p.cadence_variant)
}
