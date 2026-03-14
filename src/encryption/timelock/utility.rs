use super::{TimeLockCadence, TimePrecision, TimeFormat};

/// Compact, self-contained encoding of the time-lock settings used at
/// encryption time — suitable for storage in a ciphertext header.
///
/// Produced by [`pack`] and consumed by [`unpack`] /
/// [`derive_key_scheduled_now`](super::derive_key_scheduled_now).
/// Deliberately stores **only** the variant discriminants — not the actual
/// day/weekday/month values, which the decryption side reads from the live
/// system clock.
///
/// | Field              | Encoding                                             |
/// |--------------------|------------------------------------------------------|
/// | `time_precision`   | `0`=Hour · `1`=Quarter · `2`=Minute                  |
/// | `time_format`      | `0`=12 hr (`Hour12`) · `1`=24 hr (`Hour24`)          |
/// | `cadence_variant`  | `0`=None · `1`=DayOfWeek · `2`=DayOfMonth            |
/// |                    | `3`=MonthOfYear · `4`=DayOfWeekInMonth               |
/// |                    | `5`=DayOfMonthInMonth · `6`=DayOfWeekAndDayOfMonth   |
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

/// Pack [`TimePrecision`], [`TimeFormat`], and a [`TimeLockCadence`] reference
/// into a compact [`TimeLockParams`] for ciphertext header storage.
///
/// Only the **variant identity** of `cadence` is recorded — the actual day,
/// weekday, or month values are intentionally discarded.
///
/// # Example
///
/// ```no_run
/// # use toolkit_zero::encryption::timelock::*;
/// let p = pack(
///     TimePrecision::Minute,
///     TimeFormat::Hour24,
///     &TimeLockCadence::DayOfWeek(Weekday::Tuesday),
/// );
/// // p.time_precision == 2, p.time_format == 1, p.cadence_variant == 1
/// ```
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
pub fn pack(
    precision: TimePrecision,
    format:    TimeFormat,
    cadence:   &TimeLockCadence,
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
    TimeLockParams { time_precision: tp, time_format: tf, cadence_variant: cadence.variant_id() }
}

/// Unpack a [`TimeLockParams`] into its constituent [`TimePrecision`],
/// [`TimeFormat`], and raw cadence variant discriminant.
///
/// The returned `u8` maps as follows:
/// `0`=None, `1`=DayOfWeek, `2`=DayOfMonth, `3`=MonthOfYear,
/// `4`=DayOfWeekInMonth, `5`=DayOfMonthInMonth, `6`=DayOfWeekAndDayOfMonth.
/// Any unrecognised value is treated as `0` (None).
///
/// # Example
///
/// ```no_run
/// # use toolkit_zero::encryption::timelock::*;
/// let params = TimeLockParams { time_precision: 2, time_format: 1, cadence_variant: 4 };
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
