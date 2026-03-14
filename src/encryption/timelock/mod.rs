//! Time-locked key derivation.
//!
//! Derives a deterministic 32-byte key from a **time value** using a
//! three-pass heterogeneous KDF chain:
//!
//! | Pass | Algorithm | Role |
//! |------|-----------|------|
//! | 1 | **Argon2id** | PHC winner; sequential + random-access memory-hard; GPU/ASIC resistant |
//! | 2 | **scrypt**   | Independently designed memory-hard function (ROMix); orthogonal to Argon2 |
//! | 3 | **Argon2id** | Deepens the chain; fresh parameters and a distinct salt |
//!
//! Using two *independently designed* memory-hard functions means the chain
//! remains strong even if a weakness is discovered in one of them.
//! Every intermediate output is zeroized from memory before the next pass
//! begins.
//!
//! # Two entry points
//!
//! | `params` argument                   | Path              | Intended use                                                |
//! |-------------------------------------|-------------------|-------------------------------------------------------------|
//! | `params: None` (+ all other `Some`) | `_at` encryption  | Caller supplies cadence, time, precision, format, salts, KDF |
//! | `params: Some(p)` (rest `None`)     | `_now` decryption | All settings read from [`TimeLockParams`]; no user input    |
//!
//! Async counterparts ([`timelock_async`]) are available with the
//! `enc-timelock-async-keygen-now` / `enc-timelock-async-keygen-input` features
//! and offload the blocking KDF work to a dedicated thread so the calling
//! future's executor is never stalled.
//!
//! # Time input
//!
//! The raw KDF input is a short ASCII string constructed from the time value
//! at one of three precision levels.
//!
//! | [`TimePrecision`] | [`TimeFormat`] | Example string | Window   | Candidates/day |
//! |-------------------|----------------|----------------|----------|----------------|
//! | `Hour`    | `Hour24` | `"14"`        | 60 min   | 24             |
//! | `Hour`    | `Hour12` | `"02PM"`      | 60 min   | 12 unique × 2  |
//! | `Quarter` | `Hour24` | `"14:30"`     | 15 min   | 96             |
//! | `Quarter` | `Hour12` | `"02:30PM"`   | 15 min   | 48 unique × 2  |
//! | `Minute`  | `Hour24` | `"14:37"`     | 1 min    | 1440           |
//! | `Minute`  | `Hour12` | `"02:37PM"`   | 1 min    | 720 unique × 2 |
//!
//! > **`Hour12` note**: the same time slot recurs twice daily (AM + PM),
//! > making the derived key valid twice per day.  Use `Hour24` for a key
//! > that is uniquely valid once per day.
//!
//! > **Clock-drift (`Minute` precision)**: if both parties' clocks may
//! > differ by up to one minute, call `derive_key_now` three times with
//! > `now()-1min`, `now()`, and `now()+1min` at the call site and try each
//! > key.  The extra cost is negligible compared to one full KDF pass.
//!
//! # Salts
//!
//! [`TimeLockSalts`] holds three independent 32-byte values — one per KDF
//! pass — generated at encryption time via [`TimeLockSalts::generate`].
//! Salts are **not secret**; they prevent precomputation attacks and must be
//! stored in plaintext alongside the ciphertext header.  Supply the identical
//! salts to `derive_key_*` at decryption time.
//!
//! # Memory safety
//!
//! All intermediate KDF outputs are wrapped in [`Zeroizing`] and overwritten
//! when dropped.  [`TimeLockKey`] implements [`ZeroizeOnDrop`] so the final
//! 32-byte key is scrubbed the moment it goes out of scope.
//!
//! # Quick start
//!
//! ```no_run
//! use toolkit_zero::encryption::timelock::*;
//!
//! // ── Encryption side ───────────────────────────────────────────────────
//! let salts     = TimeLockSalts::generate();
//! let kdf       = KdfPreset::Balanced.params();
//! let lock_time = TimeLockTime::new(14, 37).unwrap();
//!
//! // Derive the encryption key (params = None → _at path).
//! let enc_key = timelock(
//!     Some(TimeLockCadence::None),
//!     Some(lock_time),
//!     Some(TimePrecision::Minute),
//!     Some(TimeFormat::Hour24),
//!     Some(salts.clone()),
//!     Some(kdf),
//!     None,
//! ).unwrap();
//!
//! // Pack all settings into a header and store alongside the ciphertext.
//! let header = pack(TimePrecision::Minute, TimeFormat::Hour24,
//!                   &TimeLockCadence::None, salts, kdf);
//!
//! // ── Decryption side ───────────────────────────────────────────────────
//! // Load header from ciphertext (params = Some → _now path).
//! // Call at 14:37 local time:
//! let dec_key = timelock(
//!     None, None, None, None, None, None,
//!     Some(header),
//! ).unwrap();
//! // enc_key.as_bytes() == dec_key.as_bytes() when called at 14:37 local time
//! ```

#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input"))]
mod helper;

#[cfg(feature = "backend-deps")]
pub mod backend_deps;

#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
pub mod utility;
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
pub use utility::{TimeLockParams, pack, unpack};

#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
use zeroize::{Zeroize, ZeroizeOnDrop};

// ─── time precision / format ──────────────────────────────────────────────────

/// How finely time is quantized when constructing the KDF input string.
///
/// Coarser precision gives a longer validity window (easier for the legitimate
/// user to hit); finer precision raises the cost of time-sweeping attacks.
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimePrecision {
    /// Quantize to the current **hour**.
    ///
    /// Input example: `"14"` (24 h) | `"02PM"` (12 h)  
    /// Valid for the entire 60-minute block.
    Hour,

    /// Quantize to the current **15-minute block** (minute snapped to
    /// 00, 15, 30, or 45).
    ///
    /// Input example: `"14:30"` (24 h) | `"02:30PM"` (12 h)  
    /// Valid for the 15-minute interval containing the chosen minute.
    Quarter,

    /// Quantize to the current **minute** (1-minute window).
    ///
    /// Input example: `"14:37"` (24 h) | `"02:37PM"` (12 h)  
    /// Strongest temporal constraint — ensure both parties' clocks are NTP
    /// synchronised to within ±30 s.
    Minute,
}

/// Clock representation used to format the time input string.
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeFormat {
    /// 24-hour clock (`00`–`23`). Every time slot is unique within a day.
    Hour24,

    /// 12-hour clock (`01`–`12`) with an `AM`/`PM` suffix.
    /// Each time slot recurs **twice daily**.
    Hour12,
}

// ─── schedule cadence ────────────────────────────────────────────────────────

/// Day of the week, Monday-based (Mon = 0 … Sun = 6).
///
/// Used as a component of [`TimeLockCadence`] to bind key derivation to a
/// specific weekday.
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Weekday {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
impl Weekday {
    /// The full English name of this weekday (e.g. `"Tuesday"`).
    pub fn name(self) -> &'static str {
        match self {
            Self::Monday    => "Monday",
            Self::Tuesday   => "Tuesday",
            Self::Wednesday => "Wednesday",
            Self::Thursday  => "Thursday",
            Self::Friday    => "Friday",
            Self::Saturday  => "Saturday",
            Self::Sunday    => "Sunday",
        }
    }

    /// Zero-based weekday number (Monday = 0, …, Sunday = 6).
    pub fn number(self) -> u8 {
        match self {
            Self::Monday    => 0,
            Self::Tuesday   => 1,
            Self::Wednesday => 2,
            Self::Thursday  => 3,
            Self::Friday    => 4,
            Self::Saturday  => 5,
            Self::Sunday    => 6,
        }
    }

    /// Convert from a `chrono::Weekday` value (used by the `_now` derivation path).
    #[cfg(feature = "enc-timelock-keygen-now")]
    pub(crate) fn from_chrono(w: chrono::Weekday) -> Self {
        match w {
            chrono::Weekday::Mon => Self::Monday,
            chrono::Weekday::Tue => Self::Tuesday,
            chrono::Weekday::Wed => Self::Wednesday,
            chrono::Weekday::Thu => Self::Thursday,
            chrono::Weekday::Fri => Self::Friday,
            chrono::Weekday::Sat => Self::Saturday,
            chrono::Weekday::Sun => Self::Sunday,
        }
    }
}

/// Month of the year (January = 1 … December = 12).
///
/// Used as a component of [`TimeLockCadence`] to bind key derivation to a
/// specific calendar month.
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Month {
    January,
    February,
    March,
    April,
    May,
    June,
    July,
    August,
    September,
    October,
    November,
    December,
}

#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
impl Month {
    /// The full English name of this month (e.g. `"February"`).
    pub fn name(self) -> &'static str {
        match self {
            Self::January   => "January",
            Self::February  => "February",
            Self::March     => "March",
            Self::April     => "April",
            Self::May       => "May",
            Self::June      => "June",
            Self::July      => "July",
            Self::August    => "August",
            Self::September => "September",
            Self::October   => "October",
            Self::November  => "November",
            Self::December  => "December",
        }
    }

    /// 1-based month number (January = 1, …, December = 12).
    pub fn number(self) -> u8 {
        match self {
            Self::January   => 1,
            Self::February  => 2,
            Self::March     => 3,
            Self::April     => 4,
            Self::May       => 5,
            Self::June      => 6,
            Self::July      => 7,
            Self::August    => 8,
            Self::September => 9,
            Self::October   => 10,
            Self::November  => 11,
            Self::December  => 12,
        }
    }

    /// Maximum number of days in this month.
    ///
    /// February = 28 (leap years are intentionally ignored — the cadence
    /// policy is meant to be stable across years).
    pub fn max_days(self) -> u8 {
        match self {
            Self::February => 28,
            Self::April | Self::June | Self::September | Self::November => 30,
            _ => 31,
        }
    }

    /// Construct from a 1-based month number (1 = January … 12 = December).
    ///
    /// # Panics
    ///
    /// Panics if `n` is outside 1–12.
    #[cfg(feature = "enc-timelock-keygen-now")]
    pub(crate) fn from_number(n: u8) -> Self {
        match n {
            1  => Self::January,
            2  => Self::February,
            3  => Self::March,
            4  => Self::April,
            5  => Self::May,
            6  => Self::June,
            7  => Self::July,
            8  => Self::August,
            9  => Self::September,
            10 => Self::October,
            11 => Self::November,
            12 => Self::December,
            _  => panic!("Month::from_number: invalid month number {}", n),
        }
    }
}

/// Cadence component of a scheduled time-lock — binds key derivation to a
/// recurring calendar pattern **in addition to** the time-of-day constraint.
///
/// Pair with a [`TimeLockTime`] (encryption path) to express policies like:
///
/// - *"only on Tuesdays at 18:00"* — `DayOfWeek(Weekday::Tuesday)` + 18h
/// - *"only on the 1st at 00:00"* — `DayOfMonth(1)` + 0h
/// - *"every Tuesday in February at 06:00"* — `DayOfWeekInMonth(Weekday::Tuesday, Month::February)` + 6h
///
/// On the decryption side, pass [`pack`] the cadence (along with precision
/// and format) to obtain a [`TimeLockParams`] to store in the ciphertext
/// header, then call [`derive_key_scheduled_now`] with those params.
///
/// `TimeLockCadence::None` is equivalent to a plain [`derive_key_at`] call —
/// no calendar dimension is mixed into the KDF input.
///
/// # Panics
///
/// Constructing [`DayOfMonthInMonth`](TimeLockCadence::DayOfMonthInMonth) is
/// always valid, but **key derivation panics** if the stored day exceeds the
/// month's maximum (e.g. day 29 for February, day 31 for April).
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeLockCadence {
    /// No calendar constraint — behaves like a plain time-lock.
    ///
    /// Compact discriminant: `0`.
    None,

    /// Valid only on the specified weekday.
    ///
    /// Compact discriminant: `1`.
    DayOfWeek(Weekday),

    /// Valid only on the specified day of any month (1–31).
    ///
    /// Days 29–31 simply never match in shorter months.
    ///
    /// Compact discriminant: `2`.
    DayOfMonth(u8),

    /// Valid only during the specified month of any year.
    ///
    /// Compact discriminant: `3`.
    MonthOfYear(Month),

    /// Valid only on the specified weekday **and** during the specified month.
    ///
    /// Compact discriminant: `4`.
    DayOfWeekInMonth(Weekday, Month),

    /// Valid only on the specified day of the specified month.
    ///
    /// Key derivation panics if the day exceeds the month's maximum.
    ///
    /// Compact discriminant: `5`.
    DayOfMonthInMonth(u8, Month),

    /// Valid only on the specified weekday **and** the specified day of month.
    ///
    /// Days 29–31 do not match in shorter months.
    ///
    /// Compact discriminant: `6`.
    DayOfWeekAndDayOfMonth(Weekday, u8),
}

#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
impl TimeLockCadence {
    /// Returns the compact variant discriminant stored in
    /// [`TimeLockParams::cadence_variant`].
    pub fn variant_id(self) -> u8 {
        match self {
            Self::None                         => 0,
            Self::DayOfWeek(_)                 => 1,
            Self::DayOfMonth(_)                => 2,
            Self::MonthOfYear(_)               => 3,
            Self::DayOfWeekInMonth(_, _)       => 4,
            Self::DayOfMonthInMonth(_, _)      => 5,
            Self::DayOfWeekAndDayOfMonth(_, _) => 6,
        }
    }

    /// Produces the cadence prefix baked into the KDF input during the
    /// encryption (`_at`) path.
    ///
    /// The prefix is empty for `None`; otherwise it is `"<component>|"` or
    /// `"<a>+<b>|"` for composite variants.
    ///
    /// # Panics
    ///
    /// Panics if `DayOfMonthInMonth(day, month)` has `day > month.max_days()`.
    pub(crate) fn bake_string(self) -> String {
        match self {
            Self::None                          => String::new(),
            Self::DayOfWeek(w)                  => format!("{}|", w.name()),
            Self::DayOfMonth(d)                 => format!("{}|", d),
            Self::MonthOfYear(m)                => format!("{}|", m.name()),
            Self::DayOfWeekInMonth(w, m)        => format!("{}+{}|", w.name(), m.name()),
            Self::DayOfMonthInMonth(d, m)       => {
                let max = m.max_days();
                if d < 1 || d > max {
                    panic!(
                        "TimeLockCadence::DayOfMonthInMonth: day {} is out of range \
                         1–{} for {}",
                        d, max, m.name()
                    );
                }
                format!("{}+{}|", d, m.name())
            }
            Self::DayOfWeekAndDayOfMonth(w, d)  => format!("{}+{}|", w.name(), d),
        }
    }
}

// ─── explicit time input ──────────────────────────────────────────────────────

/// An explicit time value supplied by the caller for encryption-time key
/// derivation.
///
/// `hour` is always expressed in **24-hour notation** (0–23) regardless of
/// the [`TimeFormat`] chosen for the KDF string — the format flag only
/// controls how the string is rendered, not how you supply the input.
///
/// # Example
///
/// ```
/// use toolkit_zero::encryption::timelock::TimeLockTime;
///
/// let t = TimeLockTime::new(14, 37).unwrap(); // 14:37 local (2:37 PM)
/// ```
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeLockTime {
    hour:   u32,  // 0–23
    minute: u32,  // 0–59
}

#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
impl TimeLockTime {
    /// Construct a `TimeLockTime` from a 24-hour `hour` (0–23) and `minute`
    /// (0–59).
    ///
    /// Returns `None` if either value is out of range.
    pub fn new(hour: u32, minute: u32) -> Option<Self> {
        if hour > 23 || minute > 59 {
            return None;
        }
        Some(Self { hour, minute })
    }

    /// The hour component (0–23).
    #[inline]
    pub fn hour(self) -> u32 { self.hour }

    /// The minute component (0–59).
    #[inline]
    pub fn minute(self) -> u32 { self.minute }
}

// ─── KDF parameters ───────────────────────────────────────────────────────────

/// Argon2id parameters for one pass of the KDF chain.
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2PassParams {
    /// Memory usage in **KiB** (e.g. `131_072` = 128 MiB).
    pub m_cost: u32,
    /// Number of passes over memory (time cost).
    pub t_cost: u32,
    /// Degree of parallelism (lanes). Keep at `1` for single-threaded use.
    pub p_cost: u32,
}

/// scrypt parameters for the second pass of the KDF chain.
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScryptPassParams {
    /// CPU/memory cost exponent: `N = 2^log_n`. Each increment doubles memory.
    pub log_n: u8,
    /// Block size (`r`). Standard value is `8`.
    pub r: u32,
    /// Parallelization factor (`p`). Keep at `1` for sequential derivation.
    pub p: u32,
}

/// Combined parameters for the full three-pass
/// Argon2id → scrypt → Argon2id KDF chain.
///
/// Prefer constructing via [`KdfPreset::params`] unless you have specific
/// tuning requirements.  All fields implement `Copy`, so this struct can be
/// stored inline in [`KdfPreset::Custom`].
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// First  pass: Argon2id.
    pub pass1: Argon2PassParams,
    /// Second pass: scrypt.
    pub pass2: ScryptPassParams,
    /// Third  pass: Argon2id (different parameters and a distinct salt).
    pub pass3: Argon2PassParams,
}

// ─── presets ──────────────────────────────────────────────────────────────────

/// Pre-tuned [`KdfParams`] sets.
///
/// Pick the variant that matches your **target platform** and security goal.
/// Use [`Custom`](KdfPreset::Custom) to supply entirely your own parameters.
///
/// > **Why device-specific presets?**  Apple Silicon has exceptional memory
/// > bandwidth (unified memory, ~400 GB/s on M2).  The same parameters that
/// > take 2 seconds on an M2 may take 15+ seconds on a typical x86-64 server.
/// > Device-specific variants let you choose a cost that is _consistent_ across
/// > the hardware you actually deploy on.
///
/// ## Generic (cross-platform)
///
/// Suitable for any platform.  Use these when you don't know or don't control
/// the target hardware.
///
/// | Preset     | Peak RAM  | Est. Mac M2 | Est. x86-64  |
/// |------------|-----------|-------------|--------------|
/// | `Fast`     | ~128 MiB  | ~500 ms     | ~1.5 s       |
/// | `Balanced` | ~512 MiB  | ~2 s        | ~8–15 s      |
/// | `Paranoid` | ~768 MiB  | ~4–6 s      | ~20–30 s     |
///
/// ## Apple Silicon (`*Mac`)
///
/// Harder parameters calibrated for Apple Silicon's superior memory bandwidth.
/// All three tiers assume at least 8 GiB unified memory (all M-series chips).
///
/// | Preset        | Peak RAM | Est. Mac M2  | Est. Mac M3/M4 |
/// |---------------|----------|--------------|----------------|
/// | `FastMac`     | ~512 MiB | ~2 s         | faster         |
/// | `BalancedMac` | ~1 GiB   | ~5–12 s      | faster         |
/// | `ParanoidMac` | ~3 GiB   | ~30–60 s     | faster         |
///
/// ## x86-64 (`*X86`)
///
/// Equivalent to Generic; provided as explicit named variants so code
/// documents intent clearly.
///
/// | Preset        | Peak RAM  | Est. x86-64  |
/// |---------------|-----------|------------------|
/// | `FastX86`     | ~128 MiB  | ~1.5 s           |
/// | `BalancedX86` | ~512 MiB  | ~8–15 s          |
/// | `ParanoidX86` | ~768 MiB  | ~20–30 s         |
///
/// ## Linux ARM64 (`*Arm`)
///
/// Tuned for AWS Graviton3 / similar high-end ARM servers.  Raspberry Pi and
/// lower-end ARM boards will be slower.
///
/// | Preset        | Peak RAM  | Est. Graviton3 |
/// |---------------|-----------|----------------|
/// | `FastArm`     | ~256 MiB  | ~3 s           |
/// | `BalancedArm` | ~512 MiB  | ~10–20 s       |
/// | `ParanoidArm` | ~768 MiB  | ~30–50 s       |
///
/// ## Custom
///
/// `Custom(KdfParams)` lets you supply exactly the parameters you measured
/// and tuned for your own hardware.
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfPreset {
    // ── generic (cross-platform) ─────────────────────────────────────────────

    /// ~128 MiB · scrypt 2¹⁶ · ~64 MiB, 3 iters each.
    Fast,
    /// ~512 MiB · scrypt 2¹⁷ · ~256 MiB, 4 iters each.
    Balanced,
    /// ~768 MiB · scrypt 2¹⁸ · ~512 MiB, 5 iters each.
    Paranoid,

    // ── Apple Silicon ─────────────────────────────────────────────────────────

    /// Dev / CI on macOS.  ~512 MiB · scrypt 2¹⁷ · ~256 MiB, 4 iters each.
    FastMac,
    /// Production on macOS (Apple Silicon).  ~1 GiB · scrypt 2¹⁸ · ~512 MiB, 4 iters each.
    BalancedMac,
    /// Maximum security on macOS.  ~3 GiB · scrypt 2²⁰ · ~1 GiB, 4 iters each.
    /// Assumes 8+ GiB unified memory (all M-series chips).
    ParanoidMac,

    // ── x86-64 ───────────────────────────────────────────────────────────────

    /// Dev / CI on x86-64.  Same params as `Fast`.
    FastX86,
    /// Production on x86-64.  Same params as `Balanced`.
    BalancedX86,
    /// Maximum security on x86-64.  Same params as `Paranoid`.
    ParanoidX86,

    // ── Linux ARM64 ──────────────────────────────────────────────────────────

    /// Dev / CI on Linux ARM64.  ~256 MiB · scrypt 2¹⁶ · ~128 MiB, 3 iters each.
    FastArm,
    /// Production on Linux ARM64.  ~512 MiB · scrypt 2¹⁷ · ~256 MiB, 5 iters each.
    BalancedArm,
    /// Maximum security on Linux ARM64.  ~768 MiB · scrypt 2¹⁸ · ~512 MiB, 5 iters each.
    ParanoidArm,

    // ── custom ────────────────────────────────────────────────────────────────

    /// Fully user-defined parameters.  Use when you have measured and tuned
    /// KDF cost on your own hardware.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(feature = "enc-timelock-keygen-input")]
    /// # {
    /// use toolkit_zero::encryption::timelock::*;
    /// let p = KdfPreset::Custom(KdfParams {
    ///     pass1: Argon2PassParams { m_cost: 262_144, t_cost: 3, p_cost: 1 },
    ///     pass2: ScryptPassParams { log_n: 16, r: 8, p: 1 },
    ///     pass3: Argon2PassParams { m_cost: 131_072, t_cost: 3, p_cost: 1 },
    /// });
    /// # }
    /// ```
    Custom(KdfParams),
}

#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
impl KdfPreset {
    /// Return the [`KdfParams`] for this preset.
    pub fn params(self) -> KdfParams {
        // Fast = ~128 MiB · scrypt 2¹⁶ · ~64 MiB
        let fast = KdfParams {
            pass1: Argon2PassParams { m_cost:  131_072, t_cost: 3, p_cost: 1 },
            pass2: ScryptPassParams { log_n: 16, r: 8, p: 1 },
            pass3: Argon2PassParams { m_cost:   65_536, t_cost: 3, p_cost: 1 },
        };
        // Balanced = ~512 MiB · scrypt 2¹⁷ · ~256 MiB
        let balanced = KdfParams {
            pass1: Argon2PassParams { m_cost:  524_288, t_cost: 4, p_cost: 1 },
            pass2: ScryptPassParams { log_n: 17, r: 8, p: 1 },
            pass3: Argon2PassParams { m_cost:  262_144, t_cost: 4, p_cost: 1 },
        };
        // Paranoid = ~768 MiB · scrypt 2¹⁸ · ~512 MiB
        let paranoid = KdfParams {
            pass1: Argon2PassParams { m_cost:  786_432, t_cost: 5, p_cost: 1 },
            pass2: ScryptPassParams { log_n: 18, r: 8, p: 1 },
            pass3: Argon2PassParams { m_cost:  524_288, t_cost: 5, p_cost: 1 },
        };

        match self {
            // Generic / x86-64 (identical params, named for code clarity)
            KdfPreset::Fast    | KdfPreset::FastX86    => fast,
            KdfPreset::Balanced | KdfPreset::BalancedX86 => balanced,
            KdfPreset::Paranoid | KdfPreset::ParanoidX86 => paranoid,
            // Apple Silicon — calibrated for M-series memory bandwidth
            KdfPreset::FastMac    => balanced, // ~512 MiB
            KdfPreset::BalancedMac => KdfParams {
                pass1: Argon2PassParams { m_cost: 1_048_576, t_cost: 4, p_cost: 1 }, // 1 GiB
                pass2: ScryptPassParams { log_n: 18, r: 8, p: 1 },
                pass3: Argon2PassParams { m_cost:   524_288, t_cost: 4, p_cost: 1 },
            },
            KdfPreset::ParanoidMac => KdfParams {
                pass1: Argon2PassParams { m_cost: 3_145_728, t_cost: 4, p_cost: 1 }, // 3 GiB
                pass2: ScryptPassParams { log_n: 20, r: 8, p: 1 },
                pass3: Argon2PassParams { m_cost: 1_048_576, t_cost: 4, p_cost: 1 }, // 1 GiB
            },
            // Linux ARM64
            KdfPreset::FastArm => KdfParams {
                pass1: Argon2PassParams { m_cost:  262_144, t_cost: 3, p_cost: 1 }, // 256 MiB
                pass2: ScryptPassParams { log_n: 16, r: 8, p: 1 },
                pass3: Argon2PassParams { m_cost:  131_072, t_cost: 3, p_cost: 1 },
            },
            KdfPreset::BalancedArm => KdfParams {
                pass1: Argon2PassParams { m_cost:  524_288, t_cost: 5, p_cost: 1 }, // 512 MiB
                pass2: ScryptPassParams { log_n: 17, r: 8, p: 1 },
                pass3: Argon2PassParams { m_cost:  262_144, t_cost: 5, p_cost: 1 },
            },
            KdfPreset::ParanoidArm => KdfParams {
                pass1: Argon2PassParams { m_cost:  786_432, t_cost: 5, p_cost: 1 }, // 768 MiB
                pass2: ScryptPassParams { log_n: 18, r: 8, p: 1 },
                pass3: Argon2PassParams { m_cost:  524_288, t_cost: 5, p_cost: 1 },
            },
            // Custom
            KdfPreset::Custom(p) => p,
        }
    }
}

// ─── salts ────────────────────────────────────────────────────────────────────

/// Three independent 32-byte random salts — one per KDF pass.
///
/// Generate once at **encryption time** via [`TimeLockSalts::generate`] and
/// store 96 bytes in the ciphertext header.  The same `TimeLockSalts` **must**
/// be supplied to [`derive_key_now`] / [`derive_key_at`] at decryption time.
///
/// Salts are **not secret** — they only prevent precomputation attacks.
/// All three fields are zeroized when this value is dropped.
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
#[derive(Debug, Clone)]
pub struct TimeLockSalts {
    /// Salt for the first Argon2id pass.
    pub s1: [u8; 32],
    /// Salt for the scrypt pass.
    pub s2: [u8; 32],
    /// Salt for the final Argon2id pass.
    pub s3: [u8; 32],
}

#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
impl TimeLockSalts {
    /// Generate three independent 32-byte salts from the OS CSPRNG.
    pub fn generate() -> Self {
        use rand::RngCore as _;
        let mut rng = rand::rng();
        let mut s = Self { s1: [0u8; 32], s2: [0u8; 32], s3: [0u8; 32] };
        rng.fill_bytes(&mut s.s1);
        rng.fill_bytes(&mut s.s2);
        rng.fill_bytes(&mut s.s3);
        s
    }

    /// Construct from raw bytes (e.g. when loading from a ciphertext header).
    pub fn from_bytes(s1: [u8; 32], s2: [u8; 32], s3: [u8; 32]) -> Self {
        Self { s1, s2, s3 }
    }

    /// Serialize to 96 contiguous bytes (`s1 ∥ s2 ∥ s3`) for header storage.
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut out = [0u8; 96];
        out[..32].copy_from_slice(&self.s1);
        out[32..64].copy_from_slice(&self.s2);
        out[64..].copy_from_slice(&self.s3);
        out
    }

    /// Deserialize from 96 contiguous bytes produced by [`to_bytes`].
    pub fn from_slice(b: &[u8; 96]) -> Self {
        let mut s1 = [0u8; 32]; s1.copy_from_slice(&b[..32]);
        let mut s2 = [0u8; 32]; s2.copy_from_slice(&b[32..64]);
        let mut s3 = [0u8; 32]; s3.copy_from_slice(&b[64..]);
        Self { s1, s2, s3 }
    }
}

#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
impl Zeroize for TimeLockSalts {
    fn zeroize(&mut self) {
        self.s1.zeroize();
        self.s2.zeroize();
        self.s3.zeroize();
    }
}

#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
impl Drop for TimeLockSalts {
    fn drop(&mut self) { self.zeroize(); }
}

// ─── output ───────────────────────────────────────────────────────────────────

/// A derived 32-byte time-locked key.
///
/// The inner bytes are **automatically overwritten** (`ZeroizeOnDrop`) the
/// moment this value is dropped.  Access the key via [`as_bytes`](Self::as_bytes).
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
pub struct TimeLockKey([u8; 32]);

#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
impl TimeLockKey {
    /// Borrow the raw 32-byte key.
    ///
    /// The reference is valid only while this `TimeLockKey` is alive.  If you
    /// must copy the bytes into another buffer, protect it with [`Zeroize`] too.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
impl Zeroize for TimeLockKey {
    #[inline]
    fn zeroize(&mut self) { self.0.zeroize(); }
}

#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
impl ZeroizeOnDrop for TimeLockKey {}

#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
impl Drop for TimeLockKey {
    fn drop(&mut self) { self.zeroize(); }
}

// ─── error ────────────────────────────────────────────────────────────────────

/// Errors returned by the `derive_key_*` functions.
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
#[derive(Debug)]
pub enum TimeLockError {
    /// An Argon2id pass failed (invalid parameters or internal error).
    Argon2(String),
    /// The scrypt pass failed (invalid parameters or output length).
    Scrypt(String),
    /// The OS clock returned an unusable value.
    #[cfg(feature = "enc-timelock-keygen-now")]
    ClockUnavailable,
    /// A [`TimeLockTime`] field was out of range.
    #[cfg(feature = "enc-timelock-keygen-input")]
    InvalidTime(String),
    /// The async task panicked inside `spawn_blocking`.
    #[cfg(any(feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
    TaskPanic(String),
    /// The caller passed `Some(time)` but `enc-timelock-keygen-input` is not
    /// active, or passed `None` but `enc-timelock-keygen-now` is not active.
    ForbiddenAction(&'static str),
}

#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
impl std::fmt::Display for TimeLockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Argon2(s)         => write!(f, "Argon2id error: {s}"),
            Self::Scrypt(s)         => write!(f, "scrypt error: {s}"),
            #[cfg(feature = "enc-timelock-keygen-now")]
            Self::ClockUnavailable  => write!(f, "system clock unavailable"),
            #[cfg(feature = "enc-timelock-keygen-input")]
            Self::InvalidTime(s)    => write!(f, "invalid time input: {s}"),
            #[cfg(any(feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
            Self::TaskPanic(s)      => write!(f, "KDF task panicked: {s}"),
            Self::ForbiddenAction(s) => write!(f, "action not permitted: {s}"),
        }
    }
}

#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
impl std::error::Error for TimeLockError {}

// ─── internal sync API ───────────────────────────────────────────────────────

/// Derive a 32-byte key from the **current system time** (decryption path).
///
/// The OS wall clock is read inside this call — the caller supplies no time
/// value.  Use this on the **decryption side** so the user never needs to
/// re-enter the unlock time.
///
/// The `precision`, `format`, and `salts` must match exactly what was used
/// during [`derive_key_at`] at encryption time (store them in the header).
///
/// # Errors
///
/// Returns [`TimeLockError`] if the system clock is unavailable or any KDF
/// pass fails.
///
/// # Example
///
/// ```ignore
/// # use toolkit_zero::encryption::timelock::*;
/// let salts = TimeLockSalts::generate();
/// let key = timelock(
///     TimeLockCadence::None,
///     None,
///     TimePrecision::Minute,
///     TimeFormat::Hour24,
///     &salts,
///     &KdfPreset::Balanced.params(),
/// ).unwrap();
/// ```
#[allow(dead_code)]
#[cfg(feature = "enc-timelock-keygen-now")]
fn derive_key_now(
    precision: TimePrecision,
    format:    TimeFormat,
    salts:     &TimeLockSalts,
    params:    &KdfParams,
) -> Result<TimeLockKey, TimeLockError> {
    let time_str = helper::format_time_now(precision, format)?;
    helper::run_kdf_chain(time_str.into_bytes(), salts, params)
}

/// Derive a 32-byte key from an **explicit [`TimeLockTime`]** (encryption path).
///
/// The caller supplies the time at which decryption should be permitted.
/// Use this on the **encryption side** — the user chooses `(hour, minute)` and
/// the result is the key that will only be reproducible by [`derive_key_now`]
/// called within the matching time window.
///
/// # Errors
///
/// Returns [`TimeLockError`] if the time value is invalid or any KDF pass
/// fails.
///
/// # Example
///
/// ```ignore
/// # use toolkit_zero::encryption::timelock::*;
/// let salts = TimeLockSalts::generate();
/// let at = TimeLockTime::new(14, 37).unwrap();
/// let key = timelock(
///     TimeLockCadence::None,
///     Some(at),
///     TimePrecision::Minute,
///     TimeFormat::Hour24,
///     &salts,
///     &KdfPreset::Balanced.params(),
/// ).unwrap();
/// ```
#[allow(dead_code)]
#[cfg(feature = "enc-timelock-keygen-input")]
fn derive_key_at(
    time:      TimeLockTime,
    precision: TimePrecision,
    format:    TimeFormat,
    salts:     &TimeLockSalts,
    params:    &KdfParams,
) -> Result<TimeLockKey, TimeLockError> {
    let time_str = helper::format_time_at(time, precision, format)?;
    helper::run_kdf_chain(time_str.into_bytes(), salts, params)
}

// ─── internal async API ──────────────────────────────────────────────────────

/// Async variant of [`derive_key_now`].
///
/// Offloads the blocking Argon2id + scrypt work to a Tokio blocking thread
/// so the calling future's executor is never stalled during derivation.
///
/// Takes `salts` and `params` by **value** (required for `'static` move into
/// `spawn_blocking`); both are zeroized before the async task exits.
///
/// Requires the `enc-timelock-async` feature.
///
/// # Errors
///
/// Returns [`TimeLockError`] if the system clock is unavailable, any KDF
/// pass fails, or the spawned task panics.
#[allow(dead_code)]
#[cfg(feature = "enc-timelock-async-keygen-now")]
async fn derive_key_now_async(
    precision: TimePrecision,
    format:    TimeFormat,
    salts:     TimeLockSalts,
    params:    KdfParams,
) -> Result<TimeLockKey, TimeLockError> {
    tokio::task::spawn_blocking(move || derive_key_now(precision, format, &salts, &params))
        .await
        .map_err(|e| TimeLockError::TaskPanic(e.to_string()))?
}

/// Async variant of [`derive_key_at`].
///
/// Offloads the blocking Argon2id + scrypt work to a Tokio blocking thread.
/// Takes `salts` and `params` by **value**; both are zeroized on drop.
///
/// Requires the `enc-timelock-async-keygen-input` feature.
#[allow(dead_code)]
#[cfg(feature = "enc-timelock-async-keygen-input")]
async fn derive_key_at_async(
    time:      TimeLockTime,
    precision: TimePrecision,
    format:    TimeFormat,
    salts:     TimeLockSalts,
    params:    KdfParams,
) -> Result<TimeLockKey, TimeLockError> {
    tokio::task::spawn_blocking(move || derive_key_at(time, precision, format, &salts, &params))
        .await
        .map_err(|e| TimeLockError::TaskPanic(e.to_string()))?
}

// ─── internal scheduled sync API ─────────────────────────────────────────────

/// Derive a 32-byte key from a [`TimeLockCadence`] anchor plus an **explicit
/// [`TimeLockTime`]** (encryption path).
///
/// Extends [`derive_key_at`] with a calendar constraint.  The KDF input
/// is `"<cadence_prefix><time_string>"`.  For [`TimeLockCadence::None`] the
/// prefix is empty, producing a result identical to [`derive_key_at`].
///
/// Store [`pack`]ed settings alongside the salts in the ciphertext header so
/// the decryption side can reconstruct the correct KDF input via
/// [`derive_key_scheduled_now`].
///
/// # Panics
///
/// Panics if `cadence` is [`TimeLockCadence::DayOfMonthInMonth`] with a day
/// that exceeds the month's maximum (e.g. day 29 for February).
///
/// # Errors
///
/// Returns [`TimeLockError`] if the time value is out of range or any KDF
/// pass fails.
///
/// # Example
///
/// ```ignore
/// # use toolkit_zero::encryption::timelock::*;
/// let salts = TimeLockSalts::generate();
/// let kdf   = KdfPreset::Balanced.params();
/// let t     = TimeLockTime::new(18, 0).unwrap();
/// // Use the public timelock() entry point (params = None → _at path):
/// let key = timelock(
///     Some(TimeLockCadence::DayOfWeek(Weekday::Tuesday)),
///     Some(t),
///     Some(TimePrecision::Hour),
///     Some(TimeFormat::Hour24),
///     Some(salts),
///     Some(kdf),
///     None,
/// ).unwrap();
/// // key is valid only at 18:xx on any Tuesday
/// ```
#[cfg(feature = "enc-timelock-keygen-input")]
fn derive_key_scheduled_at(
    cadence:   TimeLockCadence,
    time:      TimeLockTime,
    precision: TimePrecision,
    format:    TimeFormat,
    salts:     &TimeLockSalts,
    params:    &KdfParams,
) -> Result<TimeLockKey, TimeLockError> {
    let cadence_part = cadence.bake_string();
    let time_part    = helper::format_time_at(time, precision, format)?;
    let full         = format!("{}{}", cadence_part, time_part);
    helper::run_kdf_chain(full.into_bytes(), salts, params)
}

/// Derive a 32-byte key from the **current system time and calendar state**
/// using the settings stored in a [`TimeLockParams`] (decryption path).
///
/// Extends [`derive_key_now`] with calendar awareness.  The `cadence_variant`
/// field in `timelock_params` determines which calendar dimension(s) are read
/// from the live clock, making the KDF input identical to what
/// [`derive_key_scheduled_at`] produced on the matching slot.
///
/// # Errors
///
/// Returns [`TimeLockError`] if the system clock is unavailable or any KDF
/// pass fails.
///
/// # Example
///
/// ```ignore
/// # use toolkit_zero::encryption::timelock::*;
/// // Load header from ciphertext then call with params = Some(header):
/// let dec_key = timelock(
///     None, None, None, None, None, None,
///     Some(header),  // header: TimeLockParams loaded from ciphertext
/// ).unwrap();
/// ```
#[cfg(feature = "enc-timelock-keygen-now")]
fn derive_key_scheduled_now(
    timelock_params: &TimeLockParams,
) -> Result<TimeLockKey, TimeLockError> {
    let (precision, format, cadence_variant) = utility::unpack(timelock_params);
    let cadence_part = helper::bake_cadence_now(cadence_variant)?;
    let time_part    = helper::format_time_now(precision, format)?;
    let full         = format!("{}{}", cadence_part, time_part);
    helper::run_kdf_chain(full.into_bytes(), &timelock_params.salts, &timelock_params.kdf_params)
}

// ─── internal scheduled async API ───────────────────────────────────────────

/// Async variant of [`derive_key_scheduled_at`].
///
/// Offloads the blocking KDF work to a Tokio blocking thread.  Takes `salts`
/// and `params` by **value** (required for `'static` move into
/// `spawn_blocking`); both are zeroized on drop.  `cadence` and `time` are
/// `Copy`.
///
/// Requires the `enc-timelock-async-keygen-input` feature.
#[cfg(feature = "enc-timelock-async-keygen-input")]
async fn derive_key_scheduled_at_async(
    cadence:   TimeLockCadence,
    time:      TimeLockTime,
    precision: TimePrecision,
    format:    TimeFormat,
    salts:     TimeLockSalts,
    params:    KdfParams,
) -> Result<TimeLockKey, TimeLockError> {
    tokio::task::spawn_blocking(move || {
        derive_key_scheduled_at(cadence, time, precision, format, &salts, &params)
    })
    .await
    .map_err(|e| TimeLockError::TaskPanic(e.to_string()))?
}

/// Async variant of [`derive_key_scheduled_now`].
///
/// Offloads the blocking KDF work to a Tokio blocking thread.  Takes
/// `timelock_params` by **value**; the [`TimeLockSalts`] inside are
/// zeroized on drop.
///
/// Requires the `enc-timelock-async-keygen-now` feature.
#[cfg(feature = "enc-timelock-async-keygen-now")]
async fn derive_key_scheduled_now_async(
    timelock_params: TimeLockParams,
) -> Result<TimeLockKey, TimeLockError> {
    tokio::task::spawn_blocking(move || {
        derive_key_scheduled_now(&timelock_params)
    })
    .await
    .map_err(|e| TimeLockError::TaskPanic(e.to_string()))?
}

// ─── public API ───────────────────────────────────────────────────────────────

/// Derive a 32-byte time-locked key — unified sync entry point.
///
/// ## Encryption path (`params = None`)
///
/// Set `params` to `None` and supply all of `cadence`, `time`, `precision`,
/// `format`, `salts`, and `kdf` as `Some(...)`.  Requires the
/// `enc-timelock-keygen-input` feature.  After calling, use [`pack`] with the
/// same arguments to produce a [`TimeLockParams`] header for the ciphertext.
///
/// ## Decryption path (`params = Some(p)`)
///
/// Set `params` to `Some(header)` where `header` is the [`TimeLockParams`]
/// read from the ciphertext.  All other arguments are ignored and may be
/// `None`.  Requires the `enc-timelock-keygen-now` feature.
///
/// # Errors
///
/// - [`TimeLockError::ForbiddenAction`] if the required feature is not active,
///   or if the `_at` path is taken but any required `Option` argument is `None`.
/// - [`TimeLockError::Argon2`] / [`TimeLockError::Scrypt`] on KDF failure.
/// - [`TimeLockError::ClockUnavailable`] if the OS clock is unusable (`_now` path).
///
/// # Example
///
/// ```no_run
/// # use toolkit_zero::encryption::timelock::*;
/// let salts = TimeLockSalts::generate();
/// let kdf   = KdfPreset::BalancedMac.params();
///
/// // Encryption side — lock to every Tuesday at 18:00
/// let enc_key = timelock(
///     Some(TimeLockCadence::DayOfWeek(Weekday::Tuesday)),
///     Some(TimeLockTime::new(18, 0).unwrap()),
///     Some(TimePrecision::Hour),
///     Some(TimeFormat::Hour24),
///     Some(salts.clone()),
///     Some(kdf),
///     None,
/// ).unwrap();
///
/// // Pack settings + salts + kdf into header; store in ciphertext.
/// let header = pack(TimePrecision::Hour, TimeFormat::Hour24,
///                   &TimeLockCadence::DayOfWeek(Weekday::Tuesday), salts, kdf);
///
/// // Decryption side — call on a Tuesday at 18:xx:
/// let dec_key = timelock(
///     None, None, None, None, None, None,
///     Some(header),
/// ).unwrap();
/// // enc_key.as_bytes() == dec_key.as_bytes() when called at the right time
/// ```
#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input"))]
pub fn timelock(
    cadence:   Option<TimeLockCadence>,
    time:      Option<TimeLockTime>,
    precision: Option<TimePrecision>,
    format:    Option<TimeFormat>,
    salts:     Option<TimeLockSalts>,
    kdf:       Option<KdfParams>,
    params:    Option<TimeLockParams>,
) -> Result<TimeLockKey, TimeLockError> {
    if let Some(p) = params {
        // _now (decryption) path: all settings come from TimeLockParams.
        let _ = (cadence, time, precision, format, salts, kdf);  // unused on this path
        #[cfg(not(feature = "enc-timelock-keygen-now"))]
        return Err(TimeLockError::ForbiddenAction(
            "enc-timelock-keygen-now feature is required for the _now (decryption) path"
        ));
        #[cfg(feature = "enc-timelock-keygen-now")]
        return derive_key_scheduled_now(&p);
    } else {
        // _at (encryption) path: caller must supply all other arguments.
        #[cfg(not(feature = "enc-timelock-keygen-input"))]
        return Err(TimeLockError::ForbiddenAction(
            "enc-timelock-keygen-input feature is required for the _at (encryption) path; \
             pass Some(TimeLockParams) for the decryption path (requires enc-timelock-keygen-now)"
        ));
        #[cfg(feature = "enc-timelock-keygen-input")]
        {
            let c  = cadence.ok_or(TimeLockError::ForbiddenAction("_at path: cadence must be Some"))?;
            let t  = time.ok_or(TimeLockError::ForbiddenAction("_at path: time must be Some"))?;
            let pr = precision.ok_or(TimeLockError::ForbiddenAction("_at path: precision must be Some"))?;
            let fm = format.ok_or(TimeLockError::ForbiddenAction("_at path: format must be Some"))?;
            let sl = salts.ok_or(TimeLockError::ForbiddenAction("_at path: salts must be Some"))?;
            let kd = kdf.ok_or(TimeLockError::ForbiddenAction("_at path: kdf must be Some"))?;
            return derive_key_scheduled_at(c, t, pr, fm, &sl, &kd);
        }
    }
}

/// Derive a 32-byte time-locked key — unified async entry point.
///
/// Async counterpart of [`timelock`].  Same `params`-based routing: set
/// `params = Some(header)` for the **decryption** path, or `params = None`
/// with all other arguments as `Some(...)` for the **encryption** path.
/// All arguments are taken by value; the blocking KDF work is offloaded to a
/// Tokio blocking thread.
///
/// # Errors
///
/// Same as [`timelock`], plus [`TimeLockError::TaskPanic`] if the spawned
/// task panics.
#[cfg(any(feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
pub async fn timelock_async(
    cadence:   Option<TimeLockCadence>,
    time:      Option<TimeLockTime>,
    precision: Option<TimePrecision>,
    format:    Option<TimeFormat>,
    salts:     Option<TimeLockSalts>,
    kdf:       Option<KdfParams>,
    params:    Option<TimeLockParams>,
) -> Result<TimeLockKey, TimeLockError> {
    if let Some(p) = params {
        let _ = (cadence, time, precision, format, salts, kdf);
        #[cfg(not(feature = "enc-timelock-async-keygen-now"))]
        return Err(TimeLockError::ForbiddenAction(
            "enc-timelock-async-keygen-now feature is required for the async _now (decryption) path"
        ));
        #[cfg(feature = "enc-timelock-async-keygen-now")]
        return derive_key_scheduled_now_async(p).await;
    } else {
        #[cfg(not(feature = "enc-timelock-async-keygen-input"))]
        return Err(TimeLockError::ForbiddenAction(
            "enc-timelock-async-keygen-input feature is required for the async _at (encryption) path"
        ));
        #[cfg(feature = "enc-timelock-async-keygen-input")]
        {
            let c  = cadence.ok_or(TimeLockError::ForbiddenAction("_at path: cadence must be Some"))?;
            let t  = time.ok_or(TimeLockError::ForbiddenAction("_at path: time must be Some"))?;
            let pr = precision.ok_or(TimeLockError::ForbiddenAction("_at path: precision must be Some"))?;
            let fm = format.ok_or(TimeLockError::ForbiddenAction("_at path: format must be Some"))?;
            let sl = salts.ok_or(TimeLockError::ForbiddenAction("_at path: salts must be Some"))?;
            let kd = kdf.ok_or(TimeLockError::ForbiddenAction("_at path: kdf must be Some"))?;
            return derive_key_scheduled_at_async(c, t, pr, fm, sl, kd).await;
        }
    }
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(any(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input"))]
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(all(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input"))]
    use chrono::Timelike as _;

    fn fast() -> KdfParams {
        // Minimal params for fast test execution — not a real security preset.
        KdfParams {
            pass1: Argon2PassParams { m_cost: 32_768, t_cost: 1, p_cost: 1 },
            pass2: ScryptPassParams { log_n: 13, r: 8, p: 1 },
            pass3: Argon2PassParams { m_cost: 16_384, t_cost: 1, p_cost: 1 },
        }
    }
    fn salts() -> TimeLockSalts   { TimeLockSalts::generate() }

    // ── TimeLockTime construction ─────────────────────────────────────────

    #[cfg(feature = "enc-timelock-keygen-input")]
    #[test]
    fn timelocktime_valid_range() {
        assert!(TimeLockTime::new(0,  0).is_some());
        assert!(TimeLockTime::new(23, 59).is_some());
        assert!(TimeLockTime::new(14, 37).is_some());
    }

    #[cfg(feature = "enc-timelock-keygen-input")]
    #[test]
    fn timelocktime_invalid_range() {
        assert!(TimeLockTime::new(24,  0).is_none(), "hour=24 should fail");
        assert!(TimeLockTime::new( 0, 60).is_none(), "minute=60 should fail");
        assert!(TimeLockTime::new(99, 99).is_none());
    }

    // ── format_components ────────────────────────────────────────────────

    #[test]
    fn format_hour_24h() {
        let s = helper::format_components(14, 37, TimePrecision::Hour, TimeFormat::Hour24);
        assert_eq!(s, "14");
    }

    #[test]
    fn format_hour_12h() {
        let s_pm = helper::format_components(14,  0, TimePrecision::Hour, TimeFormat::Hour12);
        let s_am = helper::format_components( 2,  0, TimePrecision::Hour, TimeFormat::Hour12);
        assert_eq!(s_pm, "02PM");
        assert_eq!(s_am, "02AM");
    }

    #[test]
    fn format_quarter_snaps_correctly() {
        // 37 should snap to 30; 15 → 15; 0 → 0; 59 → 45
        assert_eq!(helper::format_components(14, 37, TimePrecision::Quarter, TimeFormat::Hour24), "14:30");
        assert_eq!(helper::format_components(14, 15, TimePrecision::Quarter, TimeFormat::Hour24), "14:15");
        assert_eq!(helper::format_components(14,  0, TimePrecision::Quarter, TimeFormat::Hour24), "14:00");
        assert_eq!(helper::format_components(14, 59, TimePrecision::Quarter, TimeFormat::Hour24), "14:45");
    }

    #[test]
    fn format_minute_exact() {
        let s = helper::format_components(9, 5, TimePrecision::Minute, TimeFormat::Hour24);
        assert_eq!(s, "09:05");
    }

    // ── derive_key_at: determinism ────────────────────────────────────────

    #[cfg(feature = "enc-timelock-keygen-input")]
    #[test]
    fn at_same_inputs_same_key() {
        let s = salts();
        let t = TimeLockTime::new(14, 37).unwrap();
        let k1 = derive_key_at(t, TimePrecision::Minute, TimeFormat::Hour24, &s, &fast()).unwrap();
        // Regenerate salts from their raw bytes to prove serialization round-trip too.
        let s2 = TimeLockSalts::from_slice(&s.to_bytes());
        let k2 = derive_key_at(t, TimePrecision::Minute, TimeFormat::Hour24, &s2, &fast()).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[cfg(feature = "enc-timelock-keygen-input")]
    #[test]
    fn at_different_salts_different_key() {
        let t = TimeLockTime::new(14, 37).unwrap();
        let k1 = derive_key_at(t, TimePrecision::Minute, TimeFormat::Hour24, &salts(), &fast()).unwrap();
        let k2 = derive_key_at(t, TimePrecision::Minute, TimeFormat::Hour24, &salts(), &fast()).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[cfg(feature = "enc-timelock-keygen-input")]
    #[test]
    fn at_different_time_different_key() {
        let s = salts();
        let t1 = TimeLockTime::new(14, 37).unwrap();
        let t2 = TimeLockTime::new(14, 38).unwrap();
        let k1 = derive_key_at(t1, TimePrecision::Minute, TimeFormat::Hour24, &s, &fast()).unwrap();
        let k2 = derive_key_at(t2, TimePrecision::Minute, TimeFormat::Hour24, &s, &fast()).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    // ── derive_key_now: liveness ──────────────────────────────────────────

    #[cfg(feature = "enc-timelock-keygen-now")]
    #[test]
    fn now_returns_nonzero_key() {
        let k = derive_key_now(TimePrecision::Hour, TimeFormat::Hour24, &salts(), &fast()).unwrap();
        assert_ne!(k.as_bytes(), &[0u8; 32]);
    }

    #[cfg(all(feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input"))]
    #[test]
    fn now_and_at_same_minute_match() {
        // Build a TimeLockTime from the current clock and confirm it produces
        // the same key as derive_key_now with Minute precision.
        let now = chrono::Local::now();
        let t = TimeLockTime::new(now.hour(), now.minute()).unwrap();
        let s = salts();
        let kn = derive_key_now(TimePrecision::Minute, TimeFormat::Hour24, &s, &fast()).unwrap();
        let ka = derive_key_at(t, TimePrecision::Minute, TimeFormat::Hour24, &s, &fast()).unwrap();
        assert_eq!(
            kn.as_bytes(), ka.as_bytes(),
            "now and explicit current time must produce the same key"
        );
    }

    // ── salt serialization round-trip ─────────────────────────────────────

    #[test]
    fn salt_round_trip() {
        let s = salts();
        let b = s.to_bytes();
        let s2 = TimeLockSalts::from_slice(&b);
        assert_eq!(s.s1, s2.s1);
        assert_eq!(s.s2, s2.s2);
        assert_eq!(s.s3, s2.s3);
    }

    // ── Custom variant ───────────────────────────────────────────────────

    #[cfg(feature = "enc-timelock-keygen-input")]
    #[test]
    fn custom_params_works() {
        // Verify Custom(KdfParams) goes through the code path without failing.
        let preset = KdfPreset::Custom(KdfPreset::Fast.params());
        let t = TimeLockTime::new(10, 0).unwrap();
        derive_key_at(t, TimePrecision::Hour, TimeFormat::Hour24, &salts(), &preset.params())
            .expect("Custom params should succeed");
    }

    #[cfg(feature = "enc-timelock-keygen-input")]
    #[test]
    fn custom_params_roundtrip_eq() {
        let p = KdfPreset::Fast.params();
        assert_eq!(KdfPreset::Custom(p).params(), p);
    }

    // ── Generic preset smoke tests (slow) ────────────────────────────────

    #[cfg(feature = "enc-timelock-keygen-input")]
    #[test]
    #[ignore = "slow (~400–600 ms) — run with `cargo test -- --ignored`"]
    fn balanced_preset_completes() {
        let t = TimeLockTime::new(10, 0).unwrap();
        let start = std::time::Instant::now();
        derive_key_at(t, TimePrecision::Hour, TimeFormat::Hour24, &salts(), &KdfPreset::Balanced.params())
            .expect("Balanced should succeed");
        println!("Balanced (generic): {:?}", start.elapsed());
    }

    #[cfg(feature = "enc-timelock-keygen-input")]
    #[test]
    #[ignore = "slow (~2 s on Mac, ~8–15 s on x86) — run with `cargo test -- --ignored`"]
    fn paranoid_preset_completes() {
        let t = TimeLockTime::new(10, 0).unwrap();
        let start = std::time::Instant::now();
        derive_key_at(t, TimePrecision::Hour, TimeFormat::Hour24, &salts(), &KdfPreset::Paranoid.params())
            .expect("Paranoid should succeed");
        println!("Paranoid (generic): {:?}", start.elapsed());
    }

    // ── Mac preset smoke tests ───────────────────────────────────────────

    #[cfg(all(feature = "enc-timelock-keygen-input", target_os = "macos"))]
    #[test]
    #[ignore = "slow (~2 s on M2) — run with `cargo test -- --ignored`"]
    fn balanced_mac_completes() {
        let t = TimeLockTime::new(10, 0).unwrap();
        let start = std::time::Instant::now();
        derive_key_at(t, TimePrecision::Hour, TimeFormat::Hour24, &salts(), &KdfPreset::BalancedMac.params())
            .expect("BalancedMac should succeed");
        println!("BalancedMac: {:?}", start.elapsed());
    }

    #[cfg(all(feature = "enc-timelock-keygen-input", target_os = "macos"))]
    #[test]
    #[ignore = "slow (~5–12 s on M2, faster on M3/M4) — run with `cargo test -- --ignored`"]
    fn paranoid_mac_completes() {
        let t = TimeLockTime::new(10, 0).unwrap();
        let start = std::time::Instant::now();
        derive_key_at(t, TimePrecision::Hour, TimeFormat::Hour24, &salts(), &KdfPreset::ParanoidMac.params())
            .expect("ParanoidMac should succeed");
        println!("ParanoidMac: {:?}", start.elapsed());
    }

    // ── x86-64 preset smoke tests ────────────────────────────────────────

    #[cfg(all(feature = "enc-timelock-keygen-input", target_arch = "x86_64"))]
    #[test]
    #[ignore = "slow (~1.5 s on typical x86-64) — run with `cargo test -- --ignored`"]
    fn balanced_x86_completes() {
        let t = TimeLockTime::new(10, 0).unwrap();
        let start = std::time::Instant::now();
        derive_key_at(t, TimePrecision::Hour, TimeFormat::Hour24, &salts(), &KdfPreset::BalancedX86.params())
            .expect("BalancedX86 should succeed");
        println!("BalancedX86: {:?}", start.elapsed());
    }

    #[cfg(all(feature = "enc-timelock-keygen-input", target_arch = "x86_64"))]
    #[test]
    #[ignore = "slow (~8–15 s on typical x86-64) — run with `cargo test -- --ignored`"]
    fn paranoid_x86_completes() {
        let t = TimeLockTime::new(10, 0).unwrap();
        let start = std::time::Instant::now();
        derive_key_at(t, TimePrecision::Hour, TimeFormat::Hour24, &salts(), &KdfPreset::ParanoidX86.params())
            .expect("ParanoidX86 should succeed");
        println!("ParanoidX86: {:?}", start.elapsed());
    }

    // ── Linux ARM64 preset smoke tests ───────────────────────────────────

    #[cfg(all(feature = "enc-timelock-keygen-input", target_arch = "aarch64", not(target_os = "macos")))]
    #[test]
    #[ignore = "slow (~3 s on Graviton3) — run with `cargo test -- --ignored`"]
    fn balanced_arm_completes() {
        let t = TimeLockTime::new(10, 0).unwrap();
        let start = std::time::Instant::now();
        derive_key_at(t, TimePrecision::Hour, TimeFormat::Hour24, &salts(), &KdfPreset::BalancedArm.params())
            .expect("BalancedArm should succeed");
        println!("BalancedArm: {:?}", start.elapsed());
    }

    #[cfg(all(feature = "enc-timelock-keygen-input", target_arch = "aarch64", not(target_os = "macos")))]
    #[test]
    #[ignore = "slow (~10–20 s on Graviton3) — run with `cargo test -- --ignored`"]
    fn paranoid_arm_completes() {
        let t = TimeLockTime::new(10, 0).unwrap();
        let start = std::time::Instant::now();
        derive_key_at(t, TimePrecision::Hour, TimeFormat::Hour24, &salts(), &KdfPreset::ParanoidArm.params())
            .expect("ParanoidArm should succeed");
        println!("ParanoidArm: {:?}", start.elapsed());
    }

    // ── Scheduled key derivation ─────────────────────────────────────────────

    #[cfg(feature = "enc-timelock-keygen-input")]
    #[test]
    fn scheduled_none_same_as_regular_at() {
        // cadence=None adds no prefix — result must equal derive_key_at
        let s = salts();
        let t = TimeLockTime::new(14, 0).unwrap();
        let regular   = derive_key_at(t, TimePrecision::Hour, TimeFormat::Hour24, &s, &fast()).unwrap();
        let scheduled = derive_key_scheduled_at(
            TimeLockCadence::None, t, TimePrecision::Hour, TimeFormat::Hour24, &s, &fast(),
        ).unwrap();
        assert_eq!(regular.as_bytes(), scheduled.as_bytes());
    }

    #[cfg(feature = "enc-timelock-keygen-input")]
    #[test]
    fn scheduled_different_weekdays_different_keys() {
        let s = salts();
        let t = TimeLockTime::new(18, 0).unwrap();
        let k_mon = derive_key_scheduled_at(
            TimeLockCadence::DayOfWeek(Weekday::Monday),
            t, TimePrecision::Hour, TimeFormat::Hour24, &s, &fast(),
        ).unwrap();
        let k_tue = derive_key_scheduled_at(
            TimeLockCadence::DayOfWeek(Weekday::Tuesday),
            t, TimePrecision::Hour, TimeFormat::Hour24, &s, &fast(),
        ).unwrap();
        assert_ne!(k_mon.as_bytes(), k_tue.as_bytes());
    }

    #[cfg(feature = "enc-timelock-keygen-input")]
    #[test]
    fn scheduled_different_months_different_keys() {
        let s = salts();
        let t = TimeLockTime::new(0, 0).unwrap();
        let k_jan = derive_key_scheduled_at(
            TimeLockCadence::MonthOfYear(Month::January),
            t, TimePrecision::Hour, TimeFormat::Hour24, &s, &fast(),
        ).unwrap();
        let k_feb = derive_key_scheduled_at(
            TimeLockCadence::MonthOfYear(Month::February),
            t, TimePrecision::Hour, TimeFormat::Hour24, &s, &fast(),
        ).unwrap();
        assert_ne!(k_jan.as_bytes(), k_feb.as_bytes());
    }

    #[cfg(feature = "enc-timelock-keygen-input")]
    #[test]
    fn scheduled_at_deterministic() {
        // Same inputs must always produce the same key
        let s  = salts();
        let t  = TimeLockTime::new(6, 0).unwrap();
        let c  = TimeLockCadence::DayOfWeekInMonth(Weekday::Friday, Month::March);
        let k1 = derive_key_scheduled_at(c, t, TimePrecision::Hour, TimeFormat::Hour24, &s, &fast()).unwrap();
        let s2 = TimeLockSalts::from_slice(&s.to_bytes());
        let k2 = derive_key_scheduled_at(c, t, TimePrecision::Hour, TimeFormat::Hour24, &s2, &fast()).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[cfg(feature = "enc-timelock-keygen-now")]
    #[test]
    fn scheduled_now_none_matches_derive_now() {
        // cadence_variant=0 (None) + Hour + Hour24 must match derive_key_now exactly.
        // TimeLockParams now carries salts+kdf; build via pack() and clone salts.
        let s = salts();
        let f = fast();
        let stored = pack(
            TimePrecision::Hour, TimeFormat::Hour24,
            &TimeLockCadence::None,
            s.clone(),
            f,
        );
        let k1 = derive_key_now(TimePrecision::Hour, TimeFormat::Hour24, &s, &f).unwrap();
        let k2 = derive_key_scheduled_now(&stored).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[cfg(any(feature = "enc-timelock-keygen-input", feature = "enc-timelock-keygen-now"))]
    #[test]
    fn pack_unpack_roundtrip() {
        let params = pack(
            TimePrecision::Minute,
            TimeFormat::Hour24,
            &TimeLockCadence::DayOfWeekInMonth(Weekday::Tuesday, Month::February),
            salts(),
            fast(),
        );
        assert_eq!(params.time_precision, 2);  // Minute
        assert_eq!(params.time_format, 1);      // Hour24
        assert_eq!(params.cadence_variant, 4);  // DayOfWeekInMonth
        let (p, f, v) = unpack(&params);
        assert!(matches!(p, TimePrecision::Minute));
        assert!(matches!(f, TimeFormat::Hour24));
        assert_eq!(v, 4);
    }

    #[cfg(feature = "enc-timelock-keygen-input")]
    #[test]
    #[should_panic(expected = "DayOfMonthInMonth")]
    fn day_of_month_in_month_panics_on_invalid_day() {
        // February can have at most 28 days; day 29 must panic
        let s = salts();
        let t = TimeLockTime::new(0, 0).unwrap();
        let _ = derive_key_scheduled_at(
            TimeLockCadence::DayOfMonthInMonth(29, Month::February),
            t, TimePrecision::Hour, TimeFormat::Hour24, &s, &fast(),
        );
    }
}