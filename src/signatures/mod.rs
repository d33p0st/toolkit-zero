//! Hardware-level system signature extraction.
//!
//! The `signatures` feature exposes [`Signature`]: a snapshot of firmware-burned
//! hardware identifiers that cannot be altered by software alone. The combined
//! SHA-256 [`fingerprint`](Signature::fingerprint) is suitable for embedding in
//! sensitive data to track its origin system and support forensic attribution.
//!
//! # What is collected
//!
//! | Field | macOS source | Windows source | Linux source | Spoofability |
//! |---|---|---|---|---|
//! | `system_serial` | IOKit / `system_profiler` | WMI `Win32_BIOS.SerialNumber` | DMI `product_serial` | Requires hardware programmer or BIOS reflash |
//! | `hardware_uuid` | IOKit / `system_profiler` | WMI `Win32_ComputerSystemProduct.UUID` | DMI `product_uuid` | Same |
//! | `board_serial` | — | WMI `Win32_BaseBoard.SerialNumber` | DMI `board_serial` | Same |
//! | `disk_serial` | `system_profiler` NVMe/SATA | WMI `Win32_DiskDrive.SerialNumber` | sysfs `/sys/block/*/device/serial` | Requires manufacturer firmware tool |
//! | `fingerprint` | SHA-256 over all present fields | — | — | Derived |
//!
//! The serial number returned in `system_serial` on Apple hardware is the
//! factory-assigned Mac serial number registered with Apple's ownership and
//! warranty database — it directly ties the device to the individual who
//! purchased it.
//!
//! # Explicitly excluded
//!
//! - **MAC addresses** — trivially changed with one `ip link` or device-driver call.
//! - **IP addresses** — dynamic and shared.
//! - **Hostname / username / UID** — changeable by any administrator.
//! - **`/etc/machine-id`** — regenerated on re-install; software-generated.
//! - **CPU CPUID PSN (Processor Serial Number)** — Intel disabled this field
//!   on all CPUs produced after the Pentium III era.
//!
//! # Usage
//!
//! ```no_run
//! use toolkit_zero::signatures::{Signature, extract};
//!
//! let sig = extract();
//! println!("platform    : {}", sig.platform);
//! println!("sys serial  : {:?}", sig.system_serial);
//! println!("hw uuid     : {:?}", sig.hardware_uuid);
//! println!("board serial: {:?}", sig.board_serial);
//! println!("disk serial : {:?}", sig.disk_serial);
//! println!("fingerprint : {}", sig.fingerprint_hex());
//!
//! // Embed in data for forensic origin tracking.
//! let bytes = sig.to_bytes();
//! let recovered = Signature::from_bytes(&bytes).unwrap();
//! assert_eq!(sig.fingerprint, recovered.fingerprint);
//!
//! // Verify a stored signature still matches this machine.
//! assert!(sig.verify());
//! ```

use sha2::{Digest, Sha256};

// ── Signature struct ──────────────────────────────────────────────────────────

/// An immutable snapshot of hardware-level system identifiers.
///
/// Every field is read from firmware or factory-burned storage and cannot be
/// altered without physical hardware access and specialised tooling.
///
/// Obtain one by calling [`extract`].
#[derive(Debug, Clone)]
pub struct Signature {
    /// Target OS platform: `"macos"`, `"windows"`, `"linux"`, or `"unknown"`.
    pub platform: &'static str,

    /// Factory system serial number burned into BIOS/UEFI firmware or IOKit.
    ///
    /// On Apple hardware this is the Mac serial number registered in Apple's
    /// ownership and warranty database, tying the device to its purchaser.
    pub system_serial: Option<String>,

    /// Hardware UUID stored in BIOS/UEFI or IOKit firmware.
    ///
    /// Globally unique per physical system board; used by macOS, Windows, and
    /// Linux as the canonical machine identity.
    pub hardware_uuid: Option<String>,

    /// Baseboard (motherboard) serial number from the SMBIOS/DMI table.
    ///
    /// Not available on Apple hardware (no user-serviceable motherboard).
    pub board_serial: Option<String>,

    /// Serial number of the primary storage device, read from drive firmware.
    ///
    /// For SSDs/NVMe this is the NAND controller's serial; for HDDs it is the
    /// drive PCB serial. Changing it requires the manufacturer's firmware tool.
    pub disk_serial: Option<String>,

    /// SHA-256 digest of all present identifiers in canonical order.
    ///
    /// Input to SHA-256 (bytes piped through the hasher in this exact order):
    ///
    /// ```text
    /// platform   \0
    /// system_serial (or empty)  \0
    /// hardware_uuid (or empty)  \0
    /// board_serial (or empty)   \0
    /// disk_serial (or empty)    \0
    /// ```
    ///
    /// Absent fields contribute only the `\0` separator.
    pub fingerprint: [u8; 32],
}

impl Signature {
    /// Returns [`fingerprint`](Signature::fingerprint) as a lowercase hex string.
    pub fn fingerprint_hex(&self) -> String {
        self.fingerprint.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Serialises the signature to a compact, self-contained byte slice.
    ///
    /// Format:
    /// ```text
    /// platform\0 system_serial\0 hardware_uuid\0 board_serial\0 disk_serial\0 fingerprint(32 B)
    /// ```
    /// Absent optional fields produce an empty segment (just `\0`).
    /// The 32-byte fingerprint is always written verbatim at the end.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        let push = |buf: &mut Vec<u8>, v: &Option<String>| {
            if let Some(s) = v {
                buf.extend_from_slice(s.as_bytes());
            }
            buf.push(0u8);
        };

        buf.extend_from_slice(self.platform.as_bytes());
        buf.push(0u8);
        push(&mut buf, &self.system_serial);
        push(&mut buf, &self.hardware_uuid);
        push(&mut buf, &self.board_serial);
        push(&mut buf, &self.disk_serial);
        buf.extend_from_slice(&self.fingerprint);
        buf
    }

    /// Deserialises a [`Signature`] previously produced by [`Signature::to_bytes`].
    ///
    /// Returns `None` if the byte slice is malformed (wrong field count or
    /// short fingerprint tail).  The fingerprint is **not** re-verified during
    /// deserialisation; call [`Signature::verify`] to check it against the
    /// current hardware.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        // Split on NUL bytes to extract the five text segments.
        let mut fields: Vec<&[u8]> = Vec::new();
        let mut start = 0usize;
        for (i, &b) in data.iter().enumerate() {
            if b == 0 {
                fields.push(&data[start..i]);
                start = i + 1;
                if fields.len() == 5 {
                    break;
                }
            }
        }

        if fields.len() < 5 {
            return None;
        }
        if data.len() < start + 32 {
            return None;
        }

        let fingerprint: [u8; 32] = data[start..start + 32].try_into().ok()?;

        let to_opt = |b: &[u8]| -> Option<String> {
            if b.is_empty() {
                None
            } else {
                String::from_utf8(b.to_vec()).ok()
            }
        };

        let platform_str = std::str::from_utf8(fields[0]).ok()?;
        let platform: &'static str = match platform_str {
            "macos"   => "macos",
            "windows" => "windows",
            "linux"   => "linux",
            _         => "unknown",
        };

        Some(Signature {
            platform,
            system_serial: to_opt(fields[1]),
            hardware_uuid: to_opt(fields[2]),
            board_serial:  to_opt(fields[3]),
            disk_serial:   to_opt(fields[4]),
            fingerprint,
        })
    }

    /// Returns `true` if this signature's fingerprint matches the hardware
    /// of the machine this code is currently running on.
    ///
    /// Internally calls [`extract`] and compares the two fingerprints in
    /// constant-time using XOR (resistant to timing side-channels).
    pub fn verify(&self) -> bool {
        let current = extract();
        // Constant-time byte comparison: XOR all bytes, OR the results.
        let mismatch = self.fingerprint
            .iter()
            .zip(current.fingerprint.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        mismatch == 0
    }
}

impl PartialEq for Signature {
    /// Two signatures are equal when their fingerprints match.
    fn eq(&self, other: &Self) -> bool {
        let mismatch = self.fingerprint
            .iter()
            .zip(other.fingerprint.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        mismatch == 0
    }
}

impl Eq for Signature {}

// ── Public extraction entry point ─────────────────────────────────────────────

/// Extract the hardware signature of the current system.
///
/// Runs platform-specific read-only queries (no elevated privileges required
/// on most consumer systems) against firmware interfaces:
///
/// - **macOS**: `system_profiler SPHardwareDataType / SPNVMeDataType / SPSerialATADataType`
/// - **Windows**: `wmic` (or PowerShell fallback for Windows 11 24H2+)
/// - **Linux**: DMI sysfs `/sys/class/dmi/id/` and `/sys/block/*/device/serial`
///
/// Fields that cannot be read on the current platform are `None`.  The
/// [`fingerprint`](Signature::fingerprint) is computed over all present values.
pub fn extract() -> Signature {
    extract_impl()
}

// ── Platform dispatch (each fn exists only for its target OS) ─────────────────

#[cfg(target_os = "macos")]
fn extract_impl() -> Signature {
    // system_profiler SPHardwareDataType example output (truncated):
    //
    //   Hardware:
    //     Hardware Overview:
    //       Model Name: MacBook Pro
    //       Serial Number (system): C02XXXXXXG8WL
    //       Hardware UUID: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
    //
    let hw = run("system_profiler", &["SPHardwareDataType"]);
    let system_serial = parse_colon_value(&hw, "Serial Number (system)");
    let hardware_uuid = parse_colon_value(&hw, "Hardware UUID");

    // Storage serial: try NVMe (M-series / modern Macs) then SATA (Intel Macs).
    let nvme = run("system_profiler", &["SPNVMeDataType"]);
    let sata = run("system_profiler", &["SPSerialATADataType"]);
    let disk_serial = parse_colon_value(&nvme, "Serial Number")
        .or_else(|| parse_colon_value(&sata, "Serial Number"));

    let fingerprint = fingerprint("macos", &system_serial, &hardware_uuid, &None, &disk_serial);

    Signature {
        platform: "macos",
        system_serial,
        hardware_uuid,
        // Apple integrates board + system; there is no separate board serial.
        board_serial: None,
        disk_serial,
        fingerprint,
    }
}

#[cfg(target_os = "windows")]
fn extract_impl() -> Signature {
    // wmic is deprecated in Windows 11 24H2 but still present on most machines.
    // PowerShell WMI is used as a fallback for systems where wmic was removed.
    let system_serial = wmic_get("bios", "SerialNumber")
        .or_else(|| ps_get("(Get-WmiObject Win32_BIOS).SerialNumber"));

    let hardware_uuid = wmic_get("csproduct", "UUID")
        .or_else(|| ps_get("(Get-WmiObject Win32_ComputerSystemProduct).UUID"));

    let board_serial = wmic_get("baseboard", "SerialNumber")
        .or_else(|| ps_get("(Get-WmiObject Win32_BaseBoard).SerialNumber"));

    let disk_serial = wmic_disk()
        .or_else(|| ps_get("(Get-WmiObject Win32_DiskDrive | Select-Object -First 1).SerialNumber"));

    let fingerprint = fingerprint("windows", &system_serial, &hardware_uuid, &board_serial, &disk_serial);

    Signature {
        platform: "windows",
        system_serial,
        hardware_uuid,
        board_serial,
        disk_serial,
        fingerprint,
    }
}

#[cfg(target_os = "linux")]
fn extract_impl() -> Signature {
    let dmi = |name: &str| read_file(&format!("/sys/class/dmi/id/{name}"));

    // DMI/SMBIOS fields — these are the same ACPI tables that Windows WMI reads.
    let hardware_uuid  = dmi("product_uuid");
    let system_serial  = dmi("product_serial");
    let board_serial   = dmi("board_serial");
    let disk_serial    = linux_disk_serial();

    let fingerprint = fingerprint("linux", &system_serial, &hardware_uuid, &board_serial, &disk_serial);

    Signature {
        platform: "linux",
        system_serial,
        hardware_uuid,
        board_serial,
        disk_serial,
        fingerprint,
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
fn extract_impl() -> Signature {
    let fp = fingerprint("unknown", &None, &None, &None, &None);
    Signature {
        platform: "unknown",
        system_serial: None,
        hardware_uuid: None,
        board_serial:  None,
        disk_serial:   None,
        fingerprint: fp,
    }
}

// ── SHA-256 fingerprint builder ───────────────────────────────────────────────

fn fingerprint(
    platform: &str,
    system_serial: &Option<String>,
    hardware_uuid: &Option<String>,
    board_serial:  &Option<String>,
    disk_serial:   &Option<String>,
) -> [u8; 32] {
    let mut h = Sha256::new();

    let feed = |h: &mut Sha256, v: &Option<String>| {
        if let Some(s) = v {
            h.update(s.as_bytes());
        }
        h.update(b"\0");
    };

    h.update(platform.as_bytes());
    h.update(b"\0");
    feed(&mut h, system_serial);
    feed(&mut h, hardware_uuid);
    feed(&mut h, board_serial);
    feed(&mut h, disk_serial);

    h.finalize().into()
}

// ── Windows helpers ───────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn wmic_get(alias: &str, field: &str) -> Option<String> {
    // wmic output format: "<FieldName>\r\n<value>\r\n\r\n"
    let out = run("wmic", &[alias, "get", field, "/value"]);
    // With /value the output is "Field=Value\r\n", simpler to parse.
    for line in out.lines() {
        if let Some(rest) = line.split_once('=') {
            let v = clean(rest.1);
            if v.is_some() {
                return v;
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn wmic_disk() -> Option<String> {
    let out = run("wmic", &["diskdrive", "get", "SerialNumber", "/value"]);
    for line in out.lines() {
        if let Some(rest) = line.split_once('=') {
            let v = clean(rest.1);
            if v.is_some() {
                return v;
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn ps_get(script: &str) -> Option<String> {
    let out = run("powershell", &["-NoProfile", "-NonInteractive", "-Command", script]);
    clean(&out)
}

// ── Linux helpers ─────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn linux_disk_serial() -> Option<String> {
    // Walk /sys/block and return the serial of the first real (non-virtual) disk.
    let Ok(entries) = std::fs::read_dir("/sys/block") else {
        return None;
    };
    let mut names: Vec<_> = entries.filter_map(|e| e.ok()).collect();
    // Sort for determinism across reboots.
    names.sort_by_key(|e| e.file_name());

    for entry in names {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // Skip loop, RAM, zram, and device-mapper virtual devices.
        if name.starts_with("loop")
            || name.starts_with("ram")
            || name.starts_with("zram")
            || name.starts_with("dm-")
        {
            continue;
        }
        let path = entry.path().join("device/serial");
        if let Some(s) = read_file(&path.to_string_lossy()) {
            return Some(s);
        }
    }
    None
}

// ── macOS / shared helpers ────────────────────────────────────────────────────

/// Run a process silently and return its stdout as a String.
/// Returns an empty string on any error.
fn run(program: &str, args: &[&str]) -> String {
    std::process::Command::new(program)
        .args(args)
        // Suppress child stderr so it doesn't leak into the caller's terminal.
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default()
}

/// Find the first line matching `"  Key: Value"` and return the trimmed value.
///
/// Used to parse `system_profiler` output on macOS.
#[cfg(target_os = "macos")]
fn parse_colon_value(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(key) {
            if let Some(rest) = rest.trim_start().strip_prefix(':') {
                return clean(rest);
            }
        }
    }
    None
}

/// Read a text file and return its trimmed, cleaned content.
fn read_file(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .as_deref()
        .and_then(clean)
}

/// Trim whitespace, normalise to UPPERCASE, and reject known BIOS placeholder
/// strings that manufacturers use when a field is unpopulated.
///
/// Returns `None` if the value is empty or a recognised placeholder.
fn clean(s: &str) -> Option<String> {
    let v = s.trim().to_uppercase();
    if v.is_empty() {
        return None;
    }
    // Common BIOS/firmware placeholder strings (case-insensitive, hence the
    // uppercase normalisation above).
    const PLACEHOLDERS: &[&str] = &[
        "N/A",
        "NA",
        "NONE",
        "NOT AVAILABLE",
        "NOT SPECIFIED",
        "TO BE FILLED BY O.E.M.",
        "TO BE FILLED BY OEM",
        "DEFAULT STRING",
        "UNDEFINED",
        "UNKNOWN",
        "00000000",
        "0000000000",
        "FFFFFFFF",
        "FFFFFFFFFFFFFFFF",
    ];
    if PLACEHOLDERS.contains(&v.as_str()) {
        return None;
    }
    Some(v)
}
