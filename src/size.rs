//! A size as a person reads it: whole bytes under a KiB, else one decimal in the largest binary unit that
//! keeps the value at 1 or above (`28.6 MiB`). One renderer, so a size reads the same wherever it prints.

use core::fmt;

/// The units past bytes, each 1024 of the one before.
const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];

/// A count of bytes, printed for a person: `12 B`, `3.1 KiB`, `28.6 MiB`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Size(pub u64);

impl fmt::Display for Size {
    /// A value that would print as `1024.0` in its unit is printed in the next one, so no size reads as a
    /// whole unit short of where it belongs. Past the last unit the value grows in TiB.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 < 1024 {
            return write!(f, "{} B", self.0);
        }
        // Precision lost past 2^53 bytes is far below the one decimal printed.
        let mut value = self.0 as f64 / 1024.0;
        let mut unit = 0;
        while unit + 1 < UNITS.len() && (value * 10.0).round() / 10.0 >= 1024.0 {
            value /= 1024.0;
            unit += 1;
        }
        write!(f, "{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
#[path = "size_tests.rs"]
mod size_tests;
