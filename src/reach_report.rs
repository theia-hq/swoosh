//! Where a root act reached: which of your devices took its cut, by name.
//!
//! A root act that cuts offers the cut to your other devices ([`Committed::offer`]) and gets back a
//! [`Reach`], which names devices and never a number: a device holds a list or it does not, and the list's
//! number means nothing to the person reading. The binary prints it.
//!
//! [`Committed::offer`]: crate::root::Committed::offer

/// Where a root act took effect.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "a root act says where it reached"]
pub enum Reach {
    /// Nothing but this machine ever admitted it.
    Complete,
    /// At least one device took the cut, or none did while this machine serves it.
    Published {
        /// The devices that hold the cut now.
        took: Vec<String>,
        /// The devices that did not take it, and why.
        missed: Vec<Missed>,
        /// The latest date a device this act revoked would have lasted to, if it revoked one.
        until: Option<u64>,
    },
    /// No device took the cut, and this machine does not serve it.
    Held {
        /// The devices that did not take it, and why.
        missed: Vec<Missed>,
        /// The latest date a device this act revoked would have lasted to, if it revoked one.
        until: Option<u64>,
    },
    /// A device holds a newer list than the one cut, or another list at its number: nothing was
    /// published.
    Behind,
    /// Made without the root: only this machine blocks it.
    LocalOnly {
        /// The latest date a device it revoked would have lasted to.
        until: u64,
    },
}

/// A device that did not take the cut.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Missed {
    /// `me/<name>`.
    pub name: String,
    /// Why it did not.
    pub why: Why,
}

/// Why a device did not take the cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// It answered that it refused it.
    Refused,
    /// It did not answer in time.
    Silent,
}
