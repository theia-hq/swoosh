//! Where a root act reached: which of your devices took its cut, by name.
//!
//! A root act that cuts offers the cut to your other devices ([`Committed::offer`]) and gets back a
//! [`Reach`]. Each variant prints one line on stderr, naming devices and never a number: a device holds a
//! list or it does not, and the list's number means nothing to the person reading.
//!
//! [`Committed::offer`]: crate::root::Committed::offer

use core::fmt;

use crate::root::Date;

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

/// What a root act did, as its line names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum What {
    /// Revoked a device or a person: `me/laptop`, `bob`.
    Revoked(String),
    /// Wrote an invite for a device: `me/laptop`.
    Invite(String),
}

impl fmt::Display for What {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Revoked(target) => write!(f, "revoked {target}"),
            Self::Invite(device) => write!(f, "{device}'s invite"),
        }
    }
}

impl Reach {
    /// The line this reach prints for `what`.
    pub fn line(&self, what: &What) -> String {
        match self {
            Self::Complete => format!("{what}: blocked. Only this machine admitted it."),
            Self::Published {
                took,
                missed,
                until,
            } => {
                let took = took_clause(took, missed);
                let head = if took.is_empty() {
                    format!("{what}.")
                } else {
                    format!("{what}: {took}.")
                };
                match until {
                    Some(until) => format!(
                        "{head} A device that never syncs admits it until {}. Anyone who shared with your \
                         root admits your devices until each one's date: tell them.",
                        Date(*until)
                    ),
                    None => head,
                }
            }
            Self::Held { .. } => format!(
                "{what}: no device took it, and this machine does not serve. Your devices get it at your \
                 next swoosh sync where one is reachable, or while this machine runs swoosh serve."
            ),
            Self::Behind => format!(
                "{what} is recorded here, but your devices hold a newer list than this copy of your root, so \
                 nothing was published. Run swoosh sync, then run this again."
            ),
            Self::LocalOnly { until } => format!(
                "{what} on this machine only. Your other devices admit it until {}. To block it everywhere, \
                 run this again where your root is kept, or here with --root <dir>.",
                Date(*until)
            ),
        }
    }

    /// The line `invite` prints after its invite: only `Behind` has one, since the invite itself says the
    /// rest.
    pub fn invite_line(&self, device: &str) -> Option<String> {
        matches!(self, Self::Behind).then(|| self.line(&What::Invite(device.to_owned())))
    }
}

/// "me/desk and me/nas have it; me/phone did not answer (it gets it on its next sync)", with a device
/// that refused listed as "me/x refused it". Empty when there is nobody to name.
fn took_clause(took: &[String], missed: &[Missed]) -> String {
    let named = |why: Why| -> Vec<String> {
        missed
            .iter()
            .filter(|device| device.why == why)
            .map(|device| device.name.clone())
            .collect()
    };
    let silent = named(Why::Silent);
    let refused = named(Why::Refused);
    let mut clauses = Vec::new();
    match took.len() {
        0 => {}
        1 => clauses.push(format!("{} has it", and(took))),
        _ => clauses.push(format!("{} have it", and(took))),
    }
    match silent.len() {
        0 => {}
        1 => clauses.push(format!(
            "{} did not answer (it gets it on its next sync)",
            and(&silent)
        )),
        _ => clauses.push(format!(
            "{} did not answer (each gets it on its next sync)",
            and(&silent)
        )),
    }
    if !refused.is_empty() {
        clauses.push(format!("{} refused it", and(&refused)));
    }
    clauses.join("; ")
}

/// "a", "a and b", "a, b and c".
fn and(names: &[String]) -> String {
    match names {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

#[cfg(test)]
#[path = "reach_report_tests.rs"]
mod reach_report_tests;
