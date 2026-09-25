//! The one name rule: every name a person types (a person, a device, a service) is 1 to 63 characters of
//! `a-z`, `0-9` and `-`, starting with a letter or digit.
//!
//! ASCII capitals fold to lowercase on input, so a name has one stored spelling. Nothing else folds, and
//! nothing else is allowed: a name can never hold the invite's `.` separator, a path's `/` or `~`, a
//! marker's `:`, or whitespace. Internal routes are dotted (`control.stop`), so no typed name can be one.
//!
//! Three names are reserved and are never a person or a device: `me`, `root` and `anyone`.

use core::str::FromStr;

use nauthy::Service;

/// A name a person typed, already known to follow the rule and already folded to lowercase.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(String);

impl Name {
    /// The longest name, in characters (every character is one ASCII byte).
    pub const MAX_LEN: usize = 63;

    /// The names that are never a person or a device.
    pub const RESERVED: [&'static str; 3] = ["me", "root", "anyone"];

    /// The name, for display and lookup.
    pub fn as_str(&self) -> &str {
        let Self(name) = self;
        name
    }

    /// Whether this is one of the [`RESERVED`](Self::RESERVED) names.
    pub fn is_reserved(&self) -> bool {
        Self::RESERVED.contains(&self.as_str())
    }

    /// This name, refused if it is reserved: the check for a name that is about to name a person or a
    /// device, rather than address one that exists (`me/laptop` addresses this person's own devices).
    pub fn unreserved(self) -> Result<Self, NameError> {
        if self.is_reserved() {
            return Err(NameError::Reserved(self.0));
        }
        Ok(self)
    }

    /// A name read back from disk or the wire, where it was stored folded. Nothing folds here: text that is
    /// not already its one spelling refuses, so each stored name has exactly one byte-string.
    pub fn stored(text: &str) -> Result<Self, NameError> {
        let name: Self = text.parse()?;
        if name.as_str() != text {
            return Err(NameError::NotAName(text.to_owned()));
        }
        Ok(name)
    }
}

/// Parse a service name a person typed (`serve --public <service>`, `grant issue <service>`, `reach <peer>
/// <service>`, ...): the one name rule, folded, as the [`Service`] the router and the grant carry. A dotted
/// internal route (`control.stop`) is never a name, so it can never be typed.
pub fn service(text: &str) -> Result<Service, NameError> {
    let name: Name = text.parse()?;
    // Every name is a service (the service alphabet is wider); the fallback keeps this total without a
    // panic path.
    name.as_str()
        .parse()
        .map_err(|_| NameError::NotAName(text.to_owned()))
}

impl FromStr for Name {
    type Err = NameError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let folded = text.to_ascii_lowercase();
        let bytes = folded.as_bytes();
        let starts_well = bytes.first().is_some_and(u8::is_ascii_alphanumeric);
        let in_alphabet = bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-');
        if !starts_well || !in_alphabet || bytes.len() > Self::MAX_LEN {
            return Err(NameError::NotAName(text.to_owned()));
        }
        Ok(Self(folded))
    }
}

impl core::fmt::Display for Name {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<Name> for String {
    fn from(Name(name): Name) -> Self {
        name
    }
}

/// Why a typed string is not a name.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NameError {
    /// The text broke the rule: empty, too long, a character outside `a-z`, `0-9` and `-`, or a first
    /// character that is not a letter or digit.
    #[error("{0} is not a name: a name uses a-z, 0-9 and -, and starts with a letter or digit.")]
    NotAName(String),
    /// The name is `me`, `root` or `anyone`, which never name a person or a device.
    #[error("{0} is reserved: pick another name")]
    Reserved(String),
}

/// The name this machine suggests for itself: its hostname, cut at the first `.`, made a name.
pub fn suggest() -> Name {
    suggest_from(&hostname())
}

/// The suggested name for a given hostname, as [`suggested_from`] makes it; a hostname that leaves no
/// name suggests `this`.
pub fn suggest_from(hostname: &str) -> Name {
    suggested_from(hostname).unwrap_or_else(|| Name("this".to_owned()))
}

/// The name a hostname leaves: cut at its first `.`, lowercased, every character outside the alphabet
/// made `-`, runs of `-` collapsed, the ends trimmed of `-`, cut to [`Name::MAX_LEN`]. `None` when nothing
/// is left, or a reserved word is (`root.local`).
pub fn suggested_from(hostname: &str) -> Option<Name> {
    let head = hostname.split('.').next().unwrap_or_default();
    let mut name = String::with_capacity(head.len());
    for character in head.chars() {
        let character = character.to_ascii_lowercase();
        let character = if character.is_ascii_lowercase() || character.is_ascii_digit() {
            character
        } else {
            '-'
        };
        if character == '-' && (name.is_empty() || name.ends_with('-')) {
            continue;
        }
        name.push(character);
    }
    let name = name.trim_end_matches('-');
    let name = &name[..name.len().min(Name::MAX_LEN)];
    // Built from the alphabet, starting with a letter or digit, and no longer than the bound: a name
    // unless it is empty (a hostname of only dots or symbols) or reserved.
    name.parse().and_then(Name::unreserved).ok()
}

/// This machine's hostname, or the empty string when the system will not say.
pub fn hostname() -> String {
    let mut buffer = [0_u8; 256];
    // SAFETY: the pointer and length describe `buffer`, which outlives the call; `gethostname` writes at
    // most that many bytes into it.
    let status =
        unsafe { libc::gethostname(buffer.as_mut_ptr().cast::<libc::c_char>(), buffer.len()) };
    if status != 0 {
        return String::new();
    }
    let end = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    String::from_utf8_lossy(&buffer[..end]).into_owned()
}

#[cfg(test)]
#[path = "names_tests.rs"]
mod names_tests;
