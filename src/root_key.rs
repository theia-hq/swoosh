//! A root's key as a person reads and types it: `root:ed01…`, so a root never passes for a machine.
//!
//! A machine's key and a root's key are the same kind of key, so only the shape tells them apart. Every
//! line prints a root with [`PREFIX`] before it and every argument that wants a root takes only that form;
//! an argument that wants a machine refuses it. The prefix is a marker for people only: the book, the
//! ledger and the wire take the inner key ([`RootKey::key`]), and this type has no serde of its own.

use core::str::FromStr;

use bifrost::{NodeId, NodeIdParseError};

use crate::peer::{KeyTextError, UnusableKey};

/// The marker a root's key is printed and typed with, ASCII case aside.
pub const PREFIX: &str = "root:";

/// How many characters of a key's text are its tag (`ed01`): every key starts with them, so a confirmation
/// token skips them.
const TAG: usize = 4;

/// How many characters a confirmation token is: the same 8 every short form shows after the tag.
const TOKEN: usize = 8;

/// A root's key, typed `root:ed01…`. Built only by parsing the prefixed form or from a key already known
/// to be a root's, so a bare key typed where a root is wanted never becomes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RootKey(NodeId);

impl RootKey {
    /// The key itself, the form stores and the wire take.
    pub fn key(self) -> NodeId {
        let Self(key) = self;
        key
    }

    /// The short form a line prints in prose: `root:ed01` and 8 more characters, then `…`.
    pub fn short(self) -> String {
        format!("{PREFIX}{}", crate::credential::short(&self.key()))
    }

    /// The token a person types to confirm an act that cannot be undone on this root: the 8 characters
    /// after the key's `ed01`. `ed01` is every key's tag, so a token holding it would check almost nothing;
    /// these 8 differ per key and are the ones every short form shows.
    pub fn token(self) -> String {
        self.key()
            .to_string()
            .chars()
            .skip(TAG)
            .take(TOKEN)
            .collect()
    }
}

impl From<NodeId> for RootKey {
    /// A key already known to be a root's: one read from the book's root slot, a pin, or a standing's
    /// issuer.
    fn from(key: NodeId) -> Self {
        Self(key)
    }
}

impl core::fmt::Display for RootKey {
    /// `root:` then the whole key, the form a command a line gives prints and a person pastes.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{PREFIX}{}", self.key())
    }
}

impl FromStr for RootKey {
    type Err = RootKeyError;

    /// Whitespace around it is trimmed; the prefix is required, in any ASCII case; the rest is read by the
    /// parser every typed key goes through, so a key nobody can hold refuses with the same line here.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.trim();
        let rest = strip(text).ok_or(RootKeyError::NoPrefix)?;
        match crate::peer::parse_key(rest) {
            Ok(key) => Ok(Self(key)),
            Err(KeyTextError::Unusable(unusable)) => Err(RootKeyError::Unusable(unusable)),
            Err(KeyTextError::NotAKey(error)) => Err(RootKeyError::NotAKey(error)),
        }
    }
}

/// Whether `text` starts with [`PREFIX`], in any ASCII case: the shape of a root's key, whatever follows.
pub fn is_prefixed(text: &str) -> bool {
    strip(text.trim_start()).is_some()
}

/// `text` without its [`PREFIX`], when it starts with one in any ASCII case.
fn strip(text: &str) -> Option<&str> {
    text.get(..PREFIX.len())
        .filter(|prefix| prefix.eq_ignore_ascii_case(PREFIX))
        .and_then(|_| text.get(PREFIX.len()..))
}

/// Why typed text is not a root's key.
#[derive(Debug, thiserror::Error)]
pub enum RootKeyError {
    /// It does not start with [`PREFIX`]: a bare key is a machine's.
    #[error("a root key starts with {PREFIX}")]
    NoPrefix,
    /// It starts with the prefix, and what follows spells no key: the key parser's own line.
    #[error(transparent)]
    NotAKey(NodeIdParseError),
    /// It starts with the prefix, and what follows spells a key nobody can hold.
    #[error(transparent)]
    Unusable(UnusableKey),
}

#[cfg(test)]
#[path = "root_key_tests.rs"]
mod tests;
