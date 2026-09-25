//! A link as a person sees it: `swoosh:` then nauthy's bare `<key>.<token>`.
//!
//! The prefix lives only at the edges a person touches: a link prints with it and parses only with it. The
//! wire, the stores and every codec carry [`nauthy::Link`], the bare form, so this type has no serde and no
//! write path. A file holds the prefixed form only when a person made it for a person (a shell redirect of
//! stdout).

use core::fmt;
use core::str::FromStr;

use bifrost::NodeId;

/// The mark every link a person sees starts with.
pub const PREFIX: &str = "swoosh:";

/// A link a person typed or will read: nauthy's link, shown and parsed with [`PREFIX`].
#[derive(Clone)]
pub struct Link(nauthy::Link);

impl Link {
    /// The bare link, for the wire and the stores.
    pub fn inner(&self) -> &nauthy::Link {
        let Self(inner) = self;
        inner
    }

    /// The bare link, taken out.
    pub fn into_inner(self) -> nauthy::Link {
        let Self(inner) = self;
        inner
    }
}

impl From<nauthy::Link> for Link {
    fn from(inner: nauthy::Link) -> Self {
        Self(inner)
    }
}

impl fmt::Display for Link {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{PREFIX}{}", self.inner())
    }
}

impl fmt::Debug for Link {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Link").field(&self.to_string()).finish()
    }
}

impl FromStr for Link {
    type Err = LinkError;

    /// Trim surrounding whitespace, require [`PREFIX`] in any ASCII case, strip it, and parse the rest as
    /// nauthy's link.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let rest = strip_prefix(text.trim()).ok_or(LinkError::Prefix)?;
        Ok(Self(rest.parse::<nauthy::Link>()?))
    }
}

/// The text after [`PREFIX`], matched in any ASCII case, or `None` when it does not start with it.
fn strip_prefix(text: &str) -> Option<&str> {
    let head = text.get(..PREFIX.len())?;
    head.eq_ignore_ascii_case(PREFIX)
        .then(|| text.get(PREFIX.len()..))
        .flatten()
}

/// Whether `text` starts with [`PREFIX`] in any ASCII case, after surrounding whitespace: the one mark of a
/// link, so a malformed link still reads as a link rather than as a name.
pub fn is_prefixed(text: &str) -> bool {
    strip_prefix(text.trim()).is_some()
}

/// Whether `text` is shaped like a bare link (`<key>.<rest>`): a key, a dot, and more. No name holds a dot,
/// so this is never a name a person meant.
pub fn looks_bare(text: &str) -> bool {
    text.trim()
        .split_once('.')
        .is_some_and(|(key, _)| key.parse::<NodeId>().is_ok())
}

/// Parse a link a person typed into the bare form the wire carries: the value parser for a flag that takes
/// a link.
pub fn parse(text: &str) -> Result<nauthy::Link, LinkError> {
    text.parse::<Link>().map(Link::into_inner)
}

/// Why text was not a link.
#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    /// The text did not start with [`PREFIX`].
    #[error("this looks like a link; a link starts with `swoosh:`")]
    Prefix,
    /// The text after [`PREFIX`] was not a link.
    #[error("not a valid link")]
    Link(#[from] nauthy::CapError),
}

#[cfg(test)]
#[path = "link_tests.rs"]
mod link_tests;
