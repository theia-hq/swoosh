//! How a reaching verb authenticates to the service it dials.
//!
//! A reaching verb's auth need was five hand-synced match arms in `main.rs` (`identity()`, `args()`,
//! `run()`, `self_badge()`, `expose_context()`) that had to agree by hand, with a `_ => Ok(None)`
//! wildcard that let a forgotten verb reach a family-gated service carrying no badge. This module makes
//! that fact ONE typed decision per verb: a [`Credential`] the verb's type is required to state (see
//! [`Reaching`](crate::reaching)), from which the badge and the [`identity`](crate::identity::Identity)
//! mode both DERIVE, so the two can never disagree.
//!
//! [`SheerLink`] and [`MemberBadge`] replace the bare `Option<String>` credentials: a `sheer:` link is
//! parse-validated at the clap boundary (via the same [`Cap::parse`] path `--present` and the far gate
//! use), so a malformed link is rejected there, not laundered the whole reach path as if valid and
//! refused opaquely at the peer.

use core::fmt;
use core::str::FromStr;

use bifrost::NodeId;
use nauthy::Cap;
use tightbeam::identity::AsNodeId as _;

/// A parsed, structurally-valid `sheer:` capability link.
///
/// A `sheer:` link that has passed [`Cap::parse`]: the scheme, the embedded root key, the base32 body,
/// and the biscuit's signature chain are all checked at construction, so holding a `SheerLink` proves
/// the bytes decoded to a real cap (it does NOT prove the cap grants any given service or is unexpired:
/// that is the far gate's job at connect). Wired as clap's value parser via [`FromStr`], so a `--present`
/// flag hands a verb an already-valid link, never a raw `String` the reach path carries unverified to
/// the peer.
///
/// It holds the original link text, validated once at construction: the exact bytes it presents to
/// [`Connector::to_node`](tightbeam::tunnel::Connector::to_node) for the far gate to re-parse, with no
/// decode/re-encode round-trip. `Cap` is not `Clone`, so the parsed form is not stored (the validated
/// text is the invariant carrier); [`cap`](Self::cap) re-parses on demand for a local check.
#[derive(Clone)]
pub struct SheerLink(String);

impl SheerLink {
    /// The original `sheer:` link text, the exact bytes the far gate re-parses. This is what a
    /// [`Connector`](tightbeam::tunnel::Connector) presents on the wire.
    pub fn link(&self) -> &str {
        &self.0
    }

    /// The decoded capability, for a local check that wants the root or revocation ids. Re-parses the
    /// validated text; it cannot have changed since construction, so a failure is a bug, not a caller
    /// error, hence a `Result` the caller may `expect` rather than a value that hides the re-parse.
    pub fn cap(&self) -> Result<Cap, nauthy::CapError> {
        Cap::parse(&self.0)
    }

    /// Consume into the owned link text, for a wire API that takes `Option<String>` (the connector).
    pub fn into_link(self) -> String {
        let Self(link) = self;
        link
    }

    /// The node this link self-addresses: the cap's ROOT key as a bifrost [`NodeId`], the node a connector
    /// dials when the link is the peer. The same target [`Connector::from_link`](tightbeam::tunnel::Connector::from_link)
    /// computes (`Cap::parse(link)?.root().node_id()`), exposed so a link-as-peer can dial it without
    /// re-implementing the cap->node conversion in a caller that should not reach into nauthy directly.
    pub fn dial_node(&self) -> Result<NodeId, nauthy::CapError> {
        Ok(self.cap()?.root().node_id())
    }

    /// The short form for output: the root key's short id, uniform with a raw key's short form. The cap
    /// re-parse cannot fail (validated at construction), so the fallback is unreachable; it names the link
    /// text rather than panicking, keeping this infallible for a display path.
    pub fn short(&self) -> String {
        self.dial_node()
            .map(|node| node.short())
            .unwrap_or_else(|_| self.0.clone())
    }
}

impl FromStr for SheerLink {
    type Err = nauthy::CapError;

    /// Parse-don't-validate at the boundary: a malformed scheme, root key, encoding, or signature chain
    /// is a clap parse error here, naming the problem, not a raw string that fails opaquely at the peer.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Cap::parse(text)?;
        Ok(Self(text.to_owned()))
    }
}

impl fmt::Debug for SheerLink {
    /// Print the link text (a `sheer:` link is public share material), not the parsed biscuit internals.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SheerLink").field(&self.0).finish()
    }
}

/// A family membership badge to present when dialing a family-gated service.
///
/// A sealed `sheer:` link carrying a `member(true)` fact, minted either by the signet holder's self-sign
/// ([`Secret::member_badge`](crate::identity::Secret::member_badge)) or loaded as a device's stored
/// signet-signed badge ([`config::load_badge`](crate::config::load_badge)). A newtype rather than a bare
/// `String` so the minted badge and a user's `--present` link (both `sheer:` links) cannot be swapped by
/// position, and so "a badge" is a domain value with one construction path, not any `String`.
#[derive(Clone)]
pub struct MemberBadge(String);

impl MemberBadge {
    /// Wrap a freshly-minted or stored badge link. Constructed only by the mint/load sites, so a bare
    /// user string cannot masquerade as a minted badge.
    pub fn new(link: String) -> Self {
        Self(link)
    }

    /// The `sheer:` link text to present on the wire.
    pub fn link(&self) -> &str {
        &self.0
    }

    /// Consume into the owned link text, for the connector's `Option<String>` wire API.
    pub fn into_link(self) -> String {
        let Self(link) = self;
        link
    }
}

impl fmt::Debug for MemberBadge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MemberBadge").field(&self.0).finish()
    }
}

/// How a reaching verb authenticates to the service it dials.
///
/// Exhaustive: every reaching verb resolves to exactly one of these, and the resolution is TOTAL (see
/// [`Reaching::credential`](crate::reaching::Reaching::credential)), so "forgot to say" is not
/// representable. Deliberately NO `Default`/`#[default]`: omission must not mint [`Anonymous`](Self::Anonymous)
/// (a stranger dial, strictly worse than today's refusal). The badge to present AND the
/// [`Identity`](crate::identity::Identity) mode both derive from this one value.
#[derive(Debug, Clone)]
pub enum Credential {
    /// Dials as a stranger by construction: the service is ungated, or the verb presents its OWN link
    /// (never swoosh's identity). A NAMED, deliberate no-badge (e.g. `forward`), not a forgettable
    /// `None`. Derives [`Identity::Ephemeral`](crate::identity::Identity::Ephemeral).
    Anonymous,
    /// Reaches a FAMILY-GATED service: presents the member badge rooted at the dialing key (a stored
    /// device badge, else the signet-holder self-sign), which an explicit `--present` link overrides.
    /// Derives [`Identity::PersistedIfPresent`](crate::identity::Identity::PersistedIfPresent), so the
    /// self-badge roots at the same key the dial binds under and the two can never disagree.
    Family {
        /// A delegate's explicit `--present` slip, if given; it overrides the default member badge. The
        /// ONLY surviving `Option` on this path, and an honest one (the user optionally overrode), not
        /// "the author forgot".
        present: Option<SheerLink>,
    },
}

impl Credential {
    /// The identity a verb with this credential must bind under. This is the ONLY place the
    /// identity/badge coupling lives, so a `Family` credential is always `PersistedIfPresent` (its badge
    /// roots at the dialing key) and an `Anonymous` one is always `Ephemeral`. `serve`/`tunnel-connect`
    /// bind `Persisted` for a different reason (a stable address / dialing under swoosh's own key) via a
    /// non-forgettable override, not this derivation.
    pub fn identity(&self) -> crate::identity::Identity {
        match self {
            Self::Family { .. } => crate::identity::Identity::PersistedIfPresent,
            Self::Anonymous => crate::identity::Identity::Ephemeral,
        }
    }
}
