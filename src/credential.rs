//! How a reaching verb authenticates to the service it dials.
//!
//! A reaching verb's auth need was five hand-synced match arms in `main.rs` (`identity()`, `args()`,
//! `run()`, `self_badge()`, `expose_context()`) that had to agree by hand, with a `_ => Ok(None)`
//! wildcard that let a forgotten verb reach a family-gated service carrying no badge. This module makes
//! that fact ONE typed decision per verb: a [`Credential`] the verb's type is required to state (see
//! [`Reaching`](crate::reaching)), from which the badge and the [`identity`](crate::identity::Identity)
//! mode both DERIVE, so the two can never disagree.
//!
//! The credential a verb carries is a [`Link`]: a `sheer:` link is parse-validated at the clap boundary
//! (the scheme, the embedded root key, the base32 body, and the signature chain, the same check the far
//! gate runs), so a malformed link is refused where the user typed it, naming the fault, rather than
//! laundered down the whole reach path as if valid and refused opaquely at the peer. [`LinkExt`] adds the
//! two reads swoosh needs of a link that nauthy does not owe a consumer.

use bifrost::NodeId;
use nauthy::Link;
use tightbeam::identity::AsNodeId as _;

/// The reads swoosh takes of a [`Link`]: the node it self-addresses and its short form for output.
///
/// An extension trait rather than a bag of free functions, because the two are one cohesive family over
/// a type this crate cannot own an inherent impl on (it lives in nauthy, so the orphan rule forbids one).
/// At the call site `link.dial_node()` then reads as the link's own behaviour, which is what it is, and
/// the cap-to-node conversion stays here instead of being re-implemented in every caller that would
/// otherwise have to reach into nauthy itself. The cap itself is NOT one of these: `Link::cap` is the
/// link's own accessor, and a same-named extension method would silently shadow it.
pub trait LinkExt {
    /// The node this link self-addresses: the cap's ROOT key as a bifrost [`NodeId`], the node a connector
    /// dials when the link IS the peer. The same target
    /// [`Connector::from_link`](tightbeam::tunnel::Connector::from_link) computes (`link.root().node_id()`).
    fn dial_node(&self) -> NodeId;

    /// The short form for output: the root key's short id, uniform with a raw key's short form, so a link
    /// peer and a key peer print the same way.
    fn short(&self) -> String;
}

impl LinkExt for Link {
    fn dial_node(&self) -> NodeId {
        self.root().node_id()
    }

    fn short(&self) -> String {
        self.dial_node().short()
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
        present: Option<Link>,
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

    /// Whether a dial with this credential may use the resident's warm reach. The default member
    /// badge reaches as THIS home's node (the peer sees the resident key, the ratified warm-reuse
    /// tradeoff); any personal credential must never ride the socket.
    pub fn warm_mode(&self) -> WarmMode {
        match self {
            Self::Family { present: None } => WarmMode::Resident,
            Self::Family { present: Some(_) } | Self::Anonymous => WarmMode::Personal,
        }
    }
}

/// Whether a dial may use the resident's warm reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarmMode {
    /// The default member-badge dial: the resident may reach as THIS home's node. The peer sees the
    /// resident key, the ratified warm-reuse tradeoff.
    Resident,
    /// A personal credential (an explicit `--present` slip, a link-as-peer, or an anonymous stranger
    /// dial): never warm. A personal credential must not ride the socket.
    Personal,
}
