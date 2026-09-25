//! A peer to dial, as typed: a saved petname, a raw key, or a self-addressing `swoosh:` link.
//!
//! A "peer to dial" is a higher-level concept than the address book, so it composes the contacts domain
//! (`ContactRef`, `Candidate`, `Contacts`) rather than squatting in it, and it unifies the two dial-target
//! types the reach and tunnel families used to keep apart: the multi-device diagnostic verbs
//! (`ping`/`speed`/`status`/`fetch`) fan a peer out via [`candidates`](Peer::candidates), the single-target
//! verbs (`reach`/`send`/`stop`/`service`/`fleet`) resolve one via [`connector`](Peer::connector). Both
//! shapes read the SAME three arms, so `alice`, `alice/desk`, a raw key, and a `swoosh:` link all parse in
//! one place, uniform across every dialing verb.

use core::str::FromStr;

use bifrost::{KeyError, NodeId, NodeIdParseError};
use nauthy::{Link, Service};
use tightbeam::tunnel::Connector;

use crate::contacts::{Candidate, ContactRef, Contacts};
use crate::credential::LinkExt as _;
use crate::link::LinkError;
use crate::names::NameError;

/// A peer a dialing verb reaches, before resolution. Replaces BOTH the reach family's old `Target` and the
/// tunnel family's old `Dial`: one type, three arms, tried in a fixed order at the clap boundary.
///
/// A `swoosh:` link supersedes the identity path (it self-addresses: it names the node to dial AND carries
/// the credential); else a raw base32 node id is dialed verbatim; else the text is a saved petname resolved
/// against the contact store just before dialing (deferred because the store loads at startup, not at the
/// clap boundary). Every dialing verb holds this in its peer slot, so `alice`, `alice/desk`, a raw key, and
/// a `swoosh:` link all parse in one place, uniform across `ping`/`speed`/`status`/`fetch`/`reach`/`send`/
/// `stop`/`service`/`ssh`.
#[derive(Debug, Clone)]
pub enum Peer {
    /// A saved petname (`alice`, `me/ci`), resolved against the store at dial time. Fan-out capable: a
    /// bare person resolves to all their devices in label order.
    Named(ContactRef),
    /// A literal node id, dialed verbatim with no store lookup.
    Raw(NodeId),
    /// A `swoosh:` capability link. Self-addressing: it supplies the dial target (the cap's root node) AND
    /// the slot-1 credential, so a separate `--present` is redundant (see the fold in [`self_present`](Self::self_present)).
    Capability(Link),
}

impl FromStr for Peer {
    type Err = PeerParseError;

    /// A `swoosh:` link first (the self-addressing capability form, parse-validated here so a malformed link
    /// fails fast at the boundary), then a raw base32 node id (always valid, never a petname, since petnames
    /// are additive), else a saved petname address (validated here, resolved against the store at dial time).
    /// A bare link (`ed01….x`) is none of these: no name holds a dot, so it refuses naming the prefix.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if crate::link::is_prefixed(text) {
            Ok(Self::Capability(crate::link::parse(text)?))
        } else {
            if let Some(node) = raw_key(text)? {
                return Ok(Self::Raw(node));
            }
            if crate::link::looks_bare(text) {
                Err(PeerParseError::Capability(LinkError::Prefix))
            } else {
                Ok(Self::Named(text.parse::<ContactRef>()?))
            }
        }
    }
}

/// A typed key that spells a key, but not one anyone can hold: the one line every typed key refuses with,
/// naming the check it failed.
#[derive(Debug, thiserror::Error)]
#[error("{text} is not a usable key: {error}")]
pub struct UnusableKey {
    /// The text as typed.
    pub text: String,
    /// Which check the key failed.
    pub error: KeyError,
}

/// Why typed text is not a key.
#[derive(Debug, thiserror::Error)]
pub enum KeyTextError {
    /// It spells a key nobody can hold.
    #[error(transparent)]
    Unusable(#[from] UnusableKey),
    /// It does not spell a key at all.
    #[error(transparent)]
    NotAKey(NodeIdParseError),
}

/// Typed text as a key: the parser every typed key goes through, so a key nobody can hold refuses with
/// the same line wherever it is typed.
pub fn parse_key(text: &str) -> Result<NodeId, KeyTextError> {
    match text.parse::<NodeId>() {
        Ok(node) => Ok(node),
        Err(NodeIdParseError::Key(error)) => Err(UnusableKey {
            text: text.to_owned(),
            error,
        }
        .into()),
        Err(other) => Err(KeyTextError::NotAKey(other)),
    }
}

/// Typed text as a key where a name may stand instead: `None` when it does not spell a key, the refusal
/// when it spells one nobody can hold (that text is a key, never a name).
pub fn raw_key(text: &str) -> Result<Option<NodeId>, UnusableKey> {
    match parse_key(text) {
        Ok(node) => Ok(Some(node)),
        Err(KeyTextError::Unusable(unusable)) => Err(unusable),
        Err(KeyTextError::NotAKey(_)) => Ok(None),
    }
}

/// Why a string was not a valid [`Peer`].
#[derive(Debug, thiserror::Error)]
pub enum PeerParseError {
    /// The text was a link without its `swoosh:` prefix, or a `swoosh:` link that did not parse.
    #[error(transparent)]
    Capability(#[from] LinkError),
    /// The text was neither a link nor a raw key, and a part of it was not a name: the name rule's own line.
    #[error(transparent)]
    Contact(#[from] NameError),
    /// The text spells a key, but not one anyone can hold.
    #[error(transparent)]
    Key(#[from] UnusableKey),
}

impl Peer {
    /// FAN-OUT resolution, for the multi-device verbs (`ping`/`speed`/`status`/`fetch`). A [`Named`](Self::Named)
    /// person resolves to ALL devices in label order; [`Raw`](Self::Raw) to one; a [`Capability`](Self::Capability)
    /// link to exactly one (the cap's root node it self-addresses), so a link degenerates to a single
    /// candidate exactly as `Raw` does. An unknown name surfaces the contact resolver's clean error, never a
    /// silent empty dial.
    ///
    /// `eyre::Result` rather than the contact resolver's typed `ResolveError`: the store's own resolve
    /// failure is the only error here, and folding it into a peer-level type would buy a caller nothing.
    /// Every caller resolves in an eyre context already.
    pub fn candidates(&self, contacts: &Contacts) -> eyre::Result<Vec<Candidate>> {
        match self {
            Self::Named(reference) => Ok(contacts.resolve_candidates(reference)?),
            Self::Raw(node) => Ok(vec![Candidate {
                label: node.short(),
                node: *node,
            }]),
            Self::Capability(link) => Ok(vec![Candidate {
                label: link.short(),
                node: link.dial_node()?,
            }]),
        }
    }

    /// SINGLE-CONNECTOR resolution, for the single-target verbs (`reach`/`send`/`stop`/`service`/`fleet`).
    /// The resolver ALWAYS builds via [`Connector::to_node`] with the slot-1/slot-2 the caller resolved;
    /// the [`Capability`](Self::Capability) arm differs ONLY in computing the dial target from the link's
    /// root. It NEVER calls [`Connector::from_link`]: the link's credential arrives as `slot1` from the
    /// ONE resolver (the peer's link is folded into `--present`), so slot 1 and slot 2 stay owned by
    /// [`resolve`](crate::reaching::resolve) for every arm. A bare person resolves to the FIRST device in
    /// label order (these verbs dial one node); an unknown petname is a loud error here.
    pub fn connector(
        &self,
        contacts: &Contacts,
        service: Service,
        slot1: Option<Link>,
        slot2: Option<Link>,
    ) -> eyre::Result<Connector> {
        let dial = match self {
            Self::Raw(id) => *id,
            Self::Capability(link) => link.dial_node()?,
            Self::Named(reference) => {
                contacts
                    .resolve_candidates(reference)?
                    .into_iter()
                    .next()
                    .ok_or_else(|| eyre::eyre!("contact '{reference}' has no device to reach"))?
                    .node
            }
        };
        let connector = Connector::to_node(dial, service, slot1);
        // Slot 2: a badge under the foreign fleet a signet-bound slip in slot 1 names. A no-op for a plain
        // dial (the host admits on slot 1 and never consults slot 2).
        Ok(match slot2 {
            Some(badge) => connector.with_membership(badge),
            None => connector,
        })
    }

    /// The credential this peer self-supplies when it is a self-addressing link, else `None`. This is what
    /// the fold prefers over an explicit `--present`: a `swoosh:` link passed AS the peer flows through the
    /// same [`resolve`](crate::reaching::resolve) path as an explicit `--present`, so a signet-bound
    /// link-as-peer computes its slot-2 member badge exactly as a `--present` link does.
    pub fn self_present(&self) -> Option<Link> {
        match self {
            Self::Capability(link) => Some(link.clone()),
            _ => None,
        }
    }

    /// Reject a redundant `--present` alongside a self-addressing link peer: the link already presents its
    /// own credential, so a second one is ambiguous. A no-op for a [`Named`](Self::Named)/[`Raw`](Self::Raw)
    /// peer, where `--present` is the credential (the fleet/delegate case, a slip rooted elsewhere). Called
    /// once at the top of each verb's run before resolving, so the conflict is loud and local while
    /// [`bind_role`](crate::reaching::Reaching::bind_role), which carries the credential, stays infallible.
    pub fn reject_redundant_present(&self, explicit: Option<&Link>) -> eyre::Result<()> {
        if matches!(self, Self::Capability(_)) && explicit.is_some() {
            eyre::bail!(
                "a `swoosh:` link peer already presents its own credential; drop `--present` (or name \
                 a petname/key peer to present a different link)"
            );
        }
        Ok(())
    }
}

impl core::fmt::Display for Peer {
    /// The peer as the user would recognize it: the name for a petname, the short key for a raw id, the
    /// link's short form (the cap root's short id) for a capability link.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Named(reference) => reference.fmt(f),
            Self::Raw(node) => f.write_str(&node.short()),
            Self::Capability(link) => f.write_str(&link.short()),
        }
    }
}

#[cfg(test)]
mod tests {
    use bifrost::NodeId;
    use nauthy::Link;

    use super::Peer;
    use crate::contacts::{Contacts, Petname};
    use crate::credential::LinkExt as _;
    use crate::link::LinkError;

    /// A distinct node id for a test, derived from a fixed seed so it is stable and comparable.
    fn node(seed: u8) -> NodeId {
        NodeId::from_ed25519_secret(&[seed; 32])
    }

    /// A real signet-bound `swoosh:` link (work issues it for a foreign fleet), so a test can assert a
    /// `Capability` peer self-addresses to the cap ROOT and folds its slip like an explicit `--present`.
    fn signet_link() -> String {
        let slip = crate::testkit::TestNode::seeded(1)
            .fleet_slip(
                &"ssh".parse().expect("valid service"),
                crate::testkit::TestRoot::seeded(2).verify_key(),
                nauthy::Request::expires_in(core::time::Duration::from_secs(3600)),
            )
            .expect("mint a signet-bound slip");
        crate::link::Link::from(slip).to_string()
    }

    /// `me/ci` parses as a `Named` peer (not a raw key, not a link), then `connector` resolves it through
    /// the contact store to the saved key. A raw key parses `Raw` and needs no store; an unknown petname is
    /// a loud `connector` error, never a silent nothing.
    #[test]
    fn a_petname_peer_resolves_through_contacts_to_the_saved_key() {
        let ci = node(7);
        let mut contacts = Contacts::default();
        contacts.add(
            "me".parse::<Petname>().expect("valid petname"),
            Some("ci".parse().expect("valid device")),
            ci,
        );

        let peer = "me/ci".parse::<Peer>().expect("a petname parses as a Peer");
        assert!(
            matches!(peer, Peer::Named(_)),
            "a saved-contact address parses as a petname to resolve, not a raw key"
        );
        let connector = peer
            .connector(&contacts, "control.stop".parse().unwrap(), None, None)
            .expect("a known petname resolves to a connector");
        assert_eq!(
            connector.dial(),
            ci,
            "the petname must dial the key it was saved under"
        );

        let raw = node(9);
        let peer = raw.to_string().parse::<Peer>().expect("a raw key parses");
        assert!(
            matches!(peer, Peer::Raw(_)),
            "a raw base32 key is a Raw peer"
        );
        assert_eq!(
            peer.connector(&contacts, "control.stop".parse().unwrap(), None, None)
                .expect("a raw key needs no store")
                .dial(),
            raw,
        );

        let ghost = "ghost".parse::<Peer>().expect("a name parses as a Peer");
        assert!(
            ghost
                .connector(&contacts, "control.stop".parse().unwrap(), None, None)
                .is_err(),
            "an unknown petname is a loud resolve error, not a silent nothing"
        );
    }

    /// A base32 key is `Raw`, never `Named`: petnames are additive, so a literal key always wins the parse
    /// order and never needs a store lookup.
    #[test]
    fn a_raw_key_parses_before_a_petname() {
        let raw = node(11);
        let peer = raw.to_string().parse::<Peer>().expect("a raw key parses");
        assert!(
            matches!(peer, Peer::Raw(_)),
            "a base32 key parses as Raw, never as a petname to resolve"
        );
    }

    /// A pasted `swoosh:<link>` parses as a `Capability` peer, and BOTH resolution shapes self-address to the
    /// cap root (`dial_node`): `candidates` yields exactly one candidate at that node, and `connector` dials
    /// it, so a link degenerates to a single target uniform with a raw key.
    #[test]
    fn a_pasted_swoosh_link_parses_as_a_peer() {
        let link = signet_link();
        let peer = link.parse::<Peer>().expect("a swoosh: link parses");
        let root = match &peer {
            Peer::Capability(link) => link.dial_node().expect("a link root is a key"),
            _ => panic!("a swoosh: link parses as a Capability peer"),
        };

        let contacts = Contacts::default();
        let candidates = peer
            .candidates(&contacts)
            .expect("a link resolves to one candidate with no store");
        assert_eq!(
            candidates.len(),
            1,
            "a link degenerates to a single candidate"
        );
        assert_eq!(
            candidates[0].node, root,
            "the one candidate is the cap root"
        );

        let connector = peer
            .connector(&contacts, "ssh".parse().unwrap(), None, None)
            .expect("a link needs no store to build a connector");
        assert_eq!(connector.dial(), root, "the connector dials the cap root");
    }

    /// A malformed `swoosh:` link is a `PeerParseError::Capability` at the boundary, not deferred to a
    /// petname lookup that would miss: the parse fails fast where the user typed it.
    #[test]
    fn parse_rejects_a_malformed_link_at_the_boundary() {
        let error = "swoosh:not-a-real-link".parse::<Peer>();
        assert!(
            matches!(
                error,
                Err(super::PeerParseError::Capability(LinkError::Link(_)))
            ),
            "a bad swoosh: link is a Capability parse error, not a petname to resolve: {error:?}"
        );
    }

    /// A bare link typed where a peer goes (`ed01….x`) is not a name and not a key: it refuses with the
    /// line that names the prefix, whatever follows the dot.
    #[test]
    fn a_bare_link_is_refused_with_the_prefix_hint() {
        let bare = crate::link::parse(&signet_link()).expect("a link");
        for text in [bare.as_str().to_owned(), format!("{}.x", node(3))] {
            let error = text.parse::<Peer>().expect_err("a bare link is refused");
            assert!(
                matches!(error, super::PeerParseError::Capability(LinkError::Prefix)),
                "{text}: {error:?}"
            );
            assert_eq!(
                error.to_string(),
                "this looks like a link; a link starts with `swoosh:`"
            );
        }
    }

    /// A `swoosh:` link peer plus an explicit `--present` is a LOUD conflict (the link already presents its
    /// own credential); a link peer with no `--present`, and a `Named`/`Raw` peer WITH `--present` (the
    /// delegate case, a slip rooted elsewhere), are both fine.
    #[test]
    fn link_peer_plus_present_is_a_loud_error() {
        let link = signet_link();
        let peer = link.parse::<Peer>().expect("a link peer");
        let explicit: Link = crate::link::parse(&link).expect("a slip");
        assert!(
            peer.reject_redundant_present(Some(&explicit)).is_err(),
            "a link peer + --present is a loud conflict, not a silent pick"
        );
        assert!(
            peer.reject_redundant_present(None).is_ok(),
            "a link peer with no --present is fine"
        );

        let named = "alice".parse::<Peer>().expect("a petname peer");
        assert!(
            named.reject_redundant_present(Some(&explicit)).is_ok(),
            "a petname peer + --present presents a slip rooted elsewhere: allowed"
        );
    }

    /// A `Capability` peer's `connector` builds via `to_node` with the slots the resolver handed it, never
    /// via `from_link` (which would ignore them and set slot 1 = the link). The observable proof here: it
    /// dials the cap root while ACCEPTING an externally-supplied slot 1, which the `from_link` shape has no
    /// parameter for, so slot ownership stayed with `reaching::resolve`. The slot CONTENT is asserted at the
    /// resolver (`reaching` tests), since a `Connector`'s presented slots are private.
    #[test]
    fn connector_uses_the_resolved_slots_not_from_link() {
        let link = signet_link();
        let peer = link.parse::<Peer>().expect("a link peer");
        let root = match &peer {
            Peer::Capability(link) => link.dial_node().expect("a link root is a key"),
            _ => panic!("a swoosh: link parses as a Capability peer"),
        };
        // The two slots come from the resolver, not from the peer link: distinct valid links prove the
        // connector took them rather than deriving slot 1 from the link itself.
        let slot1: Link = crate::link::parse(&signet_link()).expect("a valid slot-1 link");
        let slot2: Link = crate::link::parse(&signet_link()).expect("a valid slot-2 link");
        let connector = peer
            .connector(
                &Contacts::default(),
                "ssh".parse().unwrap(),
                Some(slot1),
                Some(slot2),
            )
            .expect("a link builds a connector from explicit resolver slots");
        assert_eq!(
            connector.dial(),
            root,
            "the Capability arm dials the cap root via to_node, taking the resolver's slots"
        );
    }
}
