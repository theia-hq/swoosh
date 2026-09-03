//! A peer to dial, as typed: a saved petname, a raw key, or a self-addressing `sheer:` link.
//!
//! A "peer to dial" is a higher-level concept than the address book, so it composes the contacts domain
//! (`ContactRef`, `Candidate`, `Contacts`) rather than squatting in it, and it unifies the two dial-target
//! types the reach and tunnel families used to keep apart: the multi-device diagnostic verbs
//! (`ping`/`speed`/`status`/`fetch`) fan a peer out via [`candidates`](Peer::candidates), the single-target
//! verbs (`forward`/`beam`/`stop`/`service`/`fleet`) resolve one via [`connector`](Peer::connector). Both
//! shapes read the SAME three arms, so `alice`, `alice/desk`, a raw key, and a `sheer:` link all parse in
//! one place, uniform across every dialing verb.

use core::str::FromStr;

use bifrost::NodeId;
use nauthy::SCHEME;
use tightbeam::tunnel::Connector;

use crate::contacts::{Candidate, ContactRef, ContactRefParseError, Contacts};
use crate::credential::SheerLink;

/// A peer a dialing verb reaches, before resolution. Replaces BOTH the reach family's old `Target` and the
/// tunnel family's old `Dial`: one type, three arms, tried in a fixed order at the clap boundary.
///
/// A `sheer:` link supersedes the identity path (it self-addresses: it names the node to dial AND carries
/// the credential); else a raw base32 node id is dialed verbatim; else the text is a saved petname resolved
/// against the contact store just before dialing (deferred because the store loads at startup, not at the
/// clap boundary). Every dialing verb holds this in its peer slot, so `alice`, `alice/desk`, a raw key, and
/// a `sheer:` link all parse in one place, uniform across `ping`/`speed`/`status`/`fetch`/`forward`/`beam`/
/// `stop`/`service`/`ssh`.
#[derive(Debug, Clone)]
pub enum Peer {
    /// A saved petname (`alice`, `me/qat`), resolved against the store at dial time. Fan-out capable: a
    /// bare person resolves to all their devices in label order.
    Named(ContactRef),
    /// A literal node id, dialed verbatim with no store lookup.
    Raw(NodeId),
    /// A `sheer:` capability link. Self-addressing: it supplies the dial target (the cap's root node) AND
    /// the slot-1 credential, so a separate `--present` is redundant (see the fold in [`self_present`](Self::self_present)).
    Capability(SheerLink),
}

impl FromStr for Peer {
    type Err = PeerParseError;

    /// A `sheer:` link first (the self-addressing capability form, parse-validated here so a malformed link
    /// fails fast at the boundary), then a raw base32 node id (always valid, never a petname, since petnames
    /// are additive), else a saved petname address (validated here, resolved against the store at dial time).
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.starts_with(SCHEME) {
            Ok(Self::Capability(text.parse::<SheerLink>()?))
        } else if let Ok(node) = text.parse::<NodeId>() {
            Ok(Self::Raw(node))
        } else {
            Ok(Self::Named(text.parse::<ContactRef>()?))
        }
    }
}

/// Why a string was not a valid [`Peer`].
#[derive(Debug, thiserror::Error)]
pub enum PeerParseError {
    /// The `sheer:`-prefixed text was not a valid capability link.
    #[error("invalid capability link")]
    Capability(#[from] nauthy::CapError),
    /// The text was neither a link nor a raw key, and did not parse as a petname address.
    #[error("invalid peer address")]
    Contact(#[from] ContactRefParseError),
}

impl Peer {
    /// FAN-OUT resolution, for the multi-device verbs (`ping`/`speed`/`status`/`fetch`). A [`Named`](Self::Named)
    /// person resolves to ALL devices in label order; [`Raw`](Self::Raw) to one; a [`Capability`](Self::Capability)
    /// link to exactly one (the cap's root node it self-addresses), so a link degenerates to a single
    /// candidate exactly as `Raw` does. An unknown name surfaces the contact resolver's clean error, never a
    /// silent empty dial.
    ///
    /// `eyre::Result` rather than the contact resolver's typed `ResolveError`, because the `Capability` arm
    /// self-addresses via `link.dial_node()` (a nauthy `CapError`): folding that cap concern into the
    /// address-book error would leak nauthy into the contacts domain, which stays pure (the accessor keeps
    /// nauthy knowledge in `credential.rs`). Every caller resolves in an eyre context already.
    pub fn candidates(&self, contacts: &Contacts) -> eyre::Result<Vec<Candidate>> {
        match self {
            Self::Named(reference) => Ok(contacts.resolve_candidates(reference)?),
            Self::Raw(node) => Ok(vec![Candidate {
                label: node.short(),
                node: *node,
            }]),
            Self::Capability(link) => {
                let node = link.dial_node()?;
                Ok(vec![Candidate {
                    label: link.short(),
                    node,
                }])
            }
        }
    }

    /// SINGLE-CONNECTOR resolution, for the single-target verbs (`forward`/`beam`/`stop`/`service`/`fleet`,
    /// and the `tunnel-connect` bridge). The resolver ALWAYS builds via [`Connector::to_node`] with the
    /// slot-1/slot-2 the caller resolved; the [`Capability`](Self::Capability) arm differs ONLY in computing
    /// the dial target from the link's root. It NEVER calls [`Connector::from_link`]: the link's credential
    /// arrives as `slot1` from the ONE resolver (the peer's link is folded into `--present`), so slot 1 and
    /// slot 2 stay owned by [`resolve`](crate::reaching::resolve) for every arm. A bare person resolves to
    /// the FIRST device in label order (these verbs dial one node); an unknown petname is a loud error here.
    pub fn connector(
        &self,
        contacts: &Contacts,
        service: String,
        slot1: Option<String>,
        slot2: Option<String>,
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
    /// the fold prefers over an explicit `--present`: a `sheer:` link passed AS the peer flows through the
    /// same [`resolve`](crate::reaching::resolve) path as an explicit `--present`, so a signet-bound
    /// link-as-peer computes its slot-2 member badge exactly as a `--present` link does.
    pub fn self_present(&self) -> Option<SheerLink> {
        match self {
            Self::Capability(link) => Some(SheerLink::clone(link)),
            _ => None,
        }
    }

    /// Reject a redundant `--present` alongside a self-addressing link peer: the link already presents its
    /// own credential, so a second one is ambiguous. A no-op for a [`Named`](Self::Named)/[`Raw`](Self::Raw)
    /// peer, where `--present` is the credential (the fleet/delegate case, a slip rooted elsewhere). Called
    /// once at the top of each verb's run before resolving, so the conflict is loud and local while
    /// [`credential`](crate::reaching::Reaching::credential) stays infallible.
    pub fn reject_redundant_present(&self, explicit: Option<&SheerLink>) -> eyre::Result<()> {
        if matches!(self, Self::Capability(_)) && explicit.is_some() {
            eyre::bail!(
                "a `sheer:` link peer already presents its own credential; drop `--present` (or name \
                 a petname/key peer to present a different slip)"
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

    use super::Peer;
    use crate::contacts::{Contacts, Petname};

    /// A distinct node id for a test, derived from a fixed seed so it is stable and comparable.
    fn node(seed: u8) -> NodeId {
        NodeId::from_ed25519_secret(&[seed; 32])
    }

    /// A real signet-bound `sheer:` link (work issues it for a foreign fleet), so a test can assert a
    /// `Capability` peer self-addresses to the cap ROOT and folds its slip like an explicit `--present`.
    fn signet_link() -> String {
        let work = nauthy::Identity::from_secret(&[1u8; 32]).expect("valid work secret");
        let fleet = nauthy::Identity::from_secret(&[2u8; 32])
            .expect("valid fleet secret")
            .node_id();
        tightbeam::tunnel::mint_signet_link(
            &work,
            &"ssh".parse().expect("valid service"),
            fleet,
            core::time::Duration::from_secs(3600),
        )
        .expect("mint a signet-bound slip")
    }

    /// `me/qat` parses as a `Named` peer (not a raw key, not a link), then `connector` resolves it through
    /// the contact store to the saved key. A raw key parses `Raw` and needs no store; an unknown petname is
    /// a loud `connector` error, never a silent nothing. Ported from the old `tunnel_connect` petname test.
    #[test]
    fn a_petname_peer_resolves_through_contacts_to_the_saved_key() {
        let qat = node(7);
        let mut contacts = Contacts::default();
        contacts.add(
            "me".parse::<Petname>().expect("valid petname"),
            Some("qat".parse().expect("valid device")),
            qat,
        );

        let peer = "me/qat"
            .parse::<Peer>()
            .expect("a petname parses as a Peer");
        assert!(
            matches!(peer, Peer::Named(_)),
            "a saved-contact address parses as a petname to resolve, not a raw key"
        );
        let connector = peer
            .connector(&contacts, "control.stop".to_owned(), None, None)
            .expect("a known petname resolves to a connector");
        assert_eq!(
            connector.dial(),
            qat,
            "the petname must dial the key it was saved under"
        );

        let raw = node(9);
        let peer = raw.to_string().parse::<Peer>().expect("a raw key parses");
        assert!(
            matches!(peer, Peer::Raw(_)),
            "a raw base32 key is a Raw peer"
        );
        assert_eq!(
            peer.connector(&contacts, "control.stop".to_owned(), None, None)
                .expect("a raw key needs no store")
                .dial(),
            raw,
        );

        let ghost = "ghost".parse::<Peer>().expect("a name parses as a Peer");
        assert!(
            ghost
                .connector(&contacts, "control.stop".to_owned(), None, None)
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

    /// `sheer:<link>` parses as a `Capability` peer, and BOTH resolution shapes self-address to the cap root
    /// (`dial_node`): `candidates` yields exactly one candidate at that node, and `connector` dials it, so a
    /// link degenerates to a single target uniform with a raw key.
    #[test]
    fn a_sheer_link_parses_capability_and_self_addresses() {
        let link = signet_link();
        let peer = link.parse::<Peer>().expect("a sheer: link parses");
        let root = match &peer {
            Peer::Capability(link) => link.dial_node().expect("the link self-addresses"),
            _ => panic!("a sheer: link parses as a Capability peer"),
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
            .connector(&contacts, "ssh".to_owned(), None, None)
            .expect("a link needs no store to build a connector");
        assert_eq!(connector.dial(), root, "the connector dials the cap root");
    }

    /// A malformed `sheer:` link is a `PeerParseError::Capability` at the boundary, not deferred to a
    /// petname lookup that would miss: the parse fails fast where the user typed it.
    #[test]
    fn parse_rejects_a_malformed_link_at_the_boundary() {
        let error = "sheer:not-a-real-link".parse::<Peer>();
        assert!(
            matches!(error, Err(super::PeerParseError::Capability(_))),
            "a bad sheer: link is a Capability parse error, not a petname to resolve: {error:?}"
        );
    }

    /// A `sheer:` link peer plus an explicit `--present` is a LOUD conflict (the link already presents its
    /// own credential); a link peer with no `--present`, and a `Named`/`Raw` peer WITH `--present` (the
    /// delegate case, a slip rooted elsewhere), are both fine.
    #[test]
    fn link_peer_plus_present_is_a_loud_error() {
        let link = signet_link();
        let peer = link.parse::<Peer>().expect("a link peer");
        let explicit: crate::credential::SheerLink = link.parse().expect("a slip");
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
            Peer::Capability(link) => link.dial_node().expect("the link self-addresses"),
            _ => panic!("a sheer: link parses as a Capability peer"),
        };
        let connector = peer
            .connector(
                &Contacts::default(),
                "ssh".to_owned(),
                Some("sheer:resolver-slot-one".to_owned()),
                Some("sheer:resolver-slot-two".to_owned()),
            )
            .expect("a link builds a connector from explicit resolver slots");
        assert_eq!(
            connector.dial(),
            root,
            "the Capability arm dials the cap root via to_node, taking the resolver's slots"
        );
    }
}
