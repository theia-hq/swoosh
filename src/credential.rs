//! How a reaching verb authenticates to the service it dials.
//!
//! A reaching verb's auth need was five hand-synced match arms in `main.rs` (`identity()`, `args()`,
//! `run()`, `self_badge()`, `expose_context()`) that had to agree by hand, with a `_ => Ok(None)`
//! wildcard that let a forgotten verb reach a family-gated service carrying no badge. This module makes
//! that fact ONE typed decision per verb: a [`Credential`] the verb's type is required to state (see
//! [`Reaching`](crate::reaching)), from which the badge and the [`identity`](crate::identity::Identity)
//! mode both DERIVE, so the two can never disagree.
//!
//! The credential a verb carries is a [`Link`]: a `swoosh:` link is parse-validated at the clap boundary
//! (the scheme, the embedded root key, the base32 body, and the signature chain, the same check the far
//! gate runs), so a malformed link is refused where the user typed it, naming the fault, rather than
//! laundered down the whole reach path as if valid and refused opaquely at the peer. [`LinkExt`] adds the
//! two reads swoosh needs of a link that nauthy does not owe a consumer.

use bifrost::NodeId;
use nauthy::{Link, Request, Service};
use tightbeam::identity::AsNodeId as _;

use crate::peer::Peer;

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
    /// [`Connector::from_link`](tightbeam::tunnel::Connector::from_link) computes (`link.root().node_id()`),
    /// or bifrost's reason the root is not a key it can dial.
    fn dial_node(&self) -> Result<NodeId, bifrost::KeyError>;

    /// The short form for output: the root key's short id, uniform with a raw key's short form, so a link
    /// peer and a key peer print the same way.
    fn short(&self) -> String;
}

impl LinkExt for Link {
    fn dial_node(&self) -> Result<NodeId, bifrost::KeyError> {
        self.root().node_id()
    }

    fn short(&self) -> String {
        short(&self.root())
    }
}

/// How many characters of a key's text its short form keeps: `ed01` and 8 more.
const SHORT: usize = 12;

/// The short form of a key for output: `ed01`, the next 8 characters, and `…`. One form for every key a
/// line prints short. A line that gives a command prints the whole key instead: a short key is never
/// accepted as input.
pub fn short(key: &impl core::fmt::Display) -> String {
    let mut short: String = key.to_string().chars().take(SHORT).collect();
    short.push('…');
    short
}

/// How a reaching verb authenticates to the service it dials.
///
/// A DIAL always presents something: there is no "present nothing" arm to reach for, and none meaning
/// "not applicable" either. A verb that does not dial states no credential at all (it declares
/// [`BindRole::Serving`](crate::reaching::BindRole::Serving)), so not-applicable is the ABSENCE of this
/// value rather than one of its arms. An arm that means both is the hazard: read as not-applicable it is
/// harmless, and read as a deliberate stranger dial it sends a member to their own fleet carrying
/// nothing, so the two must not share a spelling. Deliberately NO `Default`/`#[default]`: the slip
/// override is the user's choice, not the author's omission. The badge to present AND the
/// [`Identity`](crate::identity::Identity) mode both derive from this one value.
#[derive(Debug, Clone)]
pub enum Credential {
    /// Reaches a FAMILY-GATED service: presents this device's stored member badge, bound to the dialing
    /// key, unless the peer was typed as a link, which then presents instead. A machine that is not a
    /// device has none to present. Derives
    /// [`Identity::PersistedIfPresent`](crate::identity::Identity::PersistedIfPresent), so the badge is
    /// bound to the same key the dial binds under.
    Family {
        /// The link the peer was typed as, if it was one; it overrides the default member badge. The
        /// ONLY surviving `Option` on this path, and an honest one (the user typed a link where the
        /// machine goes), not "the author forgot". A link is given only where the machine goes, never
        /// beside it, so the two can never disagree.
        present: Option<Link>,
    },
    /// An `anyone` link typed as the peer: presented alone, under a throwaway key. It admits whoever holds
    /// it, so no key of this home travels with it, and revoking this machine's key closes nothing it opens.
    /// Derives [`Identity::Ephemeral`](crate::identity::Identity::Ephemeral).
    Anyone(Link),
}

impl Credential {
    /// What a dial to `peer` for `service` presents: an `anyone` link typed as the peer presents alone
    /// ([`Anyone`](Self::Anyone)); any other peer presents as this home ([`Family`](Self::Family)), with a
    /// link peer as its slip.
    pub fn dialing(peer: &Peer, service: &str) -> Self {
        match peer.self_present() {
            Some(link) if admits_anyone(&link, service) => Self::Anyone(link),
            present => Self::Family { present },
        }
    }

    /// The identity a verb with this credential must bind under. This is the ONLY place the
    /// identity/badge coupling lives, so a `Family` credential is always `PersistedIfPresent`: its badge
    /// roots at the dialing key, so the dial MUST bind that same key wherever it exists.
    /// `serve` binds `Persisted` for a different reason (one stable address across runs) via a
    /// non-forgettable override, not this derivation.
    pub fn identity(&self) -> crate::identity::Identity {
        match self {
            Self::Family { .. } => crate::identity::Identity::PersistedIfPresent,
            Self::Anyone(_) => crate::identity::Identity::Ephemeral,
        }
    }

    /// The slip a dial with this credential hands a local resident to present, or `None` when it must
    /// never ride one. The resident reaches as this home, so a [`Family`](Self::Family) dial rides it,
    /// with the link typed as the machine as its slip, if one was; an [`Anyone`](Self::Anyone) link never
    /// does, since it dials under a throwaway key of its own so nothing of this home travels with it.
    pub fn through_resident(self) -> Option<Option<Link>> {
        match self {
            Self::Family { present } => Some(present),
            Self::Anyone(_) => None,
        }
    }
}

/// The one moment this process asks whether a link admits anyone. A run asks more than once (the key it
/// binds and the credential it presents are read apart), and a link that expired between two asks would
/// bind a throwaway key yet present this home's badge under it. Asked at one moment, every ask agrees.
static ASKED_AT: std::sync::LazyLock<std::time::SystemTime> =
    std::sync::LazyLock::new(std::time::SystemTime::now);

/// Whether `link` admits a dialer it was never bound to, for `service`: the `anyone` link. It is asked of a
/// key nobody holds, so a link bound to a device or to a root's devices reads as bound, and so does one
/// that cannot admit anyone at all (expired, or for another service), which then dials as this home. It is
/// asked at [`ASKED_AT`], so every ask in one run gets the same answer.
pub fn admits_anyone(link: &Link, service: &str) -> bool {
    admits_anyone_at(link, service, *ASKED_AT)
}

/// Whether `link` admits a dialer it was never bound to, for `service`, at `now`: [`admits_anyone`] for a
/// process that answers many requests over its life, each asked at its own moment.
pub fn admits_anyone_at(link: &Link, service: &str, now: std::time::SystemTime) -> bool {
    let (Ok(service), Ok(stranger)) = (service.parse::<Service>(), nauthy::Identity::generate())
    else {
        return false;
    };
    let mut request = Request::now(service).bound_to(stranger.verifying_key());
    request.now = now;
    link.cap()
        .verify_at_root_without_revocation(&request, link.root())
        .is_ok()
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use nauthy::Request;

    use super::{Credential, admits_anyone};
    use crate::testkit::TestNode;

    /// A family dial rides a resident, with its slip if it has one; an `anyone` link never does.
    #[test]
    fn only_a_family_dial_rides_the_resident() {
        let link = || {
            TestNode::seeded(2)
                .slip(
                    &"ssh".parse().expect("a service"),
                    Request::expires_in(Duration::from_secs(3600)),
                )
                .expect("mint a slip")
                .seal()
                .expect("seal")
                .link()
                .expect("a link")
        };
        assert!(matches!(
            Credential::Family { present: None }.through_resident(),
            Some(None)
        ));
        assert!(matches!(
            Credential::Family {
                present: Some(link())
            }
            .through_resident(),
            Some(Some(_))
        ));
        assert!(Credential::Anyone(link()).through_resident().is_none());
    }

    /// One run asks whether a link admits anyone more than once, and every ask agrees even when the link
    /// expires between them: otherwise the run binds a throwaway key for the first answer and presents this
    /// home's badge under it for the second.
    #[test]
    fn every_anyone_ask_in_a_run_agrees_across_expiry() {
        let link = TestNode::seeded(1)
            .slip(
                &"ssh".parse().expect("a service"),
                Request::expires_in(Duration::from_secs(2)),
            )
            .expect("mint an anyone slip")
            .seal()
            .expect("seal")
            .link()
            .expect("a link");
        assert!(admits_anyone(&link, "ssh"), "an anyone link admits anyone");
        std::thread::sleep(Duration::from_secs(3));
        assert!(
            admits_anyone(&link, "ssh"),
            "the second ask, after the link expired, gets the first ask's answer"
        );
    }
}
