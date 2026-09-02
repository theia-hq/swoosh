//! The one thing every reaching verb must state: how it authenticates.
//!
//! A reaching verb's auth need used to be spread across five hand-synced match arms in `main.rs`, one of
//! which (`self_badge()`) ended in a `_ => Ok(None)` wildcard: a verb the author forgot to list reached a
//! family-gated service carrying no badge, and it still compiled. The [`Reaching`] trait replaces that
//! with a method the compiler forces: a verb cannot compile without stating its [`Credential`], and
//! `Credential` has no "unset" arm to fall through to, so the fleet/fetch badge-omission bug is now a
//! COMPILE error, not a runtime refusal against a real node.
//!
//! [`resolve`] is the ONE home of the `--present`-overrides-self-badge rule that used to be copy-pasted
//! into six verbs: it turns a declared [`Credential`] into the concrete badge to present, once, in the
//! composition root.

use std::path::Path;

use crate::credential::{Credential, MemberBadge};
use crate::identity::Secret;
use crate::{config, transport};

/// A verb that reaches a peer over a transport, stating how it authenticates.
///
/// The compiler forces both methods on every reaching verb, so adding a verb that forgets its auth need
/// does not compile (the fleet/fetch bug class). [`credential`](Self::credential) is TOTAL: it returns a
/// [`Credential`], an enum with no "unset" arm, so "forgot to say" is unrepresentable. The identity mode
/// derives from the credential ([`Credential::identity`]), so identity and badge can never disagree.
pub trait Reaching {
    /// The reach-family flags this verb carries (`--transport`, `--peer`). One accessor, not a match arm.
    fn reach_args(&self) -> &transport::ReachArgs;

    /// How this verb authenticates to the service it dials. Required and self-contained: a new verb
    /// cannot compile without returning a [`Credential`], and there is no `None`/default to fall through
    /// to, so a verb that reaches a family-gated service without a badge is unrepresentable.
    fn credential(&self) -> Credential;
}

/// The concrete badge a resolved [`Credential`] presents on the wire: a member badge, or nothing.
///
/// A named result rather than a bare `Option<String>` so a caller reads intent, not a nullable string:
/// [`None`](Self::None) is a deliberate stranger dial, [`Badge`](Self::Badge) a proven membership badge.
pub enum Resolved {
    /// Present no badge: an [`Anonymous`](Credential::Anonymous) dial (ungated service, or the verb
    /// presents its own link).
    None,
    /// Present this membership badge to the peer's family gate.
    Badge(MemberBadge),
}

impl Resolved {
    /// The badge link to hand a [`Connector`](tightbeam::tunnel::Connector), which takes `Option<String>`.
    /// The one place the resolved credential becomes the wire's nullable link.
    pub fn into_present(self) -> Option<String> {
        match self {
            Self::None => None,
            Self::Badge(badge) => Some(badge.into_link()),
        }
    }
}

/// Resolve a declared [`Credential`] into the concrete badge to present, ONCE, in the composition root.
///
/// The single home of the `--present`-overrides-self-badge rule copy-pasted into six verbs today:
///
/// - [`Anonymous`](Credential::Anonymous) presents nothing (a deliberate stranger dial).
/// - [`Family`](Credential::Family) presents the member badge rooted at the dialing key. A delegate's
///   explicit `--present` slip wins; else the STORED signet-signed device badge; else the signet
///   holder's own self-sign (person-zero: it IS the root, so its self-sign admits). A fresh install with
///   neither badge nor signet self-signs an ephemeral badge that the peer's gate correctly refuses.
pub async fn resolve(
    cred: Credential,
    secret: &Secret,
    key: Option<&Path>,
) -> eyre::Result<Resolved> {
    match cred {
        Credential::Anonymous => Ok(Resolved::None),
        Credential::Family { present } => {
            // A delegate's explicit `--present` slip overrides the self-badge; otherwise mint/load the
            // member badge rooted at the dialing key.
            let badge = match present {
                Some(link) => MemberBadge::new(link.into_link()),
                None => match config::load_badge(key).await? {
                    Some(stored) => MemberBadge::new(stored),
                    None => MemberBadge::new(secret.member_badge()?),
                },
            };
            Ok(Resolved::Badge(badge))
        }
    }
}
