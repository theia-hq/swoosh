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

use core::future::Future;
use std::path::Path;

use bifrost::{Discovery, Node, Session, Transport};

use crate::contacts::Contacts;
use crate::credential::{Credential, MemberBadge};
use crate::identity::{Identity, Secret};
use crate::{config, transport};

/// The uniform context every reaching verb runs against, so dispatch is ONE line (`self.run(node, ctx)`)
/// instead of a per-verb argument-threading match with a different signature per arm.
///
/// It carries what a reach-outward verb needs and no more: the [`contacts`](Self::contacts) to resolve a
/// petname, the bound [`transport`](Self::transport) label a verb reports and a failed dial names, the
/// ALREADY-RESOLVED [`present`](Self::present) badge (minted once by [`resolve`], so the verb never
/// re-derives it), and the [`key`](Self::key) path a verb that opens its own store needs. A verb ignores
/// the fields it does not use. `serve`'s `ExposeContext` is DELIBERATELY not here (Craftsman): it lives on
/// [`ServeCmd`](crate::commands::serve::ServeCmd), which reads its own, so this context stays uniform.
pub struct ReachCtx<'a> {
    /// The address book, to resolve a petname in a verb's peer slot.
    pub contacts: &'a Contacts,
    /// The bound transport label: a verb reports which backend carried the session, and a failed dial
    /// names the fix that backend needs.
    pub transport: transport::Transport,
    /// The membership badge to present, resolved ONCE in the composition root via [`resolve`] (a stored
    /// device badge, a signet-holder self-sign, or a `--present` slip). `None` for an `Anonymous` dial.
    pub present: Option<String>,
    /// The key path, for a verb that opens its OWN store (`fleet` writes contacts; a write, unlike the
    /// read-only `contacts` the reach verbs share).
    pub key: Option<&'a Path>,
}

/// A verb that reaches a peer over a transport, stating how it authenticates and how it runs.
///
/// The compiler forces every method on every reaching verb, so adding a verb that forgets its auth need
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

    /// The identity this verb binds under. REQUIRED with NO default body: a verb must state it, so a
    /// verb that needs a stable address (`serve`, `tunnel-connect`) cannot SILENTLY inherit
    /// [`Ephemeral`](Identity::Ephemeral) and come up as a broken node (a new address every run). The
    /// common reaching verbs write the one-liner `self.credential().identity()` (the derivation, so
    /// identity and badge cannot disagree); the two that need `Persisted` for a reason OTHER than
    /// family-rooting (a stable address / dialing under swoosh's own key) declare it EXPLICITLY here.
    /// This is the Adversary's non-forgettable override: `Persisted` is a written declaration, never a
    /// silent default.
    fn identity(&self) -> Identity;

    /// Run this verb against the composed node under the uniform [`ReachCtx`]. Every verb takes the same
    /// context, so the composition root dispatches with ONE line (`cmd.run(node, ctx)`), not a per-verb
    /// argument-threading match. A verb reads the ctx fields it needs and ignores the rest. The `Send`
    /// bounds on the session halves are stated once here (structured concurrency across `.await`s).
    ///
    /// Written as a returned `impl Future` (RPITIT), not `async fn`, matching the `Handler` trait: an
    /// `async fn` in a trait cannot state its auto-trait bounds and draws the `async_fn_in_trait` lint;
    /// the impls stay plain `async fn`, which coerces to this on the pinned toolchain.
    fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        ctx: ReachCtx<'_>,
    ) -> impl Future<Output = eyre::Result<()>>
    where
        Self: Sized,
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::SheerLink;

    /// An `Anonymous` credential (e.g. `forward`) resolves to NO badge: a deliberate stranger dial.
    #[tokio::test]
    async fn anonymous_presents_no_badge() {
        let secret = Secret::ephemeral();
        let resolved = resolve(Credential::Anonymous, &secret, None)
            .await
            .expect("anonymous resolves");
        assert!(
            resolved.into_present().is_none(),
            "an Anonymous dial presents no badge"
        );
    }

    /// A `Family` credential with no `--present` slip and no stored badge falls back to the signet
    /// holder's self-sign, so it ALWAYS resolves to a badge, never `None`. This is the fleet/fetch fix
    /// at the resolver: a family verb (the diagnostic verbs, `beam`, `stop`, `fleet`, and now `fetch`)
    /// cannot reach a gated service carrying no badge, because `Family` has no arm that yields nothing.
    #[tokio::test]
    async fn family_without_slip_self_signs_a_badge() {
        let secret = Secret::ephemeral();
        let resolved = resolve(Credential::Family { present: None }, &secret, None)
            .await
            .expect("family resolves");
        let link = resolved
            .into_present()
            .expect("a family dial always presents a badge (self-sign fallback)");
        assert!(
            link.starts_with("sheer:"),
            "the presented badge is a sheer: capability link, got {link}"
        );
    }

    /// A `Family` credential WITH a `--present` slip presents that slip verbatim: the delegate override
    /// wins over the self-badge, the ONE place that rule now lives.
    #[tokio::test]
    async fn family_with_slip_presents_the_slip() {
        let secret = Secret::ephemeral();
        // A real, parseable `sheer:` link to stand in for a delegate's slip: mint one off a throwaway key.
        let slip_text = Secret::ephemeral()
            .member_badge()
            .expect("mint a stand-in slip");
        let slip: SheerLink = slip_text
            .parse()
            .expect("the minted link is a valid SheerLink");
        let resolved = resolve(
            Credential::Family {
                present: Some(slip),
            },
            &secret,
            None,
        )
        .await
        .expect("family-with-slip resolves");
        assert_eq!(
            resolved.into_present().as_deref(),
            Some(slip_text.as_str()),
            "an explicit --present slip overrides the self-badge"
        );
    }
}
