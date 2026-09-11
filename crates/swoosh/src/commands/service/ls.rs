//! `swoosh service ls [--at <peer>]`: read the served menu.
//!
//! Bare (`service ls`) reads YOUR OWN running node's menu over the resident daemon's control socket: the
//! served catalog plus the LIVE disabled list, rendered as a `SERVICE  GATE  STATE` table. With no
//! resident it teaches (`swoosh serve --resident`) and exits non-zero rather than pretending to read a
//! node that is not there. `service ls --at <peer>` reads a PEER's node: it
//! reaches the peer's gated `control.services` and prints a terse `SERVICE  GATE` table (each service name and
//! whether reaching it needs a member badge, or is open to anyone). A pure READ, the client twin of the node's
//! `control.services` handler.
//!
//! `control.services` is family-gated like `ping`/`speed`/`stop`, so `service ls` presents the same self-signed
//! membership badge (or an explicit `--present` link) to prove membership before the peer admits the read. A
//! stranger is refused LOUDLY here (a typed error, non-zero exit), never a silent empty table: a refusal is not
//! "the peer serves nothing".

use bifrost::{Discovery, Node, Session as _, Transport};
use clap::Args;
use tightbeam::tunnel;
use tokio::io::AsyncReadExt as _;

use crate::commands::serve::CONTROL_SERVICES_SERVICE;
use crate::commands::serve::control_codec::DisabledList;
use crate::contacts::Contacts;
use crate::home::Home;
use crate::node_client::{ControlClient, NodeClient as _, control_error_report};
use crate::peer::Peer;
use crate::transport::ReachArgs;

/// List the served menu (bare: your own node; `--at <peer>`: a peer)
#[derive(Debug, Args)]
pub struct ServiceLsCmd {
    /// the peer to reach: a petname (`alice`, `alice/desk`), a raw node id, or a `sheer:` link
    #[arg(long, value_name = "peer")]
    pub at: Option<Peer>,
    /// present a `sheer:` cap link to a cap-gated peer (a delegate's slip)
    #[arg(
        long,
        value_name = "link",
        long_help = "Optional: your own devices need no link, the dial presents the self-signed \
                     membership badge under this identity. Pass a `sheer:` slip only to reach as a delegate."
    )]
    pub present: Option<crate::credential::SheerLink>,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl crate::reaching::Reaching for ServiceLsCmd {
    fn reach_args(&self) -> &crate::transport::ReachArgs {
        &self.reach
    }

    /// `service ls` reaches the peer's family-gated `control.services` read, so it presents the member badge
    /// rooted at the dialing key (only a family member may read the menu). `Family` fuses the identity to
    /// `PersistedIfPresent`, like `stop`/`status`. The effective slip is the FOLD of a self-addressing
    /// `sheer:` link in the `--at` peer with an explicit `--present`, threaded INTO the credential so the
    /// ONE resolver owns both slots.
    fn credential(&self) -> crate::credential::Credential {
        crate::credential::Credential::Family {
            present: self
                .at
                .as_ref()
                .and_then(Peer::self_present)
                .or_else(|| self.present.clone()),
        }
    }

    fn reject_redundant_present(&self) -> eyre::Result<()> {
        match &self.at {
            Some(peer) => peer.reject_redundant_present(self.present.as_ref()),
            None => Ok(()),
        }
    }

    fn identity(&self) -> crate::identity::Identity {
        self.credential().identity()
    }

    /// Uniform dispatch: `service ls` reads the resolved `present` badge and `contacts` (to resolve a petname
    /// like `me/qat` in its `--at` slot); it ignores `transport` and `key`. Only reached WITH `--at`: a bare
    /// `service ls` splits to [`run_local`](Self::run_local) before any transport is composed, so `at` is
    /// always `Some` here.
    async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        ctx: crate::reaching::ReachCtx<'_>,
    ) -> eyre::Result<()>
    where
        <T::Session as bifrost::Session>::Write: Send + 'static,
        <T::Session as bifrost::Session>::Read: Send + 'static,
    {
        self.run_read(node, ctx.contacts, ctx.present, ctx.membership)
            .await
    }
}

impl ServiceLsCmd {
    /// The bare (no-`--at`) path: read YOUR OWN node's live menu over the local control socket.
    /// Runs BEFORE any transport is composed (dispatched locally in the root), so a bare
    /// `swoosh service ls` never binds an endpoint it would not use. With no addressable resident
    /// the client resolution teaches the fix (`swoosh serve --resident`) and exits non-zero rather
    /// than printing an empty table that reads as "this node serves nothing".
    pub async fn run_local(self, home: &Home) -> eyre::Result<()> {
        // A bare `service ls` reaches no peer, so an explicit `--present` has nothing to select: refuse
        // it rather than silently dropping it (I.3), before touching the socket.
        crate::reaching::reject_bare_present(self.present.as_ref())?;
        let client = ControlClient::resolve(home).map_err(control_error_report)?;
        let menu = client.services().await.map_err(control_error_report)?;
        // The disabled-list diagnostic goes to stderr, BEFORE the clean stdout table (I.5): the `?`
        // cells stay on stdout, the reason explaining them rides the diagnostic stream.
        if let Some(warning) = disabled_warning(&menu.disabled) {
            eprint!("{warning}");
        }
        print!("{}", render_catalog(&menu.catalog, Some(&menu.disabled)));
        Ok(())
    }

    /// Reach the peer's gated `control.services` read and print its `SERVICE  GATE` table. Presents the
    /// resolved `present` (the self-signed membership badge, or an explicit `--present` link) so the peer's
    /// family gate admits the read; a peer that does not admit this caller refuses LOUDLY here, never a
    /// silent empty table. `--at` is required to reach this path (a bare `service ls` split to
    /// [`run_local`](Self::run_local)), so a missing target is a root-dispatch bug, surfaced as an internal
    /// error rather than a user one.
    async fn run_read<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        contacts: &Contacts,
        present: Option<String>,
        membership: Option<String>,
    ) -> eyre::Result<()> {
        let Some(peer) = self.at else {
            eyre::bail!(
                "internal: `service ls` reached the reach path without `--at` (root-dispatch bug)"
            );
        };

        // Slots 1 and 2 are ALREADY resolved by the composition root's ONE resolver (present-or-badge in
        // slot 1, a fleet badge in slot 2 only for a signet-bound slip); the fold in `credential()` routed a
        // link-as-peer through that same resolver, and the redundant-present conflict was rejected there too
        // (`Reaching::reject_redundant_present`), so the verb never threads `--present` itself.
        let connector = peer.connector(
            contacts,
            CONTROL_SERVICES_SERVICE.to_owned(),
            present,
            membership,
        )?;
        let dial = connector.dial();

        // A service-scoped session whose one `open_bi` speaks the `control.services` request and presents the
        // badge. On admission the peer writes the self-delimiting catalog blob and closes; a refusal surfaces
        // as the typed `bifrost::Error::Refused` here, rendered as the SAME teaching line the ping/status
        // ladder gives rather than the bare transport word. A refusal is not "the peer serves nothing"; a
        // genuine i/o failure keeps its own message.
        let session = connector.open_service(node).await?;
        let (writer, mut reader) = match session.open_bi().await {
            Ok(halves) => halves,
            Err(bifrost::Error::Refused(refusal)) => {
                eyre::bail!("{dial}: reached, but refused ({refusal})")
            }
            Err(error) => eyre::bail!("could not read services from {dial}: {error}"),
        };
        // The read sends nothing; drop the write half so the peer's handler write completes (the same shape
        // the roster read uses).
        drop(writer);

        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).await?;
        let catalog = tunnel::ServiceCatalog::decode(&bytes)?;

        print_catalog(&catalog);
        Ok(())
    }
}

/// Print the catalog as a terse `SERVICE  GATE` table (the remote `--at` read's shape): header then
/// one row per service (name-sorted by the catalog). An empty catalog prints just the header, so "the
/// peer serves nothing" reads as an empty table rather than no output.
fn print_catalog(catalog: &tunnel::ServiceCatalog) {
    print!("{}", render_catalog(catalog, None));
}

/// The disabled-list diagnostic for the self read, emitted on stderr beside [`render_catalog`]: an
/// explicit unknown list cannot honestly say `on` for any entry, so every state renders `?`, and this
/// line names the reason. A service the gate may refuse must never read as enabled, and I.5 keeps the
/// stdout table the clean result. `None` for a known list (nothing to warn about) or no list at all
/// (the peer read).
pub(crate) fn disabled_warning(disabled: &DisabledList) -> Option<String> {
    match disabled {
        DisabledList::Unknown(reason) => Some(format!(
            "warning: the disabled list could not be read ({reason}); states unknown\n"
        )),
        DisabledList::Known(_) => None,
    }
}

/// Render the menu table: `SERVICE  GATE` always, plus a `STATE` column when the caller holds the
/// live disabled list (the self read). A listed name renders `off`, everything else `on`. An
/// explicit unknown disabled list renders `?` for every state and names no reason here: the
/// diagnostic rides [`disabled_warning`] on stderr, so the stdout table stays the clean result.
/// Widths each column to its widest cell (min the header width) so the columns line up.
pub(crate) fn render_catalog(
    catalog: &tunnel::ServiceCatalog,
    disabled: Option<&DisabledList>,
) -> String {
    let service_width = catalog
        .entries()
        .map(|entry| entry.name.len())
        .chain([HEADER_SERVICE.len()])
        .max()
        .unwrap_or(HEADER_SERVICE.len());
    let gate_width = catalog
        .entries()
        .map(|entry| entry.posture.label().len())
        .chain([HEADER_GATE.len()])
        .max()
        .unwrap_or(HEADER_GATE.len());
    let mut out = String::new();
    if disabled.is_some() {
        out.push_str(&format!(
            "{HEADER_SERVICE:<service_width$}  {HEADER_GATE:<gate_width$}  {HEADER_STATE}\n"
        ));
    } else {
        out.push_str(&format!(
            "{HEADER_SERVICE:<service_width$}  {HEADER_GATE}\n"
        ));
    }
    for entry in catalog.entries() {
        let state = match disabled {
            None => None,
            Some(DisabledList::Known(names)) => {
                let off = names.iter().any(|name| name == &entry.name);
                Some(if off { STATE_OFF } else { STATE_ON })
            }
            Some(DisabledList::Unknown(_)) => Some(STATE_UNKNOWN),
        };
        let gate = entry.posture.label();
        match state {
            Some(state) => out.push_str(&format!(
                "{:<service_width$}  {gate:<gate_width$}  {state}\n",
                entry.name
            )),
            None => out.push_str(&format!("{:<service_width$}  {gate}\n", entry.name)),
        }
    }
    out
}

/// The `SERVICE` column header.
const HEADER_SERVICE: &str = "SERVICE";
/// The `GATE` column header.
const HEADER_GATE: &str = "GATE";
/// The `STATE` column header the self read adds.
const HEADER_STATE: &str = "STATE";
/// The live-state word for an enabled service.
const STATE_ON: &str = "on";
/// The live-state word for a disabled service.
const STATE_OFF: &str = "off";
/// The live-state word when the disabled list could not be read: the gate may still refuse, so the
/// state is honestly unknown rather than a false `on`.
const STATE_UNKNOWN: &str = "?";

#[cfg(test)]
#[path = "ls_tests.rs"]
mod ls_tests;
