//! `swoosh service --at <peer>`: read a peer's served services.
//!
//! Reaches a peer's gated `control.services` and prints a terse `SERVICE  GATE` table of what the peer
//! serves: each service name and whether reaching it needs a member badge (gated) or is open to anyone. A
//! pure READ, the client twin of the node's `control.services` handler.
//!
//! `control.services` is family-gated like `ping`/`speed`/`stop`, so `service` presents the same self-signed
//! membership badge (or an explicit `--present` link) to prove membership before the peer admits the read. A
//! stranger is refused LOUDLY here (a typed error, non-zero exit), never a silent empty table: a refusal is
//! not "the peer serves nothing".
//!
//! There is no LOCAL form (no `--at`): reading YOUR OWN running node's services needs a daemon to query the
//! live node, which swoosh has no persistent process for yet. So `--at` is required in spirit; a bare `swoosh
//! service` prints a clean "needs the daemon" message and exits non-zero rather than pretending to read a
//! node that is not there. On/off (turning a service on or off) is deferred with the daemon too.

use bifrost::{Discovery, Node, Session as _, Transport};
use clap::Args;
use tightbeam::tunnel::ServiceCatalog;
use tokio::io::AsyncReadExt as _;

use crate::commands::serve::CONTROL_SERVICES_SERVICE;
use crate::contacts::Contacts;
use crate::peer::Peer;
use crate::transport::ReachArgs;

/// Read a peer's served services: reach its `control.services` and print a `SERVICE  GATE` table.
#[derive(Debug, Args)]
pub struct ServiceCmd {
    /// the peer to read: a petname (`me/qat`, `alice`), a raw node id, or a `sheer:` link.
    /// Omit it and `service` reports that reading your own node needs the daemon (not built yet).
    #[arg(long, value_name = "peer")]
    pub at: Option<Peer>,
    /// present a `sheer:` capability link alongside a raw node id (parsed at the boundary via
    /// [`SheerLink`](crate::credential::SheerLink)'s `FromStr`)
    #[arg(long, value_name = "link")]
    pub present: Option<crate::credential::SheerLink>,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl crate::reaching::Reaching for ServiceCmd {
    fn reach_args(&self) -> &crate::transport::ReachArgs {
        &self.reach
    }

    /// `service` reaches the peer's family-gated `control.services` read, so it presents the member badge
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

    /// Uniform dispatch: `service` reads the resolved `present` badge and `contacts` (to resolve a petname
    /// like `me/qat` in its `--at` slot); it ignores `transport` and `key`. Only reached WITH `--at`: a bare
    /// `service` splits to [`run_local`](Self::run_local) before any transport is composed, so `at` is always
    /// `Some` here.
    async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        ctx: crate::reaching::ReachCtx<'_>,
    ) -> eyre::Result<()>
    where
        <T::Session as bifrost::Session>::Write: Send + 'static,
        <T::Session as bifrost::Session>::Read: Send + 'static,
    {
        self.run_service(node, ctx.contacts, ctx.present, ctx.membership)
            .await
    }
}

impl ServiceCmd {
    /// The no-`--at` path: reading YOUR OWN node's services needs a daemon to query the live node, which
    /// swoosh has no persistent process for yet. Report that and exit non-zero rather than printing an empty
    /// table that reads as "this node serves nothing". Runs BEFORE any transport is composed (dispatched
    /// locally in the root), so a bare `swoosh service` never binds an endpoint it would not use.
    pub fn run_local(self) -> eyre::Result<()> {
        eyre::bail!(
            "reading your own node's services needs the daemon (not built yet); \
             read a peer's with `swoosh service --at <peer>`"
        )
    }

    /// Reach the peer's gated `control.services` read and print its `SERVICE  GATE` table. Presents the
    /// resolved `present` (the self-signed membership badge, or an explicit `--present` link) so the peer's
    /// family gate admits the read; a peer that does not admit this caller refuses LOUDLY here, never a
    /// silent empty table. `--at` is required to reach this path (a bare `service` split to
    /// [`run_local`](Self::run_local)), so a missing target is a root-dispatch bug, surfaced as an internal
    /// error rather than a user one.
    async fn run_service<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        contacts: &Contacts,
        present: Option<String>,
        membership: Option<String>,
    ) -> eyre::Result<()> {
        let Some(peer) = self.at else {
            eyre::bail!(
                "internal: `service` reached the reach path without `--at` (root-dispatch bug)"
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
        // badge. On admission the peer writes the self-delimiting catalog blob and closes; a refusal maps to a
        // loud stream error here (a refusal is a typed loud error, never a silent empty read).
        let session = connector.open_service(node).await?;
        let (writer, mut reader) = session
            .open_bi()
            .await
            .map_err(|error| eyre::eyre!("could not read services from {dial}: {error}"))?;
        // The read sends nothing; drop the write half so the peer's handler write completes (the same shape
        // the roster read uses).
        drop(writer);

        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).await?;
        let catalog = ServiceCatalog::decode(&bytes)?;

        print_catalog(&catalog);
        node.close().await;
        Ok(())
    }
}

/// Print the catalog as a terse `SERVICE  GATE` table, header then one row per service (name-sorted by the
/// catalog). An empty catalog prints just the header, so "the peer serves nothing" reads as an empty table
/// rather than no output.
fn print_catalog(catalog: &ServiceCatalog) {
    // Width the SERVICE column to the widest name (min the header width), so the GATE column lines up.
    let width = catalog
        .entries()
        .map(|entry| entry.name.len())
        .chain([HEADER_SERVICE.len()])
        .max()
        .unwrap_or(HEADER_SERVICE.len());
    println!("{HEADER_SERVICE:<width$}  {HEADER_GATE}");
    for entry in catalog.entries() {
        println!("{:<width$}  {}", entry.name, entry.posture.label());
    }
}

/// The `SERVICE` column header.
const HEADER_SERVICE: &str = "SERVICE";
/// The `GATE` column header.
const HEADER_GATE: &str = "GATE";
