//! `swoosh fleet --pull <coord>`: learn your fleet from a coordination node.
//!
//! The client side of B1 roster-sync. A fresh device that has adopted its signet dials a coordination node
//! (any member of the fleet serving `roster:`), reads the signet-signed membership snapshot, VERIFIES it
//! against the signet it trusts, and folds the members into its contacts as `me/<device>` entries. After
//! this, `swoosh ssh me/<device>` reaches any fleet member by key, with nothing copied by hand.
//!
//! The verification is the whole security seam: a roster NOT signed by your signet (a forged blob, or one
//! from a foreign key) is refused HERE, before any contact is written. The bare `swoosh fleet` READ (list
//! the fleet you already know) is a later, offline slice (delib-30 B2); B1 ships the `--pull` that populates
//! it.

use std::path::Path;

use bifrost::{Discovery, Node, NodeId, Session, Transport};
use clap::Args;
use eyre::WrapErr as _;
use nauthy::SignedRoster;
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::tunnel::Connector;
use tokio::io::AsyncReadExt as _;

use crate::contacts::{self, ContactsStore};
use crate::transport::ReachArgs;

/// The maximum roster blob a pull reads before refusing. A personal fleet's signed snapshot is far smaller;
/// the bound stops a hostile coordination node from making the puller allocate unboundedly before the
/// signature is even checked.
const MAX_ROSTER_BLOB: u64 = 1 << 20;

/// Learn your fleet from a coordination node: pull, verify, and fold its members into your contacts.
#[derive(Debug, Args)]
pub struct FleetCmd {
    /// pull the fleet roster from this coordination node (a member serving `roster:`), verify it against
    /// your signet, and fold its members into your contacts as `me/<device>` entries
    #[arg(long, value_name = "coord-node")]
    pub pull: NodeId,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl crate::reaching::Reaching for FleetCmd {
    fn reach_args(&self) -> &crate::transport::ReachArgs {
        &self.reach
    }

    /// `fleet --pull` reaches the coordination node's family-gated `roster:` service, so it presents the
    /// member badge rooted at the dialing key. `Family` fuses the identity to `PersistedIfPresent`.
    fn credential(&self) -> crate::credential::Credential {
        crate::credential::Credential::Family { present: None }
    }

    fn identity(&self) -> crate::identity::Identity {
        self.credential().identity()
    }

    /// Uniform dispatch: unpack the reach context and run. `fleet` reads the resolved `present` badge and
    /// the `key` (it opens its OWN store to WRITE hydrated contacts, unlike the read-only `contacts`); it
    /// ignores `contacts` and `transport`.
    async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        ctx: crate::reaching::ReachCtx<'_>,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        self.run_fleet(node, ctx.present, ctx.key).await
    }
}

impl FleetCmd {
    /// Dial the coordination node's gated `roster:` service presenting this device's membership badge, read
    /// the signed blob, verify it against the adopted signet, and hydrate contacts. Refuses loudly if the
    /// node has no signet (adopt first), if the coordination node refuses the read, or if the roster is not
    /// signed by our signet.
    async fn run_fleet<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        self_badge: Option<String>,
        key: Option<&Path>,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        // The signet we verify against: the key our own gate trusts, written by `adopt`.
        let signet = crate::config::load_signet(key).await?.ok_or_else(|| {
            eyre::eyre!("this node has no signet; run `swoosh adopt <authkey>` first")
        })?;

        // Dial the GATED roster: service, presenting our membership badge so the family gate admits us.
        let session = Connector::to_node(self.pull, "roster".to_owned(), self_badge)
            .open_service(node)
            .await?;
        let (send, recv) = session
            .open_bi()
            .await
            .wrap_err("the coordination node refused the roster read")?;
        drop(send); // a roster is a read; we send nothing, so the handler's write half completes
        let mut bytes = Vec::new();
        recv.take(MAX_ROSTER_BLOB).read_to_end(&mut bytes).await?;

        // Parse, then VERIFY against the signet. A forged or foreign roster is refused here, before any
        // contact is touched.
        let signed = SignedRoster::decode(&bytes)?;
        let doc = signed.verify(signet.verify_key()).map_err(|e| {
            eyre::eyre!("roster is not signed by your signet ({e}); refusing to hydrate")
        })?;

        // Fold the verified fleet into contacts (never clobbering a local petname you set), and persist.
        let mut store = ContactsStore::open(contacts::path(key)?).await?;
        store.contacts_mut().hydrate(doc);
        store.save().await?;
        println!(
            "pulled {} member(s) into your fleet from {}; reach one with `swoosh ssh me/<device>`",
            doc.members().len(),
            self.pull.short()
        );
        Ok(())
    }
}
