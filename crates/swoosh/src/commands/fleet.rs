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

use bifrost::{Discovery, Node, Session, Transport};
use clap::Args;
use eyre::WrapErr as _;
use tightbeam::identity::AsVerifyKey as _;
use tokio::io::AsyncReadExt as _;

use crate::contacts::{self, Contacts, ContactsStore};
use crate::credential::SheerLink;
use crate::peer::Peer;
use crate::roster;
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
    #[arg(long, value_name = "peer")]
    pub pull: Peer,
    /// present a `sheer:` cap link to a cap-gated coordination node (a delegate's slip)
    #[arg(long, value_name = "link")]
    pub present: Option<SheerLink>,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl crate::reaching::Reaching for FleetCmd {
    fn reach_args(&self) -> &crate::transport::ReachArgs {
        &self.reach
    }

    /// `fleet --pull` reaches the coordination node's family-gated `roster:` service, so it presents the
    /// member badge rooted at the dialing key. `Family` fuses the identity to `PersistedIfPresent`. The
    /// effective slip is the FOLD of a self-addressing `sheer:` link in the `--pull` peer with an explicit
    /// `--present`, threaded INTO the credential so the ONE resolver owns both slots.
    fn credential(&self) -> crate::credential::Credential {
        crate::credential::Credential::Family {
            present: self.pull.self_present().or_else(|| self.present.clone()),
        }
    }

    fn reject_redundant_present(&self) -> eyre::Result<()> {
        self.pull.reject_redundant_present(self.present.as_ref())
    }

    fn identity(&self) -> crate::identity::Identity {
        self.credential().identity()
    }

    /// Uniform dispatch: unpack the reach context and run. `fleet` reads `contacts` (to resolve a petname in
    /// its `--pull` peer), the resolved `present` badge, and the `key` (it opens its OWN store to WRITE
    /// hydrated contacts, unlike the read-only `contacts`); it ignores `transport`.
    async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        ctx: crate::reaching::ReachCtx<'_>,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        self.run_fleet(node, ctx.contacts, ctx.present, ctx.membership, ctx.key)
            .await
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
        contacts: &Contacts,
        self_badge: Option<String>,
        membership: Option<String>,
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

        // Dial the GATED roster: service through the unified peer resolver (so a petname/link coordination
        // node resolves like every other verb), presenting our membership badge so the family gate admits us.
        // Slot 2 (membership) rides along for a signet-bound coordination node; a no-op on the plain member
        // dial. The redundant-present conflict was rejected in the composition root before this runs.
        let connector =
            self.pull
                .connector(contacts, "roster".to_owned(), self_badge, membership)?;
        let session = connector.open_service(node).await?;
        let (send, recv) = session
            .open_bi()
            .await
            .wrap_err("the coordination node refused the roster read")?;
        drop(send); // a roster is a read; we send nothing, so the handler's write half completes
        let mut bytes = Vec::new();
        recv.take(MAX_ROSTER_BLOB).read_to_end(&mut bytes).await?;

        // VERIFY against the signet, then parse the payload, as ONE seam. A forged or foreign roster is
        // refused here, before any contact is touched.
        let doc = roster::verify(&bytes, signet.verify_key()).map_err(|e| {
            eyre::eyre!("roster is not signed by your signet ({e}); refusing to hydrate")
        })?;

        // Fold the verified fleet into contacts (never clobbering a local petname you set), and persist.
        // hydrate REFUSES a stale/replayed snapshot (epoch at or below the persisted floor): a lagging or
        // hostile courier cannot roll the fleet back, so report the no-op honestly rather than claiming a
        // pull that did nothing.
        let mut store = ContactsStore::open(contacts::path(key)?).await?;
        let members = doc.members().len();
        let epoch = doc.epoch().0;
        if !store.contacts_mut().hydrate(&doc) {
            println!(
                "roster epoch {epoch} from {} is not newer than what you already have; nothing to update",
                self.pull
            );
            return Ok(());
        }
        store.save().await?;
        println!(
            "pulled {members} member(s) into your fleet from {}; reach one with `swoosh ssh me/<device>`",
            self.pull
        );
        Ok(())
    }
}
