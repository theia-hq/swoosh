//! `swoosh fleet --pull <coord>`: learn your fleet from a coordination node.
//!
//! The client side of roster-sync. A fresh device that has adopted its signet dials a coordination node
//! (any member of the fleet serving `roster:`), reads the signet-signed membership snapshot, VERIFIES it
//! against the signet it trusts, and folds the members into its contacts as `me/<device>` entries. After
//! this, `swoosh ssh me/<device>` reaches any fleet member by key, with nothing copied by hand.
//!
//! The verification is the whole security seam: a roster NOT signed by your signet (a forged blob, or one
//! from a foreign key) is refused HERE, before any contact is written. The bare `swoosh fleet` READ (list
//! the fleet you already know) is not built yet: today the verb only pulls, which is what populates the
//! contacts that read will one day list.

use bifrost::{Discovery, Node, Session, Transport};
use clap::Args;
use eyre::WrapErr as _;
use nauthy::{Link, Service};
use swoosh::contacts::{Contacts, ContactsStore, Hydrated};
use swoosh::home::Home;
use swoosh::peer::Peer;
use swoosh::roster;
use swoosh::transport::ReachArgs;
use tightbeam::identity::AsVerifyKey as _;
use tokio::io::AsyncReadExt as _;

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
    /// present a `sheer:` capability link to reach a gated coordination node
    #[arg(
        long,
        value_name = "link",
        long_help = "Optional: your own devices need no link; this machine's membership badge is \
                     presented automatically. Pass a `sheer:` link only to reach as a delegate."
    )]
    pub present: Option<Link>,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl swoosh::reaching::Reaching for FleetCmd {
    fn reach_args(&self) -> &swoosh::transport::ReachArgs {
        &self.reach
    }

    fn reject_redundant_present(&self) -> eyre::Result<()> {
        self.pull.reject_redundant_present(self.present.as_ref())
    }

    fn identity(&self) -> swoosh::identity::Identity {
        self.bind_role().identity()
    }

    /// Dialing, and what it dials as. It reaches a peer and never accepts connections under the
    /// home key, so its bind must not write the key's address record (0.9.0 F1).
    ///
    /// `fleet --pull` reaches the coordination node's family-gated `roster:` service, so it presents the
    /// member badge rooted at the dialing key. `Family` fuses the identity to `PersistedIfPresent`. The
    /// effective slip is the FOLD of a self-addressing `sheer:` link in the `--pull` peer with an explicit
    /// `--present`, threaded INTO the credential so the ONE resolver owns both slots.
    fn bind_role(&self) -> swoosh::reaching::BindRole {
        swoosh::reaching::BindRole::Dialing(swoosh::credential::Credential::Family {
            present: self.pull.self_present().or_else(|| self.present.clone()),
        })
    }

    /// Uniform dispatch: unpack the reach context and run. `fleet` reads `contacts` (to resolve a petname in
    /// its `--pull` peer), the resolved `present` badge, and the `home` (it opens its OWN store to WRITE
    /// hydrated contacts, unlike the read-only `contacts`); it ignores `transport`.
    async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        ctx: swoosh::reaching::ReachCtx<'_>,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        self.run_fleet(node, ctx.contacts, ctx.present, ctx.membership, ctx.home)
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
        self_badge: Option<Link>,
        membership: Option<Link>,
        home: &Home,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        // The signet we verify against: the key our own gate trusts, written by `adopt`.
        let signet = swoosh::config::load_signet(home).await?.ok_or_else(|| {
            eyre::eyre!("this node has no signet; run `swoosh adopt <invite>` first")
        })?;

        // Dial the GATED roster: service through the unified peer resolver (so a petname/link coordination
        // node resolves like every other verb), presenting our membership badge so the family gate admits us.
        // Slot 2 (membership) rides along for a signet-bound coordination node; a no-op on the plain member
        // dial. The redundant-present conflict was rejected in the composition root before this runs.
        let connector = self.pull.connector(
            contacts,
            "roster".parse::<Service>()?,
            self_badge,
            membership,
        )?;
        let session = connector.open_service(node).await?;
        let (send, recv) = session
            .open_bi()
            .await
            .wrap_err("the coordination node refused the roster read")?;
        drop(send); // a roster is a read; we send nothing, so the handler's write half completes
        let mut bytes = Vec::new();
        recv.take(MAX_ROSTER_BLOB).read_to_end(&mut bytes).await?;

        // VERIFY against the signet, then parse the payload, as ONE seam. A forged or foreign roster is
        // refused here, before any contact is touched. The EMPTY case is split out: a node that has cut
        // nothing is not a node forging rosters, and sending an operator hunting a key problem that does
        // not exist is the same class of lie as reporting a pull that taught nothing.
        let doc = roster::verify(&bytes, signet.verify_key()).map_err(|error| match error {
            roster::RosterVerifyError::Empty => eyre::eyre!(
                "{} has not cut a roster yet. Run `swoosh invite add <label>` on the machine holding \
                 your signet; that is what publishes one",
                self.pull
            ),
            other => {
                eyre::eyre!("roster is not signed by your signet ({other}); refusing to hydrate")
            }
        })?;

        // Fold the verified fleet into contacts (never clobbering a local petname you set), and persist.
        // Every arm below reports what actually happened: a refused fold writes nothing and says so, and
        // an applied one names what it BOUND and what the snapshot-replace REMOVED. Claiming a pull that
        // taught nothing, or one that silently deleted devices, is the surface lying about its own work.
        let mut store = ContactsStore::open(home.contacts()).await?;
        let epoch = doc.epoch().0;
        let applied = match store.contacts_mut().hydrate(&doc) {
            Hydrated::Unversioned => {
                // Nothing this end can do: the fix is on the machine that cut it. Say which machine and
                // which act, rather than leaving an operator to re-pull forever.
                eyre::bail!(
                    "the roster {} served carries no version, so it predates roster versioning and \
                     cannot be applied safely. Upgrade swoosh on the machine holding your signet; its \
                     next `invite add` (or `contact rm me/<device>`) publishes a versioned roster",
                    self.pull
                );
            }
            Hydrated::NotNewer { floor } => {
                println!(
                    "nothing to pull: the roster {} served is at epoch {epoch}, and you already have \
                     epoch {}",
                    self.pull, floor.0
                );
                return Ok(());
            }
            Hydrated::Applied(applied) => applied,
        };
        store.save().await?;
        // The DESTRUCTIVE half, named first because it is the surprising one: a roster is a whole
        // snapshot, so a member the owner removed disappears here. Silently dropping devices under the
        // word "pulled" is the report this line exists to prevent.
        if !applied.removed().is_empty() {
            let labels: Vec<&str> = applied
                .removed()
                .iter()
                .map(swoosh::contacts::DeviceLabel::as_str)
                .collect();
            println!(
                "removed {} device(s) your fleet no longer lists: {}",
                applied.removed().len(),
                labels.join(", ")
            );
        }
        if applied.skipped() > 0 {
            println!(
                "kept your own binding for {} member(s) (a name you set wins over the roster)",
                applied.skipped()
            );
        }
        match applied.bound() {
            // A pull that bound nothing must not name a next step that cannot work: there is no
            // `me/<device>` to reach.
            0 => println!("pulled nothing new from {}", self.pull),
            bound => println!(
                "pulled {bound} member(s) into your fleet from {}; reach one with \
                 `swoosh ssh me/<device>`",
                self.pull
            ),
        }
        Ok(())
    }
}
