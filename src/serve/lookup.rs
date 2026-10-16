use core::time::Duration;
use std::collections::HashSet;
use std::io;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::SystemTime;

use nauthy::{FileStamp, Link, VerifyKey};
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::open_policy::ProvenOnly;
use tightbeam::tunnel::{BoxRead, BoxWrite, Handler, ServeError, Served};
use tokio::io::{AsyncWrite, AsyncWriteExt as _};

use crate::contacts::{Contacts, ContactsStore};
use crate::home::Home;
use crate::standing::Standing;

/// How often [`Devices::watch`] looks at the book for a change.
const REFRESH: Duration = Duration::from_secs(1);

/// The `lookup.root` handler: hand a proven peer this machine's own standing, which names the root that
/// vouches for it, or the one miss.
///
/// PROVEN-only, and it answers only a peer whose proven key this machine saves as one machine of a person
/// (any person, `me` included): someone who knows this machine already, and so learns only what a root
/// typed into `contact add` would tell them. A stranger, a holder of a link, a key the ledger lists and a
/// key saved only as a root all get the miss. It reads nothing from the peer, and reads the book and the
/// standing afresh on every stream.
pub struct Lookup {
    home: Home,
}

impl Lookup {
    /// Build the `lookup.root` handler over `home`.
    pub fn new(home: Home) -> Self {
        Self { home }
    }
}

impl Handler for Lookup {
    // PROVEN-only: the asker presents nothing, since what it asks is who vouches for this machine.
    type Exposure = ProvenOnly;

    async fn serve(
        &self,
        served: Served<Self>,
        writer: BoxWrite,
        _reader: BoxRead,
    ) -> Result<(), ServeError> {
        // An answer that fails is the asker's to notice; this node only logs it.
        if let Err(error) = answer(&self.home, served.peer(), writer).await {
            tracing::debug!(%error, "a root lookup ended early");
        }
        Ok(())
    }
}

/// Answer one stream of `lookup.root` for `peer`, the key the transport proved: this machine's standing when
/// `peer` is saved here as one machine, else the one miss ([`crate::renewal::reply`]'s format). Never reads
/// from the peer.
pub async fn answer(
    home: &Home,
    peer: VerifyKey,
    mut writer: impl AsyncWrite + Unpin,
) -> io::Result<()> {
    let standing = standing_for(home, peer, SystemTime::now()).await;
    writer
        .write_all(&crate::renewal::reply(standing.as_ref()))
        .await?;
    writer.shutdown().await
}

/// This machine's own standing, for `peer`: only when `peer` is saved here as one machine and this machine
/// is a device of a root whose standing outlives `now`. The asker checks the standing for itself; this
/// side only declines to hand out one it knows is no use, or to anyone it does not know.
async fn standing_for(home: &Home, peer: VerifyKey, now: SystemTime) -> Option<Link> {
    let store = ContactsStore::open(home).await.ok()?;
    if !is_saved_machine(store.contacts(), &peer) {
        return None;
    }
    match Standing::read(home).await {
        Ok(Standing::Device { until, .. } | Standing::HoldsRoot { until, .. }) if until > now => {}
        _ => return None,
    }
    crate::config::load_badge(home).await.ok().flatten()
}

/// Whether `key` is saved in `contacts` as one machine of a person, `me` included: never as a root alone.
fn is_saved_machine(contacts: &Contacts, key: &VerifyKey) -> bool {
    machine_keys(contacts).contains(key)
}

/// Every key `contacts` saves as one machine of a person, `me` included.
fn machine_keys(contacts: &Contacts) -> HashSet<VerifyKey> {
    contacts
        .petnames()
        .filter_map(|person| contacts.devices(person))
        .flatten()
        .filter_map(|(_, node)| node.verify_key().ok())
        .collect()
}

/// The keys this home's book saves as one machine of a person, in memory: what the route asks for every
/// stream before it takes one of the node's proven slots, so a stranger costs no slot and no disk read.
#[derive(Clone)]
pub struct Devices {
    home: Home,
    // An `RwLock`, not a channel: the router asks from a sync check on every stream, and only
    // [`Devices::watch`] writes.
    keys: Arc<RwLock<Keys>>,
}

/// What [`Devices`] read last.
#[derive(Default)]
struct Keys {
    /// The stamps of the files the book is read from, when they were read.
    seen: Option<Vec<Seen>>,
    /// Every key saved as one machine.
    saved: HashSet<VerifyKey>,
}

/// One file's state, as far as telling a change goes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Seen {
    /// The file is not there.
    Absent,
    /// The file is there, with this stamp.
    At(FileStamp),
    /// The file could not be looked at, or its stamp could not be taken: read again next time.
    Unknown,
}

impl Devices {
    /// Read what `home`'s book holds now.
    pub async fn load(home: &Home) -> Self {
        let devices = Self {
            home: home.clone(),
            keys: Arc::default(),
        };
        devices.refresh().await;
        devices
    }

    /// Whether the book saves `key` as one machine of a person, as last read.
    pub fn knows(&self, key: &VerifyKey) -> bool {
        self.keys
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .saved
            .contains(key)
    }

    /// Read the book again when a file it is read from changed. A book that cannot be read keeps what was
    /// read before, and is read again at the next refresh.
    pub async fn refresh(&self) {
        let seen = self.seen().await;
        let unchanged = {
            let keys = self.keys.read().unwrap_or_else(PoisonError::into_inner);
            keys.seen.as_ref() == Some(&seen) && !seen.contains(&Seen::Unknown)
        };
        if unchanged {
            return;
        }
        let Ok(store) = ContactsStore::open(&self.home).await else {
            return;
        };
        *self.keys.write().unwrap_or_else(PoisonError::into_inner) = Keys {
            seen: Some(seen),
            saved: machine_keys(store.contacts()),
        };
    }

    /// The stamps of the files the book is read from: the book itself, and the pin and the list `me` comes
    /// from.
    async fn seen(&self) -> Vec<Seen> {
        let home = &self.home;
        let mut seen = Vec::new();
        for path in [home.contacts(), home.root_pub(), home.devices()] {
            seen.push(match tokio::fs::metadata(&path).await {
                Ok(meta) => FileStamp::of(&meta).map_or(Seen::Unknown, Seen::At),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Seen::Absent,
                Err(_) => Seen::Unknown,
            });
        }
        seen
    }

    /// Refresh every second, for as long as the node runs.
    pub async fn watch(&self) {
        loop {
            tokio::time::sleep(REFRESH).await;
            self.refresh().await;
        }
    }
}

#[cfg(test)]
#[path = "lookup_tests.rs"]
mod tests;
