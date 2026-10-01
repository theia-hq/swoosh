use core::time::Duration;
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::SystemTime;

use nauthy::{FileStamp, VerifyKey};
use tightbeam::open_policy::ProvenOnly;
use tightbeam::tunnel::{BoxRead, BoxWrite, Handler, ServeError, Served};

use crate::home::Home;
use crate::roster::read_held;
use crate::standing::Standing;

/// How often [`Known::watch`] looks at the pin and the update for a change.
const REFRESH: Duration = Duration::from_secs(1);

/// The `control.renewal` handler: hand the proven peer its own newest standing, or the one miss
/// ([`crate::renewal::answer`]).
///
/// PROVEN-only: it is the one route a peer the gate did not admit reaches, so it grants nothing, reads
/// nothing from the peer, and answers only for the key the transport proved. It reads the standing, the
/// revocations and the held update afresh on every stream, so it answers from what this home holds now.
pub struct Renewal {
    home: Home,
}

impl Renewal {
    /// Build the `control.renewal` handler over `home`.
    pub fn new(home: Home) -> Self {
        Self { home }
    }
}

impl Handler for Renewal {
    // PROVEN-only, because the dialer holds no standing this gate admits: that is why it asks.
    type Exposure = ProvenOnly;

    async fn serve(
        &self,
        served: Served<Self>,
        writer: BoxWrite,
        _reader: BoxRead,
    ) -> Result<(), ServeError> {
        // An answer that fails is the dialer's to notice (it reads no answer); this node only logs it.
        if let Err(error) = crate::renewal::answer(&self.home, served.peer(), writer).await {
            tracing::debug!(%error, "a pick-up ended early");
        }
        Ok(())
    }
}

/// The keys the update held here lists with a standing that has not ended, in memory: what the route asks
/// for every stream before it takes one of the node's proven slots, so a key this home holds nothing for
/// costs no slot and no disk read. It lists keys only while this home is a device of a root or holds one,
/// and its update verifies under the pin: on any other home no key reaches the handler at all.
#[derive(Clone)]
pub struct Known {
    home: Home,
    // An `RwLock`, not a channel: the router asks from a sync check on every stream, and only
    // [`Known::watch`] writes.
    rows: Arc<RwLock<Rows>>,
}

/// What [`Known`] read last.
#[derive(Default)]
struct Rows {
    /// The stamps of the files the standing and the update are read from, when they were read.
    seen: Option<Vec<Seen>>,
    /// Each listed device's key, and when its standing ends.
    live: HashMap<VerifyKey, u64>,
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

impl Known {
    /// Read what `home` holds now.
    pub async fn load(home: &Home) -> Self {
        let known = Self {
            home: home.clone(),
            rows: Arc::default(),
        };
        known.refresh().await;
        known
    }

    /// Whether the update held here lists `key` with a standing that has not ended, as last read.
    pub fn knows(&self, key: &VerifyKey) -> bool {
        let now = unix_now();
        self.rows
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .live
            .get(key)
            .is_some_and(|until| *until > now)
    }

    /// Read the standing and the update again when a file either is read from changed. A home that is not
    /// a device of a root and holds none, or whose update does not verify under the pin, lists nothing.
    pub async fn refresh(&self) {
        let seen = self.seen().await;
        {
            let rows = self.rows.read().unwrap_or_else(PoisonError::into_inner);
            let unchanged = rows.seen.as_ref() == Some(&seen) && !seen.contains(&Seen::Unknown);
            if unchanged {
                return;
            }
        }
        let live = self.listed().await;
        *self.rows.write().unwrap_or_else(PoisonError::into_inner) = Rows {
            seen: Some(seen),
            live,
        };
    }

    /// The keys the update lists, with when each standing ends, when this home's standing lets it answer.
    async fn listed(&self) -> HashMap<VerifyKey, u64> {
        let pin = match Standing::read(&self.home).await.map(|read| read.standing) {
            Ok(Standing::Device { pin, .. } | Standing::HoldsRoot { pin, .. }) => pin,
            Ok(Standing::Unpinned | Standing::InterruptedMint { .. }) | Err(_) => {
                return HashMap::new();
            }
        };
        crate::standing::pin_key(&self.home, pin)
            .ok()
            .and_then(|pin| read_held(&self.home.devices(), pin))
            .map(|(doc, _)| {
                doc.members()
                    .iter()
                    .map(|member| (member.node, member.until))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The stamps of every file this home's standing and its update are read from.
    async fn seen(&self) -> Vec<Seen> {
        let home = &self.home;
        let mut seen = Vec::new();
        for path in [
            home.key(),
            home.root_pub(),
            home.key_cert(),
            home.devices(),
            home.revoked(),
            home.root_key(),
        ] {
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

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}
