use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::SystemTime;

use bifrost::NodeId;
use nauthy::{FileStamp, VerifyKey};
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::open_policy::ProvenOnly;
use tightbeam::tunnel::{BoxRead, BoxWrite, Handler, ServeError, Served};

use crate::home::Home;
use crate::roster::read_held;

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
/// costs no slot and no disk read.
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
    /// The pin's stamp when it was read.
    signet: Option<FileStamp>,
    /// The update's stamp when it was read.
    roster: Option<FileStamp>,
    /// Each listed device's key, and when its standing ends.
    live: HashMap<VerifyKey, u64>,
}

impl Known {
    /// Read what `home` holds now.
    pub fn load(home: &Home) -> Self {
        let known = Self {
            home: home.clone(),
            rows: Arc::default(),
        };
        known.refresh();
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

    /// Read the pin and the update again when either file changed. A pin that is not one key, or an
    /// update that does not verify under it, lists nothing.
    pub fn refresh(&self) {
        let stamp = |path: std::path::PathBuf| {
            std::fs::metadata(path)
                .ok()
                .and_then(|meta| FileStamp::of(&meta))
        };
        let (signet, roster) = (stamp(self.home.signet()), stamp(self.home.roster()));
        {
            let rows = self.rows.read().unwrap_or_else(PoisonError::into_inner);
            if FileStamp::unchanged(rows.signet, signet)
                && FileStamp::unchanged(rows.roster, roster)
            {
                return;
            }
        }
        let live = std::fs::read_to_string(self.home.signet())
            .ok()
            .and_then(|text| text.trim().parse::<NodeId>().ok())
            .and_then(|pin| pin.verify_key().ok())
            .and_then(|pin| read_held(&self.home.roster(), pin))
            .map(|(doc, _)| {
                doc.members()
                    .iter()
                    .map(|member| (member.node, member.until))
                    .collect()
            })
            .unwrap_or_default();
        *self.rows.write().unwrap_or_else(PoisonError::into_inner) = Rows {
            signet,
            roster,
            live,
        };
    }

    /// Refresh every second, for as long as the node runs.
    pub async fn watch(&self) {
        loop {
            tokio::time::sleep(REFRESH).await;
            self.refresh();
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}
