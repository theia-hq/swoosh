use tightbeam::open_policy::Never;
use tightbeam::tunnel::{BoxRead, BoxWrite, Handler, ServeError, Served};

use crate::home::Home;
use crate::sync::Receive;

/// The `control.sync` handler: answer one exchange ([`crate::sync::answer`]) on each admitted stream.
///
/// GATED, member-only, because only your own devices exchange updates. It reads this home's standing, pin
/// and held update afresh on every exchange, so a pin or an update written while `serve` runs is the one
/// it answers from next, with no restart. It never signs: an update it takes was signed by the root, and
/// it folds one only on a device of that root. It answers one exchange per peer and a few in all
/// ([`Receive`]), each within [`crate::sync::ANSWER_WITHIN`], so no stream of a session holds it or its
/// buffers without bound, and no peer holds another's.
pub struct Sync {
    home: Home,
    receive: Receive,
}

impl Sync {
    /// Build the `control.sync` handler over `home`, with its own receive permit.
    pub fn new(home: Home) -> Self {
        Self {
            home,
            receive: Receive::new(),
        }
    }
}

impl Handler for Sync {
    // GATED, because only a device of this root exchanges updates: no legitimate public use.
    type Exposure = Never;

    async fn serve(
        &self,
        served: Served<Self>,
        writer: BoxWrite,
        reader: BoxRead,
    ) -> Result<(), ServeError> {
        // An exchange that fails is the dialer's to notice (it reads no answer, the stream ended for it
        // by the answer); this node only logs it.
        if let Err(error) =
            crate::sync::answer(&self.home, &self.receive, served.peer(), reader, writer).await
        {
            tracing::debug!(%error, "an exchange ended early");
        }
        Ok(())
    }
}
