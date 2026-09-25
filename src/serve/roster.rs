use tightbeam::open_policy::Never;
use tightbeam::tunnel::{BoxRead, BoxWrite, Handler, ServeError, Served};

use crate::home::Home;

/// The `control.sync` handler: answer one exchange ([`crate::sync::answer`]) on each admitted stream.
///
/// GATED, member-only, because only your own devices exchange updates. It reads this home's standing, pin
/// and held update afresh on every exchange, so a pin or an update written while `serve` runs is the one
/// it answers from next, with no restart. It never signs: an update it takes was signed by the root, and
/// it folds one only on a device of that root.
pub struct Exchange {
    home: Home,
}

impl Exchange {
    /// Build the `control.sync` handler over `home`.
    pub fn new(home: Home) -> Self {
        Self { home }
    }
}

impl Handler for Exchange {
    // GATED, because only a device of this root exchanges updates: no legitimate public use.
    type Exposure = Never;

    async fn serve(
        &self,
        _served: Served<Self>,
        writer: BoxWrite,
        reader: BoxRead,
    ) -> Result<(), ServeError> {
        // An exchange that fails is the dialer's to notice (it reads no answer); this node only logs it.
        if let Err(error) = crate::sync::answer(&self.home, reader, writer).await {
            tracing::debug!(%error, "an exchange ended early");
        }
        Ok(())
    }
}
