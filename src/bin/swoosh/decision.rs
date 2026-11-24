//! The one decision of a run's path: whether a reaching verb's streams ride the `serve` answering here or
//! a bind of its own. Made once, from the verb, after its machine resolves and before its key is read, so
//! nothing that unlocks or mints a key precedes it.

use swoosh::home::Home;
use swoosh::node_client::UidSocket;
use swoosh::reaching::{BindRole, Reaching as _};

use crate::commands::through_serve::{self, Moot};
use crate::{Dialing, Outward};

/// What a verb's streams ride when a `serve` answers here, read from the verb before anything opens.
pub(crate) enum Rides<'a> {
    /// Binds its own whatever runs here: `serve`, which is the resident; a verb typed with an `anyone`
    /// link, which never puts that link on the socket; and `revoke`, `root restore` or `join` with a reach
    /// flag, which was checked against `serve` before the act landed, so a `serve` that started since never
    /// turns that landed act into a refusal.
    Never,
    /// One machine of its own: `ping`, `speed`, `status <machine>`, `send`, `forward` (every local end),
    /// `proxy`, `stop`. The slip is the link typed as the machine, if one was.
    Dials {
        dialing: Dialing<'a>,
        slip: Option<nauthy::Link>,
    },
    /// Exchanges with your devices: `sync`, `invite`, `revoke`, `root restore`, `join`.
    Exchanges,
}

/// The run's path, decided once: a bind of its own, or the `serve` on `socket`.
pub(crate) enum Decision<'a> {
    /// Nothing answers here, or the verb never rides: the run binds its own.
    Own,
    /// A dialing verb's streams are Opens through `serve`.
    Dials {
        dialing: Dialing<'a>,
        slip: Option<nauthy::Link>,
        socket: UidSocket,
    },
    /// An exchange verb's exchanges are Opens through `serve`.
    Exchanges { socket: UidSocket },
}

impl Outward {
    /// What this verb's streams ride while `serve` answers. Exhaustive with no wildcard: a new reaching
    /// verb does not compile until it says, and a verb no list named would bind its own endpoint beside
    /// `serve`.
    pub(crate) fn rides(&self) -> Rides<'_> {
        let dialing = match self {
            Self::Serve(_) => return Rides::Never,
            Self::Ping(cmd) => Dialing::Ping(cmd),
            Self::Speed(cmd) => Dialing::Speed(cmd),
            Self::Status(cmd) => Dialing::Status(cmd),
            Self::Send(cmd) => Dialing::Send(cmd),
            // A `unix:` end too: the body refuses it on both paths, so through `serve` it binds nothing.
            Self::Forward(cmd) => Dialing::Forward(cmd),
            Self::Proxy(cmd) => Dialing::Proxy(cmd),
            Self::Stop(cmd) => Dialing::Stop(cmd),
            Self::Sync(_) | Self::Invite(_) => return Rides::Exchanges,
            // Their reach flag was refused before the act if `serve` answered then; one still set means
            // nothing answered, and the act has landed since, so the flag the person typed is honoured.
            Self::Revoke(_) | Self::RootRestore(_) | Self::Join(_) => {
                return match Moot::first(self.reach_args()) {
                    Some(_) => Rides::Never,
                    None => Rides::Exchanges,
                };
            }
        };
        match self.bind_role() {
            BindRole::Dialing(credential) => match credential.through_resident() {
                Some(slip) => Rides::Dials { dialing, slip },
                // An `anyone` link dials under a throwaway key, which `serve`'s key must never stand in for.
                None => Rides::Never,
            },
            // No dialing verb serves; were one to, it would bind as `serve` does.
            BindRole::Serving => Rides::Never,
        }
    }
}

/// Decide `outward`'s path from `home`, once. A verb that never rides binds its own with no probe.
/// Otherwise `serve` is probed once: answering gives the riding arm, and no answer (no socket, or one no
/// listener holds) gives [`Decision::Own`], read in one place for every riding verb.
///
/// # Errors
///
/// A control socket that cannot be trusted: never an own bind, since a bind beside a `serve` this run
/// cannot rule out is the thing this decision exists to prevent.
pub(crate) async fn decide<'a>(outward: &'a Outward, home: &Home) -> eyre::Result<Decision<'a>> {
    let rides = outward.rides();
    if let Rides::Never = rides {
        return Ok(Decision::Own);
    }
    let Some(socket) = answering(home).await? else {
        return Ok(Decision::Own);
    };
    Ok(match rides {
        // Returned above, unprobed; named here so a new arm of `Rides` still has to say.
        Rides::Never => Decision::Own,
        Rides::Dials { dialing, slip } => Decision::Dials {
            dialing,
            slip,
            socket,
        },
        Rides::Exchanges => Decision::Exchanges { socket },
    })
}

/// The socket of the `serve` answering `home`, if one does. The connection that showed it answers
/// carries nothing and would sit idle for the run, so it closes here: each Open takes one of its own.
async fn answering(home: &Home) -> eyre::Result<Option<UidSocket>> {
    Ok(through_serve::serve(home)
        .await?
        .map(|(socket, _probe)| socket))
}

#[cfg(test)]
#[path = "decision_tests.rs"]
pub(crate) mod tests;
