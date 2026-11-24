//! The one decision of a run's path: whether a reaching verb's streams ride the `serve` answering here or
//! a bind of its own. Made once, from the verb, after its machine resolves and before its key is read, so
//! nothing that unlocks or mints a key precedes it.

use swoosh::home::Home;
use swoosh::node_client::UidSocket;

use crate::commands::through_serve::{self, Moot};
use crate::{Dialing, Exchanging, Run};

/// What a verb's streams ride when a `serve` answers here, read from the verb before anything opens.
pub(crate) enum Rides {
    /// Binds its own whatever runs here: `serve`, which is the resident; a verb typed with an `anyone`
    /// link, which never puts that link on the socket; and `revoke`, `root restore` or `join` with a reach
    /// flag, which was checked against `serve` before the act landed, so a `serve` that started since never
    /// turns that landed act into a refusal.
    Never,
    /// One machine of its own: `ping`, `speed`, `status <machine>`, `send`, `forward` (every local end),
    /// `proxy`, `stop`. The slip is the link typed as the machine, if one was.
    Dials { slip: Option<nauthy::Link> },
    /// Exchanges with your devices: `sync`, `invite`, `revoke`, `root restore`, `join`.
    Exchanges,
}

/// The run's path, decided once: a bind of its own, or the `serve` on `socket`.
pub(crate) enum Decision {
    /// Nothing answers here, or the verb never rides: the run binds its own.
    Own(Run),
    /// A dialing verb's streams are Opens through `serve`.
    Dials {
        dialing: Dialing,
        slip: Option<nauthy::Link>,
        socket: UidSocket,
    },
    /// An exchange verb's exchanges are Opens through `serve`.
    Exchanges {
        exchanging: Exchanging,
        socket: UidSocket,
    },
}

impl Run {
    /// What this verb's streams ride while `serve` answers. Exhaustive with no wildcard: a new reaching
    /// verb does not compile until it says, and a verb no list named would bind its own endpoint beside
    /// `serve`.
    pub(crate) fn rides(&self) -> Rides {
        match self {
            Self::Serve(_) => Rides::Never,
            // Every `forward` end too, `unix:` included: the body refuses it on both paths, so through
            // `serve` it binds nothing.
            Self::Dials(dialing) => match dialing.credential().through_resident() {
                Some(slip) => Rides::Dials { slip },
                // An `anyone` link dials under a throwaway key, which `serve`'s key must never stand in for.
                None => Rides::Never,
            },
            Self::Exchanges(Exchanging::Sync(_) | Exchanging::Invite(_)) => Rides::Exchanges,
            // Their reach flag was refused before the act if `serve` answered then; one still set means
            // nothing answered, and the act has landed since, so the flag the person typed is honoured.
            Self::Exchanges(
                exchanging @ (Exchanging::Revoke(_)
                | Exchanging::RootRestore(_)
                | Exchanging::Join(_)),
            ) => match Moot::first(exchanging.reach_args()) {
                Some(_) => Rides::Never,
                None => Rides::Exchanges,
            },
        }
    }
}

/// Decide `run`'s path from `home`, once. A verb that never rides binds its own with no probe. Otherwise
/// `serve` is probed once: answering gives the riding arm, and no answer (no socket, or one no listener
/// holds) gives [`Decision::Own`], read in one place for every riding verb.
///
/// # Errors
///
/// A control socket that cannot be trusted: never an own bind, since a bind beside a `serve` this run
/// cannot rule out is the thing this decision exists to prevent.
pub(crate) async fn decide(run: Run, home: &Home) -> eyre::Result<Decision> {
    let slip = match run.rides() {
        Rides::Never => return Ok(Decision::Own(run)),
        Rides::Dials { slip } => slip,
        Rides::Exchanges => None,
    };
    let Some(socket) = answering(home).await? else {
        return Ok(Decision::Own(run));
    };
    Ok(match run {
        Run::Dials(dialing) => Decision::Dials {
            dialing,
            slip,
            socket,
        },
        Run::Exchanges(exchanging) => Decision::Exchanges { exchanging, socket },
        // Returned above, unprobed; named here so a new arm of `Run` still has to say.
        run @ Run::Serve(_) => Decision::Own(run),
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
