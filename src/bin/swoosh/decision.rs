//! The one decision of a run's path: whether a reaching verb's streams ride the `serve` answering here or
//! a bind of its own. Made once, from the verb, after its machine resolves and before its key is unlocked,
//! so nothing that unlocks or mints a key, or binds, precedes it.

use bifrost::NodeId;
use swoosh::home::Home;
use swoosh::node_client::UidSocket;
use swoosh::peer::Machine;

use crate::commands::through_serve::{self, ActLanded, Found, Landed, Moot, ThisMachine};
use crate::{Dialing, Exchanging, Run};

/// A verb split by what its streams ride when a `serve` answers here, read from the verb before anything
/// opens. Each arm holds the verb itself, so the arm [`decide`] takes and the verb it runs cannot part.
pub(crate) enum Rides {
    /// Binds its own whatever runs here: `serve`, which is the resident; a verb typed with an `anyone`
    /// link, which never puts that link on the socket; and `revoke`, `root restore` or `join` with a reach
    /// flag, which was checked against `serve` before the act landed, so a `serve` that started since never
    /// turns that landed act into a refusal.
    Never(Run),
    /// One machine of its own: `ping`, `speed`, `status <machine>`, `send`, `forward` (every local end),
    /// `proxy`, `stop`. The link is the slip, typed as the machine, if one was.
    Dials(Dialing, Option<nauthy::Link>),
    /// Exchanges with your devices: `sync`, `invite`, `revoke`, `root restore`, `join`.
    Exchanges(Exchanging),
}

/// The run's path, decided once: a bind of its own, or the `serve` on `socket`.
pub(crate) enum Decision<'m> {
    /// Nothing answers here, or the verb never rides: the run binds its own.
    Own(Run),
    /// A dialing verb's streams are Opens through `serve`.
    Dials {
        dialing: Dialing,
        /// The machine it dials, which is not this one.
        machine: &'m Machine,
        slip: Option<nauthy::Link>,
        socket: UidSocket,
        /// The key `serve` runs as.
        this: NodeId,
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
    pub(crate) fn rides(self) -> Rides {
        match self {
            run @ Self::Serve(_) => Rides::Never(run),
            // Every `forward` end too, `unix:` included: the body refuses it on both paths, so through
            // `serve` it binds nothing.
            Self::Dials(dialing) => match dialing.credential().through_resident() {
                Some(slip) => Rides::Dials(dialing, slip),
                // An `anyone` link dials under a throwaway key, which `serve`'s key must never stand in for.
                None => Rides::Never(Self::Dials(dialing)),
            },
            Self::Exchanges(exchanging @ (Exchanging::Sync(_) | Exchanging::Invite(_))) => {
                Rides::Exchanges(exchanging)
            }
            // Their reach flag was refused before the act if `serve` answered then; one still set means
            // nothing answered, and the act has landed since, so the flag the person typed is honoured.
            Self::Exchanges(
                exchanging @ (Exchanging::Revoke(_)
                | Exchanging::RootRestore(_)
                | Exchanging::Join(_)),
            ) => match Moot::first(exchanging.reach_args()) {
                Some(_) => Rides::Never(Self::Exchanges(exchanging)),
                None => Rides::Exchanges(exchanging),
            },
        }
    }
}

impl Exchanging {
    /// What of this verb's act has landed before its path is decided: `root restore` and `join` make their
    /// change locally first, so nothing a bind does can delay or stop it. A `revoke` has landed only this
    /// machine's block, which its partial landing says ([`Publish::unreached`]).
    ///
    /// [`Publish::unreached`]: crate::commands::revoke::Publish::unreached
    fn landed(&self) -> Option<Landed> {
        match self {
            Self::RootRestore(_) | Self::Join(_) => Some(Landed::Saved),
            Self::Revoke(_) | Self::Sync(_) | Self::Invite(_) => None,
        }
    }
}

/// Decide `run`'s path from `home`, once, for the `machine` it dials if it dials one. A verb that never
/// rides binds its own with no probe. Otherwise `serve` is probed once ([`through_serve::serve`]):
/// answering gives the riding arm, and only a free `serve.lock` behind no answer gives
/// [`Decision::Own`], read in one place for every riding verb.
///
/// A dialing verb's machine is checked against this machine first, on both paths, before anything is
/// opened, bound or unlocked: against the key `serve` says it runs as, or by own bind against this
/// home's key file, read with no prompt and no mint ([`swoosh::identity::peek`]). The check through
/// `serve` is advisory: a key `serve` names wrongly at worst refuses a dial, and one it misses is
/// refused by `serve` at the first Open.
///
/// # Errors
///
/// [`ThisMachine`] for a dial to this machine, and by own bind a key file the check could not read. A
/// control socket that cannot be trusted, a `serve` that holds the lock but cannot be reached, answers in
/// another version or not in time, or a lock that could not be read: never an own bind, since a bind
/// beside a `serve` this run cannot rule out is the thing this decision exists to prevent. For `root
/// restore` and `join`, whose act has landed by now, the error is [`ActLanded`], saying what of it landed;
/// for `revoke`, whose block alone has, it is the partial landing, read back, with the error in it.
pub(crate) async fn decide<'m>(
    run: Run,
    home: &Home,
    machine: Option<&'m Machine>,
) -> eyre::Result<Decision<'m>> {
    match run.rides() {
        Rides::Never(run) => Ok(Decision::Own(run)),
        Rides::Dials(dialing, slip) => {
            // Every dialing verb names its machine, resolved before the decision.
            let Some(machine) = machine else {
                eyre::bail!(
                    "internal: a dialing verb ran without its machine resolved (root-dispatch bug)"
                );
            };
            match through_serve::serve(home).await? {
                Found::Answering { socket, this } => {
                    if machine.key() == this {
                        return Err(ThisMachine::of(machine).into());
                    }
                    Ok(Decision::Dials {
                        dialing,
                        machine,
                        slip,
                        socket,
                        this,
                    })
                }
                Found::Absent => {
                    if swoosh::identity::peek(home)? == Some(machine.key()) {
                        return Err(ThisMachine::of(machine).into());
                    }
                    Ok(Decision::Own(Run::Dials(dialing)))
                }
            }
        }
        Rides::Exchanges(exchanging) => match through_serve::serve(home).await {
            Ok(Found::Answering { socket, this: _ }) => {
                Ok(Decision::Exchanges { exchanging, socket })
            }
            Ok(Found::Absent) => Ok(Decision::Own(Run::Exchanges(exchanging))),
            Err(report) => Err(match &exchanging {
                // Only the block landed: the partial landing, read back, says so with the error in it.
                Exchanging::Revoke(revoke) => revoke.publish.unreached(home, &report),
                _ => match exchanging.landed() {
                    Some(landed) => ActLanded { landed, report }.into(),
                    None => report,
                },
            }),
        },
    }
}

#[cfg(test)]
#[path = "decision_tests.rs"]
pub(crate) mod tests;
