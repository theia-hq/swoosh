//! The `serve` entry a peer would have to run for a verb's DEFAULTED service name to answer, said by
//! the CLIENT when its dial fails.
//!
//! A bare `swoosh serve` binds `ping`, `speed` and the two `control.*` routes, and nothing else: a
//! default service may cost a peer bandwidth, but never code execution, a byte of its disk, a packet
//! from its IP, or a name from its fleet. Four verbs (`ssh`, `send`, `fetch`, `fleet`) therefore
//! default to names a zero-config peer does not serve, and the refusal that comes back names nothing,
//! deliberately: the wire refusal is uniform so a stranger never learns what a node serves or does not.
//! So the client says it instead, out of the table below, which pairs each of those names with the
//! `serve` entry that binds it.
//!
//! THE RULE THIS MODULE EXISTS TO HOLD: the sentence is derived from the name the client SENT, never
//! from anything that came back. [`Unbound::teaching`] has no error in scope, so it cannot read the
//! wire even by accident, and [`Unbound::name_the_entry`] only MOVES the report it wraps: its body is
//! one match over the client's own table, so a reader confirms the property by looking at it. A
//! version that attached
//! the sentence to some failures and not others would be an oracle the day the wire refusal stops
//! being uniform, because the distinction the refusal withholds would be readable off the client's own
//! output. Attach it to every failed dial of the name, or not at all.
//!
//! The names a bare `serve` DOES bind are the other half of the same pairing, and live where the
//! clients that dial them do: [`crate::reach::PING_SERVICE`] and [`crate::reach::SPEED_SERVICE`].

/// One defaulted service name a bare `swoosh serve` does not bind, with the `serve` entry that binds
/// it.
///
/// The two halves are one row, with no public constructor, so a client can never name a service it
/// cannot also say how to serve: the pair IS the sentence. A verb takes its own default FROM its row
/// (`Unbound::SSH.name()`), so the name a verb dials and the name this table teaches for cannot drift
/// apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unbound {
    /// The wire name the verb dials when the user names no service.
    name: &'static str,
    /// The `name=target` entry a peer's `swoosh serve` must carry to bind that name.
    entry: &'static str,
}

impl Unbound {
    /// `swoosh ssh`'s default. A `sshd:` target auto-names to `ssh`, so the verb dials `ssh` while the
    /// entry spells the engine; a shell is refused from the bare set permanently (it runs as the serve
    /// process's uid, over the home that holds the node secret).
    pub const SSH: Self = Self {
        name: "ssh",
        entry: "ssh=sshd:",
    };
    /// `swoosh send`'s default: the peer receives with a `recv:` service. The entry names a DIR on
    /// purpose. A bare `recv:` sinks into the serve process's working directory, which is exactly why
    /// there is no default to inherit, so teaching the dirless spelling here would hand every operator
    /// the shape the bare set refuses.
    pub const RECV: Self = Self {
        name: "recv",
        entry: "recv=recv:<dir>",
    };
    /// `swoosh fetch`'s default: the exit node serves a `fetch:` relay. The entry names an ORIGIN for
    /// the same reason [`RECV`](Self::RECV) names a dir: an unscoped fetch is an egress relay under the
    /// peer's own IP, so the scoped spelling is the one a refusal should teach.
    pub const FETCH: Self = Self {
        name: "fetch",
        entry: "fetch=fetch:<origin>",
    };
    /// `swoosh fleet`'s service. `fleet` has no `--service` flag to drop, so naming the entry on a
    /// failed pull is its only way to satisfy the rule at all.
    pub const ROSTER: Self = Self {
        name: "roster",
        entry: "roster=roster:",
    };

    /// The wire name the verb dials when the user names no service.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The `name=target` entry a peer's `swoosh serve` must carry to bind [`name`](Self::name).
    pub const fn entry(&self) -> &'static str {
        self.entry
    }

    /// Every row, so the pairing with `serve`'s default set is one list a test can walk rather than a
    /// second list a test would have to be kept in step with by hand.
    pub fn all() -> impl Iterator<Item = &'static Self> {
        UNBOUND.iter()
    }

    /// Recognize a dialed name as one of these defaults. [`None`] for every other name, including the
    /// two a bare `serve` does bind: those need nothing said, which is the first branch of the same
    /// rule.
    pub fn dialed(name: &str) -> Option<&'static Self> {
        UNBOUND.iter().find(|unbound| unbound.name == name)
    }

    /// The one sentence a client adds locally: what a bare `serve` does not bind, and the line that
    /// binds it.
    ///
    /// Takes no error and no session, so the wire is not in scope to be read. Everything here is the
    /// client's own table.
    pub fn teaching(&self) -> String {
        format!(
            "a bare `swoosh serve` does not bind `{}`; the peer must run `swoosh serve {}`",
            self.name, self.entry
        )
    }

    /// Add [`teaching`](Self::teaching) to a failed dial of `dialed`, when `dialed` is one of these
    /// defaults, and hand back every other report untouched.
    ///
    /// `error` is MOVED through, never inspected: this body is the whole decision, and the only input
    /// it reads is the name the caller SENT. A caller must therefore apply it to EVERY way its dial of
    /// that name can fail, refusal or timeout alike, because a caller that applied it to only some of
    /// them would put the branch back where this function refuses to have one.
    pub fn name_the_entry(error: eyre::Report, dialed: &str) -> eyre::Report {
        match Self::dialed(dialed) {
            Some(unbound) => error.wrap_err(unbound.teaching()),
            None => error,
        }
    }
}

/// The table, in the order a reader meets the verbs: reach a shell, push a file, relay a fetch, learn
/// the fleet. A `static` (not a `const`) so a row can be handed out as `&'static`, which is what lets
/// [`Unbound::dialed`] return a borrow rather than a copy of a row the caller then has to own.
static UNBOUND: [Unbound; 4] = [Unbound::SSH, Unbound::RECV, Unbound::FETCH, Unbound::ROSTER];

#[cfg(test)]
#[path = "unbound_tests.rs"]
mod tests;
