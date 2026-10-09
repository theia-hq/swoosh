//! The services three verbs dial by default that a bare `swoosh serve` does not bind.
//!
//! A bare `swoosh serve` binds `ping`, `speed`, the two `control.*` routes and the member-gated update
//! route, and nothing else: a default service may cost a peer bandwidth, but never code execution, a
//! byte of its disk, or a packet from its IP. Three verbs (`ssh`, `send`, `proxy`) therefore default to
//! names a zero-config peer does not serve. A dial of one that is refused by one of your own devices
//! names the `service add` form that serves it there ([`crate::serve::entry_for`]); a dial that is not
//! answered teaches nothing, since it was never refused.
//!
//! The names a bare `serve` DOES bind are the other half of the same pairing, and live where the
//! clients that dial them do: [`crate::reach::PING_SERVICE`] and [`crate::reach::SPEED_SERVICE`].

/// One defaulted service name a bare `swoosh serve` does not bind.
///
/// No public constructor, so the table below is the whole set: a verb takes its own default FROM its row
/// (`Unbound::SSH.name()`), so the name a verb dials and the name this table holds cannot drift apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unbound {
    /// The wire name the verb dials when the user names no service.
    name: &'static str,
}

impl Unbound {
    /// `swoosh ssh`'s default: a shell, refused from the bare set permanently (it runs as the serve
    /// process's uid, over the home that holds the node secret).
    pub const SSH: Self = Self { name: "ssh" };
    /// `swoosh send`'s default: the peer receives with a `recv:` service, whose directory is the
    /// operator's to choose.
    pub const RECV: Self = Self { name: "recv" };
    /// `swoosh proxy`'s default: the exit node serves a `proxy:` relay, scoped to one site.
    pub const PROXY: Self = Self { name: "proxy" };

    /// The wire name the verb dials when the user names no service.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Every row, so the pairing with `serve`'s default set is one list a test can walk rather than a
    /// second list a test would have to be kept in step with by hand.
    pub fn all() -> impl Iterator<Item = &'static Self> {
        UNBOUND.iter()
    }

    /// Recognize a dialed name as one of these defaults. [`None`] for every other name, including the
    /// two a bare `serve` does bind.
    pub fn dialed(name: &str) -> Option<&'static Self> {
        UNBOUND.iter().find(|unbound| unbound.name == name)
    }
}

/// The table, in the order a reader meets the verbs: reach a shell, push a file, go through a proxy. A
/// `static` (not a `const`) so a row can be handed out as `&'static`, which is what lets
/// [`Unbound::dialed`] return a borrow rather than a copy of a row the caller then has to own.
static UNBOUND: [Unbound; 3] = [Unbound::SSH, Unbound::RECV, Unbound::PROXY];

#[cfg(test)]
#[path = "unbound_tests.rs"]
mod tests;
