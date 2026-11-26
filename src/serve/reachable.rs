//! How peers reach this `serve`: whether the internet is on, whether this network hears it announced,
//! and one address per class of reach, picked from the bind's own expansion.
//!
//! One fact for every screen that shows reach, so no two can come to disagree about where this
//! machine answers. The control socket carries it to `status`.
//!
//! The addresses are re-read on every ask ([`ReachSource::reachable`]): a laptop that moves networks
//! answers `status` with where it is now, not where it was when it bound. What `--local` chose and what
//! mDNS managed are fixed at bind, so they ride along unchanged.

use core::net::{IpAddr, SocketAddr};
use core::sync::atomic::{AtomicBool, Ordering};

use bifrost_mdns::{Dialable, Missing, ScopeClass};

use crate::transport::MdnsState;

/// How peers reach this machine, as one value: the bind's reach choices and one address per class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reachable {
    /// Whether this bind routes across the internet, or stays on this network (`--local`).
    pub internet: Internet,
    /// Whether this network hears the machine announced, or reaches it only by an address it is given.
    pub lan: Lan,
    /// One address per class of reach.
    pub at: Picks,
}

/// Whether this bind routes across the internet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Internet {
    /// The internet channel is up: a peer anywhere reaches this machine by its key.
    On,
    /// `--local`: no lookup and no relays, so only this network, a tunnel, or an address reaches it.
    Off,
}

impl Internet {
    /// The channel a bind has, from whether it was `--local`.
    pub fn of(local: bool) -> Self {
        if local { Self::Off } else { Self::On }
    }
}

/// Whether a peer on this network hears this machine announced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lan {
    /// mDNS announces an address another host can dial, so a peer here finds it by its key alone.
    Announced,
    /// Nothing another host can dial is announced, so a peer here needs an address handed to it.
    ByAddressOnly,
}

impl Lan {
    /// How this network hears the machine, from what its one mDNS advertisement managed. Only a record
    /// that reaches past this machine counts: a loopback record, a browse-only start and a blocked
    /// multicast all leave a peer on the network with nothing to dial by key.
    pub fn of(mdns: &MdnsState) -> Self {
        match mdns {
            MdnsState::OnLan(_) => Self::Announced,
            MdnsState::LoopbackOnly | MdnsState::BrowseOnly(_) | MdnsState::Blocked => {
                Self::ByAddressOnly
            }
        }
    }
}

/// One address per class of reach, each one a peer of that class can dial.
///
/// One per class, so a duplicate cannot exist, and an IPv4 address wins its class over an IPv6 one,
/// because it is the address a peer can paste anywhere. A class with no IPv4 shows its IPv6.
///
/// Built only by [`of`](Self::of) and by the control codec, and both go through one check
/// (the one `of` applies), so every value that exists encodes, and decodes back to itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Picks {
    /// A globally routable address ([`ScopeClass::Internet`]).
    public: Option<SocketAddr>,
    /// An address on this network ([`ScopeClass::Network`]), or the fact that the host's addresses
    /// could not be read.
    network: Network,
    /// An address on a point-to-point link ([`ScopeClass::Tunnel`]).
    tunnel: Option<SocketAddr>,
    /// A loopback address ([`ScopeClass::ThisMachine`]). Absent for a bind that named its own
    /// addresses and no loopback one: that bind answers at exactly what it named.
    computer: Option<SocketAddr>,
}

/// What this machine knows of its address on this network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// The address a peer on this network dials.
    At(SocketAddr),
    /// The host's addresses were read and none is on a network.
    Nothing,
    /// The host's addresses could not be read, so whether one is on a network is not known. Kept apart
    /// from [`Nothing`](Self::Nothing) because a screen that showed it as nothing would read offline
    /// when the host only could not look.
    Unknown,
}

impl Picks {
    /// The picks for a bind's expansion: the first address of each class in [`Dialable::all`]'s order,
    /// with an IPv4 address replacing an IPv6 one. An entry no peer of its class could dial is skipped
    /// (see `Slot::admit`). With no network address in hand and the host's addresses unread, the
    /// network is [`Network::Unknown`].
    pub fn of(dialable: &Dialable) -> Self {
        let mut slots: [Option<SocketAddr>; 4] = [None; 4];
        for at in dialable.all() {
            let class = at.scope.class();
            let Some(socket) = Slot(class).admit(at.socket) else {
                continue;
            };
            let slot = &mut slots[rank(class)];
            match slot {
                Some(kept) if kept.is_ipv4() || socket.is_ipv6() => {}
                _ => *slot = Some(socket),
            }
        }
        let unread = matches!(dialable.missing(), Missing::Interfaces(_));
        let [public, network, tunnel, computer] = slots;
        Self {
            public,
            network: match (network, unread) {
                (Some(socket), _) => Network::At(socket),
                (None, false) => Network::Nothing,
                (None, true) => Network::Unknown,
            },
            tunnel,
            computer,
        }
    }

    /// Assemble picks the control codec decoded, each address checked against its class exactly as
    /// [`of`](Self::of) checks it, so a reply can never hold what this machine would not have picked.
    /// `None` when an address does not fit its class.
    pub(crate) fn checked(
        public: Option<SocketAddr>,
        network: Network,
        tunnel: Option<SocketAddr>,
        computer: Option<SocketAddr>,
    ) -> Option<Self> {
        let fits = |class, socket: Option<SocketAddr>| {
            socket.is_none_or(|socket| Slot(class).admit(socket) == Some(socket))
        };
        let network_fits = match network {
            Network::At(socket) => fits(ScopeClass::Network, Some(socket)),
            Network::Nothing | Network::Unknown => true,
        };
        let all_fit = fits(ScopeClass::Internet, public)
            && network_fits
            && fits(ScopeClass::Tunnel, tunnel)
            && fits(ScopeClass::ThisMachine, computer);
        all_fit.then_some(Self {
            public,
            network,
            tunnel,
            computer,
        })
    }

    /// The globally routable address, if this machine has one.
    pub fn public(&self) -> Option<SocketAddr> {
        self.public
    }

    /// The address on this network, or why there is none.
    pub fn network(&self) -> Network {
        self.network
    }

    /// The address on a point-to-point link, if this machine has one.
    pub fn tunnel(&self) -> Option<SocketAddr> {
        self.tunnel
    }

    /// The loopback address, if this bind answers on one.
    pub fn computer(&self) -> Option<SocketAddr> {
        self.computer
    }
}

/// Where `class` sits among the four slots, in [`ScopeClass`]'s order. A match rather than the
/// discriminant, so a fifth class is a compile error here instead of a slot out of range.
fn rank(class: ScopeClass) -> usize {
    match class {
        ScopeClass::Internet => 0,
        ScopeClass::Network => 1,
        ScopeClass::Tunnel => 2,
        ScopeClass::ThisMachine => 3,
    }
}

/// The check one class puts on an address before it may stand for that class.
struct Slot(ScopeClass);

impl Slot {
    /// The address as it is stored and sent, when a peer of this class could dial it: a real port, an
    /// address that names one host, loopback exactly for this machine, and never a link-local IPv6
    /// address, which needs an interface scope that neither the control reply nor an address a person
    /// pastes carries. The flow label and scope id are dropped, and a v4-mapped IPv6 address is read
    /// as the IPv4 address it is, so the value is the one that decodes and a mapped loopback is
    /// loopback.
    fn admit(&self, socket: SocketAddr) -> Option<SocketAddr> {
        let ip = socket.ip().to_canonical();
        let loopback = matches!(self.0, ScopeClass::ThisMachine);
        let usable = socket.port() != 0
            && !ip.is_unspecified()
            && !ip.is_multicast()
            && !is_link_local_v6(ip)
            && !names_no_host_v4(ip)
            && ip.is_loopback() == loopback;
        usable.then(|| SocketAddr::new(ip, socket.port()))
    }
}

/// Whether `ip` is an IPv4 address no peer can dial one host at: the broadcast address, or
/// `0.0.0.0/8`, which is a source-only range.
fn names_no_host_v4(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_broadcast() || v4.octets()[0] == 0,
        IpAddr::V6(_) => false,
    }
}

/// Whether `ip` is in `fe80::/10`, matched by prefix: `Ipv6Addr` has no stable accessor for it.
fn is_link_local_v6(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(_) => false,
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    }
}

/// Where a running `serve` reads its [`Reachable`] from: the sockets it bound, and the two reach facts
/// fixed at bind.
///
/// The sockets are expanded through this host's interfaces on every [`reachable`](Self::reachable),
/// not once at bind, so the answer follows the host to a new network. It is one interface read per
/// status request, and every command that reads a running serve's services sends one.
#[derive(Debug)]
pub struct ReachSource {
    /// What the transport bound, wildcards and all, as [`Dialable::of`] takes it.
    sockets: Vec<SocketAddr>,
    /// Whether this bind routes across the internet.
    internet: Internet,
    /// How this network heard the one advertisement.
    lan: Lan,
    /// How the sockets become addresses: [`Dialable::of`], or a test's own host.
    expand: fn(Vec<SocketAddr>) -> Dialable,
    /// Whether the last read could not see the host's addresses, so an unreadable host warns once when
    /// it becomes so and not on every request after. Atomic because concurrent control connections
    /// share one source; a lost race costs at most one extra or missed warn line, never a wrong reach.
    unread: AtomicBool,
}

impl ReachSource {
    /// The source for a bind of `sockets`, with the reach facts it bound with.
    pub fn new(sockets: Vec<SocketAddr>, internet: Internet, lan: Lan) -> Self {
        Self {
            sockets,
            internet,
            lan,
            expand: Dialable::of,
            unread: AtomicBool::new(false),
        }
    }

    /// The same source over a host a test describes, so a test can move the host between two asks.
    #[cfg(test)]
    pub(crate) fn expanding_with(self, expand: fn(Vec<SocketAddr>) -> Dialable) -> Self {
        Self { expand, ..self }
    }

    /// How peers reach this machine now: the bound sockets read against the host's interfaces as they
    /// are at this call.
    ///
    /// A host whose interfaces cannot be read is logged with the cause and nothing else, at `warn`
    /// when it becomes unreadable and at `debug` while it stays so, since every service verb asks. The
    /// log goes to the journal of a supervised run, and an address there is one the person never chose
    /// to show.
    pub fn reachable(&self) -> Reachable {
        let dialable = (self.expand)(self.sockets.clone());
        let missing = dialable.missing();
        let was_unread = self
            .unread
            .swap(matches!(missing, Missing::Interfaces(_)), Ordering::Relaxed);
        if let Missing::Interfaces(cause) = missing {
            if was_unread {
                tracing::debug!(%cause, "could not read this host's addresses");
            } else {
                tracing::warn!(%cause, "could not read this host's addresses");
            }
        }
        Reachable {
            internet: self.internet,
            lan: self.lan,
            at: Picks::of(&dialable),
        }
    }
}

#[cfg(test)]
#[path = "reachable_tests.rs"]
mod reachable_tests;
