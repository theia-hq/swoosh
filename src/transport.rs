//! The transport-select seam: the one place a concrete transport is named.
//!
//! swoosh is transport-blind everywhere above this module; every verb is generic over `Node<T, D>`.
//! Here, at the composition root, a `--transport` choice binds one concrete backend under the shared
//! persisted identity and pairs it with a single composed discovery, the same for every backend:
//! the explicit `--peer` hints layered over LAN mDNS. So a peer is reached whether it was named on the
//! command line or simply heard on the network, and iroh honors an explicit hint just as quirk does.
//! `quirk+noise` composes the sealed wrapper over quirk, still under that same persisted key. Because
//! every choice derives the [`NodeId`] from the same ed25519 secret, the node keeps ONE address
//! whichever transport is bound: swap the transport, keep the key, reach the same peer. That is the
//! whole point of the seam.

use core::net::SocketAddr;
use core::str::FromStr;
use std::net::ToSocketAddrs;

use bifrost::{Layered, NodeId, StaticDiscovery};
use bifrost_mdns::{Advertising, MdnsDiscovery, MdnsError, Started};
use clap::{Args, ValueEnum};
use eyre::WrapErr as _;

/// The flags every reaching verb shares and no local verb has: which backend to bind, whether the
/// bind stays off n0, and any direct address hints. Flattened into each reach command
/// (`serve`/`ping`/`speed`/`status`) rather than made a root global, so `contact add/ls/rm` (which
/// bind no transport and dial nobody) are never offered a `--transport`/`--local`/`--peer` that would
/// do nothing there. `--home` stays a root global, since it names the node home the address book AND
/// the bound key both live in, meaningful to both families.
#[derive(Debug, Args)]
pub struct ReachArgs {
    /// which backend to bind
    #[arg(
        long,
        value_enum,
        default_value_t,
        value_name = "iroh|quirk|quirk+noise"
    )]
    pub transport: Transport,
    /// no internet discovery or relays: local mDNS or a direct --peer hint
    #[arg(long)]
    pub local: bool,
    /// direct address hint for a peer, `<key>=<addr>` (repeatable)
    // The clap id is `peer-hint`, not `peer`: this frees the id `peer` for the positional `<peer>` slot
    // every dialing verb now names, so a verb hosts both this `--peer` HINT and a positional peer without a
    // clap id collision. The flag NAME stays `--peer` (no user-facing change).
    #[arg(id = "peer-hint", long = "peer", value_name = "key=addr")]
    pub peer: Vec<PeerHint>,
}

/// Which concrete transport to bind under the shared identity. Default [`iroh`](Self::Iroh).
///
/// [`QuirkNoise`](Self::QuirkNoise) is quirk behind the sealed wrapper: the same direct-only backend
/// with a Noise handshake over it, so the reached key is proven rather than announced. Bare
/// [`Quirk`](Self::Quirk) is the announced base of the composition; a signet-rooted gate refuses to
/// arm over it and a credential is never written to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum Transport {
    /// across the internet, NAT-traversing; serves gated
    #[default]
    Iroh,
    /// our own UDP transport; direct-only; reaches open services; cannot serve gated
    Quirk,
    /// our own UDP transport; direct-only; serves gated; a Noise handshake proves the key
    #[value(name = "quirk+noise")]
    QuirkNoise,
}

impl Transport {
    /// The short name of the bound backend, for diagnostics like `swoosh status` that report which
    /// transport carried the session. The label of the concrete backend chosen at the seam, passed as a
    /// plain value so the verb stays transport-blind and never names the backend itself.
    pub fn name(self) -> &'static str {
        match self {
            Self::Iroh => "iroh",
            Self::Quirk => "quirk",
            Self::QuirkNoise => "quirk+noise",
        }
    }
}

/// A direct hint for one peer: its [`NodeId`] mapped to reachable addresses. Parsed at the clap boundary
/// from `<key>=<host:port>`, where the host may be an IP OR a DNS name (a Docker service, a LAN host): it
/// resolves via the system resolver, so a readable `nodea:9000` reaches a peer by name. Layered under LAN
/// mDNS to form the discovery both transports use.
///
/// A DIFFERENT concept from the dial target [`Peer`](crate::peer::Peer): a hint says WHERE to find a key,
/// the dial target says WHO to reach. Named `PeerHint` so the two never share the `Peer` name that used to
/// force the collision gymnastics. It retains its ORIGINAL text so `swoosh ssh` can forward it verbatim
/// into the tunnel-connect bridge, resolving the address at the actual dial site, not the launcher.
#[derive(Debug, Clone)]
pub struct PeerHint {
    node: NodeId,
    addrs: Vec<SocketAddr>,
    /// The original `<key>=<addr>` text, retained so `ssh` forwards the hint verbatim (DNS resolves at the
    /// dial site, not here).
    text: String,
}

/// The discovery both transports compose: explicit `--peer` hints layered over LAN mDNS.
///
/// The static hints lead (a hand-fed address wins over a heard one for the same peer), and mDNS fills
/// in every peer no hint named. An empty resolve from both means "no hints, let the transport try",
/// which is how iroh keeps self-discovering when nothing is known locally.
pub type Discovery = Layered<StaticDiscovery, MdnsDiscovery>;

/// How far the composed discovery's mDNS half actually reaches, read off the ONE `advertise` call that
/// started it.
///
/// A first-class reachability tell: a node that publishes nothing, a node that publishes an address only
/// it can dial, and a node other machines can hear all browse identically, so nothing downstream can ask
/// the discovery value which one it is. The banner keys its `local` line on this, so a surface reports
/// the reach that happened instead of the one it assumed. Each degraded case carries its own cause, so
/// the report names why rather than leaving the operator to guess.
///
/// swoosh's own enum rather than [`Advertising`] itself: this crosses into a clap command struct and is
/// rendered by a pure banner function the unit tests drive, and `Advertising` is constructible only by a
/// live `advertise` call.
#[derive(Debug)]
pub enum MdnsState {
    /// Advertising addresses that reach past this machine: another host hears this node and dials what
    /// it heard. Carries the published set, at least one address (the conversion below is the only
    /// constructor, over a record that is non-empty by construction).
    OnLan(Vec<SocketAddr>),
    /// Advertising loopback addresses only: another process on THIS machine finds this node by the key,
    /// and no other host can, because a loopback address names the dialer's own machine.
    LoopbackOnly,
    /// Browsing without advertising: this node hears peers and puts no record of its own on the wire,
    /// with the cause of the empty advertisement.
    BrowseOnly(MdnsError),
    /// mDNS could not start at all (multicast unavailable), so the layer fell back to
    /// [`MdnsDiscovery::disabled`]: this node neither advertises nor hears anyone, and reach falls to
    /// the internet or a handed address.
    Blocked,
}

impl From<Advertising> for MdnsState {
    /// Read the started advertisement into the state a surface reports. The loopback record's addresses
    /// are dropped on purpose: no surface may hand them to a peer, so the arm carries only its name.
    fn from(advertising: Advertising) -> Self {
        match advertising {
            Advertising::OnLan(advertised) => Self::OnLan(advertised.addrs().to_vec()),
            Advertising::LoopbackOnly(_) => Self::LoopbackOnly,
            Advertising::BrowseOnly(cause) => Self::BrowseOnly(cause),
        }
    }
}

/// The composed discovery for a freshly bound transport, plus the live state of its mDNS half.
///
/// The two travel together because the ONE `advertise` call that starts mDNS is also the one source
/// of the reach tell: a caller either composes discovery here and receives the truth about it, or it
/// would have to predict the outcome a second time from a bind it no longer owns.
pub struct ComposedDiscovery {
    /// The static hints layered over mDNS, to hand [`Node::new`](bifrost::Node::new).
    pub discovery: Discovery,
    /// How far the mDNS layer's advertisement reaches, or that it never started.
    pub mdns: MdnsState,
}

impl PeerHint {
    /// The original `<key>=<addr>` token, for `ssh` to forward verbatim into the ProxyCommand so the
    /// address resolves at the actual dial site (`tunnel-connect`), not at the launcher.
    pub fn as_arg(&self) -> &str {
        &self.text
    }

    /// Compose the discovery for a freshly bound `transport`: the `--peer` hints layered over an mDNS
    /// resolver that advertises this node at the sockets it bound and browses the LAN for peers, plus
    /// how far that advertisement reaches.
    ///
    /// Called once per run, at the seam, after the transport binds (so its bind is known). If mDNS
    /// cannot start at all (multicast blocked), discovery degrades to the static hints alone rather
    /// than failing the whole command, since a hinted or self-discovering dial still works; the
    /// returned [`MdnsState`] carries that, and every lesser degradation, so a surface can say so.
    pub fn discovery<T: bifrost::Transport>(
        transport: &T,
        peers: impl IntoIterator<Item = Self>,
    ) -> ComposedDiscovery {
        let mut hints = StaticDiscovery::new();
        for Self { node, addrs, .. } in peers {
            hints.insert(node, addrs);
        }
        // Bind truth, never `local_addr`'s hints: the hints rewrite an unspecified bind to loopback, so
        // handing them over would advertise `127.0.0.1` for a node bound to every interface and point
        // every dialer at its own machine. Discovery owns what of the bind is publishable.
        let (mdns, state) = match MdnsDiscovery::advertise(
            transport.node_id(),
            transport.bound_sockets(),
        ) {
            Ok(Started {
                discovery,
                advertising,
            }) => (discovery, MdnsState::from(advertising)),
            Err(err) => {
                tracing::warn!(error = %err, "mDNS discovery unavailable; using --peer hints only");
                (MdnsDiscovery::disabled(), MdnsState::Blocked)
            }
        };
        ComposedDiscovery {
            discovery: Layered::new(hints, mdns),
            mdns: state,
        }
    }
}

impl FromStr for PeerHint {
    /// `eyre::Report` so the clap boundary surfaces a source-chained parse failure; swoosh is a binary,
    /// so it speaks eyre rather than a typed library error here.
    type Err = eyre::Report;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (key, host) = text
            .split_once('=')
            .ok_or_else(|| eyre::eyre!("expected <key>=<host:port>"))?;
        let node = key.parse().wrap_err("invalid peer key")?;
        // An IP passes through; a DNS name (Docker service, LAN host) resolves via the system resolver.
        let addrs: Vec<SocketAddr> = host
            .to_socket_addrs()
            .wrap_err_with(|| format!("could not resolve peer address {host:?}"))?
            .collect();
        if addrs.is_empty() {
            eyre::bail!("peer address {host:?} resolved to no addresses");
        }
        // Retain the original token so `ssh` can forward it verbatim (DNS resolves at the dial site).
        Ok(Self {
            node,
            addrs,
            text: text.to_owned(),
        })
    }
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod transport_tests;
