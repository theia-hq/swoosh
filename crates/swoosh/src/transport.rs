//! The transport-select seam: the one place a concrete transport is named.
//!
//! swoosh is transport-blind everywhere above this module; every verb is generic over `Node<T, D>`.
//! Here, at the composition root, a `--transport` choice binds one concrete backend under the shared
//! persisted identity and pairs it with a single composed discovery, the same for either backend:
//! the explicit `--peer` hints layered over LAN mDNS. So a peer is reached whether it was named on the
//! command line or simply heard on the network, and iroh honors an explicit hint just as quirk does.
//! Because both backends derive the [`NodeId`] from the same ed25519 secret, the node keeps ONE
//! address whichever transport is bound: swap the transport, keep the key, reach the same peer. That
//! is the whole point of the seam.

use core::net::SocketAddr;
use core::str::FromStr;
use std::net::ToSocketAddrs;

use bifrost::{Layered, NodeId, StaticDiscovery};
use bifrost_mdns::MdnsDiscovery;
use clap::{Args, ValueEnum};
use eyre::WrapErr as _;

/// The flags every reaching verb shares and no local verb has: which backend to bind and any direct
/// address hints. Flattened into each reach command (`serve`/`ping`/`speed`/`status`) rather than made
/// a root global, so `contact add/ls/rm` (which bind no transport and dial nobody) are never offered a
/// `--transport` or `--peer` that would do nothing there. `--key` stays a root global, since it names
/// the identity dir the address book AND the bound key both live in, meaningful to both families.
#[derive(Debug, Args)]
pub struct ReachArgs {
    /// Backend to bind under this identity
    #[arg(long, value_enum, default_value_t, value_name = "iroh|quirk")]
    pub transport: Transport,
    /// Direct address hint for a peer, `<key>=<addr>` (repeatable)
    #[arg(long, value_name = "key=addr")]
    pub peer: Vec<Peer>,
}

/// Which concrete transport to bind under the shared identity. Default [`iroh`](Self::Iroh).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum Transport {
    /// across the internet, NAT-traversing
    #[default]
    Iroh,
    /// our own QUIC; LAN / direct-only
    Quirk,
}

impl Transport {
    /// The short name of the bound backend, for diagnostics like `swoosh status` that report which
    /// transport carried the session. The label of the concrete backend chosen at the seam, passed as a
    /// plain value so the verb stays transport-blind and never names the backend itself.
    pub fn name(self) -> &'static str {
        match self {
            Self::Iroh => "iroh",
            Self::Quirk => "quirk",
        }
    }
}

/// A direct hint for one peer: its [`NodeId`] mapped to reachable addresses. Parsed at the clap boundary
/// from `<key>=<host:port>`, where the host may be an IP OR a DNS name (a Docker service, a LAN host): it
/// resolves via the system resolver, so a readable `nodea:9000` reaches a peer by name. Layered under LAN
/// mDNS to form the discovery both transports use.
#[derive(Debug, Clone)]
pub struct Peer {
    node: NodeId,
    addrs: Vec<SocketAddr>,
}

/// The discovery both transports compose: explicit `--peer` hints layered over LAN mDNS.
///
/// The static hints lead (a hand-fed address wins over a heard one for the same peer), and mDNS fills
/// in every peer no hint named. An empty resolve from both means "no hints, let the transport try",
/// which is how iroh keeps self-discovering when nothing is known locally.
pub type Discovery = Layered<StaticDiscovery, MdnsDiscovery>;

impl Peer {
    /// Compose the discovery for a freshly bound `transport`: the `--peer` hints layered over an mDNS
    /// resolver that advertises this node at its bound local addresses and browses the LAN for peers.
    ///
    /// Called once per run, at the seam, after the transport binds (so its local address is known).
    /// If mDNS cannot start (multicast blocked, no addresses), discovery degrades to the static hints
    /// alone rather than failing the whole command, since a hinted or self-discovering dial still works.
    pub fn discovery<T: bifrost::Transport>(
        transport: &T,
        peers: impl IntoIterator<Item = Self>,
    ) -> Discovery {
        let mut hints = StaticDiscovery::new();
        for Self { node, addrs } in peers {
            hints.insert(node, addrs);
        }
        let local = transport.local_addr();
        let mdns = match MdnsDiscovery::advertise(local.node, local.hints) {
            Ok(mdns) => mdns,
            Err(err) => {
                tracing::warn!(error = %err, "mDNS discovery unavailable; using --peer hints only");
                MdnsDiscovery::disabled()
            }
        };
        Layered::new(hints, mdns)
    }
}

impl FromStr for Peer {
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
        Ok(Self { node, addrs })
    }
}
