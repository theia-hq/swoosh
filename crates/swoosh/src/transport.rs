//! The transport-select seam: the one place a concrete transport is named.
//!
//! swoosh is transport-blind everywhere above this module; every verb is generic over `Node<T, D>`.
//! Here, at the composition root, a `--transport` choice binds one concrete backend under the shared
//! persisted identity and pairs it with the discovery that backend needs. iroh self-discovers, so it
//! composes with [`NoDiscovery`]; quirk has no internal discovery, so it composes with a
//! [`StaticDiscovery`] seeded from `--peer` hints. Because both backends derive the [`NodeId`] from the
//! same ed25519 secret, the node keeps ONE address whichever transport is bound: swap the transport,
//! keep the key, reach the same peer. That is the whole point of the seam.

use core::net::SocketAddr;
use core::str::FromStr;

use bifrost::{NodeId, StaticDiscovery};
use clap::ValueEnum;
use eyre::WrapErr as _;

/// Which concrete transport to bind under the shared identity. Default [`iroh`](Self::Iroh).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum Transport {
    /// iroh: QUIC with NAT traversal and relay fallback, reachable across the internet. Self-
    /// discovering, so it needs no `--peer` hints.
    #[default]
    Iroh,
    /// quirk: our own from-scratch QUIC over UDP. Direct-only (no NAT traversal yet), so a client
    /// reaches a peer by feeding back the `--peer <key>=<addr>` the peer's `serve` prints.
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

/// A direct address hint for one peer: its [`NodeId`] mapped to a reachable [`SocketAddr`]. Parsed at
/// the clap boundary from `<key>=<socketaddr>`, so a handler receives already-valid domain values and
/// never re-parses a string. Feeds quirk's [`StaticDiscovery`], since quirk cannot discover a peer's
/// address on its own.
#[derive(Debug, Clone, Copy)]
pub struct Peer {
    node: NodeId,
    addr: SocketAddr,
}

impl Peer {
    /// Build a [`StaticDiscovery`] table from a set of peer hints, one direct address per identity.
    pub fn discovery(peers: impl IntoIterator<Item = Self>) -> StaticDiscovery {
        let mut discovery = StaticDiscovery::new();
        for Self { node, addr } in peers {
            discovery.insert(node, vec![addr]);
        }
        discovery
    }
}

impl FromStr for Peer {
    /// `eyre::Report` so the clap boundary surfaces a source-chained parse failure; swoosh is a binary,
    /// so it speaks eyre rather than a typed library error here.
    type Err = eyre::Report;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (key, addr) = text
            .split_once('=')
            .ok_or_else(|| eyre::eyre!("expected <key>=<socketaddr>"))?;
        let node = key.parse().wrap_err("invalid peer key")?;
        let addr = addr.parse().wrap_err("invalid peer address")?;
        Ok(Self { node, addr })
    }
}
