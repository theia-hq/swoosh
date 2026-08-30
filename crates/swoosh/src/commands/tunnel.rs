//! `swoosh tunnel`: expose a local service to peers, or bind a peer's exposed service to a local port.
//!
//! A reach group: unlike the local `contact` group, both leaves bind a transport and dial. They wrap
//! tightbeam's `expose`/`connect` in-process under swoosh's OWN persisted identity, the same one
//! `swoosh ssh` and `serve` bind, so a service exposed here roots at the key peers already dial and a
//! minted share-link verifies against it. One binary: no `tightbeam` on PATH, one identity throughout.
//!
//! Distinct from the hidden `tunnel-connect` leaf (the `swoosh ssh` ProxyCommand ABI, `--stdio` only):
//! that is plumbing for ssh; this is the public port-forward a user types. Each leaf owns its
//! `run(self, node, ...)` and carries the shared [`ReachArgs`](crate::transport::ReachArgs) so `--peer`
//! hints and `--transport` reach it like every other reaching verb.

use clap::Subcommand;

pub mod connect;
pub mod expose;

use connect::TunnelConnectCmd;
use expose::TunnelExposeCmd;

/// Expose a local service to peers, or bind a peer's exposed service to a local port.
#[derive(Debug, Subcommand)]
pub enum TunnelCmd {
    /// Expose a local service to peers who hold this node's key, gated by your signet.
    Expose(TunnelExposeCmd),
    /// Reach a peer's exposed service and bind it to a local port.
    Connect(TunnelConnectCmd),
}
