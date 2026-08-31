//! `swoosh grant`: mint, narrow, or revoke a `sheer:` capability link for one of this node's services.
//!
//! A local group: unlike the reaching verbs, no leaf binds a transport or dials. `issue` signs with this
//! node's persisted identity (the key a served service roots at); `narrow` and `revoke` are wholly
//! offline. They wrap tightbeam's cap leaves in-process, so a link minted here roots at the same key
//! `swoosh serve` runs under. One binary: no `tightbeam` on PATH, one identity throughout.

use clap::Subcommand;

use super::attenuate::AttenuateCmd;
use super::revoke::RevokeCmd;
use super::share::ShareCmd;

/// Mint, narrow, or revoke a `sheer:` capability link.
#[derive(Debug, Subcommand)]
pub enum GrantCmd {
    /// Mint a `sheer:` capability link granting one service, expiring, attenuable, delegable.
    Issue(ShareCmd),
    /// Narrow an existing `sheer:` link offline before handing it on.
    Narrow(AttenuateCmd),
    /// Revoke a `sheer:` link so this node refuses it at once, without waiting for expiry.
    Revoke(RevokeCmd),
}
