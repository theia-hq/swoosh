//! `swoosh grant`: issue, list, narrow, or revoke `swoosh:` capability links for this node's services.
//!
//! A local group: unlike the reaching verbs, no leaf binds a transport or dials. `issue` signs with this
//! node's persisted identity (the key a served service roots at); `ls`, `narrow`, and `revoke` are wholly
//! offline. They wrap tightbeam's cap leaves in-process, so a link minted here roots at the same key
//! `swoosh serve` runs under. One binary: no `tightbeam` on PATH, one identity throughout.

use clap::Subcommand;

use super::{attenuate, grant_ls, revoke, share};

/// Issue, list, narrow, or revoke `swoosh:` capability links.
#[derive(Debug, Subcommand)]
pub enum GrantCmd {
    /// Mint a `swoosh:` capability link granting one service.
    Issue(share::ShareCmd),
    /// List the grants you have issued, grouped by service.
    Ls(grant_ls::LsCmd),
    /// Narrow an existing `swoosh:` link offline before handing it on.
    Narrow(attenuate::AttenuateCmd),
    /// Revoke a grant (a `swoosh:` link or a peer you granted) at once.
    Revoke(revoke::RevokeCmd),
}
