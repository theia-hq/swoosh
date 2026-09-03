//! `swoosh grant`: issue, list, narrow, or revoke `sheer:` capability links for this node's services.
//!
//! A local group: unlike the reaching verbs, no leaf binds a transport or dials. `issue` signs with this
//! node's persisted identity (the key a served service roots at); `ls`, `narrow`, and `revoke` are wholly
//! offline. They wrap tightbeam's cap leaves in-process, so a link minted here roots at the same key
//! `swoosh serve` runs under. One binary: no `tightbeam` on PATH, one identity throughout.

use clap::Subcommand;

use super::attenuate::AttenuateCmd;
use super::grant_ls::LsCmd;
use super::revoke::RevokeCmd;
use super::share::ShareCmd;

/// Issue, list, narrow, or revoke `sheer:` capability links.
#[derive(Debug, Subcommand)]
pub enum GrantCmd {
    /// Mint a `sheer:` capability link granting one service.
    Issue(ShareCmd),
    /// List the grants you have issued, grouped by service.
    #[command(visible_alias = "list")]
    Ls(LsCmd),
    /// Narrow an existing `sheer:` link offline before handing it on.
    Narrow(AttenuateCmd),
    /// Revoke a grant (a `sheer:` link or a peer you granted) at once.
    Revoke(RevokeCmd),
}
