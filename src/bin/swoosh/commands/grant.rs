//! `swoosh grant`: issue or narrow `swoosh:` capability links for this node's services.
//!
//! A local group: unlike the reaching verbs, no leaf binds a transport or dials. `issue` signs with this
//! node's persisted identity (the key a served service roots at); `narrow` is wholly offline; `status`
//! lists what was issued, and `swoosh revoke` takes a link back. They wrap tightbeam's cap leaves
//! in-process, so a link minted here roots at the same key `swoosh serve` runs under. One binary: no
//! `tightbeam` on PATH, one identity throughout.

use clap::Subcommand;

use super::{attenuate, share};

/// Issue or narrow `swoosh:` capability links.
#[derive(Debug, Subcommand)]
pub enum GrantCmd {
    /// Mint a `swoosh:` capability link granting one service.
    Issue(share::ShareCmd),
    /// Narrow an existing `swoosh:` link offline before handing it on.
    Narrow(attenuate::AttenuateCmd),
}
