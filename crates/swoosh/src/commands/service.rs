//! `swoosh service`: the node-service control group.
//!
//! Nesting is earned: this group owns three real ops (`ls`, `enable`, `disable`), so it reads as a noun with
//! verbs, like the `grant` group. It follows the one control grammar (delib-47): BARE acts on YOUR OWN node,
//! `--at <peer>` acts on a peer.
//!
//! - `service ls [--at <peer>]` reads the served menu: bare reads your own live node over the local
//!   control socket (needs `serve --resident`), `--at` reaches a peer's `control.services`. See [`ls`].
//! - `service enable <svc>` / `service disable <svc>` toggle one of YOUR node's services by writing
//!   `<home>/disabled`, honored LIVE by a running `serve` with no restart. No `--at`: you never remotely
//!   toggle a peer's service (a wire mutation the design forbids). See [`toggle`].

use clap::Subcommand;

pub mod ls;
pub mod toggle;

pub use ls::ServiceLsCmd;
pub use toggle::ServiceToggleCmd;

/// Read, enable, or disable this node's services (or read a peer's with `service ls --at <peer>`).
#[derive(Debug, Subcommand)]
pub enum ServiceCmd {
    /// List the served menu (bare: your own node; `--at <peer>`: a peer).
    #[command(visible_alias = "list")]
    Ls(ServiceLsCmd),
    /// Re-enable a disabled service (a file-write on `<home>/disabled`, honored live, no restart).
    Enable(ServiceToggleCmd),
    /// Disable a service (a file-write on `<home>/disabled`, persisted fail-closed, honored live).
    Disable(ServiceToggleCmd),
}
