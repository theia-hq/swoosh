//! `swoosh attenuate <link>`: narrow an existing `sheer:` link, offline, before handing it on.
//!
//! A local verb: no identity, no transport, no network. Wraps tightbeam's [`AttenuateCmd`] in-process; it
//! only ever adds constraints, so the result is never broader than the input. A holder uses it to hand a
//! peer a strictly smaller slice of their own access.

use clap::Args;
use tightbeam::AttenuateCmd as Inner;

/// Narrow an existing `sheer:` link offline before handing it on.
#[derive(Debug, Args)]
pub struct AttenuateCmd {
    #[command(flatten)]
    inner: Inner,
}

impl AttenuateCmd {
    /// Narrow the link and print the result.
    pub fn run(self) -> eyre::Result<()> {
        self.inner.run()
    }
}
