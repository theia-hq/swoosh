//! `swoosh grant attenuate <link>`: narrow an existing `sheer:` link, offline, before handing it on.
//!
//! A local verb: no identity, no transport, no network. It calls tightbeam's
//! [`narrow_link`](tightbeam::tunnel::narrow_link) grant logic; it only ever adds constraints, so the result
//! is never broader than the input. A holder uses it to hand a peer a strictly smaller slice of their own
//! access.

use clap::Args;
use nauthy::Service;
use tightbeam::duration::Lifetime;

/// Narrow an existing `sheer:` link offline before handing it on.
///
/// This needs no secret and no network. It only ever adds constraints, so the result is never broader than
/// the input; a holder uses it to hand a colleague a strictly smaller slice of their own access.
#[derive(Debug, Args)]
pub struct AttenuateCmd {
    /// The `sheer:` link to narrow.
    #[arg(value_name = "link")]
    pub link: String,
    /// Restrict the link to this service (must be one the link already permits).
    #[arg(long, value_name = "service")]
    pub service: Option<Service>,
    /// Shorten the link to expire within this span from now, e.g. `30m`. Only ever tightens: a span
    /// longer than the link's remaining life does not extend it.
    #[arg(long, value_name = "duration")]
    pub expires: Option<Lifetime>,
}

impl AttenuateCmd {
    /// Narrow the link and print the result.
    pub fn run(self) -> eyre::Result<()> {
        let shorten = self.expires.map(Lifetime::duration);
        let narrowed = tightbeam::tunnel::narrow_link(&self.link, self.service.as_ref(), shorten)?;
        println!("{narrowed}");
        Ok(())
    }
}
