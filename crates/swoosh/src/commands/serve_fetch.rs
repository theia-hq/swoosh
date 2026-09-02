use fetch::OriginAllowlist;
use nauthy::Admitted;
use tightbeam::open_policy::OptIn;
use tightbeam::tunnel::{BoxRead, BoxWrite, Handler};

/// The `fetch:` handler swoosh injects: the node acts as an HTTP client and streams an origin response back
/// over the admitted stream. It carries its own SSRF guard, so it does not require the gate (a `--public
/// fetch:` is a deliberate choice, not an accidental keyless shell).
///
/// It holds the operator's [`OriginAllowlist`] baked in at expose time (`serve news=fetch:https://news.example`):
/// the handler refuses any request whose origin is not in the list before it connects. A bare `fetch:` bakes
/// an EMPTY allowlist, which is unconstrained (any public origin), so an unscoped service is unchanged.
pub(super) struct Fetch {
    pub(super) allow: OriginAllowlist,
}

impl Handler for Fetch {
    // OPT-IN: `fetch:` carries its own SSRF guard, so a `--public fetch:` is a deliberate choice, not an
    // accidental keyless shell.
    type Public = OptIn;

    async fn serve(
        &self,
        _admitted: Admitted,
        mut writer: BoxWrite,
        mut reader: BoxRead,
    ) -> eyre::Result<()> {
        fetch::serve_fetch(&mut writer, &mut reader, &self.allow).await?;
        Ok(())
    }
}
