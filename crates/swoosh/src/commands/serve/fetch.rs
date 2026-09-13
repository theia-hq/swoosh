use fetch::{Limits, OriginAllowlist};
use tightbeam::open_policy::OptIn;
use tightbeam::tunnel::{BoxRead, BoxWrite, Handler, Metering, ServeError, Served};

/// The `fetch:` handler swoosh injects: the node acts as an HTTP client and streams an origin response back
/// over the admitted stream. It carries its own SSRF guard, so it does not require the gate (a `--public
/// fetch` is a deliberate choice, not an accidental keyless shell).
///
/// It holds the operator's [`OriginAllowlist`] baked in at expose time (`serve news=fetch:https://news.example`):
/// the handler refuses any request whose origin is not in the list before it connects. A bare `fetch:` bakes
/// an EMPTY allowlist, which is unconstrained (any public origin), so an unscoped service is unchanged.
///
/// The bounds ride the scope by construction: a SCOPED instance (a non-empty allowlist) is metered (a
/// 16 MiB body cap and a 30-second total timeout), so a public fetch is a bounded unit, and an
/// unconstrained instance is member-only (the open-relay wall refuses a public one) and streams
/// unbounded, which is the metering it reports.
pub(super) struct Fetch {
    pub(super) allow: OriginAllowlist,
}

impl Fetch {
    /// The responder bounds this instance applies. Derived from the scope in ONE place, so what the
    /// handler serves and what it reports can never disagree: scoped is metered, unconstrained is the
    /// member-only unbounded path.
    fn limits(&self) -> Limits {
        if self.allow.is_unconstrained() {
            Limits::unmetered()
        } else {
            Limits::metered()
        }
    }
}

impl Handler for Fetch {
    // OPT-IN: `fetch:` carries its own SSRF guard, so a `--public fetch` is a deliberate choice, not an
    // accidental keyless shell.
    type Exposure = OptIn;

    /// The bounds this instance actually applies, read from the same scope `serve` derives them from.
    fn metering(&self) -> Metering {
        if self.limits().is_metered() {
            Metering::Metered
        } else {
            Metering::Unmetered
        }
    }

    async fn serve(
        &self,
        _served: Served<Self>,
        mut writer: BoxWrite,
        mut reader: BoxRead,
    ) -> Result<(), ServeError> {
        // `serve_fetch` already speaks `io::Error`, which the contract maps through `From`.
        fetch::serve_fetch(&mut writer, &mut reader, &self.allow, self.limits()).await?;
        Ok(())
    }
}

#[cfg(test)]
mod fetch_tests {
    use fetch::OriginAllowlist;
    use tightbeam::tunnel::{Handler as _, Metering};

    use super::Fetch;

    /// The scoped instance is metered by construction; the unconstrained one reports unmetered, which is
    /// what an open route would narrate (and the open-relay wall never lets that route be public).
    #[test]
    fn metering_follows_the_scope() {
        let scoped = Fetch {
            allow: OriginAllowlist::parse(["https://news.example"]).expect("the origin parses"),
        };
        assert_eq!(scoped.metering(), Metering::Metered);
        assert_eq!(
            Fetch {
                allow: OriginAllowlist::default(),
            }
            .metering(),
            Metering::Unmetered
        );
    }
}
