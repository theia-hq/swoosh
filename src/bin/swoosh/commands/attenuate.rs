//! `swoosh grant attenuate <link>`: narrow an existing `sheer:` link, offline, before handing it on.
//!
//! A local verb: no identity, no transport, no network. It calls nauthy's
//! [`Link::narrow`](nauthy::Link::narrow) grant logic; it only ever adds constraints, so the result
//! is never broader than the input. A holder uses it to hand a peer a strictly smaller slice of their own
//! access.

use clap::Args;
use nauthy::{CapError, Link, Service};
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
    /// restrict the link to one service
    #[arg(
        long,
        value_name = "service",
        long_help = "Narrowing only adds checks: naming a service the link does not permit yields a link \
                     nothing admits."
    )]
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
        let link: Link = self.link.parse()?;
        let narrowed = link
            .narrow(self.service.as_ref(), shorten)
            .map_err(narrow_failure)?;
        println!("{narrowed}");
        Ok(())
    }
}

/// Map a refused [`Link::narrow`] to a line a holder can act on.
///
/// The common refusal is a SEALED link (a bound slip, or a bearer slip issued without `--delegable`):
/// nauthy reports it as [`CapError::Attenuate`], whose Display is the token library's internal "tried to
/// seal an already sealed token", a string that names nothing a user can act on. Every other refusal
/// keeps its own report unchanged.
fn narrow_failure(error: CapError) -> eyre::Report {
    match error {
        CapError::Attenuate(_) => eyre::eyre!(
            "this link cannot be narrowed; only a link issued with `swoosh grant issue --delegable` can be narrowed"
        ),
        other => eyre::Report::new(other),
    }
}

#[cfg(test)]
mod tests {
    use clap::{Args as _, Command};

    use super::*;

    /// B2: a sealed link (the default from `swoosh grant issue`, and every bound slip by construction)
    /// is refused with a line naming the state and the fix, never the token library's internal
    /// "tried to seal an already sealed token".
    #[test]
    fn a_sealed_link_is_refused_with_a_teaching_line() {
        let identity = nauthy::Identity::from_secret(&[7u8; 32]).expect("valid secret");
        let link = Link::mint(
            &identity,
            &"ssh".parse().expect("valid service"),
            core::time::Duration::from_secs(3600),
        )
        .expect("mint a link")
        .seal()
        .expect("seal the link");
        let cmd = AttenuateCmd {
            link: link.to_string(),
            service: None,
            expires: Some("10m".parse().expect("a valid span")),
        };

        let error = cmd
            .run()
            .expect_err("a sealed link must refuse, never mint a pretence");
        let message = format!("{error:#}");
        assert!(
            message.contains("cannot be narrowed") && message.contains("--delegable"),
            "the refusal names the outcome and the fix: {message}"
        );
        assert!(
            !message.contains("tried to seal an already sealed token")
                && !message.contains("attenuate capability"),
            "the token library's internal string never reaches the user: {message}"
        );
    }

    /// The mapping rewrites ONLY nauthy's sealed refusal: an unsealed (delegable) link still narrows
    /// offline.
    #[test]
    fn a_delegable_link_still_narrows() {
        let identity = nauthy::Identity::from_secret(&[8u8; 32]).expect("valid secret");
        let service: Service = "ssh".parse().expect("valid service");
        let link = Link::mint(&identity, &service, core::time::Duration::from_secs(3600))
            .expect("mint a delegable link");
        let cmd = AttenuateCmd {
            link: link.to_string(),
            service: Some(service),
            expires: None,
        };
        cmd.run().expect("an unsealed link narrows offline");
    }

    /// B2: the `--service` help keeps the `-h` line to one clause and carries the monotone truth on the
    /// `--help` block, so the flag is a map row on `-h`, not a paragraph (DOCS-BAR help budget).
    #[test]
    fn service_help_splits_the_short_line_from_the_long_truth() {
        let mut cmd = AttenuateCmd::augment_args(Command::new("narrow"));
        let short = cmd
            .render_help()
            .to_string()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            short.contains("restrict the link to one service"),
            "the short help is the one-clause line: {short}"
        );
        assert!(
            !short.contains("Narrowing only adds checks"),
            "the monotone truth must not ride the short help: {short}"
        );
        assert!(
            !short.contains("must be one the link already permits"),
            "the unchecked promise is gone: {short}"
        );

        let long = cmd
            .render_long_help()
            .to_string()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            long.contains(
                "Narrowing only adds checks: naming a service the link does not permit yields a link \
                 nothing admits."
            ),
            "the long help carries the monotone truth: {long}"
        );
    }
}
