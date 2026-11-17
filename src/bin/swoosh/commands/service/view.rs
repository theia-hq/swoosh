use core::fmt;
use std::io;

use swoosh::escape::{Escaped, EscapedComplete, EscapedPath};
use swoosh::home::Home;
use swoosh::serve::control_codec::ControlError;

use crate::commands::service_rows::{Span, StateLine, width};
use crate::commands::service_state::{ReadError, ReadMode, ResidentObservation, ServiceState};

/// The bare command reads the saved next-start list and one local resident snapshot.
#[derive(Debug)]
pub struct View;

impl View {
    /// The bare command reads the saved next-start list and one local resident snapshot.
    pub async fn run(self, home: &Home) -> eyre::Result<()> {
        self.run_to(home, &mut io::stdout().lock()).await
    }

    async fn run_to(self, home: &Home, out: &mut impl io::Write) -> eyre::Result<()> {
        // Complete both observations before emitting any success-looking output.
        let state = ServiceState::read(home, ReadMode::Detail)
            .await
            .map_err(|error| read_report(home, error))?;
        render(&state, out)
    }
}

fn read_report(home: &Home, error: ReadError) -> eyre::Report {
    match error {
        ReadError::Daemon(ControlError::Protocol(_)) => {
            eyre::eyre!("could not read local service detail: invalid control response")
        }
        ReadError::Daemon(error) => eyre::eyre!("{}", Escaped(&error.to_string())),
        error => eyre::Report::new(error).wrap_err(format!(
            "could not read local service configuration from {}",
            EscapedPath(&home.serve_toml())
        )),
    }
}

fn render(state: &ServiceState, out: &mut impl io::Write) -> eyre::Result<()> {
    let ResidentObservation::Detail(snapshot) = &state.resident else {
        return Err(eyre::eyre!(
            "could not read local service detail: wrong local read mode"
        ));
    };
    let entries = state.started.entries();
    let saved: Vec<_> = entries
        .iter()
        .filter_map(|entry| entry.split_once('='))
        .collect();
    let mut rows: Vec<_> = saved
        .iter()
        .map(|&(name, configured)| {
            let bound = snapshot.as_ref().and_then(|snapshot| snapshot.get(name));
            let target = bound.map_or(configured, |pair| pair.target().as_str());
            let off = state.off.contains(name);
            let unbound = snapshot.is_some() && bound.is_none();
            // The resident's refusal bit is not the file's off mark: removal or an unreadable file sets it
            // too, so a refusing route that is not off reads neither `on` nor `off`.
            let (on, on_and) = if bound.is_some_and(|pair| pair.refused()) {
                ("refusing new connections", "refusing new connections,")
            } else {
                ("on", "on,")
            };
            // A relative path names a directory only where `serve` starts, which this reader cannot know:
            // it is shown as written beside any bound target, never compared with it.
            if state.started.is_relative(name) {
                let saved = bound.is_some().then_some(configured);
                let state = match (unbound, off) {
                    (true, false) => State::Relative("from the next start,", saved),
                    (true, true) => State::Relative("off, from the next start,", saved),
                    (false, false) => State::Relative(on_and, saved),
                    (false, true) => State::Relative("off,", saved),
                };
                return Row {
                    name,
                    target,
                    state,
                };
            }
            let next = (target != configured).then_some(configured);
            let state = match (next, unbound, off) {
                (Some(next), _, false) => State::Next(on_and, next),
                (Some(next), _, true) => State::Next("off,", next),
                (None, true, false) => State::Fixed("from the next start"),
                (None, true, true) => State::Fixed("off, from the next start"),
                (None, false, false) => State::Fixed(on),
                (None, false, true) => State::Fixed("off"),
            };
            Row {
                name,
                target,
                state,
            }
        })
        .collect();
    let held = |name: &str| saved.iter().any(|&(held, _)| held == name);
    // A bound name the file does not hold shows its bound target, in the snapshot's order (by name: it
    // carries no bind order). Nothing here says whether the start named it or the file dropped it since: the
    // snapshot carries no origin.
    for pair in snapshot.iter().flat_map(|snapshot| snapshot.pairs()) {
        let name = pair.name().as_str();
        if held(name) {
            continue;
        }
        let state = match (state.off.contains(name), pair.refused()) {
            (true, _) => "off, not saved",
            (false, true) => "refusing new connections, not saved",
            (false, false) => "on, not saved",
        };
        rows.push(Row {
            name,
            target: pair.target().as_str(),
            state: State::Fixed(state),
        });
    }
    let services = rows.len();
    // An off mark outlives removal, so the file can hold one with no service behind it: shown with no target,
    // since none is saved or bound to show.
    for name in &state.off {
        if !held(name)
            && !snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.contains(name))
        {
            rows.push(Row {
                name,
                target: "",
                state: State::Fixed("off, no service saved"),
            });
        }
    }
    write_rows(&rows, out)?;
    if services == 0 {
        if !rows.is_empty() {
            writeln!(out)?;
        }
        writeln!(
            out,
            "Serving nothing.\nTo add a service:\n  swoosh service add <service>"
        )?;
        return Ok(());
    }
    if snapshot.is_none() {
        write!(
            out,
            "\nNot serving now.\nTo start serving:\n  swoosh serve\n"
        )?;
    }
    Ok(())
}

/// Aligned rows, or stacked ones where a row cannot fit; only compact rows set the padding.
fn write_rows(rows: &[Row<'_>], out: &mut impl io::Write) -> eyre::Result<()> {
    // Ineligible large targets cannot force padding proportional to their length.
    let (mut names, mut targets) = (0, 0);
    for row in rows.iter().filter(|row| row.compact()) {
        names = names.max(width(Escaped(row.name)));
        targets = targets.max(width(EscapedComplete(row.target)));
    }
    for row in rows {
        let target_width = width(EscapedComplete(row.target));
        if row.compact() && 6 + names + targets + row.state.width() <= 80 {
            // Padding is counted by hand: an escaped name's Display does not honour a width.
            write!(out, "  {}", Escaped(row.name))?;
            for _ in width(Escaped(row.name))..names {
                write!(out, " ")?;
            }
            write!(out, "  {}", EscapedComplete(row.target))?;
            for _ in target_width..targets {
                write!(out, " ")?;
            }
            writeln!(out, "  {}", row.state)?;
        } else {
            writeln!(out, "  {}", Escaped(row.name))?;
            // An off-only row has no target, so it gets no target line.
            if !row.target.is_empty() {
                writeln!(out, "    {}", EscapedComplete(row.target))?;
            }
            let mut line = StateLine { out, column: 0 };
            match row.state {
                State::Fixed(words) => line.words(words)?,
                State::Next(prefix, next) => {
                    line.words(prefix)?;
                    line.span(Span::Target(next))?;
                    line.words("from the next start")?;
                }
                State::Relative(prefix, saved) => {
                    line.words(prefix)?;
                    if let Some(saved) = saved {
                        line.words("saved")?;
                        line.span(Span::Target(saved))?;
                    }
                    line.words(RESOLVES)?;
                }
            }
            line.finish()?;
        }
    }
    Ok(())
}

struct Row<'a> {
    name: &'a str,
    target: &'a str,
    state: State<'a>,
}

impl Row<'_> {
    fn compact(&self) -> bool {
        self.target.is_ascii()
            && self.state.ascii()
            && 6 + width(Escaped(self.name))
                + width(EscapedComplete(self.target))
                + self.state.width()
                <= 80
    }
}

#[derive(Clone, Copy)]
enum State<'a> {
    Fixed(&'static str),
    Next(&'static str, &'a str),
    /// A saved relative path: the saved text when a bound target fills the target column.
    Relative(&'static str, Option<&'a str>),
}

/// Where a saved relative path resolves: no observer can say which directory that is.
const RESOLVES: &str = "resolves where swoosh serve starts";

impl State<'_> {
    fn ascii(self) -> bool {
        match self {
            Self::Fixed(_) | Self::Relative(_, None) => true,
            Self::Next(_, next) | Self::Relative(_, Some(next)) => next.is_ascii(),
        }
    }

    fn width(self) -> usize {
        width(self)
    }
}

impl fmt::Display for State<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fixed(words) => f.write_str(words),
            Self::Next(prefix, next) => {
                write!(f, "{prefix} {} from the next start", EscapedComplete(next))
            }
            Self::Relative(prefix, Some(saved)) => {
                write!(f, "{prefix} saved {} {RESOLVES}", EscapedComplete(saved))
            }
            Self::Relative(prefix, None) => write!(f, "{prefix} {RESOLVES}"),
        }
    }
}

#[cfg(test)]
#[path = "view_tests.rs"]
mod tests;
