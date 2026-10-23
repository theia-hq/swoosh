use core::fmt::{self, Write as _};
use std::io;

use swoosh::escape::{Escaped, EscapedComplete, EscapedPath};
use swoosh::home::Home;
use swoosh::serve::control_codec::ControlError;

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
    let rows: Vec<_> = entries
        .iter()
        .filter_map(|entry| {
            let (name, configured) = entry.split_once('=')?;
            let bound = snapshot.as_ref().and_then(|snapshot| snapshot.get(name));
            let target = bound.map_or(configured, |pair| pair.target().as_str());
            let next = (target != configured).then_some(configured);
            let off = state.off.contains(name);
            let state = match (next, snapshot.is_some() && bound.is_none(), off) {
                (Some(next), _, false) => State::Next("on,", next),
                (Some(next), _, true) => State::Next("off,", next),
                (None, true, false) => State::Fixed("from the next start"),
                (None, true, true) => State::Fixed("off, from the next start"),
                (None, false, false) => State::Fixed("on"),
                (None, false, true) => State::Fixed("off"),
            };
            Some(Row {
                name,
                target,
                state,
            })
        })
        .collect();
    if rows.is_empty() {
        writeln!(
            out,
            "Serving nothing.\nTo add a service:\n  swoosh service add <service>"
        )?;
        return Ok(());
    }
    // Ineligible large targets cannot force padding proportional to their length.
    let (mut names, mut targets) = (0, 0);
    for row in rows.iter().filter(|row| row.compact()) {
        names = names.max(row.name.len());
        targets = targets.max(width(EscapedComplete(row.target)));
    }
    for row in rows {
        let target_width = width(EscapedComplete(row.target));
        if row.compact() && 6 + names + targets + row.state.width() <= 80 {
            write!(
                out,
                "  {:names$}  {}",
                row.name,
                EscapedComplete(row.target)
            )?;
            for _ in target_width..targets {
                write!(out, " ")?;
            }
            writeln!(out, "  {}", row.state)?;
        } else {
            writeln!(out, "  {}\n    {}", row.name, EscapedComplete(row.target))?;
            let mut line = StateLine { out, column: 0 };
            match row.state {
                State::Fixed(words) => line.words(words)?,
                State::Next(prefix, next) => {
                    line.words(prefix)?;
                    line.span(Span::Target(next))?;
                    line.words("from the next start")?;
                }
            }
            line.finish()?;
        }
    }
    if snapshot.is_none() {
        write!(
            out,
            "\nNot serving now.\nTo start serving:\n  swoosh serve\n"
        )?;
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
            && 6 + self.name.len() + width(EscapedComplete(self.target)) + self.state.width() <= 80
    }
}

#[derive(Clone, Copy)]
enum State<'a> {
    Fixed(&'static str),
    Next(&'static str, &'a str),
}

impl State<'_> {
    fn ascii(self) -> bool {
        match self {
            Self::Fixed(_) => true,
            Self::Next(_, next) => next.is_ascii(),
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
        }
    }
}

/// Measures escaped scalars, not terminal columns; only ASCII-target rows use compact layout.
fn width(value: impl fmt::Display) -> usize {
    struct Count(usize);
    impl fmt::Write for Count {
        fn write_str(&mut self, text: &str) -> fmt::Result {
            self.0 += text.chars().count();
            Ok(())
        }
    }
    let mut count = Count(0);
    // The counter cannot fail, and our Display implementations propagate only sink failures.
    let _ = write!(count, "{value}");
    count.0
}

/// Fixed words may wrap individually; complete targets must remain indivisible.
enum Span<'a> {
    Word(&'static str),
    Target(&'a str),
}

impl fmt::Display for Span<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Word(word) => f.write_str(word),
            Self::Target(target) => write!(f, "{}", EscapedComplete(target)),
        }
    }
}

/// Only fixed words may wrap. A target is one span even when it contains ordinary spaces.
struct StateLine<'a, W> {
    out: &'a mut W,
    column: usize,
}

impl<W: io::Write> StateLine<'_, W> {
    fn words(&mut self, words: &'static str) -> io::Result<()> {
        for word in words.split_ascii_whitespace() {
            self.span(Span::Word(word))?;
        }
        Ok(())
    }

    fn span(&mut self, span: Span<'_>) -> io::Result<()> {
        let ascii = match &span {
            Span::Word(_) => true,
            Span::Target(target) => target.is_ascii(),
        };
        let size = width(&span);
        if self.column != 0 && (!ascii || self.column + 1 + size > 80) {
            self.finish()?;
        }
        if self.column == 0 {
            write!(self.out, "    ")?;
            self.column = 4;
        } else {
            write!(self.out, " ")?;
            self.column += 1;
        }
        write!(self.out, "{span}")?;
        self.column += size;
        if !ascii {
            self.finish()?;
        }
        Ok(())
    }

    fn finish(&mut self) -> io::Result<()> {
        if self.column != 0 {
            writeln!(self.out)?;
        }
        self.column = 0;
        Ok(())
    }
}

#[cfg(test)]
#[path = "view_tests.rs"]
mod tests;
