//! The screen: swoosh's own output laid out in blocks at width 80, and styled only where a terminal shows
//! it.
//!
//! A [`Screen`] is blocks a blank line apart. A [`Block`] is an optional title, then rows, text and
//! commands. Style reaches only swoosh's own fixed words: [`Style::paint`] takes `&'static str`, so a
//! peer's name or target can never be wrapped in an escape. A screen is built whole and written once, so
//! a reader that closes early or a line logged beside it cannot tear it.

use core::fmt::{self, Write as _};
use std::borrow::Cow;
use std::io;
use std::sync::OnceLock;

use anstream::{AutoStream, ColorChoice};
use clap::builder::styling::{self, AnsiColor, Color};
use swoosh::escape::EscapedComplete;

/// The widest line a screen prints, in escaped scalars.
const WIDTH: usize = 80;

/// How one of swoosh's own fixed words is styled at a terminal.
#[derive(Clone, Copy)]
pub(crate) struct Style(styling::Style);

impl Style {
    /// A screen's title and a block's title.
    pub(crate) const TITLE: Self = Self(styling::Style::new().bold());
    /// The `error:` that leads a refusal, in clap's colour for its own.
    pub(crate) const ERROR: Self = Self(
        styling::Style::new()
            .bold()
            .fg_color(Some(Color::Ansi(AnsiColor::Red))),
    );
    /// The `warning:` that leads a line the run goes on past.
    pub(crate) const WARNING: Self = Self(
        styling::Style::new()
            .bold()
            .fg_color(Some(Color::Ansi(AnsiColor::Yellow))),
    );
    /// A value that widens who can reach a service (`anyone`): a warning's colour, by name of its own so the
    /// two may part.
    pub(crate) const RISK: Self = Self::WARNING;

    /// `text` in this style where `on` shows style, else plain. `'static` is the guard: only swoosh's own
    /// words are ever styled, never text a peer chose.
    pub(crate) fn paint(self, text: &'static str, on: &impl Paint) -> Painted {
        Painted {
            style: on.styled().then_some(self),
            text,
        }
    }
}

/// A fixed word, styled or plain, ready to format into a line written once.
pub(crate) struct Painted {
    style: Option<Style>,
    text: &'static str,
}

impl fmt::Display for Painted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.style {
            Some(Style(style)) => write!(f, "{style}{}{style:#}", self.text),
            None => f.write_str(self.text),
        }
    }
}

/// A writer that knows whether it shows style.
///
/// Plain by default: a writer that is not a terminal stream never carries an escape. Nothing here strips
/// bytes, so data written to a stream passes as it is.
pub(crate) trait Paint: io::Write {
    /// Whether style shows on this writer.
    fn styled(&self) -> bool {
        false
    }
}

/// Whether stdout shows style, decided once per run: the environment and the handle do not change under
/// a run, so every line on one stream is styled alike. A cell per stream, never one for both, since one
/// stream can be a terminal while the other is a pipe.
static STDOUT: OnceLock<bool> = OnceLock::new();
/// Whether stderr shows style; see [`STDOUT`].
static STDERR: OnceLock<bool> = OnceLock::new();

/// Styled as clap styles its own errors: `NO_COLOR` is plain, then `CLICOLOR_FORCE` styles, then
/// `CLICOLOR=0` is plain, then a terminal whose `TERM` supports colour styles. A pipe or a file is plain.
impl Paint for io::Stdout {
    fn styled(&self) -> bool {
        *STDOUT.get_or_init(|| AutoStream::choice(&io::stdout()) != ColorChoice::Never)
    }
}

/// The same decision for stderr, made for stderr's own handle.
impl Paint for io::Stderr {
    fn styled(&self) -> bool {
        *STDERR.get_or_init(|| AutoStream::choice(&io::stderr()) != ColorChoice::Never)
    }
}

/// A stream whose choice is already made, as a test forces one.
impl<S: anstream::stream::RawStream + anstream::stream::AsLockedWrite> Paint for AutoStream<S> {
    fn styled(&self) -> bool {
        self.current_choice() != ColorChoice::Never
    }
}

impl Paint for Vec<u8> {}

/// One cell of a row.
pub(crate) enum Cell<'a> {
    /// Swoosh's fixed words: they wrap at word breaks when the row stacks.
    Word(&'static str),
    /// A fixed value that widens who can reach a service, styled [`Style::RISK`].
    Risk(&'static str),
    /// A name, key or target: escaped completely, never split, never styled.
    Token(&'a str),
}

impl Cell<'_> {
    /// The cell as printed, unstyled: a token escaped, fixed words as they are.
    fn text(&self) -> Cow<'_, str> {
        match self {
            Self::Word(text) | Self::Risk(text) => Cow::Borrowed(text),
            Self::Token(token) => Cow::Owned(EscapedComplete(token).to_string()),
        }
    }

    /// Whether the cell is ASCII as given, the only cells a one-line row holds: a wide glyph counts one
    /// scalar but fills two columns, so it could never line up, and a token is judged before its escaping.
    fn is_ascii(&self) -> bool {
        match self {
            Self::Word(text) | Self::Risk(text) => text.is_ascii(),
            Self::Token(text) => text.is_ascii(),
        }
    }
}

/// One line of a block.
enum Line<'a> {
    /// Cells at indent two, aligned by column.
    Row(Vec<Cell<'a>>),
    /// A sentence or line as written, flush left. The caller escapes any peer text in it.
    Text(String),
    /// A sentence of swoosh's own fixed words, flush left, styled [`Style::RISK`]: a state that puts the key at
    /// risk.
    Risk(&'static str),
    /// A refusal's or a warning's head: its fixed word (`error:`, `warning:`) styled, then the clause.
    Head(Style, &'static str, String),
    /// A command to type, at indent two, so a triple-click copies exactly it.
    Command(String),
}

/// A titled run of lines, a blank line from the next.
#[derive(Default)]
pub(crate) struct Block<'a> {
    title: Option<&'static str>,
    /// Where the value column starts, at the least.
    column: usize,
    lines: Vec<Line<'a>>,
}

impl<'a> Block<'a> {
    /// A block under `title`. With no lines, the title is a screen's title line.
    pub(crate) fn titled(title: &'static str) -> Self {
        Self {
            title: Some(title),
            ..Self::default()
        }
    }

    /// Start the value column at `at` or later, so head blocks line up across screens.
    pub(crate) fn column(self, at: usize) -> Self {
        Self { column: at, ..self }
    }

    /// Add a row of cells, aligned with the block's other rows.
    pub(crate) fn row(mut self, cells: impl IntoIterator<Item = Cell<'a>>) -> Self {
        self.lines.push(Line::Row(cells.into_iter().collect()));
        self
    }

    /// Add a line printed as written, flush left.
    pub(crate) fn text(mut self, line: String) -> Self {
        self.lines.push(Line::Text(line));
        self
    }

    /// Add a sentence of fixed words, flush left, styled as a risk.
    pub(crate) fn risk(mut self, line: &'static str) -> Self {
        self.lines.push(Line::Risk(line));
        self
    }

    /// Add a head line: `word` (`error:`, `warning:`) in `style`, then `clause`, as `main` prints a refusal.
    pub(crate) fn head(mut self, style: Style, word: &'static str, clause: String) -> Self {
        self.lines.push(Line::Head(style, word, clause));
        self
    }

    /// Add a command to type, alone on its line at indent two.
    pub(crate) fn command(mut self, line: String) -> Self {
        self.lines.push(Line::Command(line));
        self
    }

    /// The block's lines as printed, each with its shape, styled where `styled`.
    fn print(&self, styled: bool) -> io::Result<Vec<(Shape, String)>> {
        let paint = |style, text| Painted {
            style: styled.then_some(style),
            text,
        };
        let mut printed = Vec::new();
        if let Some(title) = self.title {
            printed.push((Shape::Fact, paint(Style::TITLE, title).to_string()));
        }
        let rows: Vec<_> = self
            .lines
            .iter()
            .map(|line| match line {
                Line::Row(cells) => Some(Measured::of(cells)),
                Line::Text(_) | Line::Risk(_) | Line::Head(..) | Line::Command(_) => None,
            })
            .collect();
        let widths = self.widths(&rows);
        for (line, row) in self.lines.iter().zip(&rows) {
            match (line, row) {
                (Line::Row(cells), Some(row)) => row.print(cells, &widths, paint, &mut printed)?,
                (Line::Text(text), _) => printed.push((Shape::Prose, text.clone())),
                (Line::Risk(text), _) => {
                    printed.push((Shape::Prose, paint(Style::RISK, text).to_string()))
                }
                (Line::Head(style, word, clause), _) => {
                    printed.push((Shape::Prose, format!("{} {clause}", paint(*style, word))))
                }
                (Line::Command(command), _) => {
                    printed.push((Shape::Command, format!("  {command}")))
                }
                (Line::Row(_), None) => {}
            }
        }
        Ok(printed)
    }

    /// Each padded column's width, from the rows that fit 80 on their own. A row that cannot fit alone
    /// stacks, so it never widens the rows around it; the last cell is never padded, so it sets nothing.
    fn widths(&self, rows: &[Option<Measured<'_>>]) -> Vec<usize> {
        let mut widths = vec![self.column.saturating_sub(4)];
        for row in rows.iter().flatten() {
            let Some((_, padded)) = row.0.split_last() else {
                continue;
            };
            let own: usize = row.0.iter().map(|(_, size)| size).sum();
            if !row.1 || 2 + own + 2 * padded.len() > WIDTH {
                continue;
            }
            for (at, (_, size)) in padded.iter().enumerate() {
                match widths.get_mut(at) {
                    Some(widest) => *widest = (*widest).max(*size),
                    None => widths.push(*size),
                }
            }
        }
        widths
    }
}

/// A row's cells as printed, with their widths, computed once; and whether every cell is ASCII.
struct Measured<'c>(Vec<(Cow<'c, str>, usize)>, bool);

impl<'c> Measured<'c> {
    fn of(cells: &'c [Cell<'c>]) -> Self {
        let texts = cells
            .iter()
            .map(|cell| {
                let text = cell.text();
                let size = width(&text);
                (text, size)
            })
            .collect();
        Self(texts, cells.iter().all(Cell::is_ascii))
    }

    /// On one line where every cell is ASCII and it fits 80 at the block's widths; otherwise cell 0 alone
    /// at indent two and each later cell on its own lines at indent four.
    fn print(
        &self,
        cells: &[Cell<'_>],
        widths: &[usize],
        paint: impl Fn(Style, &'static str) -> Painted,
        printed: &mut Vec<(Shape, String)>,
    ) -> io::Result<()> {
        let shown = |cell: &Cell<'_>, text: &str| match cell {
            Cell::Risk(word) => paint(Style::RISK, word).to_string(),
            Cell::Word(_) | Cell::Token(_) => text.to_owned(),
        };
        let Some(((last, last_size), padded)) = self.0.split_last() else {
            return Ok(());
        };
        let pads: Vec<_> = padded
            .iter()
            .enumerate()
            .map(|(at, (_, size))| widths.get(at).copied().unwrap_or(0).max(*size))
            .collect();
        if self.1 && 2 + pads.iter().map(|pad| pad + 2).sum::<usize>() + last_size <= WIDTH {
            let mut line = String::from("  ");
            for ((cell, (text, size)), pad) in cells.iter().zip(padded).zip(pads) {
                line.push_str(&shown(cell, text));
                line.push_str(&" ".repeat(pad - size + 2));
            }
            if let Some(cell) = cells.last() {
                line.push_str(&shown(cell, last));
            }
            printed.push((Shape::Fact, line));
            return Ok(());
        }
        for (at, (cell, (text, _))) in cells.iter().zip(&self.0).enumerate() {
            if at == 0 {
                printed.push((Shape::Fact, format!("  {}", shown(cell, text))));
                continue;
            }
            let mut out = Vec::new();
            let mut line = StateLine {
                out: &mut out,
                column: 0,
            };
            let shape = match cell {
                Cell::Word(words) => {
                    line.words(words)?;
                    Shape::Fact
                }
                Cell::Token(token) => {
                    line.span(Span::Target(token))?;
                    Shape::Token
                }
                Cell::Risk(_) => {
                    printed.push((Shape::Fact, format!("    {}", shown(cell, text))));
                    continue;
                }
            };
            line.finish()?;
            let wrapped = String::from_utf8(out).map_err(io::Error::other)?;
            printed.extend(wrapped.lines().map(|text| (shape, text.to_owned())));
        }
        Ok(())
    }
}

/// Blocks, a blank line apart.
#[derive(Default)]
pub(crate) struct Screen<'a>(Vec<Block<'a>>);

impl<'a> Screen<'a> {
    /// Add `block` below the others, a blank line apart.
    pub(crate) fn block(mut self, block: Block<'a>) -> Self {
        self.0.push(block);
        self
    }

    /// Write every block onto `out` in one write, leaving out any with no title and no lines. Under test
    /// each line is held to the screen law first, so every screen a test writes is checked.
    pub(crate) fn write(&self, out: &mut impl Paint) -> io::Result<()> {
        let styled = out.styled();
        let blocks = self
            .0
            .iter()
            .filter(|block| block.title.is_some() || !block.lines.is_empty());
        let mut screen = String::new();
        for (at, block) in blocks.enumerate() {
            #[cfg(test)]
            {
                let plain = block.print(false)?;
                let held = plain.iter().map(|(shape, line)| (*shape, &**line));
                if let Err(breach) = law::hold(held) {
                    panic!("{breach}");
                }
            }
            if at != 0 {
                screen.push('\n');
            }
            for (_, line) in block.print(styled)? {
                screen.push_str(&line);
                screen.push('\n');
            }
        }
        out.write_all(screen.as_bytes())
    }
}

/// What a printed line is, for the law check: which of its rules apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    /// Text as written: the head, sentence and two-sentence rules, and the width.
    Prose,
    /// A command to type: never a period, and the width unless it holds a whole key.
    Command,
    /// A title, a row or a stacked row's fixed words: the width only.
    Fact,
    /// A stacked row's token, alone on its line: exempt, since it never splits.
    Token,
}

/// Measures escaped scalars, not terminal columns; only ASCII rows use the one-line layout.
pub(crate) fn width(value: impl fmt::Display) -> usize {
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
pub(crate) enum Span<'a> {
    /// A fixed word that may wrap independently.
    Word(&'static str),
    /// A complete target that never splits.
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
pub(crate) struct StateLine<'a, W> {
    /// The continuation sink.
    pub(crate) out: &'a mut W,
    /// Escaped scalar count including indentation, not terminal columns; zero means no pending line.
    pub(crate) column: usize,
}

impl<W: io::Write> StateLine<'_, W> {
    /// Append fixed words with wrapping.
    pub(crate) fn words(&mut self, words: &'static str) -> io::Result<()> {
        for word in words.split_ascii_whitespace() {
            self.span(Span::Word(word))?;
        }
        Ok(())
    }

    /// Append one indivisible span, wrapping first when needed.
    pub(crate) fn span(&mut self, span: Span<'_>) -> io::Result<()> {
        let ascii = match &span {
            Span::Word(_) => true,
            Span::Target(target) => target.is_ascii(),
        };
        let size = width(&span);
        if self.column != 0 && (!ascii || self.column + 1 + size > WIDTH) {
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

    /// End a pending line and reset its scalar count.
    pub(crate) fn finish(&mut self) -> io::Result<()> {
        if self.column != 0 {
            writeln!(self.out)?;
        }
        self.column = 0;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod law;

#[cfg(test)]
#[path = "screen_tests.rs"]
mod tests;
