use core::fmt::{self, Write as _};
use std::io;

use swoosh::escape::EscapedComplete;

/// A service row with an indivisible canonical target.
pub(super) struct Row<'a> {
    /// A validated service name.
    pub(super) name: &'a str,
    /// A fixed audience or saved-selection label.
    pub(super) audience: &'static str,
    /// A canonical target, escaped completely when rendered.
    pub(super) target: &'a str,
}

impl Row<'_> {
    fn compact(&self) -> bool {
        self.target.is_ascii()
            && 6 + self.name.len() + self.audience.len() + width(EscapedComplete(self.target)) <= 80
    }
}

/// Only compact rows contribute padding; stacked targets cannot widen other rows.
pub(super) fn label_width(rows: &[Row<'_>]) -> usize {
    rows.iter()
        .filter(|row| row.compact())
        .map(|row| row.name.len())
        .max()
        .unwrap_or(0)
}

/// Use the serving block's shared label width without changing target wrapping.
pub(super) fn render_aligned(
    rows: &[Row<'_>],
    names: usize,
    out: &mut impl io::Write,
) -> io::Result<()> {
    let audiences = rows
        .iter()
        .filter(|row| row.compact())
        .map(|row| row.audience.len())
        .max()
        .unwrap_or(0);
    for row in rows {
        if row.compact() && 6 + names + audiences + width(EscapedComplete(row.target)) <= 80 {
            writeln!(
                out,
                "  {:names$}  {:audiences$}  {}",
                row.name,
                row.audience,
                EscapedComplete(row.target)
            )?;
        } else {
            writeln!(out, "  {}", row.name)?;
            let mut line = StateLine { out, column: 0 };
            line.words(row.audience)?;
            line.finish()?;
            line.span(Span::Target(row.target))?;
            line.finish()?;
        }
    }
    Ok(())
}

/// Measures escaped scalars, not terminal columns; only ASCII-target rows use compact layout.
pub(super) fn width(value: impl fmt::Display) -> usize {
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
pub(super) enum Span<'a> {
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
pub(super) struct StateLine<'a, W> {
    /// The continuation sink.
    pub(super) out: &'a mut W,
    /// Escaped scalar count including indentation, not terminal columns; zero means no pending line.
    pub(super) column: usize,
}

impl<W: io::Write> StateLine<'_, W> {
    /// Append fixed words with wrapping.
    pub(super) fn words(&mut self, words: &'static str) -> io::Result<()> {
        for word in words.split_ascii_whitespace() {
            self.span(Span::Word(word))?;
        }
        Ok(())
    }

    /// Append one indivisible span, wrapping first when needed.
    pub(super) fn span(&mut self, span: Span<'_>) -> io::Result<()> {
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

    /// End a pending line and reset its scalar count.
    pub(super) fn finish(&mut self) -> io::Result<()> {
        if self.column != 0 {
            writeln!(self.out)?;
        }
        self.column = 0;
        Ok(())
    }
}

#[cfg(test)]
#[path = "service_rows_tests.rs"]
mod tests;
