use std::io;

use swoosh::escape::EscapedComplete;

pub(super) use crate::screen::{Span, StateLine, width};

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

#[cfg(test)]
#[path = "service_rows_tests.rs"]
mod tests;
