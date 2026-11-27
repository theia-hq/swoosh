//! Terminal escaping for text swoosh did not write.
//!
//! [`Escaped`] and [`EscapedPath`] cap output and mark a cut with `...`.
//! [`EscapedComplete`] uses the same escapes without a length cap; callers must
//! bound its input independently. Both forms escape controls and characters that
//! hide or reorder text. [`peer_cell`] escapes the same way and cuts to the room a
//! line has left, so peer text beside swoosh's words never wraps onto a line of its own.

use core::fmt;
use std::path::Path;

/// The longest an escaped text renders, in characters of output. Text from another machine is bounded
/// only by its frame, so the cap bounds what reaches a line.
pub const MAX_ESCAPED: usize = 256;

/// Letters that render as blank space on a terminal. `char::escape_debug` treats them as printable and
/// passes them raw, so a name made only of them would print as nothing and two such names would look
/// alike. They cannot forge a line or drive a terminal; they are escaped so a name is never invisible.
pub(crate) const BLANK_LETTERS: [char; 5] =
    ['\u{115f}', '\u{1160}', '\u{3164}', '\u{ffa0}', '\u{2800}'];

/// Text as it may appear on a line: control characters escaped and the length capped.
///
/// `char::escape_debug` escapes C0 and C1 controls, DEL, the format characters that reorder or hide text
/// (a bidi override, a zero-width space), quotes and the backslash, and grapheme-extending marks (a
/// combining accent renders as `\u{...}`); letters that print as blank space render as `\u{...}` too.
/// Printable text is left alone.
///
/// Escapes are written whole: when the next complete escape would pass [`MAX_ESCAPED`], the render
/// writes the `...` cut marker and stops, so the cut never lands inside a sequence.
#[derive(Debug, Clone, Copy)]
pub struct Escaped<'a>(pub &'a str);

impl fmt::Display for Escaped<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_with_limit(f, Some(MAX_ESCAPED))
    }
}

/// Complete terminal escaping without an output-length cap.
///
/// Uses the same escape policy as [`Escaped`], but never adds a cut marker.
/// It borrows the input and writes directly to the formatter without allocating;
/// formatter errors are returned.
///
/// Use only for text whose input size the caller has already bounded. This wrapper
/// does not enforce that bound.
pub struct EscapedComplete<'a>(pub &'a str);

impl fmt::Display for EscapedComplete<'_> {
    /// Write the complete escaped input without allocating; return formatter errors.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Escaped(self.0).fmt_with_limit(f, None)
    }
}

impl Escaped<'_> {
    /// Apply the shared escape policy with an optional output-character budget.
    ///
    /// `Some(limit)` counts whole escapes and writes `...` before an escape would
    /// exceed the budget. `None` streams all escapes without counting or a cut marker.
    /// Both paths borrow the input, allocate nothing and return formatter errors.
    fn fmt_with_limit(&self, f: &mut fmt::Formatter<'_>, limit: Option<usize>) -> fmt::Result {
        let mut remaining = limit;
        for ch in self.0.chars() {
            let blank = BLANK_LETTERS.contains(&ch);
            if let Some(left) = remaining.as_mut() {
                // Charge only whole escapes; subtraction also handles a usize::MAX budget.
                let width = if blank {
                    ch.escape_unicode().len()
                } else {
                    ch.escape_debug().len()
                };
                if width > *left {
                    return f.write_str("...");
                }
                *left -= width;
            }
            escape(ch, f)?;
        }
        Ok(())
    }
}

/// Write one scalar as a line shows it: a blank letter as its code point, anything else as
/// `char::escape_debug` writes it, which leaves printable text alone.
fn escape(ch: char, out: &mut impl fmt::Write) -> fmt::Result {
    if BLANK_LETTERS.contains(&ch) {
        write!(out, "{}", ch.escape_unicode())
    } else {
        write!(out, "{}", ch.escape_debug())
    }
}

/// The most columns `text` can fill in any terminal, the bound [`peer_cell`] cuts by: one per ASCII
/// scalar, two per any other.
pub fn columns(text: &str) -> usize {
    text.chars()
        .map(|scalar| if scalar.is_ascii() { 1 } else { 2 })
        .sum()
}

/// The mark a cut [`peer_cell`] ends in. It is not ASCII, so it costs two columns like any other such
/// scalar.
pub const CELL_CUT: char = '…';

/// Peer text as it sits on a line beside swoosh's own words: escaped as [`Escaped`] escapes it, then cut
/// so it fills at most `budget` terminal columns, marked with [`CELL_CUT`].
///
/// The count is an upper bound, never a width table: an ASCII scalar costs one column and every other
/// scalar costs two, the most one fills in any terminal. So a cell of wide glyphs (CJK, full-width
/// letters) can never fill more room than it was given, wrap at the screen's edge, and start a forged
/// line with the text after it. A zero-width scalar costs two as well, so a flood of them is cut like any
/// other text. The price is that a name in a wide script shows fewer glyphs than a table would allow.
/// An escape is kept whole or cut whole, never split. A budget under two holds only the mark, which is
/// swoosh's own glyph: a cut cell is at least the mark.
///
/// A cut is logged at debug with the whole text, so `RUST_LOG=debug` shows what the line left out.
pub fn peer_cell(text: &str, budget: usize) -> String {
    let (cell, cut) = cut(text, budget);
    if cut {
        tracing::debug!(text = %EscapedComplete(text), "peer text was cut to the room its line leaves");
    }
    cell
}

/// [`peer_cell`]'s cell, and whether it was cut.
fn cut(text: &str, budget: usize) -> (String, bool) {
    cut_pieces(
        text.chars().map(|ch| {
            let mut piece = String::new();
            // Writing to a `String` cannot fail.
            let _ = escape(ch, &mut piece);
            piece
        }),
        budget,
    )
}

/// `pieces` joined and cut to `budget` columns as [`peer_cell`] cuts, and whether they were cut. A piece
/// is kept whole or cut whole, never split, so an escape never ends half written.
fn cut_pieces(pieces: impl Iterator<Item = String>, budget: usize) -> (String, bool) {
    let mut cell = String::new();
    let mut used = 0;
    // Where the cell could end with the cut mark still inside the budget, and its length then.
    let mut fits_cut = 0;
    for piece in pieces {
        let next = used + columns(&piece);
        if next > budget {
            cell.truncate(fits_cut);
            cell.push(CELL_CUT);
            return (cell, true);
        }
        cell.push_str(&piece);
        used = next;
        if used + 2 <= budget {
            fits_cut = cell.len();
        }
    }
    (cell, false)
}

/// Text [`escape`] already wrote, split back into its pieces: a scalar, or a whole escape. A backslash
/// there always opens an escape (one the text held is written `\\`), which runs one scalar on, or to its
/// `}` for a `\u{..}`.
fn escaped_pieces(escaped: &str) -> impl Iterator<Item = String> + '_ {
    let mut chars = escaped.chars();
    core::iter::from_fn(move || {
        let ch = chars.next()?;
        let mut piece = String::from(ch);
        if ch == '\\' {
            let Some(next) = chars.next() else {
                return Some(piece);
            };
            piece.push(next);
            if next == 'u' {
                for ch in chars.by_ref() {
                    piece.push(ch);
                    if ch == '}' {
                        break;
                    }
                }
            }
        }
        Some(piece)
    })
}

/// The widest line swoosh prints, in columns.
pub const LINE_WIDTH: usize = 80;

/// The least room peer text keeps beside swoosh's words; with less, it takes a detail line of its own,
/// so a true word the person can read is never shrunk to a mark.
pub const PEER_FLOOR: usize = 16;

/// The room peer text has on a detail line of its own: the line, less its indent of two and the last
/// column.
pub const DETAIL_ROOM: usize = LINE_WIDTH - 2 - 1;

/// The columns left for peer text on a line whose own words take `taken` columns: what a line holds, less
/// one, so a line that ends in peer text cut to this room never wraps.
pub fn room(taken: usize) -> usize {
    LINE_WIDTH.saturating_sub(taken + 1)
}

/// The columns left for peer text at the end of a refusal's head, after `error: ` and `words`.
pub fn head_room(words: &str) -> usize {
    room("error: ".len() + columns(words))
}

/// The label a peer's text takes on a detail line of its own, value after it. Alone on a line, peer text
/// would read as swoosh's own sentence; under a label it reads as a row whose value someone else wrote.
const REASON: &str = "  reason   ";

/// The room a value has on a [`reason_row`]: [`DETAIL_ROOM`], which already holds the label's indent,
/// less the rest of the label.
pub const REASON_ROOM: usize = DETAIL_ROOM + 2 - REASON.len();

/// Peer `text` on a detail line of its own, labelled as a row, `  reason   <text>`, and cut as a
/// [`peer_cell`] to [`REASON_ROOM`].
pub fn reason_row(text: &str) -> String {
    format!("{REASON}{}", peer_cell(text, REASON_ROOM))
}

/// [`reason_row`] for text already escaped where it entered, whose first line it labels and cuts to
/// [`REASON_ROOM`] by the same column count, an escape kept whole, without escaping it again (which
/// would double every backslash an escape wrote). Any further lines are swoosh's own and keep their place under it.
pub fn escaped_reason_row(escaped: &str) -> String {
    let (first, rest) = escaped
        .split_once('\n')
        .map_or((escaped, None), |(first, rest)| (first, Some(rest)));
    let (value, _) = cut_pieces(escaped_pieces(first), REASON_ROOM);
    match rest {
        Some(rest) => format!("{REASON}{value}\n{rest}"),
        None => format!("{REASON}{value}"),
    }
}

/// Peer `text` placed after swoosh's `words` on a line whose start takes `taken` columns, closed by
/// `close` (a `)`, or nothing): on the line, cut to its room, while that room is at least [`PEER_FLOOR`];
/// else as a [`reason_row`] under `words`, with `words` losing a trailing space or opening parenthesis.
pub fn beside(taken: usize, words: &str, text: &str, close: &str) -> String {
    let room = room(taken + columns(words) + columns(close));
    if room >= PEER_FLOOR {
        return format!("{words}{}{close}", peer_cell(text, room));
    }
    let words = words.trim_end_matches([' ', '(']);
    format!("{words}\n{}", reason_row(text))
}

/// A path as it may appear on a line: [`Escaped`] over its lossy text. A home's directory names, and the
/// names of the files in it, are whatever whoever made them chose.
#[derive(Debug, Clone, Copy)]
pub struct EscapedPath<'a>(pub &'a Path);

impl fmt::Display for EscapedPath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Escaped(&self.0.to_string_lossy()).fmt(f)
    }
}

/// An error and its full cause chain as one `outer: inner` string, the form a remote error takes before
/// it goes through [`Escaped`]: the causes carry another machine's text as much as the outer message does
/// (a refusal detail, the reason a peer gave for closing).
pub fn causes(error: &dyn core::error::Error) -> String {
    let mut chain = error.to_string();
    let mut next = error.source();
    while let Some(cause) = next {
        chain.push_str(": ");
        chain.push_str(&cause.to_string());
        next = cause.source();
    }
    chain
}

/// A report as `main` prints it, its whole chain flattened into one escaped message. A connect's cause
/// carries the reason the peer gave for closing and a gate's refusal carries the peer's own detail, and
/// iroh nests that text several causes deep, so the whole chain is the only boundary: it is escaped here,
/// where it leaves the reach, with its words as they were, and cut to the room an `error:` line leaves.
/// The chain runs swoosh's words first and the peer's deepest, so a cut takes the peer's text first.
pub fn escaped_report(error: eyre::Report) -> eyre::Report {
    eyre::eyre!("{}", peer_cell(&format!("{error:#}"), head_room("")))
}

#[cfg(test)]
#[path = "escape_tests.rs"]
mod escape_tests;
