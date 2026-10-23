//! Terminal escaping for text swoosh did not write.
//!
//! [`Escaped`] and [`EscapedPath`] cap output and mark a cut with `...`.
//! [`EscapedComplete`] uses the same escapes without a length cap; callers must
//! bound its input independently. Both forms escape controls and characters that
//! hide or reorder text.

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
            if blank {
                write!(f, "{}", ch.escape_unicode())?;
            } else {
                write!(f, "{}", ch.escape_debug())?;
            }
        }
        Ok(())
    }
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
/// where it leaves the reach, with its words as they were.
pub fn escaped_report(error: eyre::Report) -> eyre::Report {
    eyre::eyre!("{}", Escaped(&format!("{error:#}")))
}

#[cfg(test)]
#[path = "escape_tests.rs"]
mod escape_tests;
