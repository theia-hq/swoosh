//! The escaper's own rules, on the text it renders: controls, bidi and format characters and blank
//! letters come out as visible escapes, the cap holds, and the cut never splits an escape.

use super::{BLANK_LETTERS, Escaped, MAX_ESCAPED};

/// A newline, ESC, a carriage return, a C1 control, a bidi override and a zero-width space all render
/// as escapes, so none can forge a line, rewrite one, drive a terminal or reorder text.
#[test]
fn hostile_text_renders_escaped() {
    assert_eq!(
        Escaped("evil\nname\u{1b}[31m\r.txt").to_string(),
        r"evil\nname\u{1b}[31m\r.txt",
    );
    assert_eq!(
        Escaped("a\u{85}b\u{202e}c\u{200b}d").to_string(),
        r"a\u{85}b\u{202e}c\u{200b}d",
    );
}

/// Letters that print as blank space render as escapes, so a name made of them is never empty.
#[test]
fn blank_letters_render_escaped() {
    let name: String = BLANK_LETTERS.iter().collect();
    assert_eq!(
        Escaped(&name).to_string(),
        r"\u{115f}\u{1160}\u{3164}\u{ffa0}\u{2800}",
    );
}

/// Long text renders at most [`MAX_ESCAPED`] characters and marks the cut.
#[test]
fn long_text_is_capped() {
    let long = "a".repeat(MAX_ESCAPED * 4);
    assert_eq!(
        Escaped(&long).to_string(),
        format!("{}...", "a".repeat(MAX_ESCAPED)),
    );
}

/// The cap cuts between escapes, never inside one: the 6-character ESC escape does not fit the last
/// slot whole, so the render backs off to the marker instead of writing a malformed half-escape.
#[test]
fn the_escaper_cuts_on_a_whole_escape() {
    let text = format!("{}\u{1b}", "a".repeat(MAX_ESCAPED - 1));
    assert_eq!(
        Escaped(&text).to_string(),
        format!("{}...", "a".repeat(MAX_ESCAPED - 1)),
    );
}
