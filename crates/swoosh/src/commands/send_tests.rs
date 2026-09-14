//! The sender's own `sent` line renders a hostile file name the same way the receiver renders a
//! peer-supplied path, so a newline in a name cannot forge a second line on this terminal and an ESC
//! cannot drive it. The rule mirrors `services/crates/transfer/src/handler.rs` (`render_path`).

use super::{MAX_RENDERED_NAME, render_name};

/// A hostile filename cannot forge a line or drive the terminal: the newline, escape byte, carriage
/// return, C1 control, bidi override, and zero-width space in these names all render escaped.
#[test]
fn a_hostile_filename_renders_escaped() {
    assert_eq!(
        render_name("evil\nname\u{1b}[31m\r.txt"),
        r"evil\nname\u{1b}[31m\r.txt",
        "a newline, an escape byte, and a carriage return never reach the line raw"
    );
    assert_eq!(
        render_name("a\u{85}b\u{202e}c\u{200b}d"),
        r"a\u{85}b\u{202e}c\u{200b}d",
        "a C1 control, a bidi override, and a zero-width space never reach the line raw"
    );
}

/// A long name cannot flood the line: the render caps at [`MAX_RENDERED_NAME`] characters and marks
/// the cut.
#[test]
fn a_long_filename_renders_capped() {
    let long = "a".repeat(MAX_RENDERED_NAME * 4);
    assert_eq!(
        render_name(&long),
        format!("{}...", "a".repeat(MAX_RENDERED_NAME)),
        "the render holds the cap and marks the cut"
    );
}

/// The cap cuts between escapes, never inside one: the ESC escape does not fit the last slot whole, so
/// the render backs off to the marker instead of emitting a malformed half-escape.
#[test]
fn a_cap_cut_never_splits_an_escape_sequence() {
    let name = format!("{}\u{1b}", "a".repeat(MAX_RENDERED_NAME - 1));
    assert_eq!(
        render_name(&name),
        format!("{}...", "a".repeat(MAX_RENDERED_NAME - 1)),
        "the cut lands before the incomplete escape"
    );
}
