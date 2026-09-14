//! The sender's own lines render a hostile file name the same way the receiver renders a
//! peer-supplied path, so a newline in a name cannot forge a second line on this terminal and an ESC
//! cannot drive it. The rule mirrors `services/crates/transfer/src/handler.rs` (`render_path`).
//!
//! The name is not the only surface: the skip line prints the whole error chain beside the escaped
//! prefix, so a path-bearing context built with a raw `Path::display` (the `stat`/`read` walk and the
//! no-file-name error) would leak the bytes the prefix escaped. These tests drive the operator's
//! exact hostile names through those paths.

use std::path::Path;

use super::{MAX_RENDERED_NAME, collect_files, file_name, render_name};

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

/// The operator's exact hostile name for the skip shape (`missing\nname\u{1b}[31m.txt`): a path that
/// cannot be stat'ed is skipped, and the WHOLE line, error chain included, must render escaped. This
/// is the leak the review caught: the prefix was escaped, the `stat <path>` context was not.
#[tokio::test]
async fn a_hostile_missing_path_renders_escaped_in_the_skip_error() {
    let path = std::env::temp_dir().join("missing\nname\u{1b}[31m.txt");
    let error = collect_files(&path)
        .await
        .expect_err("a path that does not exist is a skip");

    let message = format!("{error:#}");
    assert!(
        message.contains("stat ") && message.contains(r"missing\nname\u{1b}[31m.txt"),
        "the stat context renders the path escaped: {message:?}"
    );
    assert!(
        !message.contains('\n') && !message.contains('\u{1b}'),
        "no raw newline or ESC rides the error chain onto the skip line: {message:?}"
    );
}

/// The other skip shape the directory walk builds: an unreadable directory is wrapped as
/// `read <path>`, and that context renders escaped too.
#[cfg(unix)]
#[tokio::test]
async fn a_hostile_unreadable_directory_renders_escaped_in_the_read_error() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = std::env::temp_dir().join(format!(
        "swoosh-send-{}-no-read\nname\u{1b}[31m.txt",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("the hostile directory is created");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000))
        .expect("the directory is closed");
    let result = collect_files(&dir).await;
    // Reopen and remove first, so the asserts (and a failed one) leave no unreadable tree behind.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .expect("the directory is reopened");
    let _ = std::fs::remove_dir_all(&dir);

    // Root ignores mode 000, so the walk succeeds and this environment cannot exercise the shape.
    let Err(error) = result else {
        return;
    };
    let message = format!("{error:#}");
    assert!(
        message.contains("read ") && message.contains(r"no-read\nname\u{1b}[31m.txt"),
        "the read context renders the path escaped: {message:?}"
    );
    assert!(
        !message.contains('\n') && !message.contains('\u{1b}'),
        "no raw newline or ESC rides the error chain onto the skip line: {message:?}"
    );
}

/// A path with no final component is a hard error rather than a silent misname, and its one
/// path-bearing message renders escaped like every other.
#[test]
fn a_hostile_path_with_no_file_name_renders_escaped() {
    let error = file_name(Path::new("evil\nname\u{1b}[31m/.."))
        .expect_err("a path with no final component has no file name");

    let message = format!("{error:#}");
    assert!(
        message.contains(r"path has no file name: evil\nname\u{1b}[31m/.."),
        "the no-file-name error renders the path escaped: {message:?}"
    );
    assert!(
        !message.contains('\n') && !message.contains('\u{1b}'),
        "no raw newline or ESC reaches the skip line: {message:?}"
    );
}
