//! The escaper's own rules, on the text it renders: controls, bidi and format characters and blank
//! letters come out as visible escapes, the cap holds, and the cut never splits an escape.

use super::{BLANK_LETTERS, Escaped, EscapedPath, MAX_ESCAPED, causes};

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

/// A path renders through the same escaper, and an error's cause chain renders `outer: inner`.
#[test]
fn a_path_and_a_cause_chain_render_escaped() {
    assert_eq!(
        EscapedPath(std::path::Path::new("home\r\u{1b}[8m\nfake/key")).to_string(),
        r"home\r\u{1b}[8m\nfake/key",
    );
    let error = std::io::Error::other(eyre::eyre!("closed by peer: no\r").wrap_err("stream"));
    assert_eq!(
        Escaped(&causes(&error)).to_string(),
        r"stream: closed by peer: no\r"
    );
}

/// Every line that names a file in the home goes through [`EscapedPath`]: a home whose directory names
/// hold CR, ESC or a newline can otherwise redraw a terminal line or forge a log line. A raw
/// `Path::display` in the crate's source is allowed only where the path is not a home path: one the person
/// typed on this machine (a backup, an export, a secret file, a socket), a word handed to `ssh`, or text
/// written to a file rather than printed.
#[test]
fn no_home_path_prints_raw() {
    const NOT_A_HOME_PATH: [(&str, &str); 7] = [
        ("src/identity/backup.rs", "to.display()"),
        ("src/identity/backup.rs", "from.display()"),
        ("src/secret.rs", "path.display()"),
        ("src/root.rs", "self.to.display(), self.on.0"),
        ("src/bin/swoosh/commands/connect.rs", "path.display()"),
        ("src/bin/swoosh/commands/ssh.rs", ".display()"),
        ("src/bin/swoosh/commands/identity/", "self.path.display()"),
    ];
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut raw = Vec::new();
    let mut dirs = vec![root.join("src")];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("the source tree reads") {
            let path = entry.expect("a source entry").path();
            if path.is_dir() {
                dirs.push(path);
                continue;
            }
            let name = path.to_string_lossy();
            if !name.ends_with(".rs") || name.ends_with("_tests.rs") {
                continue;
            }
            let file = path
                .strip_prefix(root)
                .expect("under the crate")
                .to_string_lossy()
                .into_owned();
            let text = std::fs::read_to_string(&path).expect("a source file reads");
            for (index, line) in text.lines().enumerate() {
                if !line.contains(".display()") || line.trim_start().starts_with("//") {
                    continue;
                }
                let allowed = NOT_A_HOME_PATH
                    .iter()
                    .any(|(prefix, snippet)| file.starts_with(prefix) && line.contains(snippet));
                if !allowed {
                    raw.push(format!("{file}:{}: {}", index + 1, line.trim()));
                }
            }
        }
    }
    assert!(
        raw.is_empty(),
        "a path prints through Path::display, not EscapedPath:\n{}",
        raw.join("\n")
    );
}
