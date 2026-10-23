//! The shared escape policy, capped output and complete bounded-input rendering.

use core::fmt::{self, Write as _};

use super::{
    BLANK_LETTERS, Escaped, EscapedComplete, EscapedPath, MAX_ESCAPED, causes, escaped_report,
};
use crate::serve::measure_allocations;

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

#[test]
fn complete_and_capped_text_share_the_escape_policy() {
    let blanks: String = BLANK_LETTERS.iter().collect();
    for text in [
        "",
        "ordinary text 秘密",
        "evil\nname\u{1b}[31m\r.txt",
        "a\u{85}b\u{202e}c\u{200b}d",
        "\0\t\u{7f}\\\"'e\u{301}",
        blanks.as_str(),
    ] {
        assert_eq!(EscapedComplete(text).to_string(), Escaped(text).to_string());
    }
    // All control scalars get exercised individually so the capped path cannot hide a suffix.
    for ch in (0..=0x9f).filter_map(char::from_u32) {
        let mut bytes = [0; 4];
        let text = ch.encode_utf8(&mut bytes);
        assert_eq!(EscapedComplete(text).to_string(), Escaped(text).to_string());
    }
}

#[test]
fn complete_text_preserves_long_spaces_and_unicode_without_a_hidden_cap() {
    for length in [MAX_ESCAPED + 1, 4097, 16385] {
        let text = format!("  {} 秘密  ", "x".repeat(length));
        assert_eq!(EscapedComplete(&text).to_string(), text);
        assert_eq!(
            Escaped(&text).to_string(),
            format!("  {}...", "x".repeat(MAX_ESCAPED - 2)),
        );
    }
    let text = "a\n\u{2800} 秘密 ".repeat(1024);
    assert_eq!(
        EscapedComplete(&text).to_string(),
        "a\\n\\u{2800} 秘密 ".repeat(1024),
    );
}

#[test]
fn paths_causes_and_reports_keep_their_cap() {
    let text = format!("{}\n", "x".repeat(MAX_ESCAPED + 1));
    let expected = format!("{}...", "x".repeat(MAX_ESCAPED));
    assert_eq!(
        EscapedPath(std::path::Path::new(&text)).to_string(),
        expected,
    );
    let error = std::io::Error::other(text.clone());
    assert_eq!(Escaped(&causes(&error)).to_string(), expected);
    assert_eq!(escaped_report(eyre::eyre!(text)).to_string(), expected);
}

#[test]
fn complete_formatting_borrows_and_allocates_nothing() {
    let text = "a\n\u{2800} 秘密 ".repeat(1024);
    let complete = EscapedComplete(&text);
    assert_eq!(complete.0.as_ptr(), text.as_ptr());
    assert_eq!(complete.0.len(), text.len());
    assert_eq!(
        core::mem::size_of_val(&complete),
        core::mem::size_of::<&str>(),
    );
    let mut writer = FixedWriter::<32768>::default();
    let (result, allocations) = measure_allocations(|| write!(writer, "{complete}"));
    result.unwrap();
    assert_eq!(allocations, 0);
    assert_eq!(writer.as_str().unwrap(), "a\\n\\u{2800} 秘密 ".repeat(1024));

    // A heap-using control proves the allocator hook, not just the stack writer, is observed.
    let (_, allocations) = measure_allocations(|| core::hint::black_box(vec![1u8; 128]));
    assert!(allocations > 0);
}

#[test]
fn allocation_measurement_restores_tracking_after_unwind() {
    let (_, allocations) = measure_allocations(|| {
        let result = std::panic::catch_unwind(|| {
            measure_allocations(|| panic!("measurement unwind control"));
        });
        assert!(result.is_err());
        drop(core::hint::black_box(vec![1u8; 128]));
    });
    assert!(allocations > 0);
    assert_eq!(measure_allocations(|| ()).1, 0);
}

#[test]
fn formatter_failures_propagate_in_both_modes_and_in_the_cut_marker() {
    let text = "a\n\u{2800} 秘密";
    let expected = EscapedComplete(text).to_string();
    for capacity in 0..expected.len() {
        let mut capped = FixedWriter::<128> {
            capacity,
            ..Default::default()
        };
        let mut complete = FixedWriter::<128> {
            capacity,
            ..Default::default()
        };
        assert!(write!(capped, "{}", Escaped(text)).is_err());
        assert!(write!(complete, "{}", EscapedComplete(text)).is_err());
    }
    let text = "x".repeat(MAX_ESCAPED + 1);
    for capacity in MAX_ESCAPED..MAX_ESCAPED + 3 {
        let mut writer = FixedWriter::<512> {
            capacity,
            ..Default::default()
        };
        assert!(write!(writer, "{}", Escaped(&text)).is_err());
        assert_eq!(writer.as_str().unwrap(), "x".repeat(MAX_ESCAPED));
    }
    let mut writer = FixedWriter::<512>::default();
    write!(writer, "{}", Escaped(&text)).unwrap();
    assert_eq!(
        writer.as_str().unwrap(),
        format!("{}...", "x".repeat(MAX_ESCAPED))
    );
}

#[test]
fn optional_budgets_admit_only_whole_escapes() {
    for (text, limit, expected) in [
        ("", Some(0), ""),
        ("a", Some(0), "..."),
        ("a", Some(1), "a"),
        ("ab", Some(1), "a..."),
        ("\n", Some(1), "..."),
        ("\n", Some(2), "\\n"),
        ("\na", Some(2), "\\n..."),
        ("\u{1b}", Some(5), "..."),
        ("\u{1b}", Some(6), "\\u{1b}"),
        ("\u{2800}", Some(7), "..."),
        ("\u{2800}", Some(8), "\\u{2800}"),
        ("秘密", Some(2), "秘密"),
        ("a\n", Some(usize::MAX), "a\\n"),
        ("a\n", None, "a\\n"),
    ] {
        assert_eq!(WithLimit(text, limit).to_string(), expected);
    }
    let mut writer = FixedWriter::<1>::default();
    assert!(write!(writer, "{}", WithLimit("a", Some(0))).is_err());
}

struct WithLimit<'a>(&'a str, Option<usize>);

impl fmt::Display for WithLimit<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Escaped(self.0).fmt_with_limit(f, self.1)
    }
}

struct FixedWriter<const N: usize> {
    bytes: [u8; N],
    len: usize,
    capacity: usize,
}

impl<const N: usize> Default for FixedWriter<N> {
    fn default() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
            capacity: N,
        }
    }
}

impl<const N: usize> FixedWriter<N> {
    fn as_str(&self) -> Result<&str, core::str::Utf8Error> {
        core::str::from_utf8(&self.bytes[..self.len])
    }
}

impl<const N: usize> fmt::Write for FixedWriter<N> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if text.len() > self.capacity - self.len {
            return Err(fmt::Error);
        }
        let end = self.len + text.len();
        self.bytes[self.len..end].copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// Every line that names a file in the home goes through [`EscapedPath`]: a home whose directory names
/// hold CR, ESC or a newline can otherwise redraw a terminal line or forge a log line. A raw
/// `Path::display` in the crate's source is allowed only where the path is not a home path: one the person
/// typed on this machine (a backup, an export, a secret file, a socket), the known-hosts word handed to
/// `ssh`, or text written to a file rather than printed. Test code is not scanned.
#[test]
fn no_home_path_prints_raw() {
    const NOT_A_HOME_PATH: [(&str, &str); 7] = [
        ("src/identity/backup.rs", "to.display()"),
        ("src/identity/backup.rs", "from.display()"),
        ("src/secret.rs", "path.display()"),
        ("src/root.rs", "self.to.display(), self.on.0"),
        ("src/bin/swoosh/commands/connect.rs", "path.display()"),
        ("src/bin/swoosh/commands/ssh.rs", "UserKnownHostsFile="),
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
            // A file's inline test module is its last item and prints nothing a person reads, so the
            // scan stops there: at a column-0 `mod tests {` under `#[cfg(test)]`, so neither a module
            // that ships under that name nor the line inside a string ends the scan early.
            let lines: Vec<&str> = text.lines().collect();
            let end = lines
                .windows(2)
                .position(|pair| pair == ["#[cfg(test)]", "mod tests {"])
                .map_or(lines.len(), |at| at + 1);
            for (index, line) in lines[..end].iter().enumerate() {
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
