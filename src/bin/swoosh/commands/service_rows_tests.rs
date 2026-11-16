use std::io;

use super::{Row, Span, StateLine, label_width, render_aligned, width};

/// Rows aligned on their own label width, the layout with no outer label column.
fn render(rows: &[Row<'_>], out: &mut impl io::Write) -> io::Result<()> {
    render_aligned(rows, label_width(rows), out)
}

#[test]
fn complete_escaped_targets_are_indivisible_and_do_not_set_padding() {
    for target in [
        "unix:/two ordinary spaces".to_owned(),
        "unix:/秘密 with spaces".to_owned(),
        "unix:/a\n\r\t\u{1b}\\\u{202e}".to_owned(),
        format!("unix:/{} with spaces", "x".repeat(4096)),
    ] {
        let mut out = Vec::new();
        render(
            &[
                Row {
                    name: "a",
                    audience: "your devices",
                    target: &target,
                },
                Row {
                    name: "z",
                    audience: "anyone",
                    target: "ping:",
                },
            ],
            &mut out,
        )
        .unwrap();
        let out = String::from_utf8(out).unwrap();
        let escaped = format!("{}", swoosh::escape::EscapedComplete(&target));
        assert!(out.contains(&escaped));
        assert!(!out.contains("..."));
        assert!(out.lines().all(|line| !line.ends_with(' ')));
        if target.len() > 256 || !target.is_ascii() {
            assert!(out.starts_with("  a\n    your devices\n    unix:/"));
            assert!(out.ends_with("  z  anyone  ping:\n"));
        }
    }
}

#[test]
fn fixed_words_wrap_but_complete_targets_never_split() {
    let mut out = Vec::new();
    let target = format!("unix:/{} with spaces", "x".repeat(80));
    let mut line = StateLine {
        out: &mut out,
        column: 0,
    };
    line.words("off,").unwrap();
    line.span(Span::Target(&target)).unwrap();
    line.words("from the next start").unwrap();
    line.finish().unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        format!("    off,\n    {target}\n    from the next start\n")
    );
    assert_eq!(width(swoosh::escape::EscapedComplete("unix:/a\n")), 9);
}

#[test]
fn compact_boundaries_use_escaped_width_and_independent_maxima() {
    for (size, compact) in [(61, true), (62, false)] {
        let target = "x".repeat(size);
        let mut out = Vec::new();
        render(
            &[Row {
                name: "a",
                audience: "your devices",
                target: &target,
            }],
            &mut out,
        )
        .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert_eq!(out.starts_with("  a  "), compact);
        assert!(out.lines().all(|line| line.len() <= 80));
    }
    let mut out = Vec::new();
    render(&[], &mut out).unwrap();
    assert!(out.is_empty());
}

#[test]
fn row_rendering_propagates_sink_failure() {
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("broken sink"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    assert!(
        render(
            &[Row {
                name: "a",
                audience: "your devices",
                target: "ping:"
            }],
            &mut Broken
        )
        .is_err()
    );
}
