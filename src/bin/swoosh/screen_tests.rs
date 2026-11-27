use std::io;

use anstream::AutoStream;
use swoosh::escape::EscapedComplete;

use super::{Block, Cell, Paint, Screen, Span, StateLine, Style, width};

/// The screen as a pipe reads it.
fn written(screen: &Screen<'_>) -> String {
    let mut out = Vec::new();
    screen.write(&mut out).unwrap();
    String::from_utf8(out).unwrap()
}

/// Service rows in one untitled block, the layout a service list prints.
fn rows<'a>(rows: impl IntoIterator<Item = (&'a str, Cell<'a>, &'a str)>) -> Screen<'a> {
    let block = rows
        .into_iter()
        .fold(Block::default(), |block, (name, audience, target)| {
            block.row([Cell::Token(name), audience, Cell::Token(target)])
        });
    Screen::default().block(block)
}

/// Each column after the first starts at its place or later: short values keep one place, a wider first cell
/// moves the later columns right, never left, and one place is `column`'s. Red when a place past the first is
/// dropped, or `column(17)` stops padding its first column to 13.
#[test]
fn columns_start_each_column_at_its_place_or_later() {
    let table = |at: &[usize], first: &'static str| {
        written(
            &Screen::default().block(
                Block::default()
                    .columns(at.iter().copied())
                    .row([Cell::Word(first), Cell::Word("on"), Cell::Word("gloss")])
                    .row([Cell::Word("b"), Cell::Word("off"), Cell::Word("gloss")]),
            ),
        )
    };
    assert_eq!(
        table(&[15, 21], "a"),
        "  a            on    gloss\n  b            off   gloss\n"
    );
    assert_eq!(
        table(&[15, 21], "a first cell past 15"),
        "  a first cell past 15  on    gloss\n  b                     off   gloss\n"
    );
    assert_eq!(table(&[], "a"), "  a  on   gloss\n  b  off  gloss\n");
    let one = |block: Block<'static>| {
        written(&Screen::default().block(block.row([Cell::Word("key"), Cell::Word("value")])))
    };
    assert_eq!(one(Block::default().column(17)), "  key            value\n");
    assert_eq!(
        one(Block::default().column(17)),
        one(Block::default().columns([17]))
    );
}

#[test]
fn blocks_sit_a_blank_line_apart_and_columns_align() {
    let screen = Screen::default()
        .block(Block::titled("swoosh is serving"))
        .block(Block::default())
        .block(
            Block::default()
                .column(17)
                .row([Cell::Word("key"), Cell::Token("ed01example")]),
        )
        .block(
            Block::titled("serving")
                .row([Cell::Word("selection"), Cell::Word("default services")])
                .row([
                    Cell::Token("ping"),
                    Cell::Word("your devices"),
                    Cell::Token("ping:"),
                ])
                .row([
                    Cell::Token("web"),
                    Cell::Risk("anyone"),
                    Cell::Token("tcp:1"),
                ])
                .text("Serving nothing.".to_owned())
                .command("swoosh service add <service>".to_owned()),
        );
    assert_eq!(
        written(&screen),
        "swoosh is serving\n\n  key            ed01example\n\nserving\n  selection  default services\n  \
         ping       your devices  ping:\n  web        anyone        tcp:1\nServing nothing.\n  swoosh \
         service add <service>\n"
    );
    assert!(written(&Screen::default().block(Block::default())).is_empty());
}

#[test]
fn a_row_past_80_stacks_and_a_token_never_splits() {
    // A token that cannot fit, or is not ASCII, stacks alone and widens nothing.
    for target in [
        "unix:/two ordinary spaces".to_owned(),
        "unix:/秘密 with spaces".to_owned(),
        "unix:/a\n\r\t\u{1b}\\\u{202e}".to_owned(),
        format!("unix:/{} with spaces", "x".repeat(4096)),
    ] {
        let out = written(&rows([
            ("a", Cell::Word("your devices"), target.as_str()),
            ("z", Cell::Risk("anyone"), "ping:"),
        ]));
        assert!(out.contains(&EscapedComplete(&target).to_string()));
        assert!(!out.contains("..."));
        assert!(out.lines().all(|line| !line.ends_with(' ')));
        if target.len() > 256 || !target.is_ascii() {
            assert!(
                out.starts_with("  a\n    your devices\n    unix:/"),
                "{out}"
            );
            assert!(out.ends_with("  z  anyone  ping:\n"), "{out}");
        }
    }

    // Fixed words wrap; a target between them stays whole on its own line.
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
    assert_eq!(width(EscapedComplete("unix:/a\n")), 9);

    // A stacked row's fixed words wrap at a word break inside 80.
    const WORDS: &str =
        "fixed words that run past the eighty columns of a screen wrap at a word break";
    let name = "x".repeat(70);
    let screen =
        Screen::default().block(Block::default().row([Cell::Token(&name), Cell::Word(WORDS)]));
    let out = written(&screen);
    let lines: Vec<_> = out.lines().collect();
    assert_eq!(lines.len(), 3, "{out}");
    assert_eq!(lines[0], format!("  {name}"));
    assert!(
        lines[1..]
            .iter()
            .all(|line| line.starts_with("    ") && line.len() <= 80),
        "{out}"
    );
    assert_eq!(
        lines[1..]
            .iter()
            .map(|line| line.trim())
            .collect::<Vec<_>>()
            .join(" "),
        WORDS
    );

    // 80 fits on one line, 81 stacks.
    for (size, one_line) in [(61, true), (62, false)] {
        let target = "x".repeat(size);
        let out = written(&rows([("a", Cell::Word("your devices"), target.as_str())]));
        assert_eq!(out.starts_with("  a  "), one_line, "{out}");
        assert!(out.lines().all(|line| line.len() <= 80));
    }

    struct Broken;
    impl io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("broken sink"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl Paint for Broken {}
    let screen = rows([("a", Cell::Word("your devices"), "ping:")]);
    assert!(screen.write(&mut Broken).is_err());
}

#[test]
fn style_reaches_a_terminal_and_never_a_pipe() {
    let screen = Screen::default().block(Block::titled("serving").row([
        Cell::Token("\u{1b}[31mweb"),
        Cell::Risk("anyone"),
        Cell::Token("tcp:1"),
    ]));
    let (title, risk) = (Style::TITLE.0, Style::RISK.0);
    let mut terminal = AutoStream::always(Vec::new());
    screen.write(&mut terminal).unwrap();
    // The peer's escape is spelled out by the escaper; the only escapes left are swoosh's own.
    assert_eq!(
        String::from_utf8(terminal.into_inner()).unwrap(),
        format!("{title}serving{title:#}\n  \\u{{1b}}[31mweb  {risk}anyone{risk:#}  tcp:1\n")
    );
    for style in [Style::TITLE, Style::ERROR, Style::WARNING, Style::RISK] {
        let sgr = style.0;
        let painted = style.paint("error:", &AutoStream::always(Vec::new()));
        assert_eq!(painted.to_string(), format!("{sgr}error:{sgr:#}"));
        assert!(!sgr.to_string().is_empty());
        assert_eq!(style.paint("error:", &Vec::new()).to_string(), "error:");
    }

    // Stacked, a risk keeps its style on a line of its own.
    let stacked = Screen::default().block(Block::default().row([
        Cell::Token("秘"),
        Cell::Risk("anyone"),
        Cell::Token("tcp:1"),
    ]));
    let mut terminal = AutoStream::always(Vec::new());
    stacked.write(&mut terminal).unwrap();
    assert_eq!(
        String::from_utf8(terminal.into_inner()).unwrap(),
        format!("  秘\n    {risk}anyone{risk:#}\n    tcp:1\n")
    );

    let mut pipe = AutoStream::never(Vec::new());
    screen.write(&mut pipe).unwrap();
    let mut plain = Vec::new();
    screen.write(&mut plain).unwrap();
    for out in [pipe.into_inner(), plain] {
        assert!(!out.contains(&0x1b), "{}", String::from_utf8_lossy(&out));
        assert_eq!(out, b"serving\n  \\u{1b}[31mweb  anyone  tcp:1\n");
    }
}

/// The check reads every line of every block a test writes, with no line excused: the 81-column line
/// the banner once printed is caught like any other breach.
#[test]
fn a_screen_a_test_writes_is_held_to_the_law() {
    for (line, rule) in [
        (
            "to keep this machine serving after a reboot: systemctl --user enable --now swoosh",
            "Width",
        ),
        ("Two sentences. One line.", "TwoSentences"),
    ] {
        let breach = Block::default().text(line.to_owned());
        let caught = std::panic::catch_unwind(|| written(&Screen::default().block(breach)));
        let message = caught.unwrap_err().downcast::<String>().unwrap();
        assert!(message.contains(rule), "{message}");
    }
}

/// A writer that keeps each write apart, and shows style when its flag says so.
struct Counted(Vec<Vec<u8>>, bool);

impl io::Write for Counted {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.push(buf.to_vec());
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Paint for Counted {
    fn styled(&self) -> bool {
        self.1
    }
}

/// A screen is built whole and written once, styled or not, so an early-closing reader or a line logged
/// beside it cannot tear it.
#[test]
fn a_screen_is_one_write() {
    let screen = Screen::default()
        .block(Block::titled("swoosh is serving"))
        .block(Block::titled("serving").row([Cell::Token("web"), Cell::Risk("anyone")]))
        .block(Block::default().text("ctrl-c to stop".to_owned()));
    for styled in [false, true] {
        let mut out = Counted(Vec::new(), styled);
        screen.write(&mut out).unwrap();
        assert_eq!(out.0.len(), 1, "styled {styled}");
        assert_eq!(out.0[0].contains(&0x1b), styled);
    }
    // So are a refusal's line and the warning line, styled.
    let mut out = Counted(Vec::new(), true);
    crate::print_error(&eyre::eyre!("refused"), &mut out);
    let failed = swoosh::observation::Observed {
        last: Err(swoosh::observation::ObservationError::Unavailable),
        earlier: None,
    };
    crate::commands::through_serve::final_path(failed, &mut out).unwrap();
    assert_eq!(out.0.len(), 2, "{:?}", out.0);
}

/// A refusal's bytes are built by `error_lines` alone and written in one write, styled or not, so a test
/// that holds `error_lines` to the law holds what a person sees: a chain with detail lines included.
#[test]
fn error_lines_is_what_print_error_writes() {
    let refused = eyre::eyre!("could not reach me/laptop\n  On me/laptop, run swoosh serve.")
        .wrap_err("send ended");
    for styled in [false, true] {
        let mut out = Counted(Vec::new(), styled);
        crate::print_error(&refused, &mut out);
        let lines = crate::error_lines(&refused, &out);
        assert_eq!(out.0, [lines.into_bytes()], "styled {styled}");
        assert_eq!(out.0[0].contains(&0x1b), styled);
    }
    let plain = crate::error_lines(&refused, &Vec::new());
    assert_eq!(
        plain,
        "error: send ended: could not reach me/laptop\n  On me/laptop, run swoosh serve.\n"
    );
}

/// A title's value sits at the head block's value column, or one space after the title in any other block;
/// one that does not fit beside the title goes below it at indent four, whole. Red when the value moves or
/// runs past 80.
#[test]
fn a_title_carries_its_value_or_stacks_it() {
    let long = "x".repeat(70);
    assert_eq!(
        written(
            &Screen::default().block(
                Block::titled("this machine")
                    .column(17)
                    .value(Cell::Word("a value"))
            )
        ),
        "this machine     a value\n"
    );
    assert_eq!(
        written(&Screen::default().block(Block::titled("devices").value(Cell::Token("(a note)")))),
        "devices (a note)\n"
    );
    assert_eq!(
        written(
            &Screen::default().block(
                Block::titled("this machine")
                    .column(17)
                    .value(Cell::Token(&long))
            )
        ),
        format!("this machine\n    {long}\n")
    );
}
