// A source scan panics on a tree it cannot read, which is the intent; exempt it from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Two guards no running test can hold, read from `src/`. A string that names another line (`printed`,
//! `above`, `below`, `this line`) points at a line proven to print, or is a known defect owed to a later
//! change. And style takes only text fixed at build time, so a peer's text can never carry it.
//!
//! Test files, inline `mod tests` blocks and comments are skipped: only what ships is read.

use std::path::Path;

/// What stands behind a string that names another line.
enum Kind {
    /// The test `(file, fn)` asserts that the line the text names prints by default, on the same stream.
    Proven(&'static str, &'static str),
    /// A known defect, owed to this unit, and kept only while its phrase is still in its file.
    Owed(&'static str),
}

/// Every string that names another line: its file under `src/`, the phrase, and what stands behind it.
const NAMED: &[(&str, &str, Kind)] = &[
    (
        "bin/swoosh/commands/proxy.rs",
        "the URL swoosh proxy printed",
        Kind::Proven(
            "src/bin/swoosh/commands/proxy_tests.rs",
            "an_admitted_proxy_prints_its_url_alone",
        ),
    ),
    // The root prints nothing for it, so the text never reaches a screen.
    (
        "bin/swoosh/commands/through_serve.rs",
        "was printed before",
        Kind::Proven(
            "tests/exchange_route.rs",
            "a_landed_join_beside_an_unreachable_serve_prints_its_error_once",
        ),
    ),
    (
        "bin/swoosh/commands/invite.rs",
        "paste this line",
        Kind::Owed("SW4"),
    ),
    ("reach_report.rs", "the line above", Kind::Owed("SW4")),
];

/// The words that name another line.
const NAMING: [&str; 4] = ["printed", "above", "below", "this line"];

#[test]
fn every_named_line_is_proven_or_owed() {
    let mut matched = vec![0; NAMED.len()];
    for (file, text) in shipped() {
        for (line, literal) in scan(&text).literals {
            let literal = literal.to_lowercase();
            for (at, word) in NAMING.iter().flat_map(|word| words(&literal, word)) {
                // A row covers a hit when its phrase, in this file, spans the word.
                let rows: Vec<usize> = (0..NAMED.len())
                    .filter(|&row| NAMED[row].0 == file)
                    .filter(|&row| {
                        let phrase = NAMED[row].1.to_lowercase();
                        literal
                            .match_indices(&phrase)
                            .any(|(p, _)| p <= at && at + word.len() <= p + phrase.len())
                    })
                    .collect();
                assert_eq!(rows.len(), 1, "{file}:{line}: `{word}` in {literal:?}");
                matched[rows[0]] += 1;
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for ((file, phrase, kind), hits) in NAMED.iter().zip(matched) {
        match kind {
            Kind::Owed(unit) => assert!(
                hits > 0,
                "{file}: `{phrase}` is gone; drop its row ({unit})"
            ),
            Kind::Proven(test_file, test) => {
                assert!(hits > 0, "{file}: `{phrase}` is gone; drop its row");
                let source = std::fs::read_to_string(root.join(test_file)).unwrap();
                let lines: Vec<&str> = source.lines().collect();
                let at = lines
                    .iter()
                    .position(|line| line.contains(&format!("fn {test}(")));
                // The attributes right above the fn: a test that runs, never an ignored one.
                let attributes: Vec<&str> = at.map_or(Vec::new(), |at| {
                    lines[..at]
                        .iter()
                        .rev()
                        .map(|line| line.trim())
                        .take_while(|line| line.starts_with("#["))
                        .collect()
                });
                let runs = attributes
                    .iter()
                    .any(|line| *line == "#[test]" || line.starts_with("#[tokio::test"));
                let ignored = attributes.iter().any(|line| line.starts_with("#[ignore"));
                assert!(
                    runs && !ignored,
                    "{file}: `{phrase}` is proven by {test_file}::{test}, a test that runs"
                );
            }
        }
    }
}

#[test]
fn the_styling_type_takes_only_static_text() {
    let screen = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin/swoosh/screen.rs"),
    )
    .unwrap();
    let code = scan(&screen).code;
    let paint: Vec<&str> = code
        .lines()
        .filter(|line| line.contains("fn paint("))
        .collect();
    assert_eq!(paint.len(), 1, "one way to style: {paint:?}");
    assert!(paint[0].contains("text: &'static str"), "{}", paint[0]);
    // What `paint` returns holds the text as it was given, so it too takes only static text.
    let painted = code.split("struct Painted {").nth(1).unwrap_or_default();
    let fields = painted.split('}').next().unwrap_or_default();
    assert!(fields.contains("text: &'static str,"), "Painted: {fields}");
    let style = code
        .lines()
        .find(|line| line.contains("struct Style("))
        .unwrap();
    assert!(
        style.contains("struct Style(styling::Style)"),
        "a private field: {style}"
    );

    // `leak` is the one way to make a `&'static str` of a peer's `String`.
    for (file, text) in shipped()
        .into_iter()
        .filter(|(file, _)| file.starts_with("bin/"))
    {
        let code = scan(&text).code;
        assert!(
            !code.contains(".leak(") && !code.contains("::leak"),
            "{file} leaks"
        );
    }
}

/// Every shipped source file, by its path under `src/`, cut before an inline `mod tests` block.
fn shipped() -> Vec<(String, String)> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    let mut dirs = vec![src.clone()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.to_string_lossy().into_owned();
            if path.is_dir() {
                dirs.push(path);
            } else if name.ends_with(".rs") && !name.ends_with("_tests.rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                let file = path
                    .strip_prefix(&src)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                files.push((file, shipped_part(text)));
            }
        }
    }
    files
}

/// `text` before its inline `mod tests {` block, which must run to the end of the file, so nothing
/// shipped hides past it.
fn shipped_part(mut text: String) -> String {
    let Some(start) = text
        .find("\nmod tests {")
        .or(text.find("\npub(crate) mod tests {"))
    else {
        return text;
    };
    let tail = scan(&text[start..]).code;
    let mut depth = 0_i32;
    let closed = tail.char_indices().find(|&(_, c)| {
        depth += i32::from(c == '{') - i32::from(c == '}');
        c == '}' && depth == 0
    });
    let (end, _) = closed.expect("the test block closes");
    assert!(
        tail[end + 1..].trim().is_empty(),
        "code past an inline test block"
    );
    text.truncate(start);
    text
}

/// Each whole-word `word` in `text`: its byte offset, and the word.
fn words<'w>(text: &str, word: &'w str) -> Vec<(usize, &'w str)> {
    let part = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
    text.match_indices(word)
        .filter(|&(at, _)| {
            !part(text[..at].chars().next_back()) && !part(text[at + word.len()..].chars().next())
        })
        .map(|(at, _)| (at, word))
        .collect()
}

/// A source file split as the compiler reads it.
struct Scanned {
    /// Each string literal, by the line it starts on, its escapes read (a `\` line break joins).
    literals: Vec<(usize, String)>,
    /// What is neither a literal nor a comment.
    code: String,
}

/// Split `text` into its literals and its code, comments dropped. Panics on a literal or comment left
/// open, so a slip in the scan fails loudly instead of missing hits.
fn scan(text: &str) -> Scanned {
    let chars: Vec<char> = text.chars().collect();
    let at = |i: usize| chars.get(i).copied().unwrap_or('\0');
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    let (mut literals, mut code) = (Vec::new(), String::new());
    let (mut i, mut line) = (0, 1);
    while i < chars.len() {
        let from = line;
        if at(i) == '/' && at(i + 1) == '/' {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if at(i) == '/' && at(i + 1) == '*' {
            let mut depth = 0;
            loop {
                match (at(i), at(i + 1)) {
                    ('/', '*') => (depth, i) = (depth + 1, i + 2),
                    ('*', '/') => (depth, i) = (depth - 1, i + 2),
                    ('\0', _) => panic!("a comment left open at line {from}"),
                    (c, _) => (line, i) = (line + usize::from(c == '\n'), i + 1),
                }
                if depth == 0 {
                    break;
                }
            }
        } else if let Some((open, hashes, raw)) = opens(&chars, i) {
            let mut literal = String::new();
            i = open;
            loop {
                let closes = at(i) == '"' && (i + 1..=i + hashes).all(|j| at(j) == '#');
                match at(i) {
                    _ if closes => break,
                    '\0' => panic!("a literal left open at line {from}"),
                    '\\' if !raw => {
                        let escaped = at(i + 1);
                        i += 2;
                        match escaped {
                            // A `\` line break joins the lines, dropping the next one's indent.
                            '\n' => {
                                line += 1;
                                while at(i).is_whitespace() {
                                    line += usize::from(at(i) == '\n');
                                    i += 1;
                                }
                            }
                            'n' | 't' | 'r' => literal.push(' '),
                            other => literal.push(other),
                        }
                    }
                    c => {
                        line += usize::from(c == '\n');
                        literal.push(c);
                        i += 1;
                    }
                }
            }
            i += 1 + hashes;
            literals.push((from, literal));
        } else if at(i) == '\'' && (at(i + 1) == '\\' || at(i + 2) == '\'') {
            // A char literal, never a lifetime: `'"'` must not open a string.
            i += if at(i + 1) == '\\' { 3 } else { 2 };
            while at(i) != '\'' {
                i += 1;
            }
            i += 1;
        } else {
            let c = chars[i];
            line += usize::from(c == '\n');
            code.push(c);
            i += 1;
            // An identifier is read whole, so only one's first letter can open a prefixed literal.
            while ident(c) && ident(at(i)) {
                code.push(chars[i]);
                i += 1;
            }
        }
    }
    Scanned { literals, code }
}

/// Whether a string literal opens at `i`, `"`, `b"`, `c"`, `r#"` or `br#"`: where its text starts, the
/// hashes that close it, and whether it is raw, reading no escape.
fn opens(chars: &[char], i: usize) -> Option<(usize, usize, bool)> {
    let at = |i: usize| chars.get(i).copied().unwrap_or('\0');
    let mut j = i + usize::from(at(i) == 'b' || at(i) == 'c');
    let raw = at(j) == 'r';
    j += usize::from(raw);
    let hashes = chars[j.min(chars.len())..]
        .iter()
        .take_while(|&&c| c == '#')
        .count();
    (at(j + hashes) == '"' && (raw || hashes == 0)).then_some((j + hashes + 1, hashes, raw))
}
