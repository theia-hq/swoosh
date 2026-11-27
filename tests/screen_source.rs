// A source scan panics on a tree it cannot read, which is the intent; exempt it from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Two guards no running test can hold, read from `src/`. A string that names another line (`printed`,
//! `above`, `below`, `this line`) points at a line proven to print. And style takes only text fixed at build time, so a peer's text can never carry it.
//!
//! A third, of the same kind: a lock comes off a key file only where a person asked for that by name, so
//! every call that takes one off is counted, by file. And a fourth: the lock lines name the lock a removal
//! takes off, and say Touch ID the way a person does. And a fifth: the Touch ID dialog takes only words fixed
//! at build time. And a sixth: every command a shipped line or a help page names is one the binary has. And a
//! seventh: a revoke's lines that say it landed here are written only where a read-back proof prints them.
//!
//! Test files, inline `mod tests` blocks and comments are skipped: only what ships is read.

use std::path::Path;
use std::process::Command;

/// What stands behind a string that names another line.
enum Kind {
    /// The test `(file, fn)` asserts that the line the text names prints by default, on the same stream.
    Proven(&'static str, &'static str),
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
];

/// The words that name another line.
const NAMING: [&str; 4] = ["printed", "above", "below", "this line"];

#[test]
fn every_named_line_is_proven() {
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

/// Every call that takes a lock off a key file, by file: each is reached only from a `--remove`. A lock that
/// came off as a step of adding another (a replace) would be one more here.
const LOCK_REMOVALS: &[(&str, usize)] = &[
    // `lock passphrase --remove`, and `lock touch-id --remove` opened by the passphrase.
    ("identity.rs", 2),
    // `root lock touch-id --remove`.
    ("root/lock.rs", 1),
    // `lock touch-id --remove` opened by the touch itself.
    ("touch.rs", 1),
];

#[test]
fn only_a_removal_takes_a_lock_off() {
    let mut found: Vec<(String, usize)> = shipped()
        .into_iter()
        .map(|(file, text)| {
            let calls = scan(&text).code.matches("remove_lock(").count();
            (file, calls)
        })
        .filter(|&(_, calls)| calls > 0)
        .collect();
    found.sort();
    let expected: Vec<(String, usize)> = LOCK_REMOVALS
        .iter()
        .map(|&(file, calls)| (file.to_owned(), calls))
        .collect();
    assert_eq!(found, expected, "a new call that takes a lock off");
}

/// No act drops a lock as a step of adding another: the type that chose to (`Then`) and the end that said the
/// drop failed (`HalfDone`) are gone from the lock files, and neither comes back.
#[test]
fn no_lock_act_drops_the_other_lock() {
    for (file, text) in shipped()
        .into_iter()
        .filter(|(file, _)| ["identity.rs", "root/lock.rs", "touch.rs"].contains(&file.as_str()))
    {
        let code = scan(&text).code;
        for word in ["Then", "HalfDone"] {
            assert!(words(&code, word).is_empty(), "{file}: `{word}`");
        }
    }
}

/// The files that print a lock act's lines.
const LOCK_FILES: [&str; 5] = [
    "bin/swoosh/commands/lock.rs",
    "identity.rs",
    "passphrase.rs",
    "root/lock.rs",
    "touch.rs",
];

/// Every `--remove` a line prints names its method, since a bare one refuses or picks a lock the reader did
/// not name; and the lock files spell Touch ID as the reader says it, `touch-id` only inside a command, as
/// it is typed.
#[test]
fn a_lock_line_names_its_method_and_spells_touch_id() {
    for (file, text) in shipped() {
        for (line, literal) in scan(&text).literals {
            assert!(
                !literal.contains("swoosh lock --remove"),
                "{file}:{line}: a bare --remove in {literal:?}"
            );
            if !LOCK_FILES.contains(&file.as_str()) {
                continue;
            }
            for (at, _) in literal.match_indices("touch-id") {
                assert!(
                    literal[..at].ends_with("lock "),
                    "{file}:{line}: `touch-id` in prose in {literal:?}"
                );
            }
        }
    }
}

/// The words of a revoke's lines that say it landed here, each printed only from `Blocked`, the proof that
/// `revoked` read back what the revoke wrote. The proof is made nowhere else, so a line written outside its
/// file would print with no read-back.
const READ_BACK: [&str; 4] = [
    "revoked the link: ",
    "Your root revoked the device it stands for already.",
    " here for good.",
    "} for good.",
];

/// The one file that prints [`READ_BACK`]'s lines.
const READ_BACK_FILE: &str = "bin/swoosh/commands/reached.rs";

/// Each of [`READ_BACK`]'s words is in a literal of [`READ_BACK_FILE`] and of no other shipped file. Red when
/// a line that says a revoke landed is printed bare, before or without its read-back.
#[test]
fn a_landed_line_prints_only_from_its_read_back() {
    let mut seen = [false; READ_BACK.len()];
    for (file, text) in shipped() {
        for (line, literal) in scan(&text).literals {
            for (at, words) in READ_BACK.iter().enumerate() {
                if !literal.contains(words) {
                    continue;
                }
                assert_eq!(
                    file, READ_BACK_FILE,
                    "{file}:{line}: {literal:?} prints with no read-back"
                );
                seen[at] = true;
            }
        }
    }
    for (words, seen) in READ_BACK.iter().zip(seen) {
        assert!(
            seen,
            "{words:?} is no longer printed from its read-back: drop its row"
        );
    }
}

/// A root's key prints bare, `root:<key>`, never after the word `root`: `root root:` read as a stutter, and
/// named a `root:` line `status` no longer prints. Each site still owed is listed by its file and the unit
/// that owes it, and a listed site that no longer holds the phrase fails, so the list only shrinks.
#[test]
fn no_line_says_root_root() {
    // The first root's made line is SW6's; serve's admitting line is SW4g's.
    const OWED: [&str; 2] = ["root.rs", "bin/swoosh/commands/serve.rs"];
    let mut seen = [false; OWED.len()];
    for (file, text) in shipped() {
        for (line, literal) in scan(&text).literals {
            if !literal.contains("root root:") {
                continue;
            }
            match OWED.iter().position(|owed| *owed == file) {
                Some(at) => seen[at] = true,
                None => panic!("{file}:{line}: `root root:` in {literal:?}"),
            }
        }
    }
    for (owed, seen) in OWED.iter().zip(seen) {
        assert!(seen, "{owed} no longer says `root root:`: drop its row");
    }
}

/// The Touch ID dialog names the command that asked, and only words fixed at build time reach it: the one
/// call that names the command takes `&'static str`, the static holds one, and no shipped file makes one of a
/// `String` (`leak`), so a peer's text or a typed word cannot become `'static`. And one call in all of `src/`
/// names the command: the binary's, with its command's path, before any verb runs.
#[test]
fn the_dialog_takes_only_static_words() {
    let shipped: Vec<(String, String)> = shipped()
        .into_iter()
        .map(|(file, text)| (file, scan(&text).code))
        .collect();
    let code = |name: &str| {
        shipped
            .iter()
            .find_map(|(file, code)| (file == name).then_some(code.as_str()))
            .unwrap()
    };
    let lines = |name, needle| -> Vec<&str> {
        code(name)
            .lines()
            .filter(|line| line.contains(needle))
            .collect()
    };
    assert_eq!(
        lines("touch.rs", "fn for_command("),
        ["pub fn for_command(path: &'static str) {"]
    );
    assert_eq!(
        lines("touch.rs", "static COMMAND:"),
        ["static COMMAND: OnceLock<&'static str> = OnceLock::new();"]
    );
    let mut calls = Vec::new();
    for (file, code) in &shipped {
        assert!(
            !code.contains(".leak(") && !code.contains("::leak"),
            "{file} leaks"
        );
        let named = code.matches("for_command(").count() - code.matches("fn for_command(").count();
        calls.extend(core::iter::repeat_n(file.as_str(), named));
    }
    assert_eq!(calls, ["bin/swoosh/main.rs"], "one call names the command");
    assert!(code("bin/swoosh/main.rs").contains("swoosh::touch::for_command(command.path());"));
}

/// Every `swoosh <verb> [<leaf>]` a shipped literal or a rendered `-h` or `--help` names is a command the
/// binary has. Red when a line names a verb the binary lacks, as `swoosh tree` did once the verb was cut.
#[test]
fn every_named_command_exists() {
    let (commands, pages) = command_tree();
    let mut missing = Vec::new();
    let texts = pages
        .iter()
        .map(|(path, page)| (path.clone(), page.clone()));
    let literals = shipped().into_iter().flat_map(|(file, text)| {
        scan(&text)
            .literals
            .into_iter()
            .map(move |(line, literal)| (format!("{file}:{line}"), literal))
    });
    for (site, text) in texts.chain(literals) {
        for named in named_commands(&text) {
            let verb = &named[0];
            // A group's next plain word must be one of its leaves; any other verb's is an argument.
            let group = commands
                .iter()
                .any(|path| path.starts_with(&format!("{verb} ")));
            let exists = commands.contains(verb)
                && match named.get(1) {
                    Some(leaf) if group => commands.contains(&format!("{verb} {leaf}")),
                    _ => true,
                };
            if !exists {
                missing.push(format!("{site}: swoosh {}", named.join(" ")));
            }
        }
    }
    assert!(missing.is_empty(), "commands swoosh lacks: {missing:#?}");
}

/// The binary's commands, read off its own help (each verb under a heading of `swoosh --help`, each leaf in a
/// group's `Commands:`), and every `-h` and `--help` page, by the command's path.
fn command_tree() -> (Vec<String>, Vec<(String, String)>) {
    let help = |path: &[&str], flag: &str| {
        let out = Command::new(env!("CARGO_BIN_EXE_swoosh"))
            .args(path)
            .arg(flag)
            .env_remove("SWOOSH_HOME")
            .output()
            .unwrap();
        assert!(out.status.success(), "swoosh {path:?} {flag}");
        String::from_utf8(out.stdout).unwrap()
    };
    // A row is a name indented two under a heading that is not clap's own frame.
    let rows = |page: &str, under: fn(&str) -> bool| {
        let mut heading = false;
        let mut names = Vec::new();
        for line in page.lines() {
            if !line.starts_with(' ') && line.ends_with(':') {
                heading = under(line);
            } else if let Some(name) = line.strip_prefix("  ").filter(|_| heading) {
                let name = name.split_whitespace().next().unwrap_or_default();
                if name != "help" && name.starts_with(|c: char| c.is_ascii_lowercase()) {
                    names.push(name.to_owned());
                }
            }
        }
        names
    };
    let top = help(&[], "--help");
    let verbs = rows(&top, |line| {
        !["Usage:", "Options:", "Arguments:"].contains(&line)
    });
    let mut commands = Vec::new();
    let mut pages = vec![
        ("swoosh".to_owned(), top),
        ("swoosh".to_owned(), help(&[], "-h")),
    ];
    for verb in &verbs {
        let page = help(&[verb], "--help");
        for leaf in rows(&page, |line| line == "Commands:") {
            for flag in ["-h", "--help"] {
                pages.push((format!("swoosh {verb} {leaf}"), help(&[verb, &leaf], flag)));
            }
            commands.push(format!("{verb} {leaf}"));
        }
        pages.push((format!("swoosh {verb}"), help(&[verb], "-h")));
        pages.push((format!("swoosh {verb}"), page));
        commands.push(verb.clone());
    }
    (commands, pages)
}

/// Words that follow `swoosh` as a sentence's verb or a noun, never as a command.
const PROSE: &[&str] = &[
    "build",
    "cannot",
    "is",
    "looks",
    "needs",
    "never",
    "publishes",
    "uses",
    "version",
    "will",
];

/// The words after `swoosh` a text names as a command, up to two: a verb, and the plain word after it
/// unless the verb ends a clause (`swoosh serve's` names `serve`). `swoosh` as a sentence's subject
/// (`swoosh needs`), after an article (`the swoosh home`), or ending a clause names no command, and a
/// placeholder (`{verb}`, `<service>`) is no word.
fn named_commands(text: &str) -> Vec<Vec<String>> {
    let words: Vec<&str> = text.split_whitespace().collect();
    let bare = |word: &str| {
        let word = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '-');
        word.strip_suffix("'s").unwrap_or(word).to_owned()
    };
    let plain = |word: &&&str| word.starts_with(|c: char| c.is_ascii_lowercase());
    let ends = |word: &str| word.ends_with([',', '.', ':', ';', ')', '`', '\'']);
    let mut named = Vec::new();
    for (at, word) in words.iter().enumerate() {
        if word.trim_start_matches(['`', '(', '\'']) != "swoosh" {
            continue;
        }
        let after_article = at
            .checked_sub(1)
            .and_then(|before| words.get(before))
            .is_some_and(|before| ["the", "a", "The", "A"].contains(before));
        let Some(verb) = words.get(at + 1) else {
            continue;
        };
        if after_article || PROSE.contains(&bare(verb).as_str()) || !plain(&verb) {
            continue;
        }
        let mut path = vec![bare(verb)];
        if let Some(leaf) = words.get(at + 2).filter(plain).filter(|_| !ends(verb)) {
            path.push(bare(leaf));
        }
        named.push(path);
    }
    named
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
