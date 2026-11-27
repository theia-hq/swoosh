//! The help a person reads, held over the real command tree: every verb once under its heading, every row
//! one capitalized phrase that fits 80 columns, no retired word, `tree` gone, and swoosh's own sentences in
//! it held to the screen law.

use clap::{CommandFactory as _, Parser as _};

use super::GROUPS;
use crate::Cli;
use crate::screen::law;

/// `--home`'s row keeps its words until the home's own help is rewritten, so it is no row of clap's form and
/// it runs past 80. It is held apart, pinned to its widest print.
const HOME: &str = "node-home";

/// `--home`'s widest print: serve's `-h`, whose option column is the widest. A row that grows goes red.
#[cfg(target_os = "macos")]
const HOME_WIDEST: usize = 103;
/// `--home`'s widest print: serve's `-h`, whose option column is the widest. A row that grows goes red.
#[cfg(not(target_os = "macos"))]
const HOME_WIDEST: usize = 112;

/// Rows past 80 that keep their words until a later rewrite: the command's path, the row's first words and
/// its widest print, so a row that grows or comes to fit goes red. `root lock`'s method row is wide only
/// where it names Touch ID.
#[cfg(target_os = "macos")]
const WIDE: &[(&str, &str, usize)] = &[("swoosh root lock", "How your root opens", 93)];
/// Rows past 80 that keep their words until a later rewrite: the command's path, the row's first words and
/// its widest print, so a row that grows or comes to fit goes red.
#[cfg(not(target_os = "macos"))]
const WIDE: &[(&str, &str, usize)] = &[];

/// clap's frame lines past 80 with no shorter form yet: the command's path, the line's first words, and its
/// exact width, so a line that grows or comes to fit goes red.
const FRAME_WIDE: &[(&str, &str, usize)] = &[];

/// Help text that breaks the screen law by design: the command's path, the text's first words, the rule it
/// breaks and its widest printed line, so a text that grows or comes to hold goes red.
const BROKEN: &[(&str, &str, law::Rule, usize)] = &[
    // The recipe prints unwrapped, so each line pastes whole at any width.
    (
        "swoosh revoke",
        "To replace your root",
        law::Rule::Width,
        136,
    ),
];

/// Every command a person can reach, with the words that reach it, the root first, and `help` left out:
/// clap's own, it has no help of ours.
fn every_command() -> Vec<(String, clap::Command)> {
    fn walk(command: &clap::Command, path: &str, found: &mut Vec<(String, clap::Command)>) {
        for sub in command.get_subcommands() {
            if sub.get_name() == "help" || sub.is_hide_set() {
                continue;
            }
            let path = format!("{path} {}", sub.get_name());
            found.push((path.clone(), sub.clone()));
            walk(sub, &path, found);
        }
    }
    let mut root = Cli::command();
    root.build();
    let mut found = vec![("swoosh".to_owned(), root.clone())];
    walk(&root, "swoosh", &mut found);
    found
}

/// A command's `-h` and `--help`, as a pipe reads them.
fn pages(command: &mut clap::Command) -> [String; 2] {
    [
        command.render_help().to_string(),
        command.render_long_help().to_string(),
    ]
}

/// Every row a command's help shows, by its first line: each visible subcommand's about and each visible
/// argument's help, `--home`'s aside.
fn rows(command: &clap::Command) -> Vec<String> {
    let first = |text: &clap::builder::StyledStr| {
        text.to_string()
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned()
    };
    let subs = command
        .get_subcommands()
        .filter(|sub| sub.get_name() != "help" && !sub.is_hide_set())
        .filter_map(|sub| sub.get_about().map(first));
    let args = command
        .get_arguments()
        .filter(|arg| !arg.is_hide_set() && arg.get_id() != HOME)
        .filter_map(|arg| arg.get_help().map(first));
    subs.chain(args).collect()
}

/// `swoosh --help` lists every visible verb once, under the heading the command table gives it, in that
/// order. Red when a verb is missing from the groups, listed twice, or printed out of its group.
#[test]
fn every_verb_appears_once_under_a_heading() {
    let mut root = Cli::command();
    root.build();
    let mut verbs: Vec<&str> = root
        .get_subcommands()
        .filter(|sub| sub.get_name() != "help" && !sub.is_hide_set())
        .map(clap::Command::get_name)
        .collect();
    let mut grouped: Vec<&str> = GROUPS
        .iter()
        .flat_map(|(_, names)| names.iter().copied())
        .collect();
    verbs.sort_unstable();
    grouped.sort_unstable();
    assert_eq!(verbs, grouped, "each verb in exactly one group");

    let help = root.render_help().to_string();
    let mut printed: Vec<(String, String)> = Vec::new();
    let mut heading = None;
    for line in help.lines() {
        if let Some(name) = line.strip_suffix(':').filter(|_| !line.starts_with(' ')) {
            heading = Some(name.to_owned());
            continue;
        }
        let (Some(heading), Some(verb)) = (&heading, line.strip_prefix("  ")) else {
            continue;
        };
        let verb = verb.split_whitespace().next().unwrap_or_default();
        if !verb.starts_with('-') {
            printed.push((heading.clone(), verb.to_owned()));
        }
    }
    let expected: Vec<(String, String)> = GROUPS
        .iter()
        .flat_map(|(heading, names)| {
            names
                .iter()
                .map(|name| ((*heading).to_owned(), (*name).to_owned()))
        })
        .collect();
    assert_eq!(printed, expected, "{help}");
}

/// The rows each verb prints say what the verb's own help says: the template reads clap's model, so the
/// two cannot drift. Red when the template prints a row of its own.
#[test]
fn the_grouped_rows_are_the_verbs_own_help() {
    let mut root = Cli::command();
    root.build();
    let help = root.render_help().to_string();
    for sub in root.get_subcommands() {
        if sub.get_name() == "help" {
            continue;
        }
        let about = sub.get_about().unwrap().to_string();
        let row = help
            .lines()
            .find(|line| line.split_whitespace().next() == Some(sub.get_name()))
            .unwrap();
        assert_eq!(row.trim_start()[sub.get_name().len()..].trim(), about);
    }
}

/// Every rendered row of every `-h` and `--help` fits 80 columns, the indent and the name included, unless
/// it is pinned in `WIDE`. Red when a row runs past 80, or a pinned one changes width.
#[test]
fn every_help_row_fits_80() {
    let mut wide = Vec::new();
    for (path, mut command) in every_command() {
        let rows = rows(&command);
        for page in pages(&mut command) {
            for line in page.lines() {
                let held = rows
                    .iter()
                    .any(|row| !row.is_empty() && line.contains(row.as_str()));
                if held
                    && line.chars().count() > 80
                    && !wide.contains(&(path.clone(), line.to_owned()))
                {
                    wide.push((path.clone(), line.to_owned()));
                }
            }
        }
    }
    let listed = |path: &str, line: &str| {
        WIDE.iter()
            .find(|(at, words, _)| *at == path && line.trim_start().contains(words))
    };
    let unlisted: Vec<_> = wide
        .iter()
        .filter(|(path, line)| listed(path, line).is_none())
        .collect();
    assert!(unlisted.is_empty(), "rows past 80: {unlisted:#?}");
    for (at, words, pinned) in WIDE {
        let widest = wide
            .iter()
            .filter(|(path, line)| path == at && line.trim_start().contains(words))
            .map(|(_, line)| line.chars().count())
            .max();
        assert_eq!(widest, Some(*pinned), "{at} `{words}`: fix WIDE");
    }
}

/// Every verb's `--home` row is the one global row, and it prints no wider than it did. Red when it grows.
#[test]
fn the_home_row_is_pinned() {
    let mut widest = 0;
    for (path, mut command) in every_command() {
        let Some(home) = command.get_arguments().find(|arg| arg.get_id() == HOME) else {
            continue;
        };
        assert_eq!(
            home.get_help().map(ToString::to_string).as_deref(),
            Some(crate::HOME_HELP),
            "{path}"
        );
        for page in pages(&mut command) {
            for line in page.lines().filter(|line| line.contains(crate::HOME_HELP)) {
                widest = widest.max(line.chars().count());
            }
        }
    }
    assert_eq!(widest, HOME_WIDEST);
}

/// Every row is one phrase in clap's form: a capital first (or a typed form, which keeps its case), no
/// period at the end, and never two sentences. Red when a row starts lowercase, ends in a period, or holds a
/// second sentence.
#[test]
fn every_help_row_is_one_capitalized_phrase() {
    let mut found = Vec::new();
    for (path, command) in every_command() {
        for row in rows(&command) {
            // A row may open on a form typed as it is (`me/<name>`), which keeps its own case.
            let typed = row
                .split_whitespace()
                .next()
                .is_some_and(|word| word.contains(['/', '<']));
            let capital = typed || row.chars().next().is_some_and(char::is_uppercase);
            let period = row.trim_end().ends_with('.');
            let two = row
                .match_indices(". ")
                .any(|(at, _)| row[at + 2..].starts_with(|c: char| c.is_uppercase() || c == '`'));
            if !capital || period || two {
                found.push(format!("{path}: {row}"));
            }
        }
    }
    assert!(found.is_empty(), "rows not in clap's form: {found:#?}");
}

/// No rendered help names a word the glossary cut. Red when one comes back, in any row or paragraph.
#[test]
fn help_names_no_retired_word() {
    const RETIRED: [&str; 6] = ["node", "petname", "overlay", "iperf", "peer", "peers"];
    let mut found = Vec::new();
    for (path, mut command) in every_command() {
        for page in pages(&mut command) {
            for word in page.split(|c: char| !c.is_alphanumeric()) {
                if RETIRED.contains(&word.to_lowercase().as_str()) {
                    found.push(format!("{path}: {word}"));
                }
            }
        }
    }
    found.dedup();
    assert!(found.is_empty(), "retired words in help: {found:#?}");
}

/// `tree` is no verb: typed, it is clap's unknown-command refusal, exit 2. Red when `tree` returns.
#[test]
fn tree_is_not_a_verb() {
    let refused = Cli::try_parse_from(["swoosh", "tree"]).unwrap_err();
    assert_eq!(refused.kind(), clap::error::ErrorKind::InvalidSubcommand);
    assert_eq!(refused.exit_code(), 2);
    assert!(
        refused
            .to_string()
            .starts_with("error: unrecognized subcommand 'tree'"),
        "{refused}"
    );
}

/// Help is held as rows: clap's frame (each page's about line, its `Usage:` line and its headings) is held
/// to the width alone, the rows are held by the row tests, and swoosh's own sentences hold the whole screen
/// law as `--help` prints them, clap's indent included: the tagline, every text printed after a command's
/// options, and every line a long help adds after its row, one paragraph at a time. Red when a frame line
/// passes 80 or a sentence breaks the law, and when a listed one grows or comes to hold.
#[test]
fn the_help_holds_the_law() {
    let mut wide = Vec::new();
    let mut broken = Vec::new();
    for (path, mut command) in every_command() {
        for page in pages(&mut command) {
            let frame = page.lines().enumerate().filter(|(at, line)| {
                *at == 0
                    || line.starts_with("Usage: ")
                    || !line.starts_with(' ') && line.ends_with(':')
            });
            for (_, line) in frame {
                let width = line.chars().count();
                if width > 80 && !wide.contains(&(path.clone(), line.to_owned(), width)) {
                    wide.push((path.clone(), line.to_owned(), width));
                }
            }
        }
        let mut texts = Vec::new();
        if path == "swoosh" {
            texts.extend(command.get_about().map(ToString::to_string));
        }
        texts.extend(command.get_after_help().map(ToString::to_string));
        texts.extend(command.get_after_long_help().map(ToString::to_string));
        texts.extend(command.get_long_about().map(after_the_row));
        for arg in command.get_arguments().filter(|arg| !arg.is_hide_set()) {
            texts.extend(arg.get_long_help().map(after_the_row));
        }
        let page = command.render_long_help().to_string();
        for paragraph in texts.iter().flat_map(|text| text.split("\n\n")) {
            let printed = as_printed(&page, paragraph);
            if printed.trim().is_empty() {
                continue;
            }
            if let Err(breach) = law::holds(&printed) {
                let widest = printed.lines().map(|line| line.chars().count()).max();
                let words = paragraph.trim_start().to_owned();
                broken.push((path.clone(), words, breach, widest.unwrap_or_default()));
            }
        }
    }
    let unlisted: Vec<_> = wide
        .iter()
        .filter(|(path, line, width)| {
            !FRAME_WIDE
                .iter()
                .any(|(at, words, pinned)| at == path && line.starts_with(words) && pinned == width)
        })
        .collect();
    assert!(unlisted.is_empty(), "frame lines past 80: {unlisted:#?}");
    for (at, words, pinned) in FRAME_WIDE {
        assert!(
            wide.iter().any(|(path, line, width)| path == at
                && line.starts_with(words)
                && width == pinned),
            "{at} `{words}` is not {pinned} wide now: fix FRAME_WIDE"
        );
    }
    let listed = |path: &str, text: &str, breach: &law::Breach, widest: usize| {
        BROKEN.iter().any(|(at, words, rule, pinned)| {
            *at == path && text.starts_with(words) && breach.rule == *rule && *pinned == widest
        })
    };
    let unlisted: Vec<_> = broken
        .iter()
        .filter(|(path, text, breach, widest)| !listed(path, text, breach, *widest))
        .map(|(path, _, breach, widest)| format!("{path}: {breach} ({widest} wide)"))
        .collect();
    assert!(
        unlisted.is_empty(),
        "help sentences that break the law: {unlisted:#?}"
    );
    for (at, words, rule, pinned) in BROKEN {
        assert!(
            broken.iter().any(|(path, text, breach, widest)| {
                path == at && text.starts_with(words) && breach.rule == *rule && widest == pinned
            }),
            "{at} `{words}` no longer breaks {rule:?} at {pinned} wide: fix BROKEN"
        );
    }
}

/// A long help's text after its first line, which is the row and held as one.
fn after_the_row(text: &clap::builder::StyledStr) -> String {
    let text = text.to_string();
    text.split_once('\n')
        .map(|(_, rest)| rest.to_owned())
        .unwrap_or_default()
}

/// `paragraph` as `page` prints it: each of its lines replaced by the page's line that holds it, so the
/// indent clap adds counts toward the width.
fn as_printed(page: &str, paragraph: &str) -> String {
    paragraph
        .lines()
        .map(|line| {
            page.lines()
                .find(|printed| !line.trim().is_empty() && printed.trim() == line.trim())
                .unwrap_or(line)
        })
        .collect::<Vec<_>>()
        .join("\n")
}
