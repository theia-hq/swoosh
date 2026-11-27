#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The path the Touch ID dialog names (`for swoosh <path>`) is a command's place in the table, never a typed
//! word: one row per runnable command, each parsed and read back.

use clap::{CommandFactory as _, Parser as _};

use super::Cli;

/// Where a line needs a key, given at parse as one.
const KEY: &str = "<key>";

/// One minimal line per runnable command, by its path: the words after `swoosh` that name it, then what it
/// needs to parse.
const LEAVES: &[(&str, &[&str])] = &[
    ("serve", &["serve"]),
    ("stop", &["stop"]),
    ("service", &["service"]),
    ("service add", &["service", "add", "web=http:8080"]),
    ("service rm", &["service", "rm", "web"]),
    ("service on", &["service", "on", "web"]),
    ("service off", &["service", "off", "web"]),
    ("ping", &["ping", "alice"]),
    ("speed", &["speed", "alice"]),
    ("status", &["status"]),
    ("forward", &["forward", "alice", "web", "-"]),
    ("proxy", &["proxy", "alice", "https://example.com"]),
    ("send", &["send", "alice", "file"]),
    ("sync", &["sync"]),
    ("contact add", &["contact", "add", "alice", KEY]),
    ("contact rm", &["contact", "rm", "alice"]),
    ("lock", &["lock"]),
    ("root backup", &["root", "backup", "dir"]),
    ("root forget", &["root", "forget", "dir"]),
    ("root restore", &["root", "restore", "dir"]),
    ("root lock", &["root", "lock", "passphrase"]),
    ("invite", &["invite"]),
    ("join", &["join", "invite"]),
    ("leave", &["leave"]),
    ("revoke", &["revoke", "alice"]),
    ("ssh", &["ssh", "alice"]),
    ("share", &["share", "ssh", "anyone"]),
    ("tree", &["tree"]),
];

/// Every command a person can run, walked from the parser itself, has a row, and its parse names the row's
/// path: the command's own names, joined by spaces. No command takes an unknown word as a subcommand, so no
/// typed word can become a name.
#[test]
fn every_leaf_names_its_command() {
    let mut walked = Vec::new();
    runnable(&Cli::command(), &mut Vec::new(), &mut walked);
    let mut rows: Vec<String> = LEAVES.iter().map(|(path, _)| (*path).to_owned()).collect();
    walked.sort();
    rows.sort();
    assert_eq!(walked, rows, "one row per runnable command");

    let key = bifrost::NodeId::from_ed25519_secret(&[2u8; 32]).to_string();
    for (path, argv) in LEAVES {
        let typed = argv
            .iter()
            .map(|word| if *word == KEY { key.as_str() } else { word });
        let cli = Cli::try_parse_from(core::iter::once("swoosh").chain(typed))
            .unwrap_or_else(|error| panic!("{argv:?} parses: {error}"));
        let command = cli.command.expect("a command");
        assert_eq!(command.path(), *path, "{argv:?}");
        let names = path.split(' ').count();
        assert_eq!(command.path(), argv[..names].join(" "), "{argv:?}");
    }
}

/// A typed word never reaches the dialog: a peer, a nested command's argument, or one shaped like a command
/// name leaves the path as the command's alone.
#[test]
fn no_typed_word_reaches_the_dialog() {
    for (argv, path) in [
        (&["ping", "me/evil"][..], "ping"),
        (&["root", "restore", "serve"], "root restore"),
        (&["forward", "me/evil", "serve", "-"], "forward"),
    ] {
        let cli = Cli::try_parse_from(core::iter::once("swoosh").chain(argv.iter().copied()))
            .unwrap_or_else(|error| panic!("{argv:?} parses: {error}"));
        assert_eq!(cli.command.expect("a command").path(), path, "{argv:?}");
    }
}

/// The runnable commands under `command`, by path: each with no subcommands, or whose subcommands may be
/// left off. Every node is checked to take no external subcommand.
fn runnable(command: &clap::Command, at: &mut Vec<String>, found: &mut Vec<String>) {
    assert!(
        !command.is_allow_external_subcommands_set(),
        "{at:?} takes any word as a subcommand"
    );
    let mut subcommands = command.get_subcommands().peekable();
    if !at.is_empty() && (subcommands.peek().is_none() || !command.is_subcommand_required_set()) {
        found.push(at.join(" "));
    }
    for subcommand in subcommands {
        at.push(subcommand.get_name().to_owned());
        runnable(subcommand, at, found);
        at.pop();
    }
}
