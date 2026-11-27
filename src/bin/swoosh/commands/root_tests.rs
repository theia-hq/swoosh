//! The `root` group's shape: its row in `swoosh --help`, its four leaves, and its last line.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use clap::CommandFactory as _;

use crate::Cli;

/// The four leaves, each with the help line the sheet rules, in order.
const LEAVES: [(&str, &str); 4] = [
    ("backup", "Copy your root to a new directory"),
    (
        "forget",
        "Remove your root from this machine, after checking the copy in <dir>",
    ),
    ("restore", "Put your root on this machine from a copy"),
    (
        "lock",
        "Change your root's locks, on this machine or in <dir>",
    ),
];

/// `swoosh root --help`, rendered.
fn root_help() -> String {
    let mut cli = Cli::command();
    cli.build();
    cli.find_subcommand_mut("root")
        .unwrap()
        .render_help()
        .to_string()
}

/// The `root` row in `swoosh --help`, the `lock` row beside it, and the four leaves' lines, byte for byte.
/// Red when a line drifts.
#[test]
fn root_help_row_and_leaves_match_the_sheet() {
    let top = Cli::command().render_help().to_string();
    let row = |verb: &str, about: &str| {
        top.lines().any(|line| {
            let line = line.trim_start();
            line.strip_prefix(verb)
                .is_some_and(|rest| rest.trim_start() == about)
        })
    };
    assert!(
        row(
            "root",
            "Copy, restore or forget your root, or change its locks"
        ),
        "{top}"
    );
    #[cfg(target_os = "macos")]
    let lock = "Lock this machine's key with a passphrase or Touch ID";
    #[cfg(not(target_os = "macos"))]
    let lock = "Lock this machine's key with a passphrase";
    assert!(row("lock", lock), "{top}");
    assert!(!top.contains("identity"), "{top}");

    let help = root_help();
    let leaves: Vec<(String, String)> = Cli::command()
        .find_subcommand("root")
        .unwrap()
        .get_subcommands()
        .filter(|leaf| leaf.get_name() != "help")
        .map(|leaf| {
            (
                leaf.get_name().to_owned(),
                leaf.get_about().unwrap().to_string(),
            )
        })
        .collect();
    let expected: Vec<(String, String)> = LEAVES
        .iter()
        .map(|(name, about)| ((*name).to_owned(), (*about).to_owned()))
        .collect();
    assert_eq!(leaves, expected);
    for (name, about) in LEAVES {
        assert!(help.contains(about), "{name}: {help}");
    }
}

/// `swoosh root --help` ends with the two lines that say where ending a root lives, the command alone on
/// its line. Red when they are dropped.
#[test]
fn root_help_ends_with_the_revoke_line() {
    let help = root_help();
    let last: Vec<&str> = help.trim_end().lines().rev().take(2).collect();
    assert_eq!(
        last,
        [
            "  swoosh revoke --help",
            "To see how to end a root for good:"
        ],
        "{help}"
    );
}

/// A bare `swoosh root` is a usage error that prints the group's help. Red when it runs a leaf.
#[test]
fn bare_root_prints_the_groups_help() {
    let refused = <Cli as clap::Parser>::try_parse_from(["swoosh", "root"]).unwrap_err();
    assert_eq!(refused.exit_code(), 2);
    assert!(refused.to_string().contains("backup"), "{refused}");
}
