//! The machine argument and the hidden flags, read off the real command tree: every rendered usage speaks
//! the concept words, and the flags no flow needs are out of `--help` and set by their variables.

use clap::CommandFactory as _;

use crate::Cli;

/// Every subcommand of `command`, with the words that reach it, depth first.
fn walk(command: &clap::Command, path: &str, found: &mut Vec<(String, clap::Command)>) {
    for sub in command.get_subcommands() {
        let path = format!("{path} {}", sub.get_name());
        found.push((path.clone(), sub.clone()));
        walk(sub, &path, found);
    }
}

/// The built command tree, every subcommand with its path.
fn every_command() -> Vec<(String, clap::Command)> {
    let mut root = Cli::command();
    root.build();
    let mut found = Vec::new();
    walk(&root, "swoosh", &mut found);
    found
}

/// No metavar is one of the retired words: `<peer>` is `<machine>`, a count or a port is `<n>`, seconds
/// are `<s>`, a duration `<d>`, and a service `<service>`. Read off each argument's own value names, since
/// a phrase like `forward`'s `<port | unix:<path> | ->` legitimately holds a retired word.
#[test]
fn metavars_are_the_concept_words() {
    let retired = [
        "peer",
        "svc",
        "duration",
        "count",
        "seconds",
        "port",
        "name=target",
    ];
    let mut found = Vec::new();
    for (path, command) in every_command() {
        for arg in command.get_arguments() {
            for name in arg.get_value_names().unwrap_or_default() {
                if retired.contains(&name.as_str()) {
                    found.push(format!("{path}: <{name}>"));
                }
            }
        }
    }
    assert!(found.is_empty(), "retired metavars: {found:?}");

    let machine = |verb: &str| {
        let (_, command) = every_command()
            .into_iter()
            .find(|(path, _)| path == &format!("swoosh {verb}"))
            .expect("the verb exists");
        command
            .get_arguments()
            .find(|arg| arg.get_id() == "peer")
            .and_then(|arg| arg.get_value_names().map(|names| names[0].to_string()))
    };
    for verb in ["ping", "speed", "status", "ssh", "send", "forward", "proxy"] {
        assert_eq!(machine(verb).as_deref(), Some("machine"), "{verb}");
    }
}

/// Each hidden flag, the verbs that carry it, and the variable that sets it (`None`: it has none).
const HIDDEN: [(&str, Option<&str>); 7] = [
    ("transport", Some("SWOOSH_TRANSPORT")),
    ("local", Some("SWOOSH_LOCAL")),
    ("peer", Some("SWOOSH_PEER")),
    ("relay", Some("SWOOSH_RELAY")),
    ("resolver", Some("SWOOSH_RESOLVER")),
    ("quiet", Some("SWOOSH_QUIET")),
    ("service", None),
];

/// No flow needs the transport and debugging knobs, `serve --quiet` or `--service`, so none is in any
/// `--help`, and each but `--service` is read from its `SWOOSH_<FLAG>`. `--service` has no variable: its
/// default differs per verb, so one variable would retarget three verbs in every shell that set it.
#[test]
fn hidden_flags_are_absent_from_help_and_read_from_env() {
    let mut seen = std::collections::BTreeSet::new();
    for (path, mut command) in every_command() {
        let help = command.render_long_help().to_string();
        for arg in command.get_arguments() {
            let Some(long) = arg.get_long() else {
                continue;
            };
            let Some((_, variable)) = HIDDEN.iter().find(|(flag, _)| *flag == long) else {
                continue;
            };
            // `forward`'s service is a positional, never a flag; only a `--service` flag is hidden.
            seen.insert(long.to_owned());
            assert!(arg.is_hide_set(), "{path} --{long} is hidden");
            assert!(
                !help.contains(&format!("--{long}")),
                "{path} --help names --{long}"
            );
            assert_eq!(
                arg.get_env().and_then(|env| env.to_str()),
                *variable,
                "{path} --{long}'s variable"
            );
        }
    }
    let all: std::collections::BTreeSet<String> =
        HIDDEN.iter().map(|(flag, _)| (*flag).to_owned()).collect();
    assert_eq!(seen, all, "every hidden flag was found on some verb");
}
