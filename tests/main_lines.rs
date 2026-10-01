// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The lines the binary's entry point prints itself, through the real binary: a refusal's prefix, a bare
//! `swoosh`, and help that names `SWOOSH_HOME` without printing its value.

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

/// Run `swoosh <args>` with `SWOOSH_HOME` set to `home`, or unset when `None`.
fn swoosh(args: &[&str], home: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_swoosh"));
    command
        .args(args)
        .env_remove("SWOOSH_HOME")
        .env_remove("SWOOSH_KEY")
        .stdin(Stdio::null());
    if let Some(home) = home {
        command.env("SWOOSH_HOME", home);
    }
    command.output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A path under the temp dir unique to this test and process. Nothing is created there.
fn scratch(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("swoosh-main-lines-{tag}-{}", std::process::id()))
}

/// A refusal that exits 1 starts with `error: `, the prefix clap prints for a usage error (exit 2).
#[test]
fn a_refusal_starts_with_error_colon() {
    let file = scratch("file");
    std::fs::write(&file, "").unwrap();
    let out = swoosh(&["--home", file.to_str().unwrap(), "status"], None);
    let _ = std::fs::remove_file(&file);

    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(out.stdout.is_empty(), "{}", text(&out.stdout));
    assert!(
        text(&out.stderr).starts_with("error: "),
        "{}",
        text(&out.stderr)
    );
}

/// A bare `swoosh` is a mistake: its help goes to stderr, stdout stays empty, and it exits 2, with or
/// without `SWOOSH_HOME` set.
#[test]
fn bare_swoosh_prints_help_on_stderr_and_exits_2() {
    let home = scratch("bare");
    for env in [None, Some(home.to_str().unwrap())] {
        let out = swoosh(&[], env);
        assert_eq!(out.status.code(), Some(2), "SWOOSH_HOME {env:?}");
        assert!(
            out.stdout.is_empty(),
            "SWOOSH_HOME {env:?}: {}",
            text(&out.stdout)
        );
        assert!(
            text(&out.stderr).contains("Usage: swoosh"),
            "SWOOSH_HOME {env:?}: {}",
            text(&out.stderr)
        );
    }
}

/// The verbs listed under a help page's `Commands:` heading, `help` left out.
fn listed_verbs(help: &str) -> Vec<String> {
    help.lines()
        .skip_while(|line| line.trim_end() != "Commands:")
        .skip(1)
        .take_while(|line| !line.trim().is_empty())
        .filter_map(|line| line.split_whitespace().next())
        .filter(|verb| *verb != "help")
        .map(str::to_owned)
        .collect()
}

/// With `SWOOSH_HOME=/tmp/x`, no `-h` or `--help` of any listed command prints `/tmp/x`; the root help
/// still names the variable.
#[test]
fn help_never_shows_the_home_value() {
    const HOME: &str = "/tmp/x";

    let mut pending: Vec<Vec<String>> = vec![Vec::new()];
    let mut seen = 0_usize;
    while let Some(path) = pending.pop() {
        for flag in ["-h", "--help"] {
            let mut args: Vec<&str> = path.iter().map(String::as_str).collect();
            args.push(flag);
            let out = swoosh(&args, Some(HOME));
            assert!(out.status.success(), "{args:?}: {}", text(&out.stderr));
            let shown = format!("{}{}", text(&out.stdout), text(&out.stderr));
            assert!(!shown.contains(HOME), "{args:?} prints the home:\n{shown}");
            if flag == "--help" {
                for verb in listed_verbs(&text(&out.stdout)) {
                    let mut child = path.clone();
                    child.push(verb);
                    pending.push(child);
                }
            }
        }
        seen += 1;
    }
    assert!(seen > 10, "the walk reached only {seen} commands");

    let root = swoosh(&["--help"], Some(HOME));
    assert!(
        text(&root.stdout).contains("[env: SWOOSH_HOME]"),
        "{}",
        text(&root.stdout)
    );
}
