use core::time::Duration;
use std::path::Path;
use std::process::Command;

use swoosh::serve::{ServingError, Started};
use swoosh::serve_toml::ServeToml;

use super::{ProcessScratch, refusal_against, run_binary_with_deadline, swoosh_binary};

#[test]
fn relative_flags_repeat_combine_and_ignore_argument_order() {
    let expected = ["a=echo:", "z=echo:"];
    for args in [
        vec![
            "--with",
            "z=echo:",
            "--without",
            "ping",
            "--with",
            "a=echo:",
            "--without",
            "speed",
        ],
        vec![
            "--without",
            "speed",
            "--with",
            "a=echo:",
            "--without",
            "PING",
            "--with",
            "z=echo:",
        ],
    ] {
        let mut argv = vec!["swoosh", "serve"];
        argv.extend(args);
        let Some(crate::Command::Serve(cmd)) = crate::parse_from(argv).unwrap().command else {
            panic!("serve parses");
        };
        assert!(cmd.services.is_empty());
        assert_eq!(
            Started::relative(
                &ServeToml::default(),
                &cmd.with,
                &cmd.without,
                Path::new("/work")
            )
            .unwrap()
            .entries(),
            expected
        );
    }
}

#[test]
fn positional_conflicts_do_not_echo_definition_or_exclusion_credentials() {
    let secret = "bad=proxy:https://user:credential-sentinel@example.test/path";
    for args in [
        vec!["swoosh", "serve", secret, "--with", secret],
        vec!["swoosh", "serve", "--with", secret, secret],
        vec!["swoosh", "serve", secret, "--without", secret],
        vec!["swoosh", "serve", "--without", secret, secret],
    ] {
        let error = crate::parse_from(args).unwrap_err();
        let text = error.to_string();
        assert!(text.contains(
            "--with and --without cannot be used with services typed on the command line"
        ));
        assert!(!format!("{error:?} {error}").contains("credential-sentinel"));
    }
}

#[test]
fn relative_help_and_running_refusal_keep_the_approved_words() {
    let error = crate::parse_from(["swoosh", "serve", "--help"]).unwrap_err();
    let help = error.to_string();
    for words in [
        "--with <service>",
        "--without <service>",
        "Also serve this service, for this run",
        "Omit a saved/default service for this run",
        "With none named and no --with or --without, it serves the saved\n          services, or ping and speed if none are saved.",
        "Repeat or combine these flags; positional definitions cannot be\n          used with them.",
    ] {
        assert!(help.contains(words), "missing {words:?}: {help}");
    }
    for args in [&["--with", "other=echo:"][..], &["--without", "ping"][..]] {
        assert_eq!(
            refusal_against(args, &["ping"], &[]),
            "swoosh serve is already running here (pid 4121)\n  It serves ping.\n  To change how it runs, stop it first:\n    swoosh stop"
        );
    }
}

#[test]
fn bare_and_positional_startup_remain_exclusive() {
    let file = ServeToml {
        services: Some(vec!["saved=echo:".into()]),
        ..ServeToml::default()
    };
    for (args, expected) in [
        (vec!["swoosh", "serve"], vec!["saved=echo:"]),
        (vec!["swoosh", "serve", "ping"], vec!["ping=ping:"]),
    ] {
        let Some(crate::Command::Serve(mut cmd)) = crate::parse_from(args).unwrap().command else {
            panic!("serve parses");
        };
        assert!(cmd.with.is_empty() && cmd.without.is_empty());
        cmd.normalize_services(Path::new("/work")).unwrap();
        assert_eq!(
            Started::of(&cmd.services, &file, Path::new("/work"))
                .unwrap()
                .entries(),
            expected
        );
    }
    let error = Started::relative(&file, &["saved".into()], &[], Path::new("/work")).unwrap_err();
    assert!(matches!(error, ServingError::Definition(_)));
}

fn run_relative(scratch: &ProcessScratch, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(swoosh_binary());
    command
        .arg("--home")
        .arg(&scratch.home_dir)
        .args(["serve", "--local", "--expires", "1s"])
        .args(args)
        .current_dir(&scratch.base)
        .env("HOME", scratch.base.join("user"))
        .env("XDG_RUNTIME_DIR", &scratch.xdg)
        .env_remove("SWOOSH_HOME");
    run_binary_with_deadline(&mut command, Duration::from_secs(60))
}

#[test]
fn relative_launch_skips_excluded_backends_and_keeps_saved_bytes() {
    let scratch = ProcessScratch::new("rel-skip");
    let path = scratch.home_dir.join("serve.toml");
    let saved = b"services = ['raw=stdin:', 'drop=recv:', 'logs=file:missing', 'pipe=fifo:missing', 'sock=unix:missing']\noff = ['raw']\n";
    std::fs::write(&path, saved).unwrap();
    let output = run_relative(
        &scratch,
        &[
            "--without",
            "raw",
            "--without",
            "drop",
            "--without",
            "logs",
            "--without",
            "pipe",
            "--without",
            "sock",
            "--with",
            "ok=echo:",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let banner = String::from_utf8(output.stdout).unwrap();
    assert!(banner.contains("ok"));
    assert!(
        !scratch.base.join("user").exists(),
        "excluded receive cannot create an inbox"
    );
    assert!(!scratch.base.join("missing").exists());
    assert_eq!(std::fs::read(path).unwrap(), saved);
}

#[test]
fn malformed_excluded_base_and_selected_failure_leave_service_policy_unchanged() {
    for (tag, saved, args, category) in [
        (
            "rel-bad",
            "services = ['raw=stdin:', 'bad=proxy:https://user:credential-sentinel@example.test/path']\noff = ['raw']\n",
            vec!["--without", "bad", "--without", "raw"],
            "invalid saved service definition at index 2",
        ),
        (
            "rel-add",
            "services = []\noff = []\n",
            vec![
                "--with",
                "bad=proxy:https://user:credential-sentinel@example.test/path",
            ],
            "invalid service definition at index 1",
        ),
        (
            "rel-name",
            "services = []\noff = []\n",
            vec!["--without", "https://user:credential-sentinel@example.test"],
            "--without #1 is not a valid service name",
        ),
        (
            "rel-inbox",
            "services = ['drop=recv:']\noff = ['drop']\n",
            vec!["--with", "ok=echo:"],
            "could not create",
        ),
    ] {
        let scratch = ProcessScratch::new(tag);
        let path = scratch.home_dir.join("serve.toml");
        std::fs::write(&path, saved).unwrap();
        // A file where the user's home belongs makes creating the default inbox fail, so a selected
        // receive fails in preparation after selection. The earlier rows refuse before preparation.
        std::fs::write(scratch.base.join("user"), b"").unwrap();
        let output = run_relative(&scratch, &args);
        assert!(!output.status.success());
        let errors = String::from_utf8(output.stderr).unwrap();
        assert!(errors.contains(category), "{errors}");
        assert!(!errors.contains("credential-sentinel"), "{errors}");
        assert!(!scratch.base.join("missing").exists());
        assert_eq!(std::fs::read(path).unwrap(), saved.as_bytes());
    }
}

#[test]
fn relative_selected_receive_still_refuses_the_home_directory() {
    let scratch = ProcessScratch::new("rel-home");
    let path = scratch.home_dir.join("serve.toml");
    let saved = b"services = []\noff = []\n";
    std::fs::write(&path, saved).unwrap();
    let definition = format!("drop=recv:{}", scratch.home_dir.display());
    let output = run_relative(&scratch, &["--with", &definition]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("it is the swoosh home"));
    assert_eq!(std::fs::read(path).unwrap(), saved);
}
