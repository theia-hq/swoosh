//! Tests for `service on` and `service off` against a home: the write to the `off` list of
//! `<home>/serve.toml`, the refusals for a name not listed, the machine refusal, and the help.

use std::collections::BTreeSet;

use clap::Parser as _;
use swoosh::home::Home;
use swoosh::serve_toml::ServeToml;

use super::{ServiceToggleCmd, Usage, Way};

/// A fresh, empty home under a unique temp dir, so parallel tests never share a `<home>/serve.toml`.
fn temp_home(tag: &str) -> Home {
    let dir = std::env::temp_dir().join(format!("swoosh-toggle-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the temp home");
    Home::resolve(Some(dir)).expect("resolve the temp home")
}

/// The `on` or `off` leaf as the command line parses it.
fn leaf(argv: &[&str]) -> ServiceToggleCmd {
    #[derive(clap::Parser)]
    struct Wrap {
        #[command(flatten)]
        toggle: ServiceToggleCmd,
    }
    let mut line = vec!["x"];
    line.extend_from_slice(argv);
    Wrap::try_parse_from(line).expect("the leaf parses").toggle
}

/// The services turned off, read back through the same parse the gate uses.
fn off_on_disk(home: &Home) -> BTreeSet<String> {
    ServeToml::read(home).expect("read serve.toml").off
}

/// `off` of a name the list holds writes it, with nothing running, and `on` takes it back out: the
/// default counts as listed on a home that never named a list. Each says so once, and again is a no-op.
#[tokio::test]
async fn service_off_with_nothing_running_writes_the_setting() {
    let home = temp_home("off-written");
    leaf(&["ping"])
        .run(&home, Way::Off)
        .await
        .expect("off ping");
    assert_eq!(off_on_disk(&home), BTreeSet::from(["ping".to_owned()]));
    leaf(&["ping"])
        .run(&home, Way::Off)
        .await
        .expect("off again is no error");
    leaf(&["ping"]).run(&home, Way::On).await.expect("on ping");
    assert!(off_on_disk(&home).is_empty(), "ping is back on");
    assert_eq!(
        ServeToml::read(&home).expect("read").services,
        None,
        "on and off never write the list"
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// `on` of a name the list does not hold refuses, exit 1, and names the `service add` that lists it: a
/// built-in alone, `proxy` with its URL. Nothing is written.
#[tokio::test]
async fn service_on_for_a_service_not_listed_names_service_add() {
    let home = temp_home("on-unlisted");
    for (name, line) in [
        (
            "ssh",
            "ssh is not listed here; add it: swoosh service add ssh",
        ),
        (
            "proxy",
            "proxy is not listed here; add it: swoosh service add proxy:<url>",
        ),
    ] {
        let error = leaf(&[name])
            .run(&home, Way::On)
            .await
            .expect_err("a name not listed refuses");
        assert_eq!(format!("{error:#}"), line);
    }
    assert!(!home.serve_toml().exists(), "nothing written");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// Any other name is shown with a TCP target, the common case whole, never a bare `<target>`.
#[tokio::test]
async fn service_on_for_an_unknown_name_names_the_tcp_form() {
    let home = temp_home("on-unknown");
    let error = leaf(&["db"])
        .run(&home, Way::On)
        .await
        .expect_err("db is not listed");
    assert_eq!(
        format!("{error:#}"),
        "db is not listed here; add it: swoosh service add db=tcp:<address>:<port>"
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// `off` of a name the list does not hold refuses, exit 1, with no fix: it already does not answer, and
/// the name typed shows a typo.
#[tokio::test]
async fn service_off_for_a_service_not_listed_names_no_fix() {
    let home = temp_home("off-unlisted");
    let error = leaf(&["db"])
        .run(&home, Way::Off)
        .await
        .expect_err("db is not listed");
    assert_eq!(format!("{error:#}"), "db is not listed here");
    assert!(
        error.downcast_ref::<Usage>().is_none(),
        "exit 1, not a usage error"
    );
    assert!(!home.serve_toml().exists(), "nothing written");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// A machine typed after the service refuses with the service as typed in the command to run there; a
/// machine alone in the service slot shows the literal `<service>`.
#[test]
fn service_off_with_a_machine_names_the_typed_service() {
    let Err(Usage(typed)) = leaf(&["ssh", "me/nas"]).here(Way::Off).cloned() else {
        panic!("a machine refuses");
    };
    assert_eq!(
        typed,
        "swoosh service off acts only on this machine\n  To run it on nas:\n    swoosh ssh me/nas -- \
         swoosh service off ssh"
    );
    let Err(Usage(alone)) = leaf(&["me/nas"]).here(Way::On).cloned() else {
        panic!("a machine alone refuses");
    };
    assert_eq!(
        alone,
        "swoosh service on acts only on this machine\n  To run it on nas:\n    swoosh ssh me/nas -- \
         swoosh service on <service>"
    );
}

/// A second word after the service is a second service, which `on` and `off` never take: refused with the
/// rule alone, never read as a machine to `ssh` into.
#[test]
fn service_off_with_a_second_word_takes_one_service() {
    for way in [Way::Off, Way::On] {
        let Err(Usage(refused)) = leaf(&["ssh", "web"]).here(way).cloned() else {
            panic!("a second service refuses");
        };
        assert_eq!(
            refused,
            format!("swoosh service {} takes one service", way.verb())
        );
    }
}

/// A machine that is not one of yours (a contact's, or `me/` with no name), in either slot, gets the head
/// alone: an `ssh` there would reach a machine that is not yours, so no command is named.
#[test]
fn service_off_for_a_contact_machine_names_no_fix() {
    for argv in [
        &["ssh", "bob/nas"][..],
        &["bob/nas"][..],
        &["ssh", "me/"][..],
        &["me/"][..],
    ] {
        let Err(Usage(refused)) = leaf(argv).here(Way::Off).cloned() else {
            panic!("{argv:?} refuses");
        };
        assert_eq!(
            refused, "swoosh service off acts only on this machine",
            "{argv:?}"
        );
    }
}

/// A machine-shaped name is a usage error, never a name written to the `off` list.
#[tokio::test]
async fn service_off_refuses_a_machine_shaped_name() {
    let home = temp_home("off-machine");
    for argv in [&["me/nas"][..], &["ssh", "me/nas"][..]] {
        let error = leaf(argv)
            .run(&home, Way::Off)
            .await
            .expect_err("a machine refuses");
        assert!(error.downcast_ref::<Usage>().is_some(), "exit 2: {error:#}");
    }
    assert!(!home.serve_toml().exists(), "nothing written");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// `service on -h` and `service off -h` show no machine until one can be acted on, and `service -h` has
/// a row for each leaf.
#[test]
fn service_on_off_usage_hides_the_machine() {
    use clap::CommandFactory as _;

    let mut cli = crate::Cli::command();
    cli.build();
    let group = cli
        .find_subcommand_mut("service")
        .expect("service is a top-level verb");
    let rows = group.render_help().to_string();
    for row in [
        "Add services to what this machine serves",
        "Remove services from what this machine serves",
        "Turn a service on here",
        "Turn a service off here",
    ] {
        assert!(rows.contains(row), "a {row:?} row: {rows}");
    }
    for verb in ["on", "off"] {
        let leaf = group.find_subcommand_mut(verb).expect("a leaf");
        for help in [
            leaf.render_help().to_string(),
            leaf.render_long_help().to_string(),
        ] {
            assert!(
                !help.contains("me/<name>"),
                "{verb} shows the machine: {help}"
            );
        }
    }
    let off = group.find_subcommand_mut("off").expect("off");
    assert!(
        off.render_long_help()
            .to_string()
            .contains("It stays off across restarts until you run swoosh service on."),
        "off's --help line"
    );
}
