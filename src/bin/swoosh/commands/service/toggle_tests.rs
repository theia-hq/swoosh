//! Tests for `service on` and `service off` against a home: the write to the `off` list of
//! `<home>/serve.toml`, `off` of any name and `on` of a saved name or a mark, the refusal of `on` for a
//! name that is neither, the machine refusal, and the help.

use core::time::Duration;
use std::collections::BTreeSet;

use clap::Parser as _;
use swoosh::home::Home;
use swoosh::serve::Started;
use swoosh::serve_toml::{LiveServeToml, MAX_SERVE_TOML, ServeToml};
use tightbeam::enabled::EnabledServices as _;

use super::{ServiceToggleCmd, Toggled, Usage, Way, toggle};
use crate::commands::service::edit::ServiceRmCmd;

#[tokio::test]
async fn toggle_cli_discards_invalid_names_before_home_access() {
    let home = temp_home("safe-toggle-name");
    let original = b"services = ['ping']\noff = ['ping']\n";
    std::fs::write(home.serve_toml(), original).unwrap();
    for (verb, way) in [("on", Way::On), ("off", Way::Off)] {
        for entry in [
            "bad=proxy:https://user:secret@host.test/?token=private",
            "proxy:https://user:secret@host.test",
            "recv:/user:secret@host.test",
            "control.stop",
        ] {
            let Some(crate::Command::Service { command: Some(cmd) }) =
                crate::Cli::try_parse_from(["swoosh", "service", verb, entry])
                    .unwrap()
                    .command
            else {
                panic!("service toggle parses");
            };
            let cmd = match cmd {
                super::super::ServiceCmd::On(cmd) | super::super::ServiceCmd::Off(cmd) => cmd,
                _ => panic!("toggle leaf"),
            };
            let debug = format!("{cmd:?}");
            let error = cmd.run(&home, way).await.unwrap_err();
            assert!(error.downcast_ref::<Usage>().is_some());
            assert_eq!(error.to_string(), "invalid service name at index 1");
            for cause in error.chain() {
                let text = format!("{cause:?} {cause} {debug}");
                for forbidden in [entry, "secret", "private", "host.test", "NameError"] {
                    assert!(!text.contains(forbidden), "{text}");
                }
            }
            assert_eq!(std::fs::read(home.serve_toml()).unwrap(), original);
            assert_eq!(std::fs::read_dir(home.dir()).unwrap().count(), 1);
        }
    }
    let _ = std::fs::remove_dir_all(home.dir());
}

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
            "ssh is not saved here; add it: swoosh service add ssh",
        ),
        (
            "proxy",
            "proxy is not saved here; add it: swoosh service add proxy:<url>",
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
        "db is not saved here; add it: swoosh service add db=tcp:<address>:<port>"
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// `off` of a name the list does not hold writes its mark, with no `serve` running to ask: a `serve` that
/// binds the name later, however started, refuses it. The line says the name is not saved, so a typo shows.
#[tokio::test]
async fn service_off_marks_an_unsaved_name_with_no_serve_running() {
    let home = temp_home("off-unsaved");
    leaf(&["db"])
        .run(&home, Way::Off)
        .await
        .expect("off of a name not saved is written");
    assert_eq!(off_on_disk(&home), BTreeSet::from(["db".to_owned()]));
    assert_eq!(
        ServeToml::read(&home).expect("read").services,
        None,
        "off never writes the list"
    );
    let mut file = ServeToml::default();
    let toggled = toggle(&mut file, "db", Way::Off).expect("off takes any name");
    assert_eq!(toggled, Toggled::Unsaved);
    assert_eq!(
        toggled.line("db", Way::Off),
        "Turned db off here. It is not saved here."
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// `on` of a name the `off` list holds and the saved list does not clears the mark and writes nothing
/// else: no service is saved or opened. Its line never says the name is on, since no `serve` is asked.
#[tokio::test]
async fn service_on_clears_an_off_only_mark() {
    let home = temp_home("on-off-only");
    std::fs::write(home.serve_toml(), "services = []\noff = [\"web\"]\n")
        .expect("an off-only mark");
    leaf(&["web"])
        .run(&home, Way::On)
        .await
        .expect("on clears the mark");
    let file = ServeToml::read(&home).expect("read");
    assert!(file.off.is_empty(), "the mark is gone");
    assert_eq!(file.services, Some(vec![]), "nothing is saved");
    let mut file = ServeToml {
        services: Some(vec![]),
        off: BTreeSet::from(["web".to_owned()]),
        ..ServeToml::default()
    };
    let toggled = toggle(&mut file, "web", Way::On).expect("a mark is cleared");
    assert_eq!(toggled, Toggled::Unsaved);
    assert_eq!(
        toggled.line("web", Way::On),
        "web is no longer off. It is not saved here."
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// `on` of a name neither saved nor off refuses, exit 1, beside a mark for another name, and the file is
/// left byte for byte: there is no mark to clear and no route to open.
#[tokio::test]
async fn service_on_refuses_a_name_neither_off_nor_saved() {
    let home = temp_home("on-neither");
    std::fs::write(home.serve_toml(), "services = []\noff = [\"web\"]\n")
        .expect("an off-only mark");
    let before = std::fs::read(home.serve_toml()).expect("the file");
    let error = leaf(&["wbe"])
        .run(&home, Way::On)
        .await
        .expect_err("wbe is neither saved nor off");
    assert!(error.downcast_ref::<Usage>().is_none(), "exit 1");
    assert_eq!(
        format!("{error:#}"),
        "wbe is not saved here; add it: swoosh service add wbe=tcp:<address>:<port>"
    );
    assert_eq!(std::fs::read(home.serve_toml()).expect("the file"), before);
    let _ = std::fs::remove_dir_all(home.dir());
}

/// The sequence that once left a serving name out of reach: off, rm and on a saved name, then a `serve`
/// that names it on its command line. `off` still lands, and the gate that `serve` asks refuses the name.
#[tokio::test]
async fn off_after_off_rm_on_and_a_typed_serve_refuses_the_name() {
    let home = temp_home("door");
    let entry = "web=tcp:localhost:3000";
    std::fs::write(home.serve_toml(), format!("services = [\"{entry}\"]\n")).expect("web saved");
    leaf(&["web"]).run(&home, Way::Off).await.expect("off web");
    ServiceRmCmd {
        names: vec![Some(swoosh::names::service("web").expect("a name"))],
    }
    .run(&home)
    .await
    .expect("rm web");
    assert_eq!(
        off_on_disk(&home),
        BTreeSet::from(["web".to_owned()]),
        "rm keeps the mark"
    );
    leaf(&["web"])
        .run(&home, Way::On)
        .await
        .expect("on web clears the mark");
    assert!(off_on_disk(&home).is_empty());

    let cwd = std::env::current_dir().expect("a cwd");
    let gate = LiveServeToml::load_at(&home, &cwd).expect("the serve reads the file");
    gate.serving(&Started::Named(vec![entry.to_owned()]));
    let web = swoosh::names::service("web").expect("a name");
    assert!(gate.is_enabled(&web), "the typed serve admits web");

    leaf(&["web"])
        .run(&home, Way::Off)
        .await
        .expect("off web, though not saved");
    std::thread::sleep(nauthy::STAT_DEBOUNCE + Duration::from_millis(50));
    assert!(!gate.is_enabled(&web), "the gate refuses web");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// On a fresh home, a `serve` that names `web` on its command line binds it unsaved; `off` of it, typed in
/// another case, folds to the name bound, and the gate refuses it on the next stream.
#[tokio::test]
async fn off_turns_off_an_invocation_selected_unsaved_service() {
    let home = temp_home("typed-serve");
    let cwd = std::env::current_dir().expect("a cwd");
    let gate = LiveServeToml::load_at(&home, &cwd).expect("a fresh home reads");
    gate.serving(&Started::Named(vec!["web=tcp:localhost:3000".to_owned()]));
    let web = swoosh::names::service("web").expect("a name");
    assert!(gate.is_enabled(&web), "the typed serve admits web");
    leaf(&["WEB"])
        .run(&home, Way::Off)
        .await
        .expect("off of a name bound, never saved");
    std::thread::sleep(nauthy::STAT_DEBOUNCE + Duration::from_millis(50));
    assert!(!gate.is_enabled(&web), "the gate refuses web");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// Every name `off` takes is stored as a later read accepts it: folded, so its mark matches the name a
/// `serve` binds, and within the name rule, so one `off` can never leave a file every read calls damaged.
#[tokio::test]
async fn every_name_off_accepts_reads_back() {
    let home = temp_home("off-reads-back");
    let longest = "a".repeat(63);
    for (typed, stored) in [
        ("WEB", "web"),
        ("0-x", "0-x"),
        (longest.as_str(), longest.as_str()),
    ] {
        leaf(&[typed]).run(&home, Way::Off).await.expect("off");
        assert!(
            off_on_disk(&home).contains(stored),
            "{typed} is stored as {stored}"
        );
    }
    let _ = std::fs::remove_dir_all(home.dir());
}

/// An `off` that would grow the file past what a read accepts refuses, exit 1, and leaves it as it was and
/// readable.
#[tokio::test]
async fn service_off_past_the_cap_writes_nothing() {
    let home = temp_home("off-cap");
    // 65 507 bytes: a 63-character name more is 67 bytes past it, over the 65 536 a read accepts.
    let names: Vec<String> = (0..6550).map(|index| format!("n{index:05}")).collect();
    let text = format!(
        "off = [{}]\n",
        names
            .iter()
            .map(|name| format!("\"{name}\""))
            .collect::<Vec<_>>()
            .join(", ")
    );
    assert!(u64::try_from(text.len()).unwrap() <= MAX_SERVE_TOML);
    std::fs::write(home.serve_toml(), &text).expect("a file near the cap");
    let before = std::fs::read(home.serve_toml()).expect("the file");
    let error = leaf(&[&"z".repeat(63)])
        .run(&home, Way::Off)
        .await
        .expect_err("past the cap");
    assert!(error.downcast_ref::<Usage>().is_none(), "exit 1");
    assert!(
        format!("{error:#}").ends_with(
            "would grow past 64 KiB: nothing was written\n  To make room: swoosh service rm <name>, or swoosh service on <name> to clear an off mark"
        ),
        "{error:#}"
    );
    assert_eq!(std::fs::read(home.serve_toml()).expect("the file"), before);
    ServeToml::read(&home).expect("still readable");
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

/// A built-in written by hand as its name alone (`ping`) is listed, as a bare `serve` serves it, so `on`
/// turns it back on. Read the raw entries and `ping`, with no `=`, is not listed and `on` refuses.
#[tokio::test]
async fn service_on_of_a_hand_written_built_in_turns_it_on() {
    let home = temp_home("on-hand-written");
    std::fs::write(
        home.serve_toml(),
        "off = [\"ping\"]\nservices = [\"ping\"]\n",
    )
    .expect("ping listed by hand, off");
    leaf(&["ping"]).run(&home, Way::On).await.expect("on ping");
    assert!(off_on_disk(&home).is_empty(), "ping is back on");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// A list a bare `serve` refuses is refused by `on` and `off` alike, exit 1, as a saved definition by its
/// index, and nothing is written: no name on it can be trusted as listed.
#[tokio::test]
async fn service_toggle_refuses_a_list_that_is_not_services() {
    let home = temp_home("toggle-not-a-service");
    std::fs::write(home.serve_toml(), "services = [\"ping=ping:\", \"db\"]\n")
        .expect("a hand-edited list");
    let before = std::fs::read_to_string(home.serve_toml()).expect("the file");
    let line = "invalid saved service definition at index 2: invalid target form";
    for way in [Way::On, Way::Off] {
        let error = leaf(&["ping"])
            .run(&home, way)
            .await
            .expect_err("a broken list refuses");
        assert!(error.downcast_ref::<Usage>().is_none(), "exit 1");
        assert_eq!(format!("{error:#}"), line);
    }
    assert_eq!(
        std::fs::read_to_string(home.serve_toml()).expect("the file"),
        before
    );
    let _ = std::fs::remove_dir_all(home.dir());
}
