//! Tests for `service add` and `service rm` against a home: what each writes to `<home>/serve.toml`, all
//! or nothing, the lines each prints, and the usage errors.

use clap::Parser as _;
use swoosh::home::Home;
use swoosh::serve::{Added, Started};
use swoosh::serve_toml::ServeToml;

use super::{ServiceAddCmd, ServiceRmCmd, Usage, added_line};
use crate::commands::service::Running;

#[tokio::test]
async fn rm_cli_discards_invalid_names_before_home_access() {
    let home = temp_home("safe-rm-name");
    list(&home, &["ping", "speed"]);
    let before = std::fs::read(home.serve_toml()).unwrap();
    for entry in [
        "bad=proxy:https://user:secret@host.test/?token=private",
        "proxy:https://user:secret@host.test",
        "control.stop",
    ] {
        for prefix in [vec![], vec!["ping"]] {
            let index = prefix.len() + 1;
            let mut argv = vec!["swoosh", "service", "rm"];
            argv.extend(prefix);
            argv.push(entry);
            let Some(crate::Command::Service {
                command: Some(super::super::ServiceCmd::Rm(cmd)),
            }) = crate::Cli::try_parse_from(argv).unwrap().command
            else {
                panic!("service rm parses");
            };
            let debug = format!("{cmd:?}");
            let error = cmd.run(&home).await.unwrap_err();
            assert!(error.downcast_ref::<Usage>().is_some());
            assert_eq!(
                error.to_string(),
                format!("invalid service name at index {index}")
            );
            for cause in error.chain() {
                let text = format!("{cause:?} {cause} {debug}");
                for forbidden in [entry, "secret", "private", "host.test", "NameError"] {
                    assert!(!text.contains(forbidden), "{text}");
                }
            }
            assert_eq!(std::fs::read(home.serve_toml()).unwrap(), before);
            assert_eq!(std::fs::read_dir(home.dir()).unwrap().count(), 1);
        }
    }
    assert_eq!(
        rm(&["PING", "Speed"])
            .checked_names()
            .unwrap()
            .iter()
            .map(nauthy::Service::as_str)
            .collect::<Vec<_>>(),
        ["ping", "speed"]
    );
    assert!(rm(&["ping", "PING"]).checked_names().is_err());
    let _ = std::fs::remove_dir_all(home.dir());
}

/// A fresh, empty home under a unique temp dir, so parallel tests never share a `<home>/serve.toml`.
fn temp_home(tag: &str) -> Home {
    let dir = std::env::temp_dir().join(format!("swoosh-edit-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the temp home");
    Home::resolve(Some(dir)).expect("resolve the temp home")
}

/// `service add <argv>…` as the command line parses it.
fn add(argv: &[&str]) -> ServiceAddCmd {
    #[derive(clap::Parser)]
    struct Wrap {
        #[command(flatten)]
        add: ServiceAddCmd,
    }
    let mut line = vec!["x"];
    line.extend_from_slice(argv);
    Wrap::try_parse_from(line).expect("add parses").add
}

/// `service rm <argv>…` as the command line parses it.
fn rm(argv: &[&str]) -> ServiceRmCmd {
    #[derive(clap::Parser)]
    struct Wrap {
        #[command(flatten)]
        rm: ServiceRmCmd,
    }
    let mut line = vec!["x"];
    line.extend_from_slice(argv);
    Wrap::try_parse_from(line).expect("rm parses").rm
}

/// Write `services` as the home's list.
fn list(home: &Home, services: &[&str]) {
    let text = format!(
        "services = [{}]\n",
        services
            .iter()
            .map(|entry| format!("{entry:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    std::fs::write(home.serve_toml(), text).expect("write serve.toml");
}

/// The list the home records.
fn listed(home: &Home) -> Option<Vec<String>> {
    ServeToml::read(home).expect("read serve.toml").services
}

/// Adding saves an entry without binding or enabling it.
#[tokio::test]
async fn service_add_records_and_names_the_next_start() {
    let home = temp_home("records");
    list(&home, &["ssh=tcp:localhost:22"]);
    add(&["web=tcp:localhost:3000"])
        .run(&home)
        .await
        .expect("add web");
    assert_eq!(
        listed(&home),
        Some(vec![
            "ssh=tcp:localhost:22".to_owned(),
            "web=tcp:localhost:3000".to_owned()
        ])
    );
    assert_eq!(
        added_line(&Added::New("web".to_owned()), None),
        "Added web to the saved list."
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// Listed-name reports distinguish saved membership and off policy.
#[test]
fn service_add_of_a_listed_name_says_where_it_stands() {
    let listed = Added::Listed("ssh".to_owned());
    assert_eq!(added_line(&listed, None), "ssh is already listed.");
    let running = |serves: &[&str]| Running {
        serves: serves.iter().map(|&name| name.to_owned()).collect(),
        off: None,
    };
    assert_eq!(
        added_line(&listed, Some(&running(&["ssh"]))),
        "ssh is already listed."
    );
    assert_eq!(
        added_line(&listed, Some(&running(&["ping"]))),
        "ssh is already in the saved list."
    );
    assert_eq!(
        added_line(
            &Added::ListedOff("web".to_owned()),
            Some(&running(&["ping"]))
        ),
        "web is already listed and off.\nTo turn it on:\n  swoosh service on web"
    );
}

/// On a home that never named a list, an add starts from what a bare `serve` served: `ping` and
/// `speed` stay, and the new entry joins them.
#[tokio::test]
async fn service_add_on_a_never_named_home_keeps_ping_and_speed() {
    let home = temp_home("never-named");
    add(&["web=tcp:localhost:3000"])
        .run(&home)
        .await
        .expect("add web");
    assert_eq!(
        listed(&home),
        Some(vec![
            "ping=ping:".to_owned(),
            "speed=speed:".to_owned(),
            "web=tcp:localhost:3000".to_owned()
        ])
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

#[tokio::test]
async fn service_add_ssh_requires_compiled_support_and_preserves_off_policy() {
    for entry in ["ssh", "ssh=sshd:"] {
        let home = temp_home("ssh-support");
        std::fs::write(
            home.serve_toml(),
            "services = ['speed=speed:']\noff = ['ssh']\n",
        )
        .unwrap();
        #[cfg(feature = "ssh")]
        {
            add(&[entry]).run(&home).await.unwrap();
            let file = ServeToml::read(&home).unwrap();
            assert_eq!(file.services.unwrap(), ["speed=speed:", "ssh=sshd:"]);
            assert_eq!(file.off.into_iter().collect::<Vec<_>>(), ["ssh"]);
        }
        #[cfg(not(feature = "ssh"))]
        {
            let before = std::fs::read(home.serve_toml()).unwrap();
            let error = add(&[entry]).run(&home).await.unwrap_err();
            assert!(error.downcast_ref::<Usage>().is_some());
            assert_eq!(
                error.to_string(),
                "invalid positional service definition at index 1: unsupported target scheme"
            );
            assert_eq!(std::fs::read(home.serve_toml()).unwrap(), before);
            assert_eq!(std::fs::read_dir(home.dir()).unwrap().count(), 1);
        }
        let _ = std::fs::remove_dir_all(home.dir());
    }
}

/// A new target under a listed name is refused, exit 1, naming `rm` then `add`; the name is never
/// pointed elsewhere by an add.
#[tokio::test]
async fn service_add_refuses_a_new_target_under_a_listed_name() {
    let home = temp_home("retarget");
    list(&home, &["web=tcp:localhost:3000"]);
    let error = add(&["web=tcp:localhost:4000"])
        .run(&home)
        .await
        .expect_err("a retarget refuses");
    assert!(error.downcast_ref::<Usage>().is_none(), "exit 1");
    assert_eq!(
        format!("{error:#}"),
        "web already serves tcp:localhost:3000 here\n  To point it elsewhere, remove it, then add it:\n    \
         swoosh service rm web\n    swoosh service add web=tcp:localhost:4000"
    );
    assert_eq!(
        listed(&home),
        Some(vec!["web=tcp:localhost:3000".to_owned()])
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// Several typed, one refused: nothing is written, and `Nothing was added.` is the first detail line
/// under the one refusal.
#[tokio::test]
async fn service_add_of_several_is_all_or_nothing() {
    let home = temp_home("add-several");
    list(&home, &["web=tcp:localhost:3000"]);
    let before = std::fs::read_to_string(home.serve_toml()).expect("the file");
    let error = add(&[
        "probe=echo:",
        "web=tcp:localhost:4000",
        "db=tcp:localhost:5432",
    ])
    .run(&home)
    .await
    .expect_err("one retarget among three refuses");
    assert_eq!(
        format!("{error:#}"),
        "web already serves tcp:localhost:3000 here\n  Nothing was added.\n  To point it elsewhere, remove \
         it, then add it:\n    swoosh service rm web\n    swoosh service add web=tcp:localhost:4000"
    );
    assert_eq!(
        std::fs::read_to_string(home.serve_toml()).expect("the file"),
        before,
        "the file is unchanged"
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// `rm` removes the saved entry and keeps every `off` name.
#[tokio::test]
async fn service_rm_drops_one_entry() {
    let home = temp_home("rm-one");
    std::fs::write(
        home.serve_toml(),
        "off = [\"web\", \"ssh\"]\nservices = [\"ssh=tcp:localhost:22\", \"web=tcp:localhost:3000\"]\n",
    )
    .expect("write serve.toml");
    rm(&["web"]).run(&home).await.expect("rm web");
    let file = ServeToml::read(&home).expect("read");
    assert_eq!(file.services, Some(vec!["ssh=tcp:localhost:22".to_owned()]));
    assert_eq!(
        file.off.into_iter().collect::<Vec<_>>(),
        ["ssh", "web"],
        "every off name stays"
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// Several typed, one not listed: nothing is removed, and `Nothing was removed.` sits under the refusal.
#[tokio::test]
async fn service_rm_of_several_is_all_or_nothing() {
    let home = temp_home("rm-several");
    list(&home, &["ssh=tcp:localhost:22", "web=tcp:localhost:3000"]);
    let error = rm(&["web", "db"])
        .run(&home)
        .await
        .expect_err("db is not listed");
    assert_eq!(
        format!("{error:#}"),
        "db is not listed here\n  Nothing was removed."
    );
    assert_eq!(
        listed(&home),
        Some(vec![
            "ssh=tcp:localhost:22".to_owned(),
            "web=tcp:localhost:3000".to_owned()
        ])
    );
    let one = rm(&["db"]).run(&home).await.expect_err("db is not listed");
    assert_eq!(
        format!("{one:#}"),
        "db is not listed here",
        "one typed: no extra line"
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// A name typed twice in one command is a usage error, exit 2, before the home is read.
#[tokio::test]
async fn a_name_typed_twice_is_a_usage_error() {
    let home = temp_home("twice");
    let error = add(&["web=tcp:localhost:3000", "web=tcp:localhost:4000"])
        .run(&home)
        .await
        .expect_err("web twice");
    assert!(error.downcast_ref::<Usage>().is_some(), "exit 2: {error:#}");
    assert_eq!(
        format!("{error:#}"),
        "invalid positional service definition at index 2: service name already used"
    );
    let error = rm(&["web", "web"]).run(&home).await.expect_err("web twice");
    assert!(error.downcast_ref::<Usage>().is_some(), "exit 2: {error:#}");
    assert!(!home.serve_toml().exists(), "nothing read or written");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// An entry with no name or no target is a usage error, with the line that fills the missing half.
#[tokio::test]
async fn an_entry_with_no_name_or_target_is_a_usage_error() {
    let home = temp_home("unnamed");
    for (entry, line) in [
        (
            "db",
            "invalid positional service definition at index 1: invalid target form",
        ),
        (
            "tcp:localhost:3000",
            "invalid positional service definition at index 1: invalid target form",
        ),
    ] {
        let error = add(&[entry]).run(&home).await.expect_err("refused");
        assert!(error.downcast_ref::<Usage>().is_some(), "exit 2: {error:#}");
        assert_eq!(format!("{error:#}"), line);
    }
    assert!(!home.serve_toml().exists(), "nothing written");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// `rm` of the last entry records an empty list, which reads back empty and starts nothing: never the
/// default.
#[tokio::test]
async fn an_emptied_list_survives_a_write_and_read() {
    let home = temp_home("emptied");
    list(&home, &["ssh=tcp:localhost:22"]);
    rm(&["ssh"]).run(&home).await.expect("rm ssh");
    assert_eq!(
        std::fs::read_to_string(home.serve_toml()).expect("the file"),
        "services = []\n"
    );
    let file = ServeToml::read(&home).expect("read");
    assert_eq!(file.services, Some(Vec::new()));
    let started = Started::bare(&file).expect("an empty list starts");
    assert!(started.entries().is_empty(), "{started:?}");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// No writer keeps a list that names one service twice: a file edited to hold one is refused, naming the
/// file, by `add`, `rm` and a bare start alike, and the file is left as it is.
#[tokio::test]
async fn no_writer_keeps_a_duplicate_name() {
    let home = temp_home("duplicate");
    list(&home, &["web=tcp:localhost:3000", "web=tcp:localhost:4000"]);
    let before = std::fs::read_to_string(home.serve_toml()).expect("the file");
    let line = "invalid saved service definition at index 2: service name already used";
    let error = add(&["probe=echo:"]).run(&home).await.expect_err("refused");
    assert!(error.downcast_ref::<Usage>().is_none(), "exit 1");
    assert_eq!(format!("{error:#}"), line);
    let error = rm(&["web"]).run(&home).await.expect_err("refused");
    assert_eq!(format!("{error:#}"), line);
    let file = ServeToml::read(&home).expect("read");
    let error = Started::bare(&file).expect_err("a start refuses");
    assert_eq!(error.to_string(), line);
    assert_eq!(
        std::fs::read_to_string(home.serve_toml()).expect("the file"),
        before
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// No writer keeps a list holding an entry that is not a service: a file edited to hold a name with no
/// target, or a target with no name, is refused, exit 1, naming the file, by `add`, `rm` and a bare start
/// alike, never as a usage error, and the file is left as it is.
#[tokio::test]
async fn no_writer_keeps_an_entry_that_is_not_a_service() {
    for (tag, entry) in [("no-target", "db"), ("no-name", "tcp:localhost:3000")] {
        let home = temp_home(tag);
        list(&home, &["web=tcp:localhost:4000", entry]);
        let before = std::fs::read_to_string(home.serve_toml()).expect("the file");
        let line = "invalid saved service definition at index 2: invalid target form";
        let error = add(&["probe=echo:"]).run(&home).await.expect_err("refused");
        assert!(error.downcast_ref::<Usage>().is_none(), "{entry}: exit 1");
        assert_eq!(format!("{error:#}"), line);
        let error = rm(&["web"]).run(&home).await.expect_err("refused");
        assert!(error.downcast_ref::<Usage>().is_none(), "{entry}: exit 1");
        assert_eq!(format!("{error:#}"), line);
        let file = ServeToml::read(&home).expect("read");
        let error = Started::bare(&file).expect_err("a start refuses");
        assert_eq!(error.to_string(), line);
        assert_eq!(
            std::fs::read_to_string(home.serve_toml()).expect("the file"),
            before,
            "{entry}: nothing written"
        );
        let _ = std::fs::remove_dir_all(home.dir());
    }
}

#[tokio::test]
async fn add_cli_never_echoes_credentials_or_writes_a_valid_prefix() {
    let home = temp_home("safe-add-error");
    list(&home, &["speed=speed:"]);
    let before = std::fs::read(home.serve_toml()).unwrap();
    let entry = "bad=proxy:https://user:secret@host.test/?token=private";
    let parsed = crate::Cli::try_parse_from([
        "swoosh",
        "service",
        "add",
        "raw=stdin:",
        "drop=recv:",
        entry,
    ])
    .unwrap();
    let Some(crate::Command::Service {
        command: Some(super::super::ServiceCmd::Add(cmd)),
    }) = parsed.command
    else {
        panic!("service add parses")
    };
    let error = cmd.run(&home).await.unwrap_err();
    assert!(error.downcast_ref::<Usage>().is_some());
    assert_eq!(
        error.to_string(),
        "invalid positional service definition at index 3: invalid proxy origin"
    );
    for cause in error.chain() {
        let text = format!("{cause:?} {cause}");
        for forbidden in [entry, "secret", "private", "host.test"] {
            assert!(!text.contains(forbidden), "{text}");
        }
    }
    assert_eq!(std::fs::read(home.serve_toml()).unwrap(), before);
    assert_eq!(std::fs::read_dir(home.dir()).unwrap().count(), 1);
    let _ = std::fs::remove_dir_all(home.dir());
}

/// The full CLI rejects a reserved add before it can record an unmanageable list.
#[tokio::test]
async fn service_add_refuses_reserved_names_before_home_writes() {
    let home = temp_home("reserved");
    list(&home, &["ssh=tcp:localhost:22"]);
    let original = std::fs::read(home.serve_toml()).unwrap();
    let before = std::fs::metadata(home.serve_toml())
        .unwrap()
        .modified()
        .unwrap();
    for entry in [
        "control",
        "lookup",
        "CONTROL",
        "LookUp",
        "control=ping:",
        "lookup=ping:",
        "CONTROL=ping:",
        "LookUp=ping:",
    ] {
        let parsed = crate::Cli::try_parse_from([
            "swoosh",
            "--home",
            home.dir().to_str().unwrap(),
            "service",
            "add",
            entry,
        ])
        .expect("the raw operand is not echoed by a value parser");
        let Some(crate::Command::Service {
            command: Some(super::super::ServiceCmd::Add(cmd)),
        }) = parsed.command
        else {
            panic!("service add parses");
        };
        let error = cmd
            .run(&home)
            .await
            .expect_err("reserved names refuse before home writes");
        assert!(error.downcast_ref::<Usage>().is_some());
        assert_eq!(
            error.to_string(),
            "invalid positional service definition at index 1: invalid service name"
        );
        assert_eq!(std::fs::read(home.serve_toml()).unwrap(), original);
        assert_eq!(
            std::fs::metadata(home.serve_toml())
                .unwrap()
                .modified()
                .unwrap(),
            before
        );
        assert_eq!(std::fs::read_dir(home.dir()).unwrap().count(), 1);
    }
    let _ = std::fs::remove_dir_all(home.dir());
}
