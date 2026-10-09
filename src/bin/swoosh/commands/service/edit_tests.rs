//! Tests for `service add` and `service rm` against a home: what each writes to `<home>/serve.toml`, all
//! or nothing, the lines each prints, and the usage errors.

use clap::Parser as _;
use swoosh::home::Home;
use swoosh::serve::{Added, Started};
use swoosh::serve_toml::ServeToml;

use super::{ServiceAddCmd, ServiceRmCmd, Usage, added_line};
use crate::commands::service::Running;

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

/// An add records the entry in `serve.toml`, and its line says it is served from the next start, whether
/// or not a `serve` runs: it binds nothing now.
#[tokio::test]
async fn service_add_records_and_names_the_next_start() {
    let home = temp_home("records");
    list(&home, &["ssh=sshd:"]);
    add(&["web=tcp:localhost:3000"])
        .run(&home)
        .await
        .expect("add web");
    assert_eq!(
        listed(&home),
        Some(vec![
            "ssh=sshd:".to_owned(),
            "web=tcp:localhost:3000".to_owned()
        ])
    );
    assert_eq!(
        added_line(&Added::New("web".to_owned()), None),
        "Added web; it is served when swoosh serve next starts."
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// The lines for a name already listed: plain, or with when it is served when the running `serve` did
/// not bind it, or with how to turn it on when it is off.
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
        "ssh is already listed; it is served when swoosh serve next starts."
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
    add(&["ssh"]).run(&home).await.expect("add ssh");
    assert_eq!(
        listed(&home),
        Some(vec![
            "ping=ping:".to_owned(),
            "speed=speed:".to_owned(),
            "ssh=sshd:".to_owned()
        ])
    );
    let _ = std::fs::remove_dir_all(home.dir());
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
    let error = add(&["ssh", "web=tcp:localhost:4000", "db=tcp:localhost:5432"])
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

/// `rm` drops the one entry named, with its `off` row, and keeps the rest.
#[tokio::test]
async fn service_rm_drops_one_entry() {
    let home = temp_home("rm-one");
    std::fs::write(
        home.serve_toml(),
        "off = [\"web\", \"ssh\"]\nservices = [\"ssh=sshd:\", \"web=tcp:localhost:3000\"]\n",
    )
    .expect("write serve.toml");
    rm(&["web"]).run(&home).await.expect("rm web");
    let file = ServeToml::read(&home).expect("read");
    assert_eq!(file.services, Some(vec!["ssh=sshd:".to_owned()]));
    assert_eq!(
        file.off.into_iter().collect::<Vec<_>>(),
        ["ssh"],
        "web's row goes"
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// Several typed, one not listed: nothing is removed, and `Nothing was removed.` sits under the refusal.
#[tokio::test]
async fn service_rm_of_several_is_all_or_nothing() {
    let home = temp_home("rm-several");
    list(&home, &["ssh=sshd:", "web=tcp:localhost:3000"]);
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
            "ssh=sshd:".to_owned(),
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
        "web is named twice; each service needs its own name"
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
        ("db", "db needs a target, like db=tcp:<address>:<port>"),
        (
            "tcp:localhost:3000",
            "tcp:localhost:3000 needs a name, like web=tcp:localhost:3000",
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
    list(&home, &["ssh=sshd:"]);
    rm(&["ssh"]).run(&home).await.expect("rm ssh");
    assert_eq!(
        std::fs::read_to_string(home.serve_toml()).expect("the file"),
        "services = []\n"
    );
    let file = ServeToml::read(&home).expect("read");
    assert_eq!(file.services, Some(Vec::new()));
    let started = Started::bare(&file, &home.serve_toml()).expect("an empty list starts");
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
    let path = home.serve_toml();
    let line = format!(
        "web is named twice in {}\n  Each service needs its own name; swoosh will not guess which one to keep.",
        path.display()
    );
    let error = add(&["ssh"]).run(&home).await.expect_err("refused");
    assert!(error.downcast_ref::<Usage>().is_none(), "exit 1");
    assert_eq!(format!("{error:#}"), line);
    let error = rm(&["web"]).run(&home).await.expect_err("refused");
    assert_eq!(format!("{error:#}"), line);
    let file = ServeToml::read(&home).expect("read");
    let error = Started::bare(&file, &path).expect_err("a start refuses");
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
        let path = home.serve_toml();
        let line = format!(
            "{} lists {entry} as a service, and it is not one, so serve will not start unless you name its \
             services",
            path.display()
        );
        let error = add(&["ssh"]).run(&home).await.expect_err("refused");
        assert!(error.downcast_ref::<Usage>().is_none(), "{entry}: exit 1");
        assert_eq!(format!("{error:#}"), line);
        let error = rm(&["web"]).run(&home).await.expect_err("refused");
        assert!(error.downcast_ref::<Usage>().is_none(), "{entry}: exit 1");
        assert_eq!(format!("{error:#}"), line);
        let file = ServeToml::read(&home).expect("read");
        let error = Started::bare(&file, &path).expect_err("a start refuses");
        assert_eq!(error.to_string(), line);
        assert_eq!(
            std::fs::read_to_string(home.serve_toml()).expect("the file"),
            before,
            "{entry}: nothing written"
        );
        let _ = std::fs::remove_dir_all(home.dir());
    }
}
