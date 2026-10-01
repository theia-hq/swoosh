//! Tests for the `service enable`/`disable` file toggle: the round-trip on the services off in
//! `<home>/serve.toml`, the sorted rewrite, and idempotency.

use std::collections::BTreeSet;

use swoosh::home::Home;

use super::{ServiceToggleCmd, disabled};

/// A fresh, empty home under a unique temp dir, so parallel tests never share a `<home>/serve.toml`.
fn temp_home(tag: &str) -> Home {
    let dir = std::env::temp_dir().join(format!("swoosh-toggle-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the temp home");
    Home::resolve(Some(dir)).expect("resolve the temp home")
}

/// The disabled set currently on disk, read back through the same parse the oracle uses.
fn disabled_on_disk(home: &Home) -> BTreeSet<String> {
    disabled(home).expect("read serve.toml")
}

/// A `disable` writes the name into `<home>/serve.toml`; an `enable` takes it back out. The core round-trip.
#[tokio::test]
async fn disable_then_enable_round_trips() {
    let home = temp_home("round-trip");

    ServiceToggleCmd {
        service: "speed".parse().expect("a service"),
    }
    .run_disable(&home)
    .await
    .expect("disable speed");
    assert!(
        disabled_on_disk(&home).contains("speed"),
        "speed is written to the disabled file"
    );

    ServiceToggleCmd {
        service: "speed".parse().expect("a service"),
    }
    .run_enable(&home)
    .await
    .expect("enable speed");
    assert!(
        !disabled_on_disk(&home).contains("speed"),
        "speed is removed from the disabled file"
    );

    let _ = std::fs::remove_dir_all(home.dir());
}

/// Disabling accumulates distinct names and the file is name-sorted (a clean diff, the denylist's shape).
#[tokio::test]
async fn disables_accumulate_sorted_and_idempotent() {
    let home = temp_home("accumulate");

    for name in ["speed", "ping", "speed"] {
        ServiceToggleCmd {
            service: name.parse().expect("a service"),
        }
        .run_disable(&home)
        .await
        .expect("disable");
    }

    let on_disk = disabled_on_disk(&home);
    assert_eq!(
        on_disk.iter().cloned().collect::<Vec<_>>(),
        vec!["ping".to_owned(), "speed".to_owned()],
        "distinct names only (idempotent), name-sorted"
    );

    // The raw file holds the names sorted.
    let body = std::fs::read_to_string(home.serve_toml()).expect("read raw");
    assert_eq!(body, "off = [\"ping\", \"speed\"]\n", "sorted");

    let _ = std::fs::remove_dir_all(home.dir());
}

/// Enabling a service that was never disabled is a no-op, not an error (idempotent).
#[tokio::test]
async fn enable_of_an_untouched_service_is_a_noop() {
    let home = temp_home("enable-noop");
    ServiceToggleCmd {
        service: "ping".parse().expect("a service"),
    }
    .run_enable(&home)
    .await
    .expect("enable a never-disabled service succeeds");
    assert!(disabled_on_disk(&home).is_empty(), "nothing disabled");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// `serve.toml` is the one file for what `serve` runs: a `serve` that names its services, `service off`,
/// and `serve --relay --resolver` each land their own field in it and keep every field the others wrote,
/// and the home holds no file of its own for any of them.
#[tokio::test]
async fn serve_toml_holds_services_off_relay_and_resolver() {
    use swoosh::serve::Started;
    use swoosh::serve_toml::ServeToml;
    use swoosh::transport::{ReachArgs, Transport};

    let home = temp_home("one-file");
    let read = || ServeToml::read(&home).expect("read serve.toml");

    Started::of(&["ssh=sshd:".to_owned()], &home, std::path::Path::new("/"))
        .expect("named")
        .record(&swoosh::home::HomeWrite::take(&home).await.unwrap(), &home)
        .expect("a named serve records its services");
    assert_eq!(read().services, ["ssh=sshd:"]);

    ServiceToggleCmd {
        service: "speed".parse().expect("a service"),
    }
    .run_disable(&home)
    .await
    .expect("disable");
    assert_eq!(read().services, ["ssh=sshd:"], "the services stay");
    assert_eq!(read().off, BTreeSet::from(["speed".to_owned()]));

    ReachArgs {
        transport: Transport::default(),
        local: false,
        peer: Vec::new(),
        relay: Some("https://relay.example".parse().expect("a relay")),
        resolver: Some("https://dns.example/pkarr".parse().expect("a resolver")),
    }
    .persist_reach(&home)
    .await
    .expect("serve keeps its relay and resolver");
    let all = read();
    assert_eq!(all.services, ["ssh=sshd:"], "the services stay");
    assert_eq!(
        all.off,
        BTreeSet::from(["speed".to_owned()]),
        "so do the off"
    );
    assert_eq!(all.relay.as_deref(), Some("https://relay.example/"));
    assert_eq!(all.resolver.as_deref(), Some("https://dns.example/pkarr"));

    ServiceToggleCmd {
        service: "speed".parse().expect("a service"),
    }
    .run_enable(&home)
    .await
    .expect("enable");
    let all = read();
    assert!(all.off.is_empty(), "speed is back on");
    assert!(
        all.services.len() == 1 && all.relay.is_some() && all.resolver.is_some(),
        "and the rest stay: {all:?}"
    );

    for gone in ["serving", "disabled", "relay", "resolver"] {
        assert!(!home.dir().join(gone).exists(), "no {gone} file");
    }
    let _ = std::fs::remove_dir_all(home.dir());
}

/// `service --help` lists `enable` and `disable` on rows of at most 100 columns, and names no home file:
/// a person is never meant to open `serve.toml`.
#[test]
fn enable_and_disable_help_rows_fit_and_name_no_file() {
    use clap::CommandFactory as _;

    let mut cli = crate::Cli::command();
    let help = cli
        .find_subcommand_mut("service")
        .expect("service is a top-level verb")
        .render_help()
        .to_string();
    for verb in ["enable", "disable"] {
        let row = help
            .lines()
            .find(|line| line.trim_start().starts_with(verb))
            .unwrap_or_else(|| panic!("a {verb} row: {help}"));
        assert!(
            row.chars().count() <= 100,
            "{verb}'s row is too wide: {row}"
        );
        assert!(
            !row.contains("serve.toml"),
            "{verb}'s row names a file: {row}"
        );
    }
}
